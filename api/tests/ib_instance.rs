/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide::{
    api::rpc::IbPartitionSearchConfig,
    api::Api,
    cfg::IBFabricConfig,
    db::{
        instance_address::InstanceAddress,
        machine::{Machine, MachineSearchConfig},
    },
    model::machine::{InstanceState, ManagedHostState},
};
use common::api_fixtures::{
    create_managed_host, create_test_env,
    ib_partition::{create_ib_partition, DEFAULT_TENANT},
    instance::{config_for_ib_config, create_instance_with_ib_config, delete_instance},
    network_segment::FIXTURE_NETWORK_SEGMENT_ID,
    TestEnv, TestEnvOverrides,
};
use forge_uuid::infiniband::IBPartitionId;
use forge_uuid::machine::MachineId;
use rpc::forge::{forge_server::Forge, IbPartitionStatus, TenantState};
use tonic::Request;

pub mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

async fn get_partition_status(api: &Api, ib_partition_id: IBPartitionId) -> IbPartitionStatus {
    let segment = api
        .find_ib_partitions(Request::new(rpc::forge::IbPartitionQuery {
            id: Some(ib_partition_id.into()),
            search_config: Some(IbPartitionSearchConfig {
                include_history: false,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .ib_partitions
        .remove(0);

    segment.status.unwrap()
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_create_instance_with_ib_config(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        mtu: carbide::ib::IBMtu(2),
        rate_limit: carbide::ib::IBRateLimit(10),
        max_partition_per_tenant: 16,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let (ib_partition_id, ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;

    env.run_ib_partition_controller_iteration().await;

    let ib_partition_status = get_partition_status(&env.api, ib_partition_id).await;
    assert_eq!(
        TenantState::try_from(ib_partition_status.state).unwrap(),
        TenantState::Ready
    );
    assert_eq!(
        ib_partition.status.clone().unwrap().state,
        ib_partition_status.state
    );
    assert_eq!(
        ib_partition.status.clone().unwrap().pkey,
        ib_partition_status.pkey
    );
    assert!(ib_partition_status.pkey.is_some());
    assert!(ib_partition_status.mtu.is_none());
    assert!(ib_partition_status.rate_limit.is_none());
    assert!(ib_partition_status.service_level.is_none());

    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = env
        .pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert!(matches!(
        Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    txn.commit().await.unwrap();

    env.run_ib_partition_controller_iteration().await;

    let ib_partition_status = get_partition_status(&env.api, ib_partition_id).await;
    assert_eq!(
        TenantState::try_from(ib_partition_status.state).unwrap(),
        TenantState::Ready
    );
    assert!(ib_partition_status.pkey.is_some());
    assert!(ib_partition_status.mtu.is_none());
    assert!(ib_partition_status.rate_limit.is_none());
    assert!(ib_partition_status.service_level.is_none());

    let ib_config = rpc::forge::InstanceInfinibandConfig {
        ib_interfaces: vec![
            rpc::forge::InstanceIbInterfaceConfig {
                function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                virtual_function_id: None,
                ib_partition_id: Some(ib_partition_id.into()),
                device: "MT2910 Family [ConnectX-7]".to_string(),
                vendor: None,
                device_instance: 1,
            },
            rpc::forge::InstanceIbInterfaceConfig {
                function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                virtual_function_id: None,
                ib_partition_id: Some(ib_partition_id.into()),
                device: "MT27800 Family [ConnectX-5]".to_string(),
                vendor: None,
                device_instance: 0,
            },
        ],
    };

    let (instance_id, _instance) =
        create_instance_with_ib_config(&env, &dpu_machine_id, &host_machine_id, ib_config.clone())
            .await;

    let mut txn = env
        .pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    assert!(matches!(
        Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Assigned {
            instance_state: InstanceState::Ready
        }
    ));
    txn.commit().await.unwrap();

    env.run_ib_partition_controller_iteration().await;

    let ib_partition_status = get_partition_status(&env.api, ib_partition_id).await;
    assert_eq!(
        TenantState::try_from(ib_partition_status.state).unwrap(),
        TenantState::Ready
    );
    assert!(ib_partition_status.pkey.is_some());
    assert_eq!(ib_partition_status.mtu.unwrap(), 2);
    assert_eq!(ib_partition_status.rate_limit.unwrap(), 10);
    assert_eq!(
        ib_partition_status.service_level.unwrap(),
        carbide::ib::IBServiceLevel::default().0
    );

    let instance = env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .remove(0);
    assert_eq!(
        instance.machine_id.clone().unwrap().id,
        host_machine_id.to_string()
    );
    assert_eq!(
        instance
            .status
            .as_ref()
            .unwrap()
            .tenant
            .as_ref()
            .unwrap()
            .state(),
        rpc::TenantState::Ready
    );

    let ib_config = instance
        .config
        .as_ref()
        .unwrap()
        .infiniband
        .as_ref()
        .unwrap();
    let ib_status = instance
        .status
        .as_ref()
        .unwrap()
        .infiniband
        .as_ref()
        .unwrap();

    assert_eq!(ib_config.ib_interfaces.len(), 2);
    // select the second MT2910 Family [ConnectX-7] and the first MT27800 Family [ConnectX-5] which are sorted by slots
    // |       device               |    slot    |        guid       |   index |
    // MT2910 Family [ConnectX-7]    0000:b1:00.0    946dae03002ac103      0
    // MT2910 Family [ConnectX-7]    0000:b1:00.1    946dae03002ac102      1
    // MT2910 Family [ConnectX-7]    0000:c1:00.0    946dae03002ac101      2
    // MT2910 Family [ConnectX-7]    0000:c1:00.1    946dae03002ac100      3
    // MT27800 Family [ConnectX-5]   0000:98:00.0    946dae03002ac752      0
    // MT27800 Family [ConnectX-5]   0000:98:00.1    946dae03002ac753      1
    if let Some(iface) = ib_config.ib_interfaces.first() {
        assert_eq!(
            iface.function_type,
            rpc::forge::InterfaceFunctionType::Physical as i32
        );
        assert_eq!(iface.virtual_function_id, None);
        assert_eq!(iface.device, "MT2910 Family [ConnectX-7]");
        assert_eq!(iface.vendor, None);
        assert_eq!(iface.device_instance, 1);
        assert_eq!(iface.ib_partition_id, Some(ib_partition_id.into()));
    } else {
        panic!("ib configuration is incorrect.");
    }
    if let Some(iface) = ib_status.ib_interfaces.first() {
        assert_eq!(iface.pf_guid, Some("946dae03002ac102".to_string()));
        assert_eq!(iface.guid, Some("946dae03002ac102".to_string()));
    } else {
        panic!("ib configuration is incorrect.");
    }

    if let Some(iface) = ib_config.ib_interfaces.get(1) {
        assert_eq!(
            iface.function_type,
            rpc::forge::InterfaceFunctionType::Physical as i32
        );
        assert_eq!(iface.virtual_function_id, None);
        assert_eq!(iface.device, "MT27800 Family [ConnectX-5]");
        assert_eq!(iface.vendor, None);
        assert_eq!(iface.device_instance, 0);
        assert_eq!(iface.ib_partition_id, Some(ib_partition_id.into()));
    } else {
        panic!("ib configuration is incorrect.");
    }
    if let Some(iface) = ib_status.ib_interfaces.get(1) {
        assert_eq!(iface.pf_guid, Some("946dae03002ac752".to_string()));
        assert_eq!(iface.guid, Some("946dae03002ac752".to_string()));
    } else {
        panic!("ib configuration is incorrect.");
    }

    delete_instance(&env, instance_id, &dpu_machine_id, &host_machine_id).await;

    // Address is freed during delete
    let mut txn = env
        .pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert!(matches!(
        Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, *FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        0
    );
    txn.commit().await.unwrap();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_can_not_create_instance_for_not_enough_ib_device(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (ib_partition_id, _ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let result = try_allocate_instance(
        &env,
        &host_machine_id,
        rpc::forge::InstanceInfinibandConfig {
            ib_interfaces: vec![rpc::forge::InstanceIbInterfaceConfig {
                function_type: rpc::forge::InterfaceFunctionType::Physical as _,
                virtual_function_id: None,
                ib_partition_id: Some(ib_partition_id.into()),
                device: "MT2910 Family [ConnectX-7]".to_string(),
                vendor: None,
                device_instance: 10, // not enough devices
            }],
        },
    )
    .await;

    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("not enough ib device"),
        "Error message should contain 'not enough ib device', but is {}",
        error
    );
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_can_not_create_instance_for_no_ib_device(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (ib_partition_id, _ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let result = try_allocate_instance(
        &env,
        &host_machine_id,
        rpc::forge::InstanceInfinibandConfig {
            ib_interfaces: vec![rpc::forge::InstanceIbInterfaceConfig {
                function_type: rpc::forge::InterfaceFunctionType::Physical as _,
                virtual_function_id: None,
                ib_partition_id: Some(ib_partition_id.into()),
                device: "MT28908  Family [ConnectX-6]".to_string(), // no ib devices
                vendor: None,
                device_instance: 0,
            }],
        },
    )
    .await;

    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("no ib device"),
        "Error message should contain 'no ib device', but is {}",
        error
    );
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_can_not_create_instance_for_reuse_ib_device(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (ib_partition_id, _ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let result = try_allocate_instance(
        &env,
        &host_machine_id,
        rpc::forge::InstanceInfinibandConfig {
            ib_interfaces: vec![
                rpc::forge::InstanceIbInterfaceConfig {
                    function_type: rpc::forge::InterfaceFunctionType::Physical as _,
                    virtual_function_id: None,
                    ib_partition_id: Some(ib_partition_id.into()),
                    device: "MT2910 Family [ConnectX-7]".to_string(), // no ib devices
                    vendor: None,
                    device_instance: 0,
                },
                rpc::forge::InstanceIbInterfaceConfig {
                    function_type: rpc::forge::InterfaceFunctionType::Physical as _,
                    virtual_function_id: None,
                    ib_partition_id: Some(ib_partition_id.into()),
                    device: "MT2910 Family [ConnectX-7]".to_string(), // no ib devices
                    vendor: None,
                    device_instance: 0,
                },
            ],
        },
    )
    .await;

    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("is reused"),
        "Error message should contain 'is reused', but is {}",
        error
    );
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_can_not_create_instance_with_inconsistent_tenant(pool: sqlx::PgPool) {
    let env = create_test_env(pool).await;
    let (ib_partition_id, _ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        "FAKE_TENANT".to_string(),
    )
    .await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

    let result = try_allocate_instance(
        &env,
        &host_machine_id,
        rpc::forge::InstanceInfinibandConfig {
            ib_interfaces: vec![
                rpc::forge::InstanceIbInterfaceConfig {
                    function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                    virtual_function_id: None,
                    ib_partition_id: Some(ib_partition_id.into()),
                    device: "MT2910 Family [ConnectX-7]".to_string(),
                    vendor: None,
                    device_instance: 1,
                },
                rpc::forge::InstanceIbInterfaceConfig {
                    function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                    virtual_function_id: None,
                    ib_partition_id: Some(ib_partition_id.into()),
                    device: "MT27800 Family [ConnectX-5]".to_string(),
                    vendor: None,
                    device_instance: 0,
                },
            ],
        },
    )
    .await;

    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("instance inconsistent with the tenant"),
        "Error message should contain 'instance inconsistent with the tenant', but is {}",
        error
    );
}

/// Tries to create an Instance using the Forge API
/// This does not drive the instance state machine until the ready state.
pub async fn try_allocate_instance(
    env: &TestEnv,
    host_machine_id: &MachineId,
    ib_config: rpc::forge::InstanceInfinibandConfig,
) -> Result<(uuid::Uuid, rpc::forge::Instance), tonic::Status> {
    let config = config_for_ib_config(ib_config);

    let instance = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            instance_id: None,
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(config),
            metadata: Some(rpc::forge::Metadata {
                name: "test_instance".to_string(),
                description: "tests/ib_instance".to_string(),
                labels: Vec::new(),
            }),
        }))
        .await?;

    let instance = instance.into_inner();
    let instance_id =
        uuid::Uuid::try_from(instance.id.clone().expect("Missing instance ID")).unwrap();
    Ok((instance_id, instance))
}
