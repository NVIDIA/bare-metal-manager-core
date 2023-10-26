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
    db::{
        instance_address::InstanceAddress,
        machine::{Machine, MachineSearchConfig},
    },
    model::machine::{machine_id::MachineId, InstanceState, ManagedHostState},
};

use common::api_fixtures::{
    create_managed_host, create_test_env,
    ib_partition::create_ib_partition,
    instance::{create_instance_with_config, delete_instance},
    network_segment::FIXTURE_NETWORK_SEGMENT_ID,
    TestEnv,
};
use rpc::forge::forge_server::Forge;

pub mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_create_instance_with_ib_config(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (ib_partition_id, _ib_partition) =
        create_ib_partition(&env, "test_ib_partition".to_string()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = pool
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
        create_instance(&env, &dpu_machine_id, &host_machine_id, ib_config).await;

    let mut txn = pool
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
    if let Some(iface) = ib_config.ib_interfaces.get(0) {
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
    if let Some(iface) = ib_status.ib_interfaces.get(0) {
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
    let mut txn = pool
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
        InstanceAddress::count_by_segment_id(&mut txn, FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        0
    );
    txn.commit().await.unwrap();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_can_not_create_instance_for_not_enough_ib_device(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (ib_partition_id, _ib_partition) =
        create_ib_partition(&env, "test_ib_partition".to_string()).await;
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
    let env = create_test_env(pool.clone()).await;
    let (ib_partition_id, _ib_partition) =
        create_ib_partition(&env, "test_ib_partition".to_string()).await;
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
    let env = create_test_env(pool.clone()).await;
    let (ib_partition_id, _ib_partition) =
        create_ib_partition(&env, "test_ib_partition".to_string()).await;
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

pub async fn create_instance(
    env: &TestEnv,
    dpu_machine_id: &MachineId,
    host_machine_id: &MachineId,
    ib_config: rpc::forge::InstanceInfinibandConfig,
) -> (uuid::Uuid, rpc::forge::Instance) {
    let config = config_for_ib_config(ib_config);

    create_instance_with_config(env, dpu_machine_id, host_machine_id, config).await
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
            ssh_keys: vec![],
        }))
        .await?;

    let instance = instance.into_inner();
    let instance_id =
        uuid::Uuid::try_from(instance.id.clone().expect("Missing instance ID")).unwrap();
    Ok((instance_id, instance))
}

fn config_for_ib_config(
    ib_config: rpc::forge::InstanceInfinibandConfig,
) -> rpc::forge::InstanceConfig {
    let network = rpc::forge::InstanceNetworkConfig {
        interfaces: vec![rpc::forge::InstanceInterfaceConfig {
            function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    };

    rpc::forge::InstanceConfig {
        tenant: Some(rpc::TenantConfig {
            user_data: Some("SomeRandomData".to_string()),
            custom_ipxe: "SomeRandomiPxe".to_string(),
            tenant_organization_id: "Tenant1".to_string(),
            tenant_keyset_ids: vec![],
            always_boot_with_custom_ipxe: false,
        }),
        network: Some(network),
        infiniband: Some(ib_config),
    }
}
