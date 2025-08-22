/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::cfg::file::IBFabricConfig;
use crate::ib::{DEFAULT_IB_FABRIC_NAME, Filter, IBFabricManager};
use crate::tests::common;
use crate::tests::common::api_fixtures::TestEnvOverrides;
use crate::{api::Api, model::machine::ManagedHostState};
use common::api_fixtures::{
    TestEnv, create_managed_host,
    ib_partition::{DEFAULT_TENANT, create_ib_partition},
    instance::{config_for_ib_config, create_instance_with_ib_config},
};
use forge_uuid::infiniband::IBPartitionId;
use forge_uuid::machine::MachineId;
use rpc::forge::{IbPartitionSearchConfig, IbPartitionStatus, TenantState, forge_server::Forge};
use tonic::Request;

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

#[crate::sqlx_test]
async fn test_create_instance_with_ib_config(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        mtu: crate::ib::IBMtu(2),
        rate_limit: crate::ib::IBRateLimit(10),
        max_partition_per_tenant: 16,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;
    let segment_id = env.create_vpc_and_tenant_segment().await;

    let (ib_partition_id, ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;
    let hex_pkey = ib_partition.status.as_ref().unwrap().pkey().to_string();
    let pkey_u16: u16 = u16::from_str_radix(
        hex_pkey
            .strip_prefix("0x")
            .expect("Pkey needs to be in hex format"),
        16,
    )
    .expect("Failed to parse string to integer");

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
    assert_eq!(&hex_pkey, ib_partition_status.pkey.as_ref().unwrap());
    assert!(ib_partition_status.mtu.is_none());
    assert!(ib_partition_status.rate_limit.is_none());
    assert!(ib_partition_status.service_level.is_none());

    let mh = create_managed_host(&env).await;
    let machine = mh.host().rpc_machine().await;

    assert_eq!(&machine.state, "Ready");
    let discovery_info = machine.discovery_info.as_ref().unwrap();
    assert_eq!(discovery_info.infiniband_interfaces.len(), 6);
    assert!(machine.ib_status.as_ref().is_some());
    assert_eq!(machine.ib_status.as_ref().unwrap().ib_interfaces.len(), 6);

    let mut ib_ifaces = discovery_info.infiniband_interfaces.clone();
    ib_ifaces.sort_by_key(|iface| iface.pci_properties.as_ref().unwrap().slot().to_string());

    // select the second MT2910 Family [ConnectX-7] and the first MT27800 Family [ConnectX-5] which are sorted by slots
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

    // Check which GUIDs these device/device_instance combinations should map to
    let guid_cx7 = ib_ifaces
        .iter()
        .filter(|iface| {
            iface.pci_properties.as_ref().unwrap().description() == "MT2910 Family [ConnectX-7]"
        })
        .nth(1)
        .unwrap()
        .guid
        .clone();
    let guid_cx5 = ib_ifaces
        .iter()
        .find(|iface| {
            iface.pci_properties.as_ref().unwrap().description() == "MT27800 Family [ConnectX-5]"
        })
        .unwrap()
        .guid
        .clone();

    let (instance_id, instance) =
        create_instance_with_ib_config(&env, &mh, ib_config.clone(), segment_id).await;

    let machine = mh.host().rpc_machine().await;
    assert_eq!(&machine.state, "Assigned/Ready");
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_ib_monitor_machines_with_missing_pkeys_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_ib_monitor_machines_with_unexpected_pkeys_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("forge_ib_monitor_machines_with_unknown_pkeys_count")
            .unwrap(),
        "0"
    );

    let check_instance = env.one_instance(instance_id).await;
    assert_eq!(instance.machine_id(), mh.id);
    assert_eq!(instance.status().tenant(), rpc::TenantState::Ready);
    assert_eq!(instance, check_instance);

    let ib_config = check_instance.config().infiniband();
    assert_eq!(ib_config.ib_interfaces.len(), 2);

    let ib_status = check_instance.status().infiniband();
    assert_eq!(ib_status.configs_synced(), rpc::SyncState::Synced);
    assert_eq!(ib_status.ib_interfaces.len(), 2);

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
        assert_eq!(iface.pf_guid, Some(guid_cx7.clone()));
        assert_eq!(iface.guid, Some(guid_cx7.clone()));
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
        assert_eq!(iface.pf_guid, Some(guid_cx5.clone()));
        assert_eq!(iface.guid, Some(guid_cx5.clone()));
    } else {
        panic!("ib configuration is incorrect.");
    }

    // Check if ports have been registered at UFM
    let ib_conn = env
        .ib_fabric_manager
        .connect(DEFAULT_IB_FABRIC_NAME)
        .await
        .unwrap();
    let ports = ib_conn
        .find_ib_port(Some(Filter {
            guids: None,
            pkey: Some(pkey_u16),
            state: None,
        }))
        .await
        .unwrap();
    assert_eq!(
        ports.len(),
        2,
        "The expected amount of ports for pkey {hex_pkey} has not been registered"
    );

    mh.delete_instance(&env, instance_id).await;

    // Check whether the IB ports are still bound to the partition
    let ports = ib_conn
        .find_ib_port(Some(Filter {
            guids: None,
            pkey: Some(pkey_u16),
            state: None,
        }))
        .await
        .unwrap();
    assert!(
        ports.is_empty(),
        "IB ports have not been removed for pkey {hex_pkey}"
    );
}

#[crate::sqlx_test]
async fn test_can_not_create_instance_for_not_enough_ib_device(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let (ib_partition_id, _ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

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
        "Error message should contain 'not enough ib device', but is {error}"
    );
}

#[crate::sqlx_test]
async fn test_can_not_create_instance_for_no_ib_device(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let (ib_partition_id, _ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

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
        "Error message should contain 'no ib device', but is {error}"
    );
}

#[crate::sqlx_test]
async fn test_can_not_create_instance_for_reuse_ib_device(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let (ib_partition_id, _ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

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
        "Error message should contain 'is reused', but is {error}"
    );
}

#[crate::sqlx_test]
async fn test_can_not_create_instance_with_inconsistent_tenant(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let (ib_partition_id, _ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        "FAKE_TENANT".to_string(),
    )
    .await;
    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await.into();

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
        "Error message should contain 'instance inconsistent with the tenant', but is {error}"
    );
}

#[crate::sqlx_test]
async fn test_can_not_create_instance_for_inactive_ib_device(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: true,
        mtu: crate::ib::IBMtu(2),
        rate_limit: crate::ib::IBRateLimit(100),
        max_partition_per_tenant: 8,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let (ib_partition_id, _ib_partition) = create_ib_partition(
        &env,
        "test_ib_partition".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;

    env.run_ib_partition_controller_iteration().await;

    let mh = create_managed_host(&env).await;
    let machine = mh.host().rpc_machine().await;

    let discovery_info = machine.discovery_info.as_ref().unwrap();
    // Use only CX7 interfaces in this test
    let device_name = "MT2910 Family [ConnectX-7]".to_string();
    let mut cx7_ifaces: Vec<_> = discovery_info
        .infiniband_interfaces
        .iter()
        .filter(|iface| {
            iface
                .pci_properties
                .as_ref()
                .unwrap()
                .description
                .as_ref()
                .unwrap()
                == &device_name
        })
        .collect();
    cx7_ifaces.sort_by_key(|iface| iface.pci_properties.as_ref().unwrap().slot());

    // Find the first IB Port of the Machine in order to down it
    let guids = [cx7_ifaces[0].guid.clone(), cx7_ifaces[1].guid.clone()];

    env.ib_fabric_manager
        .get_mock_manager()
        .set_port_state(&guids[1], false);
    env.run_ib_fabric_monitor_iteration().await;

    let result = try_allocate_instance(
        &env,
        &mh.id,
        rpc::forge::InstanceInfinibandConfig {
            ib_interfaces: vec![
                // guids[0]
                rpc::forge::InstanceIbInterfaceConfig {
                    function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                    virtual_function_id: None,
                    ib_partition_id: Some(ib_partition_id.into()),
                    device: device_name.clone(),
                    vendor: None,
                    device_instance: 0,
                },
                // guids[1]
                rpc::forge::InstanceIbInterfaceConfig {
                    function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                    virtual_function_id: None,
                    ib_partition_id: Some(ib_partition_id.into()),
                    device: device_name.clone(),
                    vendor: None,
                    device_instance: 1,
                },
            ],
        },
    )
    .await;

    let expected_err = format!("UFM detected inactive state for GUID: {}", guids[1]);

    assert!(result.is_err());
    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains(&expected_err),
        "Error message should contain '{expected_err}', but is '{error}'"
    );
}

#[crate::sqlx_test]
async fn test_ib_skip_update_infiniband_status(pool: sqlx::PgPool) {
    let mut config = common::api_fixtures::get_config();
    config.ib_config = Some(IBFabricConfig {
        enabled: false,
        ..Default::default()
    });

    let env = common::api_fixtures::create_test_env_with_overrides(
        pool,
        TestEnvOverrides::with_config(config),
    )
    .await;

    let mh = create_managed_host(&env).await;

    env.run_machine_state_controller_iteration().await;

    let mut txn = env
        .pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let machine = mh.host().db_machine(&mut txn).await;
    txn.commit().await.unwrap();

    assert_eq!(machine.current_state(), &ManagedHostState::Ready);
    assert!(!machine.is_dpu());
    assert!(machine.hardware_info.as_ref().is_some());
    assert_eq!(
        machine
            .hardware_info
            .as_ref()
            .unwrap()
            .infiniband_interfaces
            .len(),
        6
    );
    assert!(machine.infiniband_status_observation.as_ref().is_none());
}

/// Tries to create an Instance using the Forge API
/// This does not drive the instance state machine until the ready state.
pub async fn try_allocate_instance(
    env: &TestEnv,
    host_machine_id: &MachineId,
    ib_config: rpc::forge::InstanceInfinibandConfig,
) -> Result<(uuid::Uuid, rpc::forge::Instance), tonic::Status> {
    let segment_id = env.create_vpc_and_tenant_segment().await;
    let config = config_for_ib_config(ib_config, segment_id);

    let instance = env
        .api
        .allocate_instance(tonic::Request::new(rpc::forge::InstanceAllocationRequest {
            instance_id: None,
            machine_id: host_machine_id.into(),
            instance_type_id: None,
            config: Some(config),
            metadata: Some(rpc::forge::Metadata {
                name: "test_instance".to_string(),
                description: "tests/ib_instance".to_string(),
                labels: Vec::new(),
            }),
            allow_unhealthy_machine: false,
        }))
        .await?;

    let instance = instance.into_inner();
    let instance_id =
        uuid::Uuid::try_from(instance.id.clone().expect("Missing instance ID")).unwrap();
    Ok((instance_id, instance))
}
