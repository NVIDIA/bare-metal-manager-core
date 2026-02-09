/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::collections::{HashMap, HashSet};

use carbide_uuid::infiniband::IBPartitionId;
use carbide_uuid::machine::MachineId;
use common::api_fixtures::ib_partition::{DEFAULT_TENANT, create_ib_partition};
use common::api_fixtures::instance::{config_for_ib_config, create_instance_with_ib_config};
use common::api_fixtures::{TestEnv, create_managed_host};
use model::ib::DEFAULT_IB_FABRIC_NAME;
use model::machine::ManagedHostState;
use rpc::forge::forge_server::Forge;
use rpc::forge::{IbPartitionStatus, TenantState};
use tonic::Request;

use crate::api::Api;
use crate::cfg::file::IBFabricConfig;
use crate::ib::{Filter, IBFabric, IBFabricManager};
use crate::tests::common;
use crate::tests::common::api_fixtures::TestEnvOverrides;

async fn get_partition_status(api: &Api, ib_partition_id: IBPartitionId) -> IbPartitionStatus {
    let segment = api
        .find_ib_partitions_by_ids(Request::new(rpc::forge::IbPartitionsByIdsRequest {
            ib_partition_ids: vec![ib_partition_id],
            include_history: false,
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

    // select the second MT2910 Family [ConnectX-7] and the first MT27800 Family [ConnectX-5] which are sorted by slots
    let ib_config = rpc::forge::InstanceInfinibandConfig {
        ib_interfaces: vec![
            rpc::forge::InstanceIbInterfaceConfig {
                function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                virtual_function_id: None,
                ib_partition_id: Some(ib_partition_id),
                device: "MT2910 Family [ConnectX-7]".to_string(),
                vendor: None,
                device_instance: 1,
            },
            rpc::forge::InstanceIbInterfaceConfig {
                function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                virtual_function_id: None,
                ib_partition_id: Some(ib_partition_id),
                device: "MT27800 Family [ConnectX-5]".to_string(),
                vendor: None,
                device_instance: 0,
            },
        ],
    };

    // Check which GUIDs these device/device_instance combinations should map to
    let machine_guids = guids_by_device(&machine);
    let guid_cx7 = machine_guids.get("MT2910 Family [ConnectX-7]").unwrap()[1].clone();
    let guid_cx5 = machine_guids.get("MT27800 Family [ConnectX-5]").unwrap()[0].clone();

    let (tinstance, instance) =
        create_instance_with_ib_config(&env, &mh, ib_config.clone(), segment_id).await;

    let machine = mh.host().rpc_machine().await;
    assert_eq!(&machine.state, "Assigned/Ready");
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machines_with_missing_pkeys_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machines_with_unexpected_pkeys_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machines_with_unknown_pkeys_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .parsed_metrics("carbide_ib_monitor_ufm_changes_applied_total"),
        vec![
            (
                "{fabric=\"default\",operation=\"bind_guid_to_pkey\",status=\"error\"}".to_string(),
                "0".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"bind_guid_to_pkey\",status=\"ok\"}".to_string(),
                "2".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"unbind_guid_from_pkey\",status=\"error\"}"
                    .to_string(),
                "0".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"unbind_guid_from_pkey\",status=\"ok\"}"
                    .to_string(),
                "0".to_string()
            )
        ]
    );

    let check_instance = tinstance.rpc_instance().await;
    assert_eq!(instance.machine_id(), mh.id);
    assert_eq!(instance.status().tenant(), rpc::TenantState::Ready);
    assert_eq!(instance, check_instance);

    let applied_ib_config = check_instance.config().infiniband();
    assert_eq!(*applied_ib_config, ib_config);

    let ib_status = check_instance.status().infiniband();
    assert_eq!(ib_status.configs_synced(), rpc::SyncState::Synced);
    assert_eq!(ib_status.ib_interfaces.len(), 2);

    if let Some(iface) = ib_status.ib_interfaces.first() {
        assert_eq!(iface.pf_guid, Some(guid_cx7.clone()));
        assert_eq!(iface.guid, Some(guid_cx7.clone()));
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
        .new_client(DEFAULT_IB_FABRIC_NAME)
        .await
        .unwrap();
    verify_pkey_guids(
        ib_conn.clone(),
        &[(pkey_u16, vec![guid_cx5.clone(), guid_cx7.clone()])],
    )
    .await;

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

    tinstance.delete().await;

    // Check whether the IB ports are still bound to the partition
    verify_pkey_guids(ib_conn.clone(), &[(pkey_u16, vec![])]).await;
    assert_eq!(
        env.test_meter
            .parsed_metrics("carbide_ib_monitor_ufm_changes_applied_total"),
        vec![
            (
                "{fabric=\"default\",operation=\"bind_guid_to_pkey\",status=\"error\"}".to_string(),
                "0".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"bind_guid_to_pkey\",status=\"ok\"}".to_string(),
                "2".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"unbind_guid_from_pkey\",status=\"error\"}"
                    .to_string(),
                "0".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"unbind_guid_from_pkey\",status=\"ok\"}"
                    .to_string(),
                "2".to_string()
            )
        ]
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
                ib_partition_id: Some(ib_partition_id),
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
                ib_partition_id: Some(ib_partition_id),
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
                    ib_partition_id: Some(ib_partition_id),
                    device: "MT2910 Family [ConnectX-7]".to_string(), // no ib devices
                    vendor: None,
                    device_instance: 0,
                },
                rpc::forge::InstanceIbInterfaceConfig {
                    function_type: rpc::forge::InterfaceFunctionType::Physical as _,
                    virtual_function_id: None,
                    ib_partition_id: Some(ib_partition_id),
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
        error.contains("is configured more than once"),
        "Error message should contain 'is configured more than once', but is {error}"
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
                    ib_partition_id: Some(ib_partition_id),
                    device: "MT2910 Family [ConnectX-7]".to_string(),
                    vendor: None,
                    device_instance: 1,
                },
                rpc::forge::InstanceIbInterfaceConfig {
                    function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                    virtual_function_id: None,
                    ib_partition_id: Some(ib_partition_id),
                    device: "MT27800 Family [ConnectX-5]".to_string(),
                    vendor: None,
                    device_instance: 0,
                },
            ],
        },
    )
    .await;

    let error = result.expect_err("expected allocation to fail").to_string();
    let expected_err =
        format!("IB Partition {ib_partition_id} is not owned by the tenant {DEFAULT_TENANT}",);
    assert!(
        error.contains(&expected_err),
        "Error message should contain '{expected_err}', but is {error}"
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
                    ib_partition_id: Some(ib_partition_id),
                    device: device_name.clone(),
                    vendor: None,
                    device_instance: 0,
                },
                // guids[1]
                rpc::forge::InstanceIbInterfaceConfig {
                    function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                    virtual_function_id: None,
                    ib_partition_id: Some(ib_partition_id),
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

#[crate::sqlx_test]
async fn test_update_instance_ib_config(pool: sqlx::PgPool) {
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
    let segment_id: carbide_uuid::network::NetworkSegmentId =
        env.create_vpc_and_tenant_segment().await;

    let (ib_partition1_id, ib_partition1) = create_ib_partition(
        &env,
        "test_ib_partition1".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;
    let hex_pkey1 = ib_partition1.status.as_ref().unwrap().pkey().to_string();
    let pkey1_u16: u16 = u16::from_str_radix(
        hex_pkey1
            .strip_prefix("0x")
            .expect("Pkey needs to be in hex format"),
        16,
    )
    .expect("Failed to parse string to integer");
    let (ib_partition2_id, ib_partition2) = create_ib_partition(
        &env,
        "test_ib_partition2".to_string(),
        DEFAULT_TENANT.to_string(),
    )
    .await;
    let hex_pkey2 = ib_partition2.status.as_ref().unwrap().pkey().to_string();
    let pkey2_u16: u16 = u16::from_str_radix(
        hex_pkey2
            .strip_prefix("0x")
            .expect("Pkey needs to be in hex format"),
        16,
    )
    .expect("Failed to parse string to integer");

    let mh = create_managed_host(&env).await;
    let machine = mh.host().rpc_machine().await;

    assert_eq!(&machine.state, "Ready");
    let discovery_info = machine.discovery_info.as_ref().unwrap();
    let machine_guids = guids_by_device(&machine);
    assert_eq!(discovery_info.infiniband_interfaces.len(), 6);
    assert!(machine.ib_status.as_ref().is_some());
    assert_eq!(machine.ib_status.as_ref().unwrap().ib_interfaces.len(), 6);

    // select the second MT2910 Family [ConnectX-7] and the first MT27800 Family [ConnectX-5] which are sorted by slots
    let ib_config = rpc::forge::InstanceInfinibandConfig {
        ib_interfaces: vec![
            rpc::forge::InstanceIbInterfaceConfig {
                function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                virtual_function_id: None,
                ib_partition_id: Some(ib_partition1_id),
                device: "MT2910 Family [ConnectX-7]".to_string(),
                vendor: None,
                device_instance: 0,
            },
            rpc::forge::InstanceIbInterfaceConfig {
                function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                virtual_function_id: None,
                ib_partition_id: Some(ib_partition2_id),
                device: "MT2910 Family [ConnectX-7]".to_string(),
                vendor: None,
                device_instance: 1,
            },
        ],
    };

    // Check which GUIDs these device/device_instance combinations should map to
    let guid_cx7_1 = machine_guids.get("MT2910 Family [ConnectX-7]").unwrap()[0].clone();
    let guid_cx7_2 = machine_guids.get("MT2910 Family [ConnectX-7]").unwrap()[1].clone();
    let guid_cx5_1 = machine_guids.get("MT27800 Family [ConnectX-5]").unwrap()[0].clone();

    let (tinstance, instance) =
        create_instance_with_ib_config(&env, &mh, ib_config.clone(), segment_id).await;

    let machine = mh.host().rpc_machine().await;
    assert_eq!(&machine.state, "Assigned/Ready");
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machines_with_missing_pkeys_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machines_with_unexpected_pkeys_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machines_with_unknown_pkeys_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .parsed_metrics("carbide_ib_monitor_ufm_changes_applied_total"),
        vec![
            (
                "{fabric=\"default\",operation=\"bind_guid_to_pkey\",status=\"error\"}".to_string(),
                "0".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"bind_guid_to_pkey\",status=\"ok\"}".to_string(),
                "2".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"unbind_guid_from_pkey\",status=\"error\"}"
                    .to_string(),
                "0".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"unbind_guid_from_pkey\",status=\"ok\"}"
                    .to_string(),
                "0".to_string()
            )
        ]
    );

    let check_instance = tinstance.rpc_instance().await;
    assert_eq!(instance.machine_id(), mh.id);
    assert_eq!(instance.status().tenant(), rpc::TenantState::Ready);
    assert_eq!(instance, check_instance);
    let initial_config_version = instance.config_version();
    let initial_ib_config_version = instance.ib_config_version();
    let initial_network_config_version = instance.network_config_version();

    let applied_ib_config = check_instance.config().infiniband();
    assert_eq!(*applied_ib_config, ib_config);

    let ib_status = check_instance.status().infiniband();
    assert_eq!(ib_status.configs_synced(), rpc::SyncState::Synced);
    assert_eq!(ib_status.ib_interfaces.len(), 2);

    if let Some(iface) = ib_status.ib_interfaces.first() {
        assert_eq!(iface.pf_guid, Some(guid_cx7_1.clone()));
        assert_eq!(iface.guid, Some(guid_cx7_1.clone()));
    } else {
        panic!("ib configuration is incorrect.");
    }

    if let Some(iface) = ib_status.ib_interfaces.get(1) {
        assert_eq!(iface.pf_guid, Some(guid_cx7_2.clone()));
        assert_eq!(iface.guid, Some(guid_cx7_2.clone()));
    } else {
        panic!("ib configuration is incorrect.");
    }

    // Check if ports have been registered at UFM
    let ib_conn = env
        .ib_fabric_manager
        .new_client(DEFAULT_IB_FABRIC_NAME)
        .await
        .unwrap();
    verify_pkey_guids(
        ib_conn.clone(),
        &[
            (pkey1_u16, vec![guid_cx7_1.clone()]),
            (pkey2_u16, vec![guid_cx7_2.clone()]),
        ],
    )
    .await;

    // Update the IB config. This deletes one interface, and adds another one
    let ib_config2 = rpc::forge::InstanceInfinibandConfig {
        ib_interfaces: vec![
            rpc::forge::InstanceIbInterfaceConfig {
                function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                virtual_function_id: None,
                ib_partition_id: Some(ib_partition2_id),
                device: "MT2910 Family [ConnectX-7]".to_string(),
                vendor: None,
                device_instance: 1,
            },
            rpc::forge::InstanceIbInterfaceConfig {
                function_type: rpc::forge::InterfaceFunctionType::Physical as i32,
                virtual_function_id: None,
                ib_partition_id: Some(ib_partition2_id),
                device: "MT27800 Family [ConnectX-5]".to_string(),
                vendor: None,
                device_instance: 0,
            },
        ],
    };

    let mut new_config = instance.config().inner().clone();
    new_config.infiniband = Some(ib_config2.clone());

    let instance = env
        .api
        .update_instance_config(tonic::Request::new(
            rpc::forge::InstanceConfigUpdateRequest {
                instance_id: instance.id().into(),
                if_version_match: None,
                config: Some(new_config.clone()),
                metadata: Some(instance.metadata().clone()),
            },
        ))
        .await
        .unwrap()
        .into_inner();
    let instance_status = instance.status.as_ref().unwrap();
    assert_eq!(instance_status.configs_synced(), rpc::SyncState::Pending);
    assert_eq!(
        instance_status.tenant.as_ref().unwrap().state(),
        rpc::TenantState::Configuring
    );

    let applied_ib_config = instance
        .config
        .as_ref()
        .unwrap()
        .infiniband
        .as_ref()
        .unwrap();
    assert_eq!(*applied_ib_config, ib_config2);

    let ib_status = instance_status.infiniband.as_ref().unwrap();
    assert_eq!(ib_status.configs_synced(), rpc::SyncState::Pending);
    assert_eq!(ib_status.ib_interfaces.len(), 2);

    if let Some(iface) = ib_status.ib_interfaces.first() {
        assert_eq!(iface.pf_guid, Some(guid_cx7_2.clone()));
        assert_eq!(iface.guid, Some(guid_cx7_2.clone()));
    } else {
        panic!("ib configuration is incorrect.");
    }

    if let Some(iface) = ib_status.ib_interfaces.get(1) {
        assert_eq!(iface.pf_guid, Some(guid_cx5_1.clone()));
        assert_eq!(iface.guid, Some(guid_cx5_1.clone()));
    } else {
        panic!("ib configuration is incorrect.");
    }

    // DPU needs to acknowledge the newest config version
    mh.network_configured(&env).await;

    // First IB partition fabric monitor iteration detects the desync and fixes it
    env.run_ib_fabric_monitor_iteration().await;
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machine_ib_status_updates_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machines_with_missing_pkeys_count")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machines_with_unexpected_pkeys_count")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .parsed_metrics("carbide_ib_monitor_ufm_changes_applied_total"),
        vec![
            (
                "{fabric=\"default\",operation=\"bind_guid_to_pkey\",status=\"error\"}".to_string(),
                "0".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"bind_guid_to_pkey\",status=\"ok\"}".to_string(),
                "3".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"unbind_guid_from_pkey\",status=\"error\"}"
                    .to_string(),
                "0".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"unbind_guid_from_pkey\",status=\"ok\"}"
                    .to_string(),
                "1".to_string()
            )
        ]
    );
    verify_pkey_guids(
        ib_conn.clone(),
        &[
            (pkey1_u16, vec![]),
            (pkey2_u16, vec![guid_cx7_2.clone(), guid_cx5_1.clone()]),
        ],
    )
    .await;

    // Second IB partition fabric monitor reports no desync
    env.run_ib_fabric_monitor_iteration().await;
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machine_ib_status_updates_count")
            .unwrap(),
        "1"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machines_with_missing_pkeys_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .formatted_metric("carbide_ib_monitor_machines_with_unexpected_pkeys_count")
            .unwrap(),
        "0"
    );
    assert_eq!(
        env.test_meter
            .parsed_metrics("carbide_ib_monitor_ufm_changes_applied_total"),
        vec![
            (
                "{fabric=\"default\",operation=\"bind_guid_to_pkey\",status=\"error\"}".to_string(),
                "0".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"bind_guid_to_pkey\",status=\"ok\"}".to_string(),
                "3".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"unbind_guid_from_pkey\",status=\"error\"}"
                    .to_string(),
                "0".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"unbind_guid_from_pkey\",status=\"ok\"}"
                    .to_string(),
                "1".to_string()
            )
        ]
    );

    // Instance shows ready state again
    let instance = tinstance.rpc_instance().await;
    let instance_status = instance.status();
    assert_eq!(instance_status.configs_synced(), rpc::SyncState::Synced);
    assert_eq!(instance_status.tenant(), rpc::TenantState::Ready);
    let new_config_version = instance.config_version();
    let new_ib_config_version = instance.ib_config_version();
    let new_network_config_version = instance.network_config_version();
    assert_eq!(
        new_config_version.version_nr(),
        initial_config_version.version_nr() + 1
    );
    assert_eq!(
        new_ib_config_version.version_nr(),
        initial_ib_config_version.version_nr() + 1
    );
    assert_eq!(new_network_config_version, initial_network_config_version);

    let applied_ib_config = instance.config().infiniband();
    assert_eq!(*applied_ib_config, ib_config2);

    let ib_status = instance_status.infiniband();
    assert_eq!(ib_status.configs_synced(), rpc::SyncState::Synced);
    assert_eq!(ib_status.ib_interfaces.len(), 2);

    if let Some(iface) = ib_status.ib_interfaces.first() {
        assert_eq!(iface.pf_guid, Some(guid_cx7_2.clone()));
        assert_eq!(iface.guid, Some(guid_cx7_2.clone()));
    } else {
        panic!("ib configuration is incorrect.");
    }

    if let Some(iface) = ib_status.ib_interfaces.get(1) {
        assert_eq!(iface.pf_guid, Some(guid_cx5_1.clone()));
        assert_eq!(iface.guid, Some(guid_cx5_1.clone()));
    } else {
        panic!("ib configuration is incorrect.");
    }

    tinstance.delete().await;

    // Check whether all partition bindings have been removed
    verify_pkey_guids(
        ib_conn.clone(),
        &[
            (pkey1_u16, Vec::<String>::new()),
            (pkey2_u16, Vec::<String>::new()),
        ],
    )
    .await;
    assert_eq!(
        env.test_meter
            .parsed_metrics("carbide_ib_monitor_ufm_changes_applied_total"),
        vec![
            (
                "{fabric=\"default\",operation=\"bind_guid_to_pkey\",status=\"error\"}".to_string(),
                "0".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"bind_guid_to_pkey\",status=\"ok\"}".to_string(),
                "3".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"unbind_guid_from_pkey\",status=\"error\"}"
                    .to_string(),
                "0".to_string()
            ),
            (
                "{fabric=\"default\",operation=\"unbind_guid_from_pkey\",status=\"ok\"}"
                    .to_string(),
                "3".to_string()
            )
        ]
    );
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
            machine_id: Some(*host_machine_id),
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
    let instance_id: uuid::Uuid = instance.id.expect("Missing instance ID").into();
    Ok((instance_id, instance))
}

fn guids_by_device(machine: &rpc::forge::Machine) -> HashMap<String, Vec<String>> {
    let mut ib_ifaces = machine
        .discovery_info
        .as_ref()
        .unwrap()
        .infiniband_interfaces
        .clone();
    ib_ifaces.sort_by_key(|iface| iface.pci_properties.as_ref().unwrap().slot().to_string());

    let mut guids: HashMap<String, Vec<String>> = HashMap::new();
    for iface in ib_ifaces.iter() {
        let device = iface
            .pci_properties
            .as_ref()
            .unwrap()
            .description()
            .to_string();
        guids.entry(device).or_default().push(iface.guid.clone());
    }

    guids
}

async fn verify_pkey_guids(
    ib_conn: std::sync::Arc<dyn IBFabric>,
    pkey_to_guids: &[(u16, Vec<String>)],
) {
    for (pkey_u16, expected_guids) in pkey_to_guids {
        let ports = ib_conn
            .find_ib_port(Some(Filter {
                guids: None,
                pkey: Some(*pkey_u16),
                state: None,
            }))
            .await
            .unwrap();
        let actual_guids: HashSet<String> = ports.into_iter().map(|port| port.guid).collect();
        let expected_guids: HashSet<String> = expected_guids.iter().cloned().collect();
        assert_eq!(actual_guids, expected_guids);
    }
}
