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
use std::{collections::HashMap, net::IpAddr, time::SystemTime};

use ::rpc::forge::forge_server::Forge;
use carbide::{
    db::{
        dhcp_record::InstanceDhcpRecord,
        instance::{status::network::update_instance_network_status_observation, Instance},
        instance_address::InstanceAddress,
        machine::{Machine, MachineSearchConfig},
        ObjectFilter, UuidKeyedObjectFilter,
    },
    instance::{allocate_instance, InstanceAllocationRequest},
    model::{
        instance::{
            config::{
                infiniband::{InstanceIbInterfaceConfig, InstanceInfinibandConfig},
                network::{InstanceNetworkConfig, InterfaceFunctionId, InterfaceFunctionType},
                tenant_config::TenantConfig,
                InstanceConfig,
            },
            status::{
                network::{
                    InstanceInterfaceStatus, InstanceInterfaceStatusObservation,
                    InstanceNetworkStatusObservation,
                },
                tenant::TenantState,
                SyncState,
            },
        },
        machine::machine_id::try_parse_machine_id,
        machine::{InstanceState, ManagedHostState},
        tenant::TenantOrganizationId,
    },
    state_controller::{
        machine::handler::MachineStateHandler,
        snapshot_loader::{DbSnapshotLoader, InstanceSnapshotLoader, MachineStateSnapshotLoader},
    },
};
use chrono::Utc;
use common::api_fixtures::{
    create_managed_host, create_test_env, dpu,
    ib_subnet::create_ib_subnet,
    instance::{create_instance, delete_instance, FIXTURE_CIRCUIT_ID},
    network_segment::{FIXTURE_NETWORK_SEGMENT_ID, FIXTURE_NETWORK_SEGMENT_ID_1},
};
use mac_address::MacAddress;

pub mod common;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_crud_instance(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let dpu_loopback_ip = dpu::loopback_ip(&mut txn, &dpu_machine_id).await;
    assert!(Instance::find_by_relay_ip(&mut txn, dpu_loopback_ip)
        .await
        .unwrap()
        .is_none());
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        0
    );
    assert!(matches!(
        Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
            .await
            .unwrap()
            .unwrap()
            .current_state(),
        ManagedHostState::Ready
    ));
    txn.commit().await.unwrap();

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    });

    let (instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        network,
        None,
        vec![],
    )
    .await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let fetched_instance = Instance::find_by_relay_ip(&mut txn, dpu_loopback_ip)
        .await
        .unwrap()
        .unwrap_or_else(|| {
            panic!("find_by_relay_ip for loopback {dpu_loopback_ip} didn't find any instances")
        });
    assert_eq!(fetched_instance.machine_id, host_machine_id);
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        1
    );

    let network_config = fetched_instance.network_config.clone();
    assert_eq!(network_config.version.version_nr(), 1);
    let mut network_config_no_addresses = network_config.value.clone();
    for iface in network_config_no_addresses.interfaces.iter_mut() {
        assert_eq!(iface.ip_addrs.len(), 1);
        iface.ip_addrs.clear();
    }
    assert_eq!(
        network_config_no_addresses,
        InstanceNetworkConfig::for_segment_id(FIXTURE_NETWORK_SEGMENT_ID)
    );

    assert!(fetched_instance.network_status_observation.is_some());
    assert!(fetched_instance.use_custom_pxe_on_boot);

    let _ = Instance::use_custom_ipxe_on_next_boot(&host_machine_id, false, &mut txn).await;
    let fetched_instance = Instance::find_by_relay_ip(&mut txn, dpu_loopback_ip)
        .await
        .unwrap()
        .unwrap();

    assert!(!fetched_instance.use_custom_pxe_on_boot);
    txn.commit().await.unwrap();

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    // TODO: The MAC here doesn't matter. It's not used for lookup
    let parsed_mac = "ff:ff:ff:ff:ff:ff".parse::<MacAddress>().unwrap();
    let record = InstanceDhcpRecord::find_for_instance(
        &mut txn,
        parsed_mac,
        FIXTURE_CIRCUIT_ID.to_string(),
        fetched_instance,
    )
    .await
    .unwrap();

    // This should the first IP. Algo does not look into machine_interface_addresses
    // table for used addresses for instance.
    assert_eq!(record.address().to_string(), "192.0.2.3");
    assert_eq!(
        &record.address(),
        network_config.value.interfaces[0]
            .ip_addrs
            .iter()
            .next()
            .unwrap()
            .1
    );
    let machine = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let snapshot_loader = DbSnapshotLoader {};
    let snapshot = snapshot_loader
        .load_instance_snapshot(&mut txn, instance_id, machine.current_state())
        .await
        .unwrap();

    let tenant_config = snapshot
        .config
        .tenant
        .as_ref()
        .expect("Expecting tenant status");
    assert_eq!(
        tenant_config,
        &TenantConfig {
            user_data: Some("SomeRandomData".to_string()),
            custom_ipxe: "SomeRandomiPxe".to_string(),
            tenant_organization_id: TenantOrganizationId::try_from("Tenant1".to_string()).unwrap(),
            tenant_keyset_ids: vec![],
        }
    );

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
async fn test_instance_network_status_sync(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    });

    let (instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        network,
        None,
        vec![],
    )
    .await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    // When no network status has been observed, we report an interface
    // list with no IPs and MACs to the user
    let snapshot_loader = DbSnapshotLoader {};
    let machine = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let snapshot = snapshot_loader
        .load_instance_snapshot(&mut txn, instance_id, machine.current_state())
        .await
        .unwrap();

    let pf_addr = *snapshot.config.network.interfaces[0]
        .ip_addrs
        .iter()
        .next()
        .unwrap()
        .1;

    let mut updated_network_status = InstanceNetworkStatusObservation {
        config_version: snapshot.network_config_version,
        interfaces: vec![InstanceInterfaceStatusObservation {
            function_id: InterfaceFunctionId::Physical {},
            mac_address: None,
            addresses: vec![pf_addr],
        }],
        observed_at: Utc::now(),
    };

    update_instance_network_status_observation(&mut txn, instance_id, &updated_network_status)
        .await
        .unwrap();

    let machine = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();

    let snapshot = snapshot_loader
        .load_instance_snapshot(&mut txn, instance_id, machine.current_state())
        .await
        .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
        Some(&updated_network_status)
    );

    let status = snapshot.derive_status().unwrap();
    assert_eq!(status.configs_synced, SyncState::Synced);
    assert_eq!(status.network.configs_synced, SyncState::Synced);
    assert_eq!(status.infiniband.configs_synced, SyncState::Synced);
    assert_eq!(status.tenant.as_ref().unwrap().state, TenantState::Ready);
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::Physical {},
            mac_address: None,
            addresses: vec![pf_addr],
        }]
    );

    updated_network_status.interfaces[0].mac_address =
        Some(MacAddress::new([11, 12, 13, 14, 15, 16]).into());
    update_instance_network_status_observation(&mut txn, instance_id, &updated_network_status)
        .await
        .unwrap();
    let machine = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let snapshot = snapshot_loader
        .load_instance_snapshot(&mut txn, instance_id, machine.current_state())
        .await
        .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
        Some(&updated_network_status)
    );
    let status = snapshot.derive_status().unwrap();
    assert_eq!(status.configs_synced, SyncState::Synced);
    assert_eq!(status.network.configs_synced, SyncState::Synced);
    assert_eq!(status.tenant.as_ref().unwrap().state, TenantState::Ready);
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::Physical {},
            mac_address: Some(MacAddress::new([11, 12, 13, 14, 15, 16])),
            addresses: vec![pf_addr],
        }]
    );

    // Assuming the config would change, the status should become unsynced again
    let next_config_version = snapshot.network_config_version.increment();
    let (_,): (uuid::Uuid,) = sqlx::query_as(
        "UPDATE instances SET network_config_version=$1 WHERE id = $2::uuid returning id",
    )
    .bind(&next_config_version.version_string())
    .bind(instance_id)
    .fetch_one(&mut *txn)
    .await
    .unwrap();
    let machine = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let snapshot = snapshot_loader
        .load_instance_snapshot(&mut txn, instance_id, machine.current_state())
        .await
        .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
        Some(&updated_network_status)
    );
    let status = snapshot.derive_status().unwrap();
    assert_eq!(status.configs_synced, SyncState::Pending);
    assert_eq!(status.network.configs_synced, SyncState::Pending);
    // TODO: This is wrong - it should become `Configuring`
    assert_eq!(
        status.tenant.as_ref().unwrap().state,
        TenantState::Provisioning
    );
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::Physical {},
            mac_address: None,
            addresses: Vec::new(),
        }]
    );

    // When the observation catches up, we are good again
    // The extra VF is ignored
    updated_network_status.config_version = next_config_version;
    updated_network_status
        .interfaces
        .push(InstanceInterfaceStatusObservation {
            function_id: InterfaceFunctionId::Virtual { id: 0 },
            mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 6]).into()),
            addresses: vec!["127.1.2.3".parse().unwrap()],
        });

    update_instance_network_status_observation(&mut txn, instance_id, &updated_network_status)
        .await
        .unwrap();
    let machine = Machine::find_one(&mut txn, &host_machine_id, MachineSearchConfig::default())
        .await
        .unwrap()
        .unwrap();
    let snapshot = snapshot_loader
        .load_instance_snapshot(&mut txn, instance_id, machine.current_state())
        .await
        .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
        Some(&updated_network_status)
    );
    let status = snapshot.derive_status().unwrap();
    assert_eq!(status.configs_synced, SyncState::Synced);
    assert_eq!(status.network.configs_synced, SyncState::Synced);
    assert_eq!(status.tenant.as_ref().unwrap().state, TenantState::Ready);
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::Physical {},
            mac_address: Some(MacAddress::new([11, 12, 13, 14, 15, 16])),
            addresses: vec![pf_addr],
        }]
    );

    txn.commit().await.unwrap();
    delete_instance(&env, instance_id, &dpu_machine_id, &host_machine_id).await;
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_snapshot_is_included_in_machine_snapshot(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let snapshot_loader = DbSnapshotLoader {};

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let snapshot = snapshot_loader
        .load_machine_snapshot(&mut txn, &host_machine_id)
        .await
        .unwrap();
    assert!(
        snapshot.instance.is_none(),
        "Expected instance snapshot to be not available"
    );
    txn.commit().await.unwrap();

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    });

    let (instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        network,
        None,
        vec![],
    )
    .await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let snapshot = snapshot_loader
        .load_machine_snapshot(&mut txn, &host_machine_id)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    let instance_snapshot = snapshot
        .instance
        .expect("Expected instance snapshot to be available");
    assert_eq!(instance_snapshot.network_config_version.version_nr(), 1);

    // We expect IP addresses to be allocated. but we can't compare them to the
    // request since they are automatically and randomly assigned
    let mut network_config = instance_snapshot.config.network.clone();
    assert_eq!(network_config.interfaces[0].ip_addrs.len(), 1);
    network_config.interfaces[0].ip_addrs.clear();
    assert_eq!(
        network_config,
        InstanceNetworkConfig::for_segment_id(FIXTURE_NETWORK_SEGMENT_ID)
    );

    assert_eq!(
        instance_snapshot.config.tenant,
        Some(TenantConfig {
            user_data: Some("SomeRandomData".to_string()),
            custom_ipxe: "SomeRandomiPxe".to_string(),
            tenant_organization_id: TenantOrganizationId::try_from("Tenant1".to_string()).unwrap(),
            tenant_keyset_ids: vec![],
        })
    );

    delete_instance(&env, instance_id, &dpu_machine_id, &host_machine_id).await;
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_can_not_create_instance_for_dpu(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();
    let dpu_machine_id = dpu::create_dpu_machine(&env, &host_sim.config).await;

    let request = InstanceAllocationRequest {
        machine_id: try_parse_machine_id(&dpu_machine_id).unwrap(),
        config: InstanceConfig {
            tenant: Some(TenantConfig {
                user_data: Some("SomeRandomData".to_string()),
                custom_ipxe: "SomeRandomiPxe".to_string(),
                tenant_organization_id: TenantOrganizationId::try_from("Tenant1".to_string())
                    .unwrap(),
                tenant_keyset_ids: vec![],
            }),
            network: InstanceNetworkConfig::for_segment_id(FIXTURE_NETWORK_SEGMENT_ID),
            infiniband: InstanceInfinibandConfig::for_ib_subnet_id(FIXTURE_NETWORK_SEGMENT_ID),
        },
        ssh_keys: vec!["mykey1".to_owned()],
    };

    // Note: This also requests a background task in the DB for creating managed
    // resources. That's however ok - we will just ignore it and not execute
    // that task. Later we might also verify that the creation of those resources
    // is requested
    let result = allocate_instance(request, &pool).await;
    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("is of type Dpu and can not be converted into an instance"),
        "Error message should contain 'is of type Dpu and can not be converted into an instance', but is {}",
        error
    );
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_address_creation(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, FIXTURE_NETWORK_SEGMENT_ID_1)
            .await
            .unwrap(),
        0
    );
    txn.commit().await.unwrap();

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID_1.into()),
            },
        ],
    });

    let (instance_id, instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        network,
        None,
        vec![],
    )
    .await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, FIXTURE_NETWORK_SEGMENT_ID_1)
            .await
            .unwrap(),
        1
    );

    // The addresses should show up in the internal config
    let snapshot_loader = DbSnapshotLoader {};
    let snapshot = snapshot_loader
        .load_machine_snapshot(&mut txn, &host_machine_id)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    let instance_snapshot = snapshot.instance.unwrap();
    let network_config = instance_snapshot.config.network;
    assert_eq!(network_config.interfaces[0].ip_addrs.len(), 1);
    assert_eq!(
        network_config.interfaces[0]
            .ip_addrs
            .iter()
            .next()
            .unwrap()
            .1,
        &"192.0.2.3".parse::<IpAddr>().unwrap()
    );
    assert_eq!(network_config.interfaces[1].ip_addrs.len(), 1);
    assert_eq!(
        network_config.interfaces[1]
            .ip_addrs
            .iter()
            .next()
            .unwrap()
            .1,
        &"192.0.3.3".parse::<IpAddr>().unwrap()
    );

    let segment_ip = HashMap::from([(None, "192.0.2.3"), (Some(0), "192.0.3.3")]);

    env.api
        .record_observed_instance_network_status(tonic::Request::new(
            rpc::InstanceNetworkStatusObservation {
                instance_id: Some(instance_id.into()),
                config_version: instance.network_config_version,
                observed_at: Some(SystemTime::now().into()),
                interfaces: vec![
                    rpc::InstanceInterfaceStatusObservation {
                        function_type: rpc::InterfaceFunctionType::from(
                            InterfaceFunctionType::Physical,
                        ) as i32,
                        virtual_function_id: None,
                        mac_address: None,
                        addresses: vec!["192.0.2.3".to_string()],
                    },
                    rpc::InstanceInterfaceStatusObservation {
                        function_type: rpc::InterfaceFunctionType::from(
                            InterfaceFunctionType::Virtual,
                        ) as i32,
                        virtual_function_id: Some(0),
                        mac_address: None,
                        addresses: vec!["192.0.3.3".to_string()],
                    },
                ],
            },
        ))
        .await
        .unwrap();

    let instance = &env
        .api
        .find_instances(tonic::Request::new(rpc::forge::InstanceSearchQuery {
            id: Some(instance_id.into()),
        }))
        .await
        .unwrap()
        .into_inner()
        .instances[0];

    for interface in instance.status.clone().unwrap().network.unwrap().interfaces {
        assert_eq!(
            interface.addresses[0],
            segment_ip
                .get(&interface.virtual_function_id)
                .unwrap()
                .to_owned()
        );
    }
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_instance_add_infiniband_data_via_migration(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    });

    let (instance_id, _instance) = create_instance(
        &env,
        &dpu_machine_id,
        &host_machine_id,
        network,
        None,
        vec![],
    )
    .await;

    let handler = MachineStateHandler::default();
    env.run_machine_state_controller_iteration(host_machine_id, &handler)
        .await;

    let instance = env
        .find_instances(Some(instance_id.into()))
        .await
        .instances
        .remove(0);
    let status = instance.status.as_ref().unwrap();
    assert_eq!(
        status.tenant.as_ref().unwrap().state(),
        rpc::TenantState::Ready
    );
    assert_eq!(status.configs_synced(), rpc::SyncState::Synced);
}

// TODO(gk) Restore after https://jirasw.nvidia.com/browse/FORGE-2243
//#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn _test_cannot_create_instance_on_unhealthy_dpu(pool: sqlx::PgPool) -> eyre::Result<()> {
    let env = create_test_env(pool.clone()).await;
    let (host_machine_id, dpu_machine_id) = create_managed_host(&env).await;
    let mut txn = pool.begin().await?;

    let machine = &Machine::find(
        &mut txn,
        ObjectFilter::One(host_machine_id.clone()),
        MachineSearchConfig::default(),
    )
    .await?[0];
    let (_, version) = machine.network_config().clone().take();

    // Give it an unhealthy network
    let netstat_req = tonic::Request::new(rpc::forge::DpuNetworkStatus {
        dpu_machine_id: Some(dpu_machine_id.to_string().into()),
        observed_at: None, // server sets it
        health: Some(rpc::forge::NetworkHealth {
            is_healthy: false,
            passed: vec![],
            failed: vec!["lol".to_string(), "everything".to_string()],
            message: Some("test_cannot_create_instance_on_unhealthy_dpu".to_string()),
        }),
        network_config_version: Some(version.version_string()),
        instance_config_version: None,
        interfaces: vec![rpc::InstanceInterfaceStatusObservation {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            virtual_function_id: None,
            mac_address: None,
            addresses: vec![],
        }],
        network_config_error: None,
        instance_id: None,
        dpu_agent_version: Some("test_cannot_create_instance_on_unhealthy_dpu".to_string()),
    });
    env.api.record_dpu_network_status(netstat_req).await?;

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    });

    let result = env
        .api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            machine_id: Some(rpc::MachineId {
                id: host_machine_id.to_string(),
            }),
            config: Some(rpc::InstanceConfig {
                tenant: Some(rpc::TenantConfig {
                    user_data: Some("SomeRandomData".to_string()),
                    custom_ipxe: "SomeRandomiPxe".to_string(),
                    tenant_organization_id: "Tenant1".to_string(),
                    tenant_keyset_ids: vec![],
                }),
                network,
                infiniband: None,
            }),
            ssh_keys: vec!["mykey1".to_owned()],
        }))
        .await;
    let Err(err) = result else {
        panic!("Creating an instance should have been refused");
    };
    if err.code() != tonic::Code::Unavailable {
        panic!("Expected grpc code UNAVAILABLE, got {}", err.code());
    }
    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_crud_instance_with_ib_config(pool: sqlx::PgPool) {
    let env = create_test_env(pool.clone()).await;
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

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    });

    let (ib_subnet_id, _ib_subnet) = create_ib_subnet(&env, "test_ib_subnet".to_string()).await;
    let ib = Some(rpc::InstanceInfinibandConfig {
        ib_interfaces: vec![
            rpc::InstanceIbInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                virtual_function_id: None,
                ib_subnet_id: Some(ib_subnet_id.into()),
                device: "MT2910 Family [ConnectX-7]".to_string(),
                vendor: None,
                device_instance: 1,
            },
            rpc::InstanceIbInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                virtual_function_id: None,
                ib_subnet_id: Some(ib_subnet_id.into()),
                device: "MT27800 Family [ConnectX-5]".to_string(),
                vendor: None,
                device_instance: 0,
            },
        ],
    });

    let (instance_id, _instance) =
        create_instance(&env, &dpu_machine_id, &host_machine_id, network, ib, vec![]).await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let fetched_instance_vec = Instance::find(&mut txn, UuidKeyedObjectFilter::One(instance_id))
        .await
        .expect("Could not find an instance");

    let Some(fetched_instance) = fetched_instance_vec.last() else {
        panic!("Could not find an instance for {}", instance_id);
    };

    assert_eq!(fetched_instance.machine_id, host_machine_id);
    assert_eq!(
        InstanceAddress::count_by_segment_id(&mut txn, FIXTURE_NETWORK_SEGMENT_ID)
            .await
            .unwrap(),
        1
    );

    let ib_config = fetched_instance.ib_config.clone();
    assert_eq!(ib_config.version.version_nr(), 1);
    let ibs = ib_config.value.clone();
    assert_eq!(ibs.ib_interfaces.len(), 2);
    // select the second MT2910 Family [ConnectX-7] and the first MT27800 Family [ConnectX-5] which are sorted by slots
    // |       device               |    slot    |        guid       |   index |
    // MT2910 Family [ConnectX-7]    0000:b1:00.0    946dae03002ac103      0
    // MT2910 Family [ConnectX-7]    0000:b1:00.1    946dae03002ac102      1
    // MT2910 Family [ConnectX-7]    0000:c1:00.0    946dae03002ac101      2
    // MT2910 Family [ConnectX-7]    0000:c1:00.1    946dae03002ac100      3
    // MT27800 Family [ConnectX-5]   0000:98:00.0    946dae03002ac752      0
    // MT27800 Family [ConnectX-5]   0000:98:00.1    946dae03002ac753      1
    if let Some(ib) = ibs.ib_interfaces.get(0) {
        assert_eq!(ib.guid, Some("946dae03002ac102".to_string()));
    } else {
        panic!("ib configuration is incorrect.");
    }
    if let Some(ib) = ibs.ib_interfaces.get(1) {
        assert_eq!(ib.guid, Some("946dae03002ac752".to_string()));
    } else {
        panic!("ib configuration is incorrect.");
    }

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

    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

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

    let (ib_subnet_id, _ib_subnet) = create_ib_subnet(&env, "test_ib_subnet".to_string()).await;

    let request = InstanceAllocationRequest {
        machine_id: host_machine_id.clone(),
        config: InstanceConfig {
            tenant: Some(TenantConfig {
                user_data: Some("SomeRandomData".to_string()),
                custom_ipxe: "SomeRandomiPxe".to_string(),
                tenant_organization_id: TenantOrganizationId::try_from("Tenant1".to_string())
                    .unwrap(),
                tenant_keyset_ids: vec![],
            }),
            network: InstanceNetworkConfig::for_segment_id(FIXTURE_NETWORK_SEGMENT_ID),
            infiniband: InstanceInfinibandConfig {
                ib_interfaces: vec![InstanceIbInterfaceConfig {
                    function_id: InterfaceFunctionId::Physical {},
                    ib_subnet_id,
                    guid: None,
                    device: "MT2910 Family [ConnectX-7]".to_string(),
                    vendor: None,
                    device_instance: 10, // not enough devices
                }],
            },
        },
        ssh_keys: vec!["mykey1".to_owned()],
    };

    let result = allocate_instance(request, &pool).await;
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

    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

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

    let (ib_subnet_id, _ib_subnet) = create_ib_subnet(&env, "test_ib_subnet".to_string()).await;

    let request = InstanceAllocationRequest {
        machine_id: host_machine_id.clone(),
        config: InstanceConfig {
            tenant: Some(TenantConfig {
                user_data: Some("SomeRandomData".to_string()),
                custom_ipxe: "SomeRandomiPxe".to_string(),
                tenant_organization_id: TenantOrganizationId::try_from("Tenant1".to_string())
                    .unwrap(),
                tenant_keyset_ids: vec![],
            }),
            network: InstanceNetworkConfig::for_segment_id(FIXTURE_NETWORK_SEGMENT_ID),
            infiniband: InstanceInfinibandConfig {
                ib_interfaces: vec![InstanceIbInterfaceConfig {
                    function_id: InterfaceFunctionId::Physical {},
                    ib_subnet_id,
                    guid: None,
                    device: "MT28908  Family [ConnectX-6]".to_string(), // no ib devices
                    vendor: None,
                    device_instance: 0,
                }],
            },
        },
        ssh_keys: vec!["mykey1".to_owned()],
    };

    let result = allocate_instance(request, &pool).await;
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

    let (host_machine_id, _dpu_machine_id) = create_managed_host(&env).await;

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

    let (ib_subnet_id, _ib_subnet) = create_ib_subnet(&env, "test_ib_subnet".to_string()).await;

    let request = InstanceAllocationRequest {
        machine_id: host_machine_id.clone(),
        config: InstanceConfig {
            tenant: Some(TenantConfig {
                user_data: Some("SomeRandomData".to_string()),
                custom_ipxe: "SomeRandomiPxe".to_string(),
                tenant_organization_id: TenantOrganizationId::try_from("Tenant1".to_string())
                    .unwrap(),
                tenant_keyset_ids: vec![],
            }),
            network: InstanceNetworkConfig::for_segment_id(FIXTURE_NETWORK_SEGMENT_ID),
            infiniband: InstanceInfinibandConfig {
                ib_interfaces: vec![
                    InstanceIbInterfaceConfig {
                        function_id: InterfaceFunctionId::Physical {},
                        ib_subnet_id,
                        guid: None,
                        device: "MT2910 Family [ConnectX-7]".to_string(), // no ib devices
                        vendor: None,
                        device_instance: 0,
                    },
                    InstanceIbInterfaceConfig {
                        function_id: InterfaceFunctionId::Physical {},
                        ib_subnet_id,
                        guid: None,
                        device: "MT2910 Family [ConnectX-7]".to_string(), // no ib devices
                        vendor: None,
                        device_instance: 0,
                    },
                ],
            },
        },
        ssh_keys: vec!["mykey1".to_owned()],
    };

    let result = allocate_instance(request, &pool).await;
    let error = result.expect_err("expected allocation to fail").to_string();
    assert!(
        error.contains("is reused"),
        "Error message should contain 'is reused', but is {}",
        error
    );
}
