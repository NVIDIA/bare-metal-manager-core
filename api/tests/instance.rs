/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use chrono::Utc;
use log::LevelFilter;
use mac_address::MacAddress;

use ::rpc::{
    forge::{forge_server::Forge, InstanceReleaseRequest},
    MachineStateMachineInput,
};
use carbide::{
    db::{
        dhcp_record::InstanceDhcpRecord,
        instance::{
            config::network::load_instance_network_config,
            status::network::{
                load_instance_network_status_observation,
                update_instance_network_status_observation,
            },
            Instance,
        },
        machine::Machine,
    },
    instance::{allocate_instance, InstanceAllocationRequest},
    model::instance::{
        config::{
            network::{InstanceNetworkConfig, InterfaceFunctionId, InterfaceFunctionType},
            tenant::{TenantConfig, TenantOrg},
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
    state_controller::snapshot_loader::{
        DbSnapshotLoader, InstanceSnapshotLoader, MachineStateSnapshotLoader,
    },
};
use common::api_fixtures::{
    create_test_api,
    dpu::create_dpu_machine,
    network_segment::{FIXTURE_NETWORK_SEGMENT_ID, FIXTURE_NETWORK_SEGMENT_NO_VPC_NO_ID},
    TestApi,
};

pub mod common;

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_crud_instance(pool: sqlx::PgPool) {
    let api = create_test_api(pool.clone());
    prepare_machine(&pool).await;
    let parsed_relay = "192.168.0.1".parse::<IpAddr>().unwrap();
    let parsed_mac = "ff:ff:ff:ff:ff:ff".parse::<MacAddress>().unwrap();
    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    assert!(Instance::find_by_relay_ip(&mut txn, parsed_relay)
        .await
        .unwrap()
        .is_none());
    txn.commit().await.unwrap();

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::PhysicalFunction as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    });

    let (instance_id, _instance) = create_instance(&api, network).await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let fetched_instance = Instance::find_by_relay_ip(&mut txn, parsed_relay)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched_instance.machine_id, FIXTURE_MACHINE_ID);

    let network_config = load_instance_network_config(&mut txn, instance_id)
        .await
        .unwrap();
    assert_eq!(network_config.version.version_nr(), 1);
    assert_eq!(
        network_config.config,
        InstanceNetworkConfig::for_segment_id(FIXTURE_NETWORK_SEGMENT_ID)
    );

    let network_status_observation =
        load_instance_network_status_observation(&mut txn, instance_id)
            .await
            .unwrap();
    assert!(network_status_observation.is_none());

    assert!(fetched_instance.use_custom_pxe_on_boot);

    let _ = Instance::use_custom_ipxe_on_next_boot(FIXTURE_MACHINE_ID, false, &mut txn).await;
    let fetched_instance = Instance::find_by_relay_ip(&mut txn, parsed_relay)
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
    assert_eq!(record.address().ip().to_string(), "192.0.2.3");
    let snapshot_loader = DbSnapshotLoader::default();
    let snapshot = snapshot_loader
        .load_instance_snapshot(&mut txn, instance_id)
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
            tenant_org: TenantOrg::try_from("Tenant1".to_string()).unwrap(),
        }
    );

    txn.commit().await.unwrap();

    delete_instance(&api, instance_id).await;
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_instance_network_status_sync(pool: sqlx::PgPool) {
    let api = create_test_api(pool.clone());
    prepare_machine(&pool).await;
    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::PhysicalFunction as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    });

    let (instance_id, _instance) = create_instance(&api, network).await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    // When no network status has been observed, we report an interface
    // list with no IPs and MACs to the user
    let snapshot_loader = DbSnapshotLoader::default();
    let snapshot = snapshot_loader
        .load_instance_snapshot(&mut txn, instance_id)
        .await
        .unwrap();
    assert!(snapshot.observations.network.is_none());

    let status = snapshot.derive_status();
    assert_eq!(status.configs_synced, SyncState::Pending);
    assert_eq!(status.network.configs_synced, SyncState::Pending);
    assert_eq!(
        status.tenant.as_ref().unwrap().state,
        TenantState::Provisioning
    );
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::PhysicalFunctionId {},
            mac_address: None,
            addresses: Vec::new(),
        }]
    );

    let mut updated_network_status = InstanceNetworkStatusObservation {
        config_version: snapshot.network_config_version,
        interfaces: vec![InstanceInterfaceStatusObservation {
            function_id: InterfaceFunctionId::PhysicalFunctionId {},
            mac_address: None,
            addresses: Vec::new(),
        }],
        observed_at: Utc::now(),
    };

    update_instance_network_status_observation(&mut txn, instance_id, &updated_network_status)
        .await
        .unwrap();

    let snapshot = snapshot_loader
        .load_instance_snapshot(&mut txn, instance_id)
        .await
        .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
        Some(&updated_network_status)
    );
    let status = snapshot.derive_status();
    assert_eq!(status.configs_synced, SyncState::Synced);
    assert_eq!(status.network.configs_synced, SyncState::Synced);
    assert_eq!(status.tenant.as_ref().unwrap().state, TenantState::Ready);
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::PhysicalFunctionId {},
            mac_address: None,
            addresses: Vec::new(),
        }]
    );

    updated_network_status.interfaces[0]
        .addresses
        .push("112.113.114.115".parse().unwrap());
    updated_network_status.interfaces[0].mac_address =
        Some(MacAddress::new([11, 12, 13, 14, 15, 16]).into());
    update_instance_network_status_observation(&mut txn, instance_id, &updated_network_status)
        .await
        .unwrap();
    let snapshot = snapshot_loader
        .load_instance_snapshot(&mut txn, instance_id)
        .await
        .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
        Some(&updated_network_status)
    );
    let status = snapshot.derive_status();
    assert_eq!(status.configs_synced, SyncState::Synced);
    assert_eq!(status.network.configs_synced, SyncState::Synced);
    assert_eq!(status.tenant.as_ref().unwrap().state, TenantState::Ready);
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::PhysicalFunctionId {},
            mac_address: Some(MacAddress::new([11, 12, 13, 14, 15, 16])),
            addresses: vec!["112.113.114.115".parse().unwrap()],
        }]
    );

    // Assuming the config would change, the status should become unsynced again
    let next_config_version = snapshot.network_config_version.increment();
    let (_,): (uuid::Uuid,) = sqlx::query_as(
        "UPDATE instances SET network_config_version=$1 WHERE id = $2::uuid returning id",
    )
    .bind(&next_config_version.to_version_string())
    .bind(instance_id)
    .fetch_one(&mut txn)
    .await
    .unwrap();
    let snapshot = snapshot_loader
        .load_instance_snapshot(&mut txn, instance_id)
        .await
        .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
        Some(&updated_network_status)
    );
    let status = snapshot.derive_status();
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
            function_id: InterfaceFunctionId::PhysicalFunctionId {},
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
            function_id: InterfaceFunctionId::VirtualFunctionId { id: 1 },
            mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 6]).into()),
            addresses: vec!["127.1.2.3".parse().unwrap()],
        });

    update_instance_network_status_observation(&mut txn, instance_id, &updated_network_status)
        .await
        .unwrap();
    let snapshot = snapshot_loader
        .load_instance_snapshot(&mut txn, instance_id)
        .await
        .unwrap();

    assert_eq!(
        snapshot.observations.network.as_ref(),
        Some(&updated_network_status)
    );
    let status = snapshot.derive_status();
    assert_eq!(status.configs_synced, SyncState::Synced);
    assert_eq!(status.network.configs_synced, SyncState::Synced);
    assert_eq!(status.tenant.as_ref().unwrap().state, TenantState::Ready);
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::PhysicalFunctionId {},
            mac_address: Some(MacAddress::new([11, 12, 13, 14, 15, 16])),
            addresses: vec!["112.113.114.115".parse().unwrap()],
        }]
    );

    txn.commit().await.unwrap();
    delete_instance(&api, instance_id).await;
}

const FIXTURE_CIRCUIT_ID: &str = "vlan_100";
const FIXTURE_MACHINE_ID: uuid::Uuid = uuid::uuid!("52dfecb4-8070-4f4b-ba95-f66d0f51fd98");
#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_instance_snapshot_is_included_in_machine_snapshot(pool: sqlx::PgPool) {
    let api = create_test_api(pool.clone());
    prepare_machine(&pool).await;

    let snapshot_loader = DbSnapshotLoader::default();

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let snapshot = snapshot_loader
        .load_machine_snapshot(&mut txn, FIXTURE_MACHINE_ID)
        .await
        .unwrap();
    assert!(
        snapshot.instance.is_none(),
        "Expected instance snapshot to be not available"
    );
    txn.commit().await.unwrap();

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::PhysicalFunction as i32,
            network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
        }],
    });

    let (instance_id, _instance) = create_instance(&api, network).await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    let snapshot = snapshot_loader
        .load_machine_snapshot(&mut txn, FIXTURE_MACHINE_ID)
        .await
        .unwrap();
    txn.commit().await.unwrap();
    let instance_snapshot = snapshot
        .instance
        .expect("Expected instance snapshot to be available");
    assert_eq!(instance_snapshot.network_config_version.version_nr(), 1);
    assert_eq!(
        instance_snapshot.config.network,
        InstanceNetworkConfig::for_segment_id(FIXTURE_NETWORK_SEGMENT_ID)
    );
    assert!(instance_snapshot.observations.network.is_none());

    assert_eq!(
        instance_snapshot.config.tenant,
        Some(TenantConfig {
            user_data: Some("SomeRandomData".to_string()),
            custom_ipxe: "SomeRandomiPxe".to_string(),
            tenant_org: TenantOrg::try_from("Tenant1".to_string()).unwrap(),
        })
    );

    delete_instance(&api, instance_id).await;
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_can_not_create_instance_for_dpu(pool: sqlx::PgPool) {
    let api = create_test_api(pool.clone());

    let dpu_machine_id = create_dpu_machine(&api).await;

    let request = InstanceAllocationRequest {
        machine_id: dpu_machine_id.try_into().unwrap(),
        config: InstanceConfig {
            tenant: Some(TenantConfig {
                user_data: Some("SomeRandomData".to_string()),
                custom_ipxe: "SomeRandomiPxe".to_string(),
                tenant_org: TenantOrg::try_from("Tenant1".to_string()).unwrap(),
            }),
            network: InstanceNetworkConfig::for_segment_id(FIXTURE_NETWORK_SEGMENT_ID),
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
        error.contains("is a DPU"),
        "Error message should contain 'is a DPU', but is {}",
        error
    );
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_instance_address_creation(pool: sqlx::PgPool) {
    let api = create_test_api(pool.clone());
    prepare_machine(&pool).await;
    let txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let network = Some(rpc::InstanceNetworkConfig {
        interfaces: vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::PhysicalFunction as i32,
                network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_ID.into()),
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::VirtualFunction as i32,
                network_segment_id: Some(FIXTURE_NETWORK_SEGMENT_NO_VPC_NO_ID.into()),
            },
        ],
    });

    let (instance_id, instance) = create_instance(&api, network).await;

    let segment_ip = HashMap::from([(None, "192.0.2.3"), (Some(1), "192.0.3.3")]);

    api.record_observed_instance_network_status(tonic::Request::new(
        rpc::InstanceNetworkStatusObservation {
            instance_id: Some(instance_id.into()),
            config_version: instance.network_config_version,
            observed_at: Some(SystemTime::now().into()),
            interfaces: vec![
                rpc::InstanceInterfaceStatusObservation {
                    function_type: rpc::InterfaceFunctionType::from(
                        InterfaceFunctionType::PhysicalFunction,
                    ) as i32,
                    virtual_function_id: None,
                    mac_address: None,
                    addresses: vec!["192.0.2.3".to_string()],
                },
                rpc::InstanceInterfaceStatusObservation {
                    function_type: rpc::InterfaceFunctionType::from(
                        InterfaceFunctionType::VirtualFunction,
                    ) as i32,
                    virtual_function_id: Some(1),
                    mac_address: None,
                    addresses: vec!["192.0.3.3".to_string()],
                },
            ],
        },
    ))
    .await
    .unwrap();

    let instance = &api
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
    txn.commit().await.unwrap();
}

async fn delete_instance(api: &TestApi, instance_id: uuid::Uuid) {
    api.release_instance(tonic::Request::new(InstanceReleaseRequest {
        id: Some(instance_id.into()),
    }))
    .await
    .expect("Delete instance failed.");
}

async fn prepare_machine(pool: &sqlx::PgPool) {
    let mut txn = pool.begin().await.unwrap();
    let machine = Machine::find_one(&mut txn, FIXTURE_MACHINE_ID)
        .await
        .unwrap()
        .unwrap();
    machine
        .advance(&mut txn, &MachineStateMachineInput::Discover)
        .await
        .unwrap();
    machine
        .advance(&mut txn, &MachineStateMachineInput::Adopt)
        .await
        .unwrap();
    machine
        .advance(&mut txn, &MachineStateMachineInput::Test)
        .await
        .unwrap();
    machine
        .advance(&mut txn, &MachineStateMachineInput::Commission)
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

async fn create_instance(
    api: &TestApi,
    network: Option<rpc::InstanceNetworkConfig>,
) -> (uuid::Uuid, rpc::Instance) {
    // Note: This also requests a background task in the DB for creating managed
    // resources. That's however ok - we will just ignore it and not execute
    // that task. Later we might also verify that the creation of those resources
    // is requested
    let info = api
        .allocate_instance(tonic::Request::new(rpc::InstanceAllocationRequest {
            machine_id: Some(FIXTURE_MACHINE_ID.into()),
            config: Some(rpc::InstanceConfig {
                tenant: Some(rpc::TenantConfig {
                    user_data: Some("SomeRandomData".to_string()),
                    custom_ipxe: "SomeRandomiPxe".to_string(),
                    tenant_org: "Tenant1".to_string(),
                }),
                network,
            }),
            ssh_keys: vec!["mykey1".to_owned()],
        }))
        .await
        .expect("Create instance failed.")
        .into_inner();

    let instance_id = uuid::Uuid::try_from(info.id.clone().expect("Missing instance ID")).unwrap();
    (instance_id, info)
}
