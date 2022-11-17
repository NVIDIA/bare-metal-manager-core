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
use carbide::{
    db::{
        dhcp_record::DhcpRecord,
        instance::{
            config::network::load_instance_network_config,
            status::network::{
                load_instance_network_status_observation,
                update_instance_network_status_observation,
            },
            DeleteInstance, Instance,
        },
        machine::Machine,
    },
    instance::{allocate_instance, InstanceAllocationRequest},
    machine_state_controller::snapshot_loader::{DbSnapshotLoader, InstanceSnapshotLoader},
    model::instance::{
        config::{
            network::{InstanceNetworkConfig, InterfaceFunctionId},
            tenant::TenantConfig,
            InstanceConfig,
        },
        status::{
            network::{
                InstanceInterfaceStatus, InstanceInterfaceStatusObservation,
                InstanceNetworkStatusObservation,
            },
            SyncState,
        },
    },
};

use ::rpc::MachineStateMachineInput;
use chrono::Utc;
use log::LevelFilter;
use mac_address::MacAddress;
use std::net::IpAddr;

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
    let parsed_relay = "192.0.2.1".parse::<IpAddr>().unwrap();
    let parsed_mac = "ff:ff:ff:ff:ff:ff".parse::<MacAddress>().unwrap();
    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    assert!(
        Instance::find_by_mac_and_relay(&mut txn, parsed_relay, parsed_mac)
            .await
            .unwrap()
            .is_none()
    );
    txn.commit().await.unwrap();

    let instance = create_instance(pool.clone()).await;

    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let fetched_instance = Instance::find_by_mac_and_relay(&mut txn, parsed_relay, parsed_mac)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched_instance.machine_id, FIXTURE_MACHINE_ID);

    let network_config = load_instance_network_config(&mut txn, instance.id)
        .await
        .unwrap();
    assert_eq!(network_config.version.version_nr(), 1);
    assert_eq!(
        network_config.config,
        InstanceNetworkConfig::for_segment_id(FIXTURE_NETWORK_SEGMENT_ID)
    );

    let network_status_observation =
        load_instance_network_status_observation(&mut txn, instance.id)
            .await
            .unwrap();
    assert!(network_status_observation.is_none());

    assert!(fetched_instance.use_custom_pxe_on_boot);

    let _ = Instance::use_custom_ipxe_on_next_boot(FIXTURE_MACHINE_ID, false, &mut txn).await;
    let fetched_instance = Instance::find_by_mac_and_relay(&mut txn, parsed_relay, parsed_mac)
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

    let record = DhcpRecord::find_for_instance(
        &mut txn,
        &parsed_mac,
        &FIXTURE_NETWORK_SEGMENT_ID,
        FIXTURE_MACHINE_ID,
    )
    .await
    .unwrap();
    txn.commit().await.unwrap();

    println!("Assigned address: {}", record.address());
    delete_instance(pool, instance.id).await;
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_instance_network_status_sync(pool: sqlx::PgPool) {
    let instance = create_instance(pool.clone()).await;
    let instance_id = instance.id;

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

    update_instance_network_status_observation(&mut txn, instance.id, &updated_network_status)
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
    update_instance_network_status_observation(&mut txn, instance.id, &updated_network_status)
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
    .bind(&instance_id)
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

    update_instance_network_status_observation(&mut txn, instance.id, &updated_network_status)
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
    assert_eq!(
        status.network.interfaces,
        vec![InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::PhysicalFunctionId {},
            mac_address: Some(MacAddress::new([11, 12, 13, 14, 15, 16])),
            addresses: vec!["112.113.114.115".parse().unwrap()],
        }]
    );
}

const FIXTURE_NETWORK_SEGMENT_ID: uuid::Uuid = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");
const FIXTURE_MACHINE_ID: uuid::Uuid = uuid::uuid!("52dfecb4-8070-4f4b-ba95-f66d0f51fd98");

async fn delete_instance(pool: sqlx::PgPool, instance_id: uuid::Uuid) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    DeleteInstance { instance_id }
        .delete(&mut txn)
        .await
        .expect("Delete instance failed.");
}

async fn create_instance(pool: sqlx::PgPool) -> Instance {
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

    let request = InstanceAllocationRequest {
        machine_id: FIXTURE_MACHINE_ID,
        config: InstanceConfig {
            tenant: Some(TenantConfig {
                user_data: Some("SomeRandomData".to_string()),
                custom_ipxe: "SomeRandomiPxe".to_string(),
                tenant_id: "Tenant1".to_string(),
            }),
            network: InstanceNetworkConfig::for_segment_id(FIXTURE_NETWORK_SEGMENT_ID),
        },
        ssh_keys: vec!["mykey1".to_owned()],
    };

    // Note: This also requests a background task in the DB for creating managed
    // resources. That's however ok - we will just ignore it and not execute
    // that task. Later we might also verify that the creation of those resources
    // is requested
    allocate_instance(request, &pool).await.unwrap()
}
