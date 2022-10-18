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
use carbide::db::instance_subnet::InstanceSubnet;
use carbide::db::machine_interface::MachineInterface;
use log::LevelFilter;
use mac_address::MacAddress;

use ::rpc::MachineStateMachineInput;
use carbide::db::instance::{DeleteInstance, Instance, NewInstance};
use carbide::db::{dhcp_record::DhcpRecord, machine::Machine};
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
    let (instance, segment_id) = create_instance(pool.clone()).await;
    let mut txn = pool
        .clone()
        .begin()
        .await
        .expect("Unable to create transaction on database pool");
    //println!("Instance details: {:?}", instance);
    let machine = Machine::find_one(&mut txn, instance.machine_id)
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
    machine
        .advance(&mut txn, &MachineStateMachineInput::Assign)
        .await
        .unwrap();

    let fetched_instance = Instance::find_by_mac_and_relay(&mut txn, parsed_relay, parsed_mac)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fetched_instance.machine_id, *machine.id());

    assert!(fetched_instance.use_custom_pxe_on_boot);

    let _ = Instance::use_custom_ipxe_on_next_boot(*machine.id(), false, &mut txn).await;
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

    let record = DhcpRecord::find_for_instance(&mut txn, &parsed_mac, &segment_id, *machine.id())
        .await
        .unwrap();
    txn.commit().await.unwrap();

    println!("Assigned address: {}", record.address());
    delete_instance(pool, instance.id).await;
}

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

async fn create_instance(pool: sqlx::PgPool) -> (Instance, uuid::Uuid) {
    let mut txn = pool
        .begin()
        .await
        .expect("Unable to create transaction on database pool");

    let segment_id: uuid::Uuid = "91609f10-c91d-470d-a260-6293ea0c1200".parse().unwrap();
    let instance = NewInstance {
        machine_id: "52dfecb4-8070-4f4b-ba95-f66d0f51fd98".parse().unwrap(),
        segment_id,
        user_data: Some("SomeRandomData".to_string()),
        custom_ipxe: "SomeRandomiPxe".to_string(),
        ssh_keys: vec!["mykey1".to_owned()],
    }
    .persist(&mut txn)
    .await
    .expect("Unable to create new instance");

    let machine_interface = MachineInterface::find_by_segment_id(&mut txn, &segment_id)
        .await
        .unwrap()
        .remove(0);

    let subnet =
        InstanceSubnet::create(&mut txn, &machine_interface, segment_id, instance.id, None)
            .await
            .unwrap();

    instance
        .assign_address(&mut txn, subnet, segment_id)
        .await
        .unwrap();
    txn.commit().await.unwrap();

    (instance, segment_id)
}
