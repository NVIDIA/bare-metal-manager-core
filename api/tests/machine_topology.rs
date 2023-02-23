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
        machine::Machine, machine_interface::MachineInterface, machine_topology::MachineTopology,
        network_segment::NetworkSegment,
    },
    model::{hardware_info::HardwareInfo, machine::machine_id::MachineId},
};
use log::LevelFilter;
use mac_address::MacAddress;

pub mod common;
use common::api_fixtures::{
    host::create_host_hardware_info, network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Warn)
        .init();
}

const FIXTURE_CREATED_DOMAIN_ID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_crud_machine_topology(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    // We can't use the fixture created Machine here, since it already has a topology attached
    // therefore we create a new one

    let mut txn = pool.begin().await?;

    let segment = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_NETWORK_SEGMENT_ID),
    )
    .await
    .unwrap()
    .remove(0);

    let iface = MachineInterface::create(
        &mut txn,
        &segment,
        &MacAddress::new([0xa, 0xb, 0xc, 0xd, 0xe, 0xf]),
        Some(FIXTURE_CREATED_DOMAIN_ID),
        "myhost".to_string(),
        true,
        carbide::db::address_selection_strategy::AddressSelectionStrategy::Automatic,
    )
    .await
    .unwrap();

    let hardware_info = create_host_hardware_info();
    let machine_id = MachineId::from_hardware_info(&hardware_info).unwrap();
    let machine = Machine::get_or_create(&mut txn, Some(machine_id), iface)
        .await
        .unwrap();

    txn.commit().await?;

    let mut txn = pool.begin().await?;

    MachineTopology::create(&mut txn, machine.id(), &hardware_info).await?;

    txn.commit().await?;

    let mut txn = pool.begin().await?;

    let topos = MachineTopology::find_by_machine_ids(&mut txn, &[*machine.id()])
        .await
        .unwrap();
    assert_eq!(topos.len(), 1);
    let topo = topos.get(machine.id()).unwrap();
    assert_eq!(topo.len(), 1);

    let returned_hw_info = topo[0].topology().discovery_data.info.clone();
    assert_eq!(returned_hw_info, hardware_info);

    // Hardware info is available on the machine
    let machine2 = Machine::find_one(&mut txn, *machine.id())
        .await
        .unwrap()
        .unwrap();

    let rpc_machine = rpc::Machine::try_from(machine2).unwrap();
    let discovery_info = rpc_machine.discovery_info.unwrap();
    let retrieved_hw_info = HardwareInfo::try_from(discovery_info).unwrap();

    assert_eq!(retrieved_hw_info, hardware_info);

    txn.commit().await?;

    // Updating a machine topology won't have any impact
    let mut txn = pool.begin().await?;

    let mut new_info = hardware_info.clone();
    new_info.cpus[0].model = "SnailSpeedCpu".to_string();

    assert!(
        MachineTopology::create(&mut txn, machine.id(), &hardware_info)
            .await?
            .is_none()
    );

    let machine2 = Machine::find_one(&mut txn, *machine.id())
        .await
        .unwrap()
        .unwrap();

    let rpc_machine = rpc::Machine::try_from(machine2).unwrap();
    let discovery_info = rpc_machine.discovery_info.unwrap();
    let retrieved_hw_info = HardwareInfo::try_from(discovery_info).unwrap();

    assert_eq!(retrieved_hw_info, hardware_info);

    txn.commit().await?;

    Ok(())
}
