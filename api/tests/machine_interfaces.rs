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
        address_selection_strategy::AddressSelectionStrategy, dpu_machine::DpuMachine,
        machine::Machine, machine_interface::MachineInterface, network_segment::NetworkSegment,
        vpc_resource_leaf::VpcResourceLeaf,
    },
    model::machine::machine_id::MachineId,
    CarbideError,
};
use log::LevelFilter;
use mac_address::MacAddress;
use sqlx::{Connection, Postgres};
use std::str::FromStr;

pub mod common;
use common::api_fixtures::{
    dpu::create_dpu_hardware_info, network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};

#[ctor::ctor]
fn setup() {
    pretty_env_logger::formatted_timed_builder()
        .filter_level(LevelFilter::Error)
        .init();
}

async fn get_fixture_network_segment(
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<NetworkSegment, Box<dyn std::error::Error>> {
    carbide::db::network_segment::NetworkSegment::find(
        txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_NETWORK_SEGMENT_ID),
        carbide::db::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?
    .pop()
    .ok_or_else(|| {
        format!(
            "Can't find the Network Segment by well-known-uuid: {}",
            FIXTURE_NETWORK_SEGMENT_ID
        )
        .into()
    })
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn only_one_primary_interface_per_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = get_fixture_network_segment(&mut txn.begin().await?).await?;

    let new_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    let machine_id = MachineId::from_hardware_info(&create_dpu_hardware_info()).unwrap();
    let new_machine = Machine::get_or_create(&mut txn, Some(machine_id), new_interface, false)
        .await
        .expect("Unable to create machine");

    txn.commit().await.unwrap();

    let mut txn = pool.begin().await?;

    let mut should_failed_machine_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ef").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    let output = should_failed_machine_interface
        .associate_interface_with_machine(&mut txn, new_machine.id())
        .await;

    txn.commit().await.unwrap();

    assert!(matches!(output, Err(CarbideError::OnePrimaryInterface)));

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn many_non_primary_interfaces_per_machine(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = get_fixture_network_segment(&mut txn.begin().await?).await?;

    MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await
    .expect("Unable to create machine interface");

    txn.commit().await.unwrap();
    let mut txn = pool.begin().await?;

    let should_be_ok_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ef").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        false,
        AddressSelectionStrategy::Automatic,
    )
    .await;

    txn.commit().await.unwrap();

    assert!(should_be_ok_interface.is_ok());

    Ok(())
}

const DPU_MACHINE_INT_ID: uuid::Uuid = uuid::uuid!("ad871735-efaa-406e-a83e-9ff63b1bc145");
const DPU_MACHINE_ID: uuid::Uuid = uuid::uuid!("52dfecb4-8070-4f4b-ba95-f66d0f51fd98");
const HOST_MACHINE_ID: uuid::Uuid = uuid::uuid!("52dfecb4-8070-4f4b-ba95-f66d0f51fd99");

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_find_machine_by_loopback(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;
    let machine_interface = VpcResourceLeaf::find_associated_dpu_machine_interface(
        &mut txn,
        "192.168.0.1".parse().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(machine_interface.id, DPU_MACHINE_INT_ID);
    Ok(())
}

#[sqlx::test(fixtures(
    "create_domain",
    "create_vpc",
    "create_network_segment",
    "create_machine"
))]
async fn test_dpu_machine_test(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let machine = DpuMachine::find_by_machine_id(&mut txn, &DPU_MACHINE_ID)
        .await
        .unwrap();

    assert_eq!(machine._machine_interface_id(), &DPU_MACHINE_INT_ID);
    let machine = DpuMachine::find_by_machine_id(&mut txn, &HOST_MACHINE_ID).await;

    assert!(machine.is_err());
    Ok(())
}
