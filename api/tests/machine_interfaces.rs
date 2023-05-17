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

use std::str::FromStr;

use carbide::{
    db::{
        address_selection_strategy::AddressSelectionStrategy, machine::Machine,
        machine_interface::MachineInterface, network_segment::NetworkSegment,
    },
    model::machine::machine_id::MachineId,
    CarbideError,
};
use mac_address::MacAddress;
use sqlx::{Connection, Postgres};

pub mod common;
use common::api_fixtures::{
    dpu::create_dpu_hardware_info, network_segment::FIXTURE_NETWORK_SEGMENT_ID,
    FIXTURE_DHCP_RELAY_ADDRESS,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
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
    let (new_machine, _is_new) =
        Machine::get_or_create(&mut txn, &machine_id, new_interface, false)
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

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn return_existing_machine_interface_on_rediscover(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // TODO: This tests only DHCP without Machines. For Interfaces with a Machine,
    // there are tests in `machine_dhcp.rs`
    // This should also be migrated to use actual API calls
    let mut txn = pool.begin().await?;

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let new_machine = MachineInterface::validate_existing_mac_and_create(
        &mut txn,
        test_mac,
        FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap(),
    )
    .await?;

    let existing_machine = MachineInterface::validate_existing_mac_and_create(
        &mut txn,
        test_mac,
        FIXTURE_DHCP_RELAY_ADDRESS.parse().unwrap(),
    )
    .await?;

    assert_eq!(new_machine.id(), existing_machine.id());

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_rename_machine(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = get_fixture_network_segment(&mut txn.begin().await?).await?;

    let interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        MacAddress::from_str("ff:ff:ff:ff:ff:ff").as_ref().unwrap(),
        None,
        "peppersmacker2".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;
    txn.commit().await.unwrap();

    let mut txn = pool.begin().await?;

    let mut updated_interface = MachineInterface::find_one(&mut txn, interface.id).await?;
    assert_eq!(updated_interface.hostname(), "peppersmacker2");

    let new_hostname = "peppersmacker400";
    updated_interface
        .update_hostname(&mut txn, new_hostname)
        .await?;

    txn.commit().await?;

    assert_eq!(updated_interface.hostname(), new_hostname);

    Ok(())
}
