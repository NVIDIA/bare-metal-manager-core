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
use carbide::db::{
    address_selection_strategy::AddressSelectionStrategy, machine::Machine,
    machine_interface::MachineInterface, network_segment::NetworkSegment,
};
use carbide::model::machine::machine_id::MachineId;
use carbide::CarbideError;

pub mod common;
use common::api_fixtures::{
    dpu::create_dpu_hardware_info, network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn prevent_duplicate_mac_addresses(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let network_segment = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_NETWORK_SEGMENT_ID),
        carbide::db::network_segment::NetworkSegmentSearchConfig::default(),
    )
    .await?
    .pop()
    .unwrap();

    let test_mac = "ff:ff:ff:ff:ff:ff".parse().unwrap();

    let new_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        &test_mac,
        None,
        "foobar".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    let machine_id = MachineId::from_hardware_info(&create_dpu_hardware_info()).unwrap();
    let (_new_machine, _) = Machine::get_or_create(&mut txn, &machine_id, new_interface).await?;

    let duplicate_interface = MachineInterface::create(
        &mut txn,
        &network_segment,
        &test_mac,
        None,
        "foobar".to_string(),
        true,
        AddressSelectionStrategy::Automatic,
    )
    .await;

    txn.commit().await?;

    assert!(matches!(
        duplicate_interface,
        Err(CarbideError::NetworkSegmentDuplicateMacAddress(_))
    ));

    Ok(())
}
