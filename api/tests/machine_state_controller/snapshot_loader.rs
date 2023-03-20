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
    model::machine::machine_id::MachineId,
    state_controller::snapshot_loader::{DbSnapshotLoader, MachineStateSnapshotLoader},
    CarbideError, CarbideResult,
};
use mac_address::MacAddress;
use sqlx::Executor;

use crate::common::api_fixtures::{
    dpu::create_dpu_hardware_info, network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};

const FIXTURE_CREATED_DOMAIN_ID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

#[sqlx::test]
async fn test_snapshot_loader(pool: sqlx::PgPool) -> CarbideResult<()> {
    let mut txn = pool
        .begin()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "begin", e))?;

    // Workaround to make the fixtures work from a different directory
    for fixture in &["create_domain", "create_vpc", "create_network_segment"] {
        let content = std::fs::read(format!("{}/{}.sql", FIXTURE_DIR, fixture)).unwrap();
        let content = String::from_utf8(content).unwrap();
        txn.execute(content.as_str())
            .await
            .unwrap_or_else(|e| panic!("failed to apply test fixture {:?}: {:?}", fixture, e));
    }

    let segment = NetworkSegment::find(
        &mut txn,
        carbide::db::UuidKeyedObjectFilter::One(FIXTURE_NETWORK_SEGMENT_ID),
        carbide::db::network_segment::NetworkSegmentSearchConfig::default(),
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

    let hardware_info = create_dpu_hardware_info();
    let stable_machine_id = MachineId::from_hardware_info(&hardware_info).unwrap();
    let machine = Machine::get_or_create(&mut txn, Some(stable_machine_id), iface)
        .await
        .unwrap();

    txn.commit()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "commit", e))?;

    let mut txn = pool
        .begin()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "begin", e))?;

    MachineTopology::create(&mut txn, machine.id(), &hardware_info).await?;
    txn.commit()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "commit", e))?;

    let mut txn = pool
        .begin()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "begin", e))?;

    let snapshot_loader = DbSnapshotLoader::default();
    let snapshot = snapshot_loader
        .load_machine_snapshot(&mut txn, *machine.id())
        .await
        .unwrap();

    assert_eq!(snapshot.machine_id, *machine.id());
    assert_eq!(snapshot.hardware_info, hardware_info);

    Ok(())
}
