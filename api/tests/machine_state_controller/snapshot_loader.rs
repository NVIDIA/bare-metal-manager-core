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

use carbide::{
    db::{
        machine::Machine, machine_interface::MachineInterface, machine_topology::MachineTopology,
        network_segment::NetworkSegment, DatabaseError,
    },
    model::machine::machine_id::MachineId,
    state_controller::snapshot_loader::{
        DbSnapshotLoader, MachineStateSnapshotLoader, SnapshotLoaderError,
    },
    CarbideError,
};
use mac_address::MacAddress;
use sqlx::Executor;
use std::str::FromStr;

use crate::common::api_fixtures::{
    create_test_env, dpu::create_dpu_hardware_info, network_segment::FIXTURE_NETWORK_SEGMENT_ID,
};

const FIXTURE_CREATED_DOMAIN_ID: uuid::Uuid = uuid::uuid!("1ebec7c1-114f-4793-a9e4-63f3d22b5b5e");

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

#[sqlx::test]
async fn test_snapshot_loader(pool: sqlx::PgPool) -> eyre::Result<()> {
    let mut txn = pool
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin", e))?;

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

    txn.commit().await.unwrap();

    let env = create_test_env(pool.clone()).await;
    let host_sim = env.start_managed_host_sim();

    let hardware_info = create_dpu_hardware_info(&host_sim.config);
    let stable_machine_id = MachineId::from_hardware_info(&hardware_info).unwrap();

    let mut txn = pool
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin", e))?;
    let (machine, _is_new) = Machine::get_or_create(&mut txn, &stable_machine_id, &iface)
        .await
        .unwrap();
    iface
        .associate_interface_with_dpu_machine(&mut txn, &stable_machine_id)
        .await
        .unwrap();

    let host_machine_interface = MachineInterface::create_host_machine_interface_proactively(
        &mut txn,
        Some(&hardware_info),
        machine.id(),
    )
    .await?;

    let predicted_machine_id = MachineId::host_id_from_dpu_hardware_info(&hardware_info)
        .map_err(|err| CarbideError::InvalidArgument(format!("hardware info: {err}")))?;
    let _ =
        Machine::get_or_create(&mut txn, &predicted_machine_id, &host_machine_interface).await?;

    txn.commit()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "commit", e))?;

    let mut txn = pool
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin", e))?;

    MachineTopology::create_or_update(&mut txn, machine.id(), &hardware_info).await?;
    txn.commit()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "commit", e))?;

    let mut txn = pool
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin", e))?;

    let snapshot_loader = DbSnapshotLoader {};
    let snapshot = snapshot_loader
        .load_machine_snapshot(&mut txn, machine.id())
        .await
        .unwrap();

    assert_eq!(snapshot.dpu_snapshot.machine_id, *machine.id());
    assert_eq!(snapshot.dpu_snapshot.hardware_info.unwrap(), hardware_info);

    // Now try a non-existent DPU. This happens if we force-delete it.
    let missing_dpu_id =
        MachineId::from_str("fm100ds1forsgf39sldfcbmi0jvs8g4ik9iqtbma89k0gom104sl397eke0")?;
    let err = snapshot_loader
        .load_machine_snapshot(&mut txn, &missing_dpu_id)
        .await
        .unwrap_err();
    match err {
        SnapshotLoaderError::HostNotFound(_) => {} // expected
        unexpected => {
            panic!("load_machine_snapshot of missing DPU should be HostNotFound. Instead got {unexpected}");
        }
    }

    Ok(())
}
