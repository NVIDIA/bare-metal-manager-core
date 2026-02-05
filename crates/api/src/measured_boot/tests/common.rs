/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! tests/common.rs
//!
//! Shared code by measured boot tests.

use std::str::FromStr;

use carbide_uuid::machine::MachineId;
use measured_boot::machine::CandidateMachine;
use model::hardware_info::HardwareInfo;
use model::machine::ManagedHostState;
use model::metadata::Metadata;
use sqlx::PgConnection;

use crate::state_controller::machine::io::CURRENT_STATE_MODEL_VERSION;

pub fn load_topology_json(path: &str) -> HardwareInfo {
    const TEST_DATA_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/measured_boot/tests/test_data"
    );

    let path = format!("{TEST_DATA_DIR}/{path}");
    let data = std::fs::read(path).unwrap();
    serde_json::from_slice::<HardwareInfo>(&data).unwrap()
}

pub async fn create_test_machine(
    txn: &mut PgConnection,
    machine_id: &str,
    topology: &HardwareInfo,
) -> eyre::Result<CandidateMachine> {
    let machine_id = MachineId::from_str(machine_id)?;
    db::machine::create(
        txn,
        None,
        &machine_id,
        ManagedHostState::Ready,
        &Metadata::default(),
        None,
        true,
        CURRENT_STATE_MODEL_VERSION,
    )
    .await?;
    db::machine_topology::create_or_update(txn, &machine_id, topology).await?;
    let machine = db::measured_boot::machine::from_id(txn, machine_id).await?;
    assert_eq!(machine_id, machine.machine_id);
    Ok(machine)
}
