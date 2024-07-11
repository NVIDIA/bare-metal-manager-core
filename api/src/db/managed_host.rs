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
//!
//! Database access methods for manipulating the state of a ManagedHost (Host+DPUs)
//!

use crate::db::{instance::Instance, machine::Machine, DatabaseError};
use crate::model::machine::machine_id::MachineId;
use crate::model::machine::{MachineSnapshot, ManagedHostStateSnapshot};

/// Loads a ManagedHost snapshot from the database
pub async fn load_snapshot(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    machine_id: &MachineId,
) -> Result<Option<ManagedHostStateSnapshot>, DatabaseError> {
    let host_machine = if machine_id.machine_type().is_dpu() {
        Machine::find_host_by_dpu_machine_id(txn, machine_id).await?
    } else {
        Machine::find_one(
            txn,
            machine_id,
            crate::db::machine::MachineSearchConfig::default(),
        )
        .await?
    };

    let Some(host_machine) = host_machine else {
        return Ok(None);
    };

    let dpus = Machine::find_dpus_by_host_machine_id(txn, host_machine.id()).await?;

    let host_snapshot: MachineSnapshot = host_machine.into();

    let mut dpu_snapshots: Vec<MachineSnapshot> = Vec::new();
    for dpu in dpus {
        dpu_snapshots.push(dpu.into());
    }

    let instance = Instance::find_by_machine_id(txn, &host_snapshot.machine_id).await?;

    let managed_state = host_snapshot.current.state.clone();
    let snapshot = ManagedHostStateSnapshot {
        host_snapshot,
        dpu_snapshots,
        instance,
        managed_state,
    };

    Ok(Some(snapshot))
}
