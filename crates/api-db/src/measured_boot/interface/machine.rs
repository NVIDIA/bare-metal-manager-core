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

/*!
 *  Code for working the machine_topologies table in the
 *  database, leveraging the machine-specific record types.
*/

use carbide_uuid::machine::MachineId;
use measured_boot::records::{MeasurementJournalRecord, MeasurementMachineState};
use sqlx::PgConnection;

use crate::DatabaseError;
use crate::db_read::DbReader;
use crate::measured_boot::interface::common;
use crate::measured_boot::machine::CandidateMachineRecord;

/// get_candidate_machine_state figures out the current state of the given
/// machine ID by checking its most recent bundle (or lack thereof), and
/// using that result to give it a corresponding MeasurementMachineState.
pub async fn get_candidate_machine_state(
    txn: impl DbReader<'_>,
    machine_id: MachineId,
) -> Result<MeasurementMachineState, DatabaseError> {
    Ok(match get_latest_journal_for_id(txn, machine_id).await? {
        Some(record) => record.state,
        None => MeasurementMachineState::Discovered,
    })
}

/// get_latest_journal_for_id returns the latest journal record for the
/// provided machine ID.
pub async fn get_latest_journal_for_id(
    txn: impl DbReader<'_>,
    machine_id: MachineId,
) -> Result<Option<MeasurementJournalRecord>, DatabaseError> {
    let query = "select distinct on (machine_id) * from measurement_journal where machine_id = $1 order by machine_id,ts desc";
    sqlx::query_as(query)
        .bind(machine_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::new("get_latest_journal_for_id", e))
}

/// get_candidate_machine_record_by_id returns a CandidateMachineRecord row.
pub async fn get_candidate_machine_record_by_id(
    txn: &mut PgConnection,
    machine_id: MachineId,
) -> Result<Option<CandidateMachineRecord>, DatabaseError> {
    common::get_object_for_id(txn, machine_id)
        .await
        .map_err(|e| e.with_op_name("get_candidate_machine_record_by_id"))
}

/// get_candidate_machine_records returns all MockMachineRecord rows,
/// primarily for the purpose of `mock-machine list`.
pub async fn get_candidate_machine_records(
    txn: &mut PgConnection,
) -> Result<Vec<CandidateMachineRecord>, DatabaseError> {
    common::get_all_objects(txn)
        .await
        .map_err(|e| e.with_op_name("get_candidate_machine_records"))
}
