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
 *  Code for working the measuremment_journal and measurement_journal_values
 *  tables in the database, leveraging the journal-specific record types.
*/

use crate::measured_boot::dto::keys::{
    MeasurementBundleId, MeasurementJournalId, MeasurementReportId, MeasurementSystemProfileId,
};
use crate::measured_boot::dto::records::{MeasurementJournalRecord, MeasurementMachineState};
use crate::measured_boot::interface::common;
use crate::model::machine::machine_id::MachineId;
use sqlx::{Postgres, Transaction};

///////////////////////////////////////////////////////////////////////////////
/// insert_measurement_journal_record is a very basic insert of a
/// new row into the measurement_journals table. Is it expected that
/// this is wrapped by a more formal call (where a txn is initialized)
/// to also set corresponding value records.
///////////////////////////////////////////////////////////////////////////////

pub async fn insert_measurement_journal_record(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
    report_id: MeasurementReportId,
    profile_id: Option<MeasurementSystemProfileId>,
    bundle_id: Option<MeasurementBundleId>,
    state: MeasurementMachineState,
) -> eyre::Result<MeasurementJournalRecord> {
    let query =
                "insert into measurement_journal(machine_id, report_id, profile_id, bundle_id, state) values($1, $2, $3, $4, $5) returning *";
    let journal = sqlx::query_as::<_, MeasurementJournalRecord>(query)
        .bind(machine_id)
        .bind(report_id)
        .bind(profile_id)
        .bind(bundle_id)
        .bind(state)
        .fetch_one(&mut **txn)
        .await?;
    Ok(journal)
}

///////////////////////////////////////////////////////////////////////////////
/// delete_journal_where_id deletes a journal record.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_journal_where_id(
    txn: &mut Transaction<'_, Postgres>,
    journal_id: MeasurementJournalId,
) -> eyre::Result<Option<MeasurementJournalRecord>> {
    common::delete_object_where_id(txn, journal_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_journal_record_by_id returns a populated
/// MeasurementJournalRecord for the given `journal_id`,
/// if it exists. This leverages the generic get_object_for_id
/// function since its a simple/common pattern.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_journal_record_by_id(
    txn: &mut Transaction<'_, Postgres>,
    journal_id: MeasurementJournalId,
) -> eyre::Result<Option<MeasurementJournalRecord>> {
    common::get_object_for_id(txn, journal_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_journal_records returns all MeasurementJournalRecord
/// instances in the database. This leverages the generic get_all_objects
/// function since its a simple/common pattern.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_journal_records(
    txn: &mut Transaction<'_, Postgres>,
) -> eyre::Result<Vec<MeasurementJournalRecord>> {
    common::get_all_objects(txn).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_journal_records_for_machine_id returns all journal
/// records for a given machine ID, which is used by the `journal list`
/// CLI option.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_journal_records_for_machine_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> eyre::Result<Vec<MeasurementJournalRecord>> {
    common::get_objects_where_id(txn, machine_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_journal_ids_by_values returns a journal
/// whose values match the input values.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_journal_ids_by_values(
    txn: &mut Transaction<'_, Postgres>,
    values: &[common::PcrRegisterValue],
) -> eyre::Result<Vec<MeasurementReportId>> {
    common::get_ids_for_bundle_values(txn, "measurement_journal_values", values).await
}
