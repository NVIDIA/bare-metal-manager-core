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
 *  Code for working the measuremment_reports and measurement_reports_values
 *  tables in the database, leveraging the report-specific record types.
*/

use crate::measured_boot::dto::keys::MeasurementReportId;
use crate::measured_boot::dto::records::{MeasurementReportRecord, MeasurementReportValueRecord};

use crate::measured_boot::interface::common;
use crate::model::machine::machine_id::MachineId;
use sqlx::{Pool, Postgres, QueryBuilder, Transaction};

///////////////////////////////////////////////////////////////////////////////
/// match_report takes a list of PcrRegisterValues (i.e. register:sha256)
/// and returns all matching report entries for it.
///
/// The intent is bundle operations can call this to see what reports
/// match the bundle.
///////////////////////////////////////////////////////////////////////////////

pub fn where_pcr_pairs(
    query: &mut QueryBuilder<'_, Postgres>,
    values: &[common::PcrRegisterValue],
) {
    query.push("where (pcr_register, sha256) in (");
    for (pair_index, value) in values.iter().enumerate() {
        query.push("(");
        query.push_bind(value.pcr_register);
        query.push(",");
        query.push_bind(value.sha256.clone());
        query.push(")");
        if pair_index < values.len() - 1 {
            query.push(", ");
        }
    }
    query.push(") ");
}

pub async fn match_report(
    db_conn: &Pool<Postgres>,
    values: &[common::PcrRegisterValue],
) -> eyre::Result<Vec<MeasurementReportRecord>> {
    if values.is_empty() {
        return Err(eyre::eyre!("must have at least one PCR register value"));
    }
    let mut txn = db_conn.begin().await?;
    match_latest_reports_with_txn(&mut txn, values).await
}

pub async fn match_latest_reports_with_txn(
    txn: &mut Transaction<'_, Postgres>,
    values: &[common::PcrRegisterValue],
) -> eyre::Result<Vec<MeasurementReportRecord>> {
    if values.is_empty() {
        return Err(eyre::eyre!("must have at least one PCR register value"));
    }

    let columns = [
        "measurement_reports.report_id",
        "measurement_reports.machine_id",
        "measurement_reports.ts",
    ]
    .join(", ");

    let pcr_register_len = values.len();

    let mut query: QueryBuilder<'_, Postgres> = QueryBuilder::new(format!(
        "select {columns} from measurement_reports
        join
            measurement_reports_values
                on measurement_reports.report_id=measurement_reports_values.report_id
        join
            (select distinct on (machine_id) * from measurement_reports order by machine_id,ts desc) as latest_reports
                on measurement_reports_values.report_id=latest_reports.report_id ", columns=columns));
    where_pcr_pairs(&mut query, values);

    query.push("group by measurement_reports.report_id ");
    query.push("having count(*) = ");
    query.push_bind(pcr_register_len as i16);

    let prepared = query.build_query_as::<MeasurementReportRecord>();
    Ok(prepared.fetch_all(&mut **txn).await?)
}

///////////////////////////////////////////////////////////////////////////////
/// insert_measurement_report_record is a very basic insert of a
/// new row into the measurement_reports table. Is it expected that
/// this is wrapped by a more formal call (where a txn is initialized)
/// to also set corresponding value records.
///////////////////////////////////////////////////////////////////////////////

pub async fn insert_measurement_report_record(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> eyre::Result<MeasurementReportRecord> {
    let query = "insert into measurement_reports(machine_id) values($1) returning *";
    Ok(sqlx::query_as::<_, MeasurementReportRecord>(query)
        .bind(machine_id)
        .fetch_one(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// insert_measurement_report_value_records takes a vec of
/// Strings and subsequently calls an individual insert
/// for each value. It is assumed this is called by a parent
/// wrapper where a transaction is created.
///////////////////////////////////////////////////////////////////////////////

pub async fn insert_measurement_report_value_records(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
    values: &[common::PcrRegisterValue],
) -> eyre::Result<Vec<MeasurementReportValueRecord>> {
    if values.is_empty() {
        return Err(eyre::eyre!("must have at least one report value"));
    }
    let mut records: Vec<MeasurementReportValueRecord> = Vec::new();
    for value in values.iter() {
        records.push(insert_measurement_report_value_record(txn, report_id, value).await?);
    }
    Ok(records)
}

///////////////////////////////////////////////////////////////////////////////
/// insert_measurement_report_value_record inserts a single report value.
///////////////////////////////////////////////////////////////////////////////

async fn insert_measurement_report_value_record(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
    value: &common::PcrRegisterValue,
) -> eyre::Result<MeasurementReportValueRecord> {
    let query = "insert into measurement_reports_values(report_id, pcr_register, sha256) values($1, $2, $3) returning *";
    Ok(sqlx::query_as::<_, MeasurementReportValueRecord>(query)
        .bind(report_id)
        .bind(value.pcr_register)
        .bind(&value.sha256)
        .fetch_one(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// get_all_measurement_report_records returns all MeasurementReportRecord
/// instances in the database. This leverages the generic get_all_objects
/// function since its a simple/common pattern.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_all_measurement_report_records(
    txn: &mut Transaction<'_, Postgres>,
) -> eyre::Result<Vec<MeasurementReportRecord>> {
    common::get_all_objects(txn).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_all_measurement_report_value_records returns all
/// MeasurementReportValueRecord instances in the database. This leverages
/// the generic get_all_objects function since its a simple/common pattern.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_all_measurement_report_value_records(
    txn: &mut Transaction<'_, Postgres>,
) -> eyre::Result<Vec<MeasurementReportValueRecord>> {
    common::get_all_objects(txn).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_report_record_by_id returns a populated
/// MeasurementReportRecord for the given `report_id`,
/// if it exists. This leverages the generic get_object_for_id
/// function since its a simple/common pattern.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_report_record_by_id(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
) -> eyre::Result<Option<MeasurementReportRecord>> {
    common::get_object_for_id(txn, report_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_report_records_for_machine_id returns all report
/// records for a given machine ID, which is used by the `report list`
/// CLI option.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_report_records_for_machine_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> eyre::Result<Vec<MeasurementReportRecord>> {
    common::get_objects_where_id(txn, machine_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_report_values_for_report_id returns
/// all of the measurement values associated with a given
/// `report_id`. This call leverages the generic
/// get_objects_where_id, allowing a caller to get a list
/// of multiple objects matching a given PgUuid, where
/// the PgUuid is probably a reference/foreign key.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_report_values_for_report_id(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
) -> eyre::Result<Vec<MeasurementReportValueRecord>> {
    common::get_objects_where_id(txn, report_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_measurement_report_ids_by_values returns a report
/// whose values match the input values.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_measurement_report_ids_by_values(
    txn: &mut Transaction<'_, Postgres>,
    values: &[common::PcrRegisterValue],
) -> eyre::Result<Vec<MeasurementReportId>> {
    common::get_ids_for_bundle_values(txn, "measurement_reports_values", values).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_latest_measurement_report_records_by_machine_id returns the most
/// recent measurement report IDs sent by each machine.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_latest_measurement_report_records_by_machine_id(
    txn: &mut Transaction<'_, Postgres>,
) -> eyre::Result<Vec<MeasurementReportRecord>> {
    let query =
        "select distinct on (machine_id) * from measurement_reports order by machine_id,ts desc";
    Ok(sqlx::query_as::<_, MeasurementReportRecord>(query)
        .fetch_all(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// delete_report_for_id deletes a report record.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_report_for_id(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
) -> eyre::Result<MeasurementReportRecord> {
    match common::delete_object_where_id(txn, report_id).await? {
        Some(record) => Ok(record),
        None => Err(eyre::eyre!("could not find report for ID")),
    }
}

///////////////////////////////////////////////////////////////////////////////
/// delete_report_values_for_id deletes all report
/// value records for a report.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_report_values_for_id(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
) -> eyre::Result<Vec<MeasurementReportValueRecord>> {
    common::delete_objects_where_id(txn, report_id).await
}
