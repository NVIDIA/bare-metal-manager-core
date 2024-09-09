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

use std::ops::DerefMut;

use crate::db::DatabaseError;
use crate::measured_boot::dto::keys::MeasurementReportId;
use crate::measured_boot::dto::records::{MeasurementReportRecord, MeasurementReportValueRecord};

use crate::measured_boot::interface::common;
use forge_uuid::machine::MachineId;
use sqlx::{Postgres, QueryBuilder, Transaction};

/// match_latest_reports takes a list of PcrRegisterValues (i.e. register:sha256)
/// and returns all latest matching report entries for it.
///
/// The intent is bundle operations can call this to see what reports
/// match the bundle.
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

pub async fn match_latest_reports(
    txn: &mut Transaction<'_, Postgres>,
    values: &[common::PcrRegisterValue],
) -> Result<Vec<MeasurementReportRecord>, DatabaseError> {
    if values.is_empty() {
        return Err(DatabaseError::new(
            file!(),
            line!(),
            "match_latest_reports",
            sqlx::Error::Protocol(String::from("empty values list")),
        ));
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

    let prepared = query.build_query_as();

    prepared
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "match_latest_reports", e))
}

/// insert_measurement_report_record is a very basic insert of a
/// new row into the measurement_reports table. Is it expected that
/// this is wrapped by a more formal call (where a txn is initialized)
/// to also set corresponding value records.
pub async fn insert_measurement_report_record(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> Result<MeasurementReportRecord, DatabaseError> {
    let query = "insert into measurement_reports(machine_id) values($1) returning *";
    sqlx::query_as(query)
        .bind(machine_id)
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "insert_measurement_report_record", e))
}

/// insert_measurement_report_value_records takes a vec of
/// Strings and subsequently calls an individual insert
/// for each value. It is assumed this is called by a parent
/// wrapper where a transaction is created.
pub async fn insert_measurement_report_value_records(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
    values: &[common::PcrRegisterValue],
) -> Result<Vec<MeasurementReportValueRecord>, DatabaseError> {
    if values.is_empty() {
        return Err(DatabaseError::new(
            file!(),
            line!(),
            "match_latest_reports",
            sqlx::Error::Protocol(String::from("empty PcrRegisterValues list")),
        ));
    }

    let mut records: Vec<MeasurementReportValueRecord> = Vec::new();
    for value in values.iter() {
        records.push(insert_measurement_report_value_record(txn, report_id, value).await?);
    }
    Ok(records)
}

/// insert_measurement_report_value_record inserts a single report value.
async fn insert_measurement_report_value_record(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
    value: &common::PcrRegisterValue,
) -> Result<MeasurementReportValueRecord, DatabaseError> {
    let query = "insert into measurement_reports_values(report_id, pcr_register, sha256) values($1, $2, $3) returning *";
    sqlx::query_as(query)
        .bind(report_id)
        .bind(value.pcr_register)
        .bind(&value.sha256)
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "insert_measurement_report_value_record",
                e,
            )
        })
}

/// get_all_measurement_report_records returns all MeasurementReportRecord
/// instances in the database. This leverages the generic get_all_objects
/// function since its a simple/common pattern.
pub async fn get_all_measurement_report_records(
    txn: &mut Transaction<'_, Postgres>,
) -> Result<Vec<MeasurementReportRecord>, DatabaseError> {
    common::get_all_objects(txn).await.map_err(|e| {
        DatabaseError::new(
            file!(),
            line!(),
            "get_all_measurement_report_records",
            e.source,
        )
    })
}

/// get_all_measurement_report_value_records returns all
/// MeasurementReportValueRecord instances in the database. This leverages
/// the generic get_all_objects function since its a simple/common pattern.
pub async fn get_all_measurement_report_value_records(
    txn: &mut Transaction<'_, Postgres>,
) -> Result<Vec<MeasurementReportValueRecord>, DatabaseError> {
    common::get_all_objects(txn).await.map_err(|e| {
        DatabaseError::new(
            file!(),
            line!(),
            "get_all_measurement_report_value_records",
            e.source,
        )
    })
}

/// get_measurement_report_record_by_id returns a populated
/// MeasurementReportRecord for the given `report_id`,
/// if it exists. This leverages the generic get_object_for_id
/// function since its a simple/common pattern.
pub async fn get_measurement_report_record_by_id(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
) -> Result<Option<MeasurementReportRecord>, DatabaseError> {
    common::get_object_for_id(txn, report_id)
        .await
        .map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "get_measurement_report_record_by_id",
                e.source,
            )
        })
}

/// get_measurement_report_records_for_machine_id returns all report
/// records for a given machine ID, which is used by the `report list`
/// CLI option.
pub async fn get_measurement_report_records_for_machine_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MachineId,
) -> Result<Vec<MeasurementReportRecord>, DatabaseError> {
    common::get_objects_where_id(txn, machine_id)
        .await
        .map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "get_measurement_report_records_for_machine_id",
                e.source,
            )
        })
}

/// get_measurement_report_values_for_report_id returns
/// all of the measurement values associated with a given
/// `report_id`. This call leverages the generic
/// get_objects_where_id, allowing a caller to get a list
/// of multiple objects matching a given PgUuid, where
/// the PgUuid is probably a reference/foreign key.
pub async fn get_measurement_report_values_for_report_id(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
) -> Result<Vec<MeasurementReportValueRecord>, DatabaseError> {
    common::get_objects_where_id(txn, report_id)
        .await
        .map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "get_measurement_report_values_for_report_id",
                e.source,
            )
        })
}

/// get_measurement_report_ids_by_values returns a report
/// whose values match the input values.
pub async fn get_measurement_report_ids_by_values(
    txn: &mut Transaction<'_, Postgres>,
    values: &[common::PcrRegisterValue],
) -> Result<Vec<MeasurementReportId>, DatabaseError> {
    common::get_ids_for_bundle_values(txn, "measurement_reports_values", values)
        .await
        .map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "get_measurement_report_ids_by_values",
                e.source,
            )
        })
}

/// get_latest_measurement_report_records_by_machine_id returns the most
/// recent measurement report IDs sent by each machine.
pub async fn get_latest_measurement_report_records_by_machine_id(
    txn: &mut Transaction<'_, Postgres>,
) -> Result<Vec<MeasurementReportRecord>, DatabaseError> {
    let query =
        "select distinct on (machine_id) * from measurement_reports order by machine_id,ts desc";
    sqlx::query_as(query)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "get_latest_measurement_report_records_by_machine_id",
                e,
            )
        })
}

/// delete_report_for_id deletes a report record.
pub async fn delete_report_for_id(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
) -> Result<Option<MeasurementReportRecord>, DatabaseError> {
    common::delete_object_where_id(txn, report_id).await
}

/// delete_report_values_for_id deletes all report
/// value records for a report.
pub async fn delete_report_values_for_id(
    txn: &mut Transaction<'_, Postgres>,
    report_id: MeasurementReportId,
) -> Result<Vec<MeasurementReportValueRecord>, DatabaseError> {
    common::delete_objects_where_id(txn, report_id)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "delete_report_values_for_id", e.source))
}
