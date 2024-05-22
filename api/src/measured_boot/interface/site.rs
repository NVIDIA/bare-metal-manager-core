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
 *  Code for working the measurement_trusted_machines and measurement_trusted_profiles
 *  tables in the database, leveraging the site-specific record types.
*/

use crate::measured_boot::dto::keys::{
    MeasurementApprovedMachineId, MeasurementApprovedProfileId, MeasurementSystemProfileId,
    MockMachineId,
};
use crate::measured_boot::dto::records::{
    MeasurementApprovedMachineRecord, MeasurementApprovedProfileRecord, MeasurementApprovedType,
};
use crate::measured_boot::dto::traits::DbTable;
use crate::measured_boot::interface::common;
use sqlx::{Pool, Postgres, Transaction};

pub async fn insert_into_approved_machines(
    db_conn: &Pool<Postgres>,
    machine_id: MockMachineId,
    approval_type: MeasurementApprovedType,
    pcr_registers: Option<String>,
    comments: Option<String>,
) -> eyre::Result<MeasurementApprovedMachineRecord> {
    let mut txn = db_conn.begin().await?;
    let query = "insert into measurement_approved_machines(machine_id, approval_type, pcr_registers, comments) values($1, $2, $3, $4) returning *";
    let record = sqlx::query_as::<_, MeasurementApprovedMachineRecord>(query)
        .bind(machine_id)
        .bind(approval_type)
        .bind(pcr_registers)
        .bind(comments)
        .fetch_one(&mut *txn)
        .await?;
    txn.commit().await?;
    Ok(record)
}

pub async fn remove_from_approved_machines_by_approval_id(
    txn: &mut Transaction<'_, Postgres>,
    approval_id: MeasurementApprovedMachineId,
) -> eyre::Result<MeasurementApprovedMachineRecord> {
    let query = "delete from measurement_approved_machines where approval_id = $1 returning *";
    Ok(sqlx::query_as::<_, MeasurementApprovedMachineRecord>(query)
        .bind(approval_id)
        .fetch_one(&mut **txn)
        .await?)
}

pub async fn remove_from_approved_machines_by_machine_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<MeasurementApprovedMachineRecord> {
    let query = "delete from measurement_approved_machines where machine_id = $1 returning *";
    Ok(sqlx::query_as::<_, MeasurementApprovedMachineRecord>(query)
        .bind(machine_id)
        .fetch_one(&mut **txn)
        .await?)
}

pub async fn get_approved_machines(
    db_conn: &Pool<Postgres>,
) -> eyre::Result<Vec<MeasurementApprovedMachineRecord>> {
    let mut txn = db_conn.begin().await?;
    common::get_all_objects(&mut txn).await
}

pub async fn get_approval_for_machine_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<Option<MeasurementApprovedMachineRecord>> {
    common::get_object_for_id(txn, machine_id).await
}

pub async fn insert_into_approved_profiles(
    db_conn: &Pool<Postgres>,
    profile_id: MeasurementSystemProfileId,
    approval_type: MeasurementApprovedType,
    pcr_registers: Option<String>,
    comments: Option<String>,
) -> eyre::Result<MeasurementApprovedProfileRecord> {
    let mut txn = db_conn.begin().await?;
    let query = "insert into measurement_approved_profiles(profile_id, approval_type, pcr_registers, comments) values($1, $2, $3, $4) returning *";
    let record = sqlx::query_as::<_, MeasurementApprovedProfileRecord>(query)
        .bind(profile_id)
        .bind(approval_type)
        .bind(pcr_registers)
        .bind(comments)
        .fetch_one(&mut *txn)
        .await?;
    txn.commit().await?;
    Ok(record)
}

pub async fn remove_from_approved_profiles_by_approval_id(
    txn: &mut Transaction<'_, Postgres>,
    approval_id: MeasurementApprovedProfileId,
) -> eyre::Result<MeasurementApprovedProfileRecord> {
    let query = "delete from measurement_approved_profiles where approval_id = $1 returning *";
    Ok(sqlx::query_as::<_, MeasurementApprovedProfileRecord>(query)
        .bind(approval_id)
        .fetch_one(&mut **txn)
        .await?)
}

pub async fn remove_from_approved_profiles_by_profile_id(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
) -> eyre::Result<MeasurementApprovedProfileRecord> {
    let query = "delete from measurement_approved_profiles where profile_id = $1 returning *";
    Ok(sqlx::query_as::<_, MeasurementApprovedProfileRecord>(query)
        .bind(profile_id)
        .fetch_one(&mut **txn)
        .await?)
}

pub async fn get_approved_profiles(
    db_conn: &Pool<Postgres>,
) -> eyre::Result<Vec<MeasurementApprovedProfileRecord>> {
    let mut txn = db_conn.begin().await?;
    common::get_all_objects(&mut txn).await
}

pub async fn get_approval_for_profile_id(
    txn: &mut Transaction<'_, Postgres>,
    profile_id: MeasurementSystemProfileId,
) -> eyre::Result<Option<MeasurementApprovedProfileRecord>> {
    // TODO(chet): get_object_for_id should become fetch_optional.
    let query = "select * from measurement_approved_profiles where profile_id = $1";
    Ok(sqlx::query_as::<_, MeasurementApprovedProfileRecord>(query)
        .bind(profile_id)
        .fetch_optional(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// import_measurement_approved_machines takes a vector of
/// MeasurementApprovedMachineRecord and calls
/// import_measurement_approved_machine for each of them.
///
/// This is used for doing full site imports, and is wrapped in a transaction
/// such that, if any of it fails, none of it will be committed.
///////////////////////////////////////////////////////////////////////////////

pub async fn import_measurement_approved_machines(
    txn: &mut Transaction<'_, Postgres>,
    records: Vec<MeasurementApprovedMachineRecord>,
) -> eyre::Result<Vec<MeasurementApprovedMachineRecord>> {
    let mut committed = Vec::<MeasurementApprovedMachineRecord>::new();
    for record in records.iter() {
        committed.push(import_measurement_approved_machine(&mut *txn, record).await?);
    }
    Ok(committed)
}

///////////////////////////////////////////////////////////////////////////////
/// import_measurement_approved_machine inserts a single
/// MeasurementApprovedMachineRecord.
///
/// This is used for doing full site imports, and the intent is that this
/// is called by import_measurement_approved_machines as part of inserting a
/// bunch of machine approvals.
///////////////////////////////////////////////////////////////////////////////

pub async fn import_measurement_approved_machine(
    txn: &mut Transaction<'_, Postgres>,
    record: &MeasurementApprovedMachineRecord,
) -> eyre::Result<MeasurementApprovedMachineRecord> {
    let query = format!(
        "insert into {}(approval_id, machine_id, state, ts, comments) values($1, $2, $3, $4, $5) returning *",
        MeasurementApprovedMachineRecord::db_table_name()
    );
    Ok(
        sqlx::query_as::<_, MeasurementApprovedMachineRecord>(&query)
            .bind(record.approval_id)
            .bind(record.machine_id.clone())
            .bind(record.approval_type)
            .bind(record.ts)
            .bind(record.comments.clone())
            .fetch_one(&mut **txn)
            .await?,
    )
}

///////////////////////////////////////////////////////////////////////////////
/// import_measurement_approved_profiles takes a vector of
/// MeasurementApprovedMachineRecord and calls
/// import_measurement_approved_profile for each of them.
///
/// This is used for doing full site imports, and is wrapped in a transaction
/// such that, if any of it fails, none of it will be committed.
///////////////////////////////////////////////////////////////////////////////

pub async fn import_measurement_approved_profiles(
    txn: &mut Transaction<'_, Postgres>,
    records: Vec<MeasurementApprovedProfileRecord>,
) -> eyre::Result<Vec<MeasurementApprovedProfileRecord>> {
    let mut committed = Vec::<MeasurementApprovedProfileRecord>::new();
    for record in records.iter() {
        committed.push(import_measurement_approved_profile(&mut *txn, record).await?);
    }
    Ok(committed)
}

///////////////////////////////////////////////////////////////////////////////
/// import_measurement_approved_profile inserts a single
/// MeasurementApprovedProfileRecord.
///
/// This is used for doing full site imports, and the intent is that this
/// is called by import_measurement_approved_profiles as part of inserting a
/// bunch of machine approvals.
///////////////////////////////////////////////////////////////////////////////

pub async fn import_measurement_approved_profile(
    txn: &mut Transaction<'_, Postgres>,
    record: &MeasurementApprovedProfileRecord,
) -> eyre::Result<MeasurementApprovedProfileRecord> {
    let query = format!(
        "insert into {}(approval_id, profile_id, state, ts, comments) values($1, $2, $3, $4, $5) returning *",
        MeasurementApprovedProfileRecord::db_table_name()
    );
    Ok(
        sqlx::query_as::<_, MeasurementApprovedProfileRecord>(&query)
            .bind(record.approval_id)
            .bind(record.profile_id)
            .bind(record.approval_type)
            .bind(record.ts)
            .bind(record.comments.clone())
            .fetch_one(&mut **txn)
            .await?,
    )
}
