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

/*
///////////////////////////////////////////////////////////////////////////////
/// db/interface/machine.rs
///
/// Code for working the mock_machines and mock_machines_attrs tables in the
/// database, leveraging the mock-machine-specific record types.
///////////////////////////////////////////////////////////////////////////////
*/

use crate::measured_boot::dto::keys::MockMachineId;
use crate::measured_boot::dto::records::{
    MeasurementJournalRecord, MeasurementMachineState, MockMachineAttrRecord, MockMachineRecord,
};

use crate::measured_boot::interface::common;
use sqlx::{Pool, Postgres, Transaction};
use std::collections::HashMap;

///////////////////////////////////////////////////////////////////////////////
/// get_discovery_attributes returns a hashmap of values from DiscoveryInfo
/// used for matching to a machine profile.
///
/// TODO(chet): This is currently mocked out to just pull from the mock
/// machines table, but in real life, this will pull DiscoveryInfo data
/// and return a hashmap from that data.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_discovery_attributes(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<HashMap<String, String>> {
    let attrs = get_mock_machine_attrs_for_machine_id(txn, machine_id).await?;
    let total_attrs = attrs.len();
    let attr_map: HashMap<String, String> =
        attrs.into_iter().map(|rec| (rec.key, rec.value)).collect();
    if total_attrs != attr_map.len() {
        return Err(eyre::eyre!("detected attribute key collision"));
    }
    common::filter_machine_discovery_attrs(&attr_map)
}

///////////////////////////////////////////////////////////////////////////////
/// get_mock_machine_state figures out the current state of the given
/// machine ID by checking its most recent bundle (or lack thereof), and
/// using that result to give it a corresponding MockMachineState.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_mock_machine_state(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<MeasurementMachineState> {
    Ok(
        match get_latest_journal_for_id(&mut *txn, machine_id).await? {
            Some(record) => record.state,
            None => MeasurementMachineState::Discovered,
        },
    )
}

///////////////////////////////////////////////////////////////////////////////
/// get_latest_journal_for_id returns the latest journal record for the
/// provided machine ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_latest_journal_for_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<Option<MeasurementJournalRecord>> {
    let query = "select distinct on (machine_id) * from measurement_journal where machine_id = $1 order by machine_id,ts desc";
    Ok(sqlx::query_as::<_, MeasurementJournalRecord>(query)
        .bind(machine_id)
        .fetch_optional(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// insert_mock_machine_record creates a single entry for a new mock machine,
/// with the expectation that attributes will accompany this by way of a
/// subsequent call to insert_mock_machine_attr_records.
///////////////////////////////////////////////////////////////////////////////

pub async fn insert_mock_machine_record(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<MockMachineRecord> {
    let query = "insert into mock_machines(machine_id) values($1) returning *";
    match sqlx::query_as::<_, MockMachineRecord>(query)
        .bind(machine_id)
        .fetch_one(&mut **txn)
        .await
    {
        Ok(record) => Ok(record),
        Err(sqlx_err) => {
            let is_db_err = sqlx_err.as_database_error();
            match is_db_err {
                Some(db_err) => match db_err.kind() {
                    sqlx::error::ErrorKind::UniqueViolation => {
                        Err(eyre::eyre!("machine already exists"))
                    }
                    _ => Err(eyre::eyre!(
                        "database error creating machine record: {}",
                        db_err
                    )),
                },
                None => Err(eyre::eyre!("error creating machine record: {}", sqlx_err)),
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// insert_mock_machine_attr_records takes a hashmap of
/// k/v attributes and subsequently calls an individual insert
/// for each pair. It is assumed this is called by a parent
/// wrapper where a transaction is created.
///////////////////////////////////////////////////////////////////////////////

pub async fn insert_mock_machine_attr_records(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
    attrs: &HashMap<String, String>,
) -> eyre::Result<Vec<MockMachineAttrRecord>> {
    let mut attributes: Vec<MockMachineAttrRecord> = Vec::new();
    for (key, value) in attrs.iter() {
        attributes
            .push(insert_mock_machine_attr_record(txn, machine_id.clone(), key, value).await?);
    }
    Ok(attributes)
}

///////////////////////////////////////////////////////////////////////////////
/// insert_mock_machine_attr_record inserts a single machine
/// attribute (k/v) pair.
///////////////////////////////////////////////////////////////////////////////

async fn insert_mock_machine_attr_record(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
    key: &String,
    value: &String,
) -> eyre::Result<MockMachineAttrRecord> {
    let query =
        "insert into mock_machines_attrs(machine_id, key, value) values($1, $2, $3) returning *";
    Ok(sqlx::query_as::<_, MockMachineAttrRecord>(query)
        .bind(machine_id)
        .bind(key)
        .bind(value)
        .fetch_one(&mut **txn)
        .await?)
}

///////////////////////////////////////////////////////////////////////////////
/// delete_mock_machine_record_where_id deletes a mock machine with the
/// given machine ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn delete_mock_machine_record_where_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<Option<MockMachineRecord>> {
    common::delete_object_where_id(txn, machine_id.clone()).await
}

pub async fn delete_mock_machine_attrs_where_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<Vec<MockMachineAttrRecord>> {
    common::delete_objects_where_id(txn, machine_id.clone()).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_mock_machine_by_id returns a single MockMachineRecord instance
/// for the given machine ID.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_mock_machine_by_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<Option<MockMachineRecord>> {
    common::get_object_for_id(&mut *txn, machine_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_mock_machine_attrs_for_machine_id returns all machine attribute
/// records associated with the provided MockMachineId.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_mock_machine_attrs_for_machine_id(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: MockMachineId,
) -> eyre::Result<Vec<MockMachineAttrRecord>> {
    common::get_objects_where_id(txn, machine_id).await
}

///////////////////////////////////////////////////////////////////////////////
/// get_mock_machines_records returns all MockMachineRecord rows,
/// primarily for the purpose of `mock-machine list`.
///////////////////////////////////////////////////////////////////////////////

pub async fn get_mock_machines_records(
    db_conn: &Pool<Postgres>,
) -> eyre::Result<Vec<MockMachineRecord>> {
    let mut txn = db_conn.begin().await?;
    common::get_all_objects(&mut txn).await
}
