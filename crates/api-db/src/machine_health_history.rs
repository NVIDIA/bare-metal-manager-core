/*
* SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
* SPDX-License-Identifier: LicenseRef-NvidiaProprietary
*
* NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
* property and proprietary rights in and to this material, related
* documentation and any modifications thereto. Any use, reproduction,
* disclosure or distribution of this material and related documentation
* without an express license agreement from NVIDIA CORPORATION or
* its affiliates is strictly prohibited.
*/
use std::hash::Hasher;

use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use model::machine::MachineHealthHistoryRecord;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgConnection, Row};

use crate::DatabaseError;

/// History of Machine health for a single Machine
#[derive(Debug, Clone)]
struct DbMachineHealthHistoryRecord {
    /// The ID of the machine that experienced the state change
    pub machine_id: MachineId,

    /// The observed health of the Machine
    pub health: health_report::HealthReport,

    /// The time when the health was observed
    pub time: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for DbMachineHealthHistoryRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(DbMachineHealthHistoryRecord {
            machine_id: row.try_get("machine_id")?,
            health: row
                .try_get::<sqlx::types::Json<health_report::HealthReport>, _>("health")?
                .0,
            time: row.try_get("time")?,
        })
    }
}

impl From<DbMachineHealthHistoryRecord> for model::machine::MachineHealthHistoryRecord {
    fn from(record: DbMachineHealthHistoryRecord) -> Self {
        Self {
            health: record.health,
            time: record.time,
        }
    }
}

/// Retrieve the health history for a list of Machines
///
/// It returns a [HashMap][std::collections::HashMap] keyed by the machine ID and
/// the history of health that has been observed by the Machine, starting with the
/// oldest.
pub async fn find_by_machine_ids(
    txn: &mut PgConnection,
    ids: &[MachineId],
) -> Result<std::collections::HashMap<MachineId, Vec<MachineHealthHistoryRecord>>, DatabaseError> {
    let query = "SELECT machine_id, health, time
        FROM machine_health_history
        WHERE machine_id=ANY($1)
        ORDER BY id ASC";
    let str_ids: Vec<String> = ids.iter().map(|id| id.to_string()).collect();
    let query_results = sqlx::query_as::<_, DbMachineHealthHistoryRecord>(query)
        .bind(str_ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    let mut histories = std::collections::HashMap::new();
    for result in query_results.into_iter() {
        let records: &mut Vec<MachineHealthHistoryRecord> =
            histories.entry(result.machine_id).or_default();
        records.push(result.into());
    }
    Ok(histories)
}

/// Retrieve the health history for a single Machine within a time range
///
/// Returns a list of health history records for the specified machine
/// between start_time (inclusive) and end_time (inclusive), ordered by time ascending.
/// Limits results to 1,000 records by default to prevent excessive memory usage.
pub async fn find_by_time_range(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    start_time: &DateTime<Utc>,
    end_time: &DateTime<Utc>,
) -> Result<Vec<MachineHealthHistoryRecord>, DatabaseError> {
    let query = "SELECT machine_id, health, time
        FROM machine_health_history
        WHERE machine_id = $1
          AND time >= $2
          AND time <= $3
        ORDER BY time ASC
        LIMIT 1000";

    let machine_id_str = machine_id.to_string();
    let query_results = sqlx::query_as::<_, DbMachineHealthHistoryRecord>(query)
        .bind(machine_id_str)
        .bind(start_time)
        .bind(end_time)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(query_results.into_iter().map(|r| r.into()).collect())
}

/// Store a new health history record for a Machine
pub async fn persist(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    health: &health_report::HealthReport,
) -> Result<(), DatabaseError> {
    // Calculate a hash value of the Report, that we can compare to the latest
    // health value written.
    // If the report did not change, skip the insert.
    // This behavior is achieved by using a sub-query to extract the last written
    // hash for a Machine, and comparing it to the most recent hash.
    // Note: Since it uses a hash, there is a minor chance of not writing an
    // entry even if health changed.
    let mut hasher = rustc_hash::FxHasher::default();
    health.hash_without_timestamps(&mut hasher);
    let health_hash = format!("{:#x}", hasher.finish());

    let query = "WITH new_history_record as(
            SELECT $1 as machine_id,
            $2::jsonb as health,
            $3 as health_hash,
            $4 as time
        ),
        last_history_record as(
            SELECT health_hash FROM machine_health_history
            WHERE machine_id = $1
            ORDER BY id DESC
            LIMIT 1
        )
        INSERT INTO machine_health_history (machine_id, health, health_hash, time)
        SELECT * FROM new_history_record
        WHERE NOT EXISTS (SELECT health_hash FROM last_history_record WHERE last_history_record.health_hash = new_history_record.health_hash);";
    let _query_result = sqlx::query(query)
        .bind(machine_id)
        .bind(sqlx::types::Json(health))
        .bind(health_hash)
        .bind(chrono::Utc::now())
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

/// Renames all health entries using one Machine ID into using another Machine ID
pub async fn update_machine_ids(
    // TODO: Test Me
    txn: &mut PgConnection,
    old_machine_id: &MachineId,
    new_machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machine_health_history SET machine_id=$1 WHERE machine_id=$2";
    sqlx::query(query)
        .bind(new_machine_id)
        .bind(old_machine_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}
