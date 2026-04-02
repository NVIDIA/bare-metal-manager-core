/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::hash::Hasher;

use chrono::{DateTime, Utc};
use model::health::HealthHistoryRecord;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgConnection, Row};

use crate::DatabaseError;

/// History of health for a single Object
#[derive(Debug, Clone)]
struct DbHealthHistoryRecord {
    /// The ID of the object associated with the health record
    pub object_id: String,

    /// The observed health of the object
    pub health: health_report::HealthReport,

    /// The time when the health was observed
    pub time: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for DbHealthHistoryRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(DbHealthHistoryRecord {
            object_id: row.try_get("object_id")?,
            health: row
                .try_get::<sqlx::types::Json<health_report::HealthReport>, _>("health")?
                .0,
            time: row.try_get("time")?,
        })
    }
}

impl From<DbHealthHistoryRecord> for model::health::HealthHistoryRecord {
    fn from(record: DbHealthHistoryRecord) -> Self {
        Self {
            health: record.health,
            time: record.time,
        }
    }
}

/// Identifies the table that is used to store health history
#[derive(Debug, Copy, Clone)]
pub enum HealthHistoryTableId {
    Machine,
}

impl HealthHistoryTableId {
    pub fn sql_table(self) -> &'static str {
        match self {
            HealthHistoryTableId::Machine => "machine_health_history",
        }
    }
}

/// Retrieve the health history for a list of Objects
///
/// It returns a [HashMap][std::collections::HashMap] keyed by the object ID and
/// the history of health that has been observed by the object, starting with the
/// newest.
pub async fn find_by_object_ids(
    txn: &mut PgConnection,
    table_id: HealthHistoryTableId,
    ids: &[impl std::fmt::Display],
    // Only include records between the given start and end time
    start_time: Option<DateTime<Utc>>,
    end_time: Option<DateTime<Utc>>,
) -> Result<std::collections::HashMap<String, Vec<HealthHistoryRecord>>, DatabaseError> {
    let mut qb = sqlx::QueryBuilder::new("SELECT object_id, health, time FROM ");
    qb.push(table_id.sql_table());
    qb.push(" WHERE object_id IN");

    qb.push(" (");
    let mut separated = qb.separated(", ");
    for id in ids {
        separated.push_bind(id.to_string());
    }
    qb.push(")");

    if let Some(start_time) = start_time {
        qb.push(" AND time >= ");
        qb.push_bind(start_time);
    }
    if let Some(end_time) = end_time {
        qb.push(" AND time <= ");
        qb.push_bind(end_time);
    }

    qb.push(" ORDER BY id DESC");

    let query = qb.build_query_as();
    let query_results: Vec<DbHealthHistoryRecord> = query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query("find_health_history", e))?;

    let mut histories = std::collections::HashMap::new();
    for result in query_results.into_iter() {
        let records: &mut Vec<HealthHistoryRecord> =
            histories.entry(result.object_id.clone()).or_default();
        records.push(result.into());
    }
    Ok(histories)
}

/// Store a new health history record for an object
pub async fn persist(
    txn: &mut PgConnection,
    table_id: HealthHistoryTableId,
    object_id: &impl std::fmt::Display,
    health: &health_report::HealthReport,
) -> Result<(), DatabaseError> {
    // Calculate a hash value of the Report, that we can compare to the latest
    // health value written.
    // If the report did not change, skip the insert.
    // This behavior is achieved by using a sub-query to extract the last written
    // hash for an object, and comparing it to the most recent hash.
    // Note: Since it uses a hash, there is a minor chance of not writing an
    // entry even if health changed.
    let mut hasher = rustc_hash::FxHasher::default();
    health.hash_without_timestamps(&mut hasher);
    let health_hash = format!("{:#x}", hasher.finish());

    let sql_table = table_id.sql_table();
    let query = format!("WITH new_history_record as(
            SELECT $1 as object_id,
            $2::jsonb as health,
            $3 as health_hash,
            $4 as time
        ),
        last_history_record as(
            SELECT health_hash FROM {sql_table}
            WHERE object_id = $1
            ORDER BY id DESC
            LIMIT 1
        )
        INSERT INTO {sql_table} (object_id, health, health_hash, time)
        SELECT * FROM new_history_record
        WHERE NOT EXISTS (SELECT health_hash FROM last_history_record WHERE last_history_record.health_hash = new_history_record.health_hash);");
    let _query_result = sqlx::query(&query)
        .bind(object_id.to_string())
        .bind(sqlx::types::Json(health))
        .bind(health_hash)
        .bind(chrono::Utc::now())
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(&query, e))?;
    Ok(())
}

/// Renames all health entries using one Object ID into using another Object ID
pub async fn update_object_ids(
    txn: &mut PgConnection,
    table_id: HealthHistoryTableId,
    old_object_id: &impl std::fmt::Display,
    new_object_id: &impl std::fmt::Display,
) -> Result<(), DatabaseError> {
    let sql_table = table_id.sql_table();
    let query = format!("UPDATE {sql_table} SET object_id=$1 WHERE object_id=$2");
    sqlx::query(&query)
        .bind(new_object_id.to_string())
        .bind(old_object_id.to_string())
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(&query, e))?;

    Ok(())
}
