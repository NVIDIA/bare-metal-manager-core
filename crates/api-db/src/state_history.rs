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

use chrono::{DateTime, Utc};
use config_version::ConfigVersion;
use model::state_history::StateHistoryRecord;
use serde::Serialize;
use sqlx::postgres::PgRow;
use sqlx::{Encode, FromRow, PgConnection, Postgres, Row, Type};

use crate::{DatabaseError, DatabaseResult};

#[derive(Debug, Clone)]
struct DbStateHistoryRecord {
    object_id: String,
    state: String,
    state_version: ConfigVersion,
    timestamp: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for DbStateHistoryRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(Self {
            object_id: row.try_get("object_id")?,
            state: row.try_get("state")?,
            state_version: row.try_get("state_version")?,
            timestamp: row.try_get("timestamp")?,
        })
    }
}

impl From<DbStateHistoryRecord> for StateHistoryRecord {
    fn from(record: DbStateHistoryRecord) -> Self {
        StateHistoryRecord {
            state: record.state,
            state_version: record.state_version,
            time: Some(record.timestamp),
        }
    }
}

/// Identifies the table that is used to store state history.
#[derive(Debug, Copy, Clone)]
pub enum StateHistoryTableId {
    Machine,
    NetworkSegment,
    DpaInterface,
    IbPartition,
    PowerShelf,
    Rack,
    Switch,
}

impl StateHistoryTableId {
    pub fn sql_table(self) -> &'static str {
        match self {
            StateHistoryTableId::Machine => "machine_state_history",
            StateHistoryTableId::NetworkSegment => "network_segment_state_history",
            StateHistoryTableId::DpaInterface => "dpa_interface_state_history",
            StateHistoryTableId::IbPartition => "ib_partition_state_history",
            StateHistoryTableId::PowerShelf => "power_shelf_state_history",
            StateHistoryTableId::Rack => "rack_state_history",
            StateHistoryTableId::Switch => "switch_state_history",
        }
    }

    pub fn object_id_column(self) -> &'static str {
        match self {
            StateHistoryTableId::Machine => "machine_id",
            StateHistoryTableId::NetworkSegment => "segment_id",
            StateHistoryTableId::DpaInterface => "interface_id",
            StateHistoryTableId::IbPartition => "partition_id",
            StateHistoryTableId::PowerShelf => "power_shelf_id",
            StateHistoryTableId::Rack => "rack_id",
            StateHistoryTableId::Switch => "switch_id",
        }
    }

    fn object_id_sql_type(self) -> &'static str {
        match self {
            StateHistoryTableId::NetworkSegment
            | StateHistoryTableId::DpaInterface
            | StateHistoryTableId::IbPartition => "uuid",
            StateHistoryTableId::Machine
            | StateHistoryTableId::PowerShelf
            | StateHistoryTableId::Rack
            | StateHistoryTableId::Switch => "varchar",
        }
    }
}

/// Retrieve state history for a list of objects.
///
/// It returns a [HashMap][std::collections::HashMap] keyed by object ID and
/// values of all states that have been entered, starting with the oldest.
pub async fn find_by_object_ids(
    txn: &mut PgConnection,
    table_id: StateHistoryTableId,
    ids: &[impl std::fmt::Display],
) -> DatabaseResult<std::collections::HashMap<String, Vec<StateHistoryRecord>>> {
    if ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }

    let mut qb = sqlx::QueryBuilder::new("SELECT ");
    qb.push(table_id.object_id_column());
    qb.push("::TEXT AS object_id, state::TEXT, state_version, timestamp FROM ");
    qb.push(table_id.sql_table());
    qb.push(" WHERE ");
    qb.push(table_id.object_id_column());
    qb.push("::TEXT IN (");

    let mut separated = qb.separated(", ");
    for id in ids {
        separated.push_bind(id.to_string());
    }
    qb.push(") ORDER BY id ASC");

    let query_results: Vec<DbStateHistoryRecord> = qb
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query("find_state_history", e))?;

    let mut histories = std::collections::HashMap::new();
    for result in query_results {
        let object_id = result.object_id.clone();
        let records: &mut Vec<StateHistoryRecord> = histories.entry(object_id).or_default();
        records.push(result.into());
    }
    Ok(histories)
}

/// Retrieve state history for a single object.
pub async fn for_object(
    txn: &mut PgConnection,
    table_id: StateHistoryTableId,
    object_id: &impl std::fmt::Display,
) -> DatabaseResult<Vec<StateHistoryRecord>> {
    let mut query = sqlx::QueryBuilder::new("SELECT state::TEXT, state_version, timestamp FROM ");
    query.push(table_id.sql_table());
    query.push(" WHERE ");
    query.push(table_id.object_id_column());
    query.push("::TEXT = ");
    query.push_bind(object_id.to_string());
    query.push(" ORDER BY id ASC");
    query
        .build_query_as::<StateHistoryRecord>()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query("state_history::for_object", e))
}

/// Store a state history record for an object.
pub async fn persist<ID, S>(
    txn: &mut PgConnection,
    table_id: StateHistoryTableId,
    object_id: &ID,
    state: &S,
    state_version: ConfigVersion,
) -> DatabaseResult<StateHistoryRecord>
where
    ID: std::fmt::Display + Sync,
    for<'q> &'q ID: Encode<'q, Postgres> + Type<Postgres>,
    S: Serialize + Sync,
{
    let mut query = sqlx::QueryBuilder::new("INSERT INTO ");
    query.push(table_id.sql_table());
    query.push(" (");
    query.push(table_id.object_id_column());
    query.push(", state, state_version) VALUES (");
    query.push_bind(object_id);
    query.push(", ");
    query.push_bind(sqlx::types::Json(state));
    query.push(", ");
    query.push_bind(state_version);
    query.push(
        ")
        RETURNING state::TEXT, state_version, timestamp",
    );
    query
        .build_query_as::<StateHistoryRecord>()
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query("state_history::persist", e))
}

/// Rename all history entries using one object ID into using another object ID.
pub async fn update_object_ids(
    txn: &mut PgConnection,
    table_id: StateHistoryTableId,
    old_object_id: &impl std::fmt::Display,
    new_object_id: &impl std::fmt::Display,
) -> DatabaseResult<()> {
    let mut query = sqlx::QueryBuilder::new("UPDATE ");
    query.push(table_id.sql_table());
    query.push(" SET ");
    query.push(table_id.object_id_column());
    query.push(" = ");
    query.push_bind(new_object_id.to_string());
    query.push("::");
    query.push(table_id.object_id_sql_type());
    query.push(" WHERE ");
    query.push(table_id.object_id_column());
    query.push("::TEXT = ");
    query.push_bind(old_object_id.to_string());
    query
        .build()
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query("state_history::update_object_ids", e))?;

    Ok(())
}

/// Delete all state history entries for an object.
pub async fn delete_by_object_id(
    txn: &mut PgConnection,
    table_id: StateHistoryTableId,
    object_id: &impl std::fmt::Display,
) -> DatabaseResult<u64> {
    let mut query = sqlx::QueryBuilder::new("DELETE FROM ");
    query.push(table_id.sql_table());
    query.push(" WHERE ");
    query.push(table_id.object_id_column());
    query.push("::TEXT = ");
    query.push_bind(object_id.to_string());
    let result = query
        .build()
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query("state_history::delete_by_object_id", e))?;
    Ok(result.rows_affected())
}
