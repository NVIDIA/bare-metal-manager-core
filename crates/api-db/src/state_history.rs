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
use sqlx::{FromRow, PgConnection, Row};

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
    VpcPrefix,
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
            StateHistoryTableId::VpcPrefix => "vpc_prefix_state_history",
            StateHistoryTableId::DpaInterface => "dpa_interface_state_history",
            StateHistoryTableId::IbPartition => "ib_partition_state_history",
            StateHistoryTableId::PowerShelf => "power_shelf_state_history",
            StateHistoryTableId::Rack => "rack_state_history",
            StateHistoryTableId::Switch => "switch_state_history",
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

    let mut qb =
        sqlx::QueryBuilder::new("SELECT object_id, state::TEXT, state_version, timestamp FROM ");
    qb.push(table_id.sql_table());
    qb.push(" WHERE object_id IN (");

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
    query.push(" WHERE object_id = ");
    query.push_bind(object_id.to_string());
    query.push(" ORDER BY id ASC");
    query
        .build_query_as::<StateHistoryRecord>()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query("state_history::for_object", e))
}

/// Store a state history record for an object.
pub async fn persist<S>(
    txn: &mut PgConnection,
    table_id: StateHistoryTableId,
    object_id: &impl std::fmt::Display,
    state: &S,
    state_version: ConfigVersion,
) -> DatabaseResult<StateHistoryRecord>
where
    S: Serialize + Sync,
{
    let mut query = sqlx::QueryBuilder::new("INSERT INTO ");
    query.push(table_id.sql_table());
    query.push(" (object_id, state, state_version) VALUES (");
    query.push_bind(object_id.to_string());
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
    query.push(" SET object_id = ");
    query.push_bind(new_object_id.to_string());
    query.push(" WHERE object_id = ");
    query.push_bind(old_object_id.to_string());
    query
        .build()
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query("state_history::update_object_ids", e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use sqlx::PgPool;

    use super::{StateHistoryTableId, find_by_object_ids, for_object, persist, update_object_ids};

    const TABLES: [StateHistoryTableId; 8] = [
        StateHistoryTableId::Machine,
        StateHistoryTableId::NetworkSegment,
        StateHistoryTableId::VpcPrefix,
        StateHistoryTableId::DpaInterface,
        StateHistoryTableId::IbPartition,
        StateHistoryTableId::PowerShelf,
        StateHistoryTableId::Rack,
        StateHistoryTableId::Switch,
    ];

    // This test helper intentionally keeps the first transaction open while it verifies that the
    // per-object advisory lock blocks a concurrent writer.
    #[allow(txn_held_across_await)]
    async fn assert_concurrent_retention(
        pool: &PgPool,
        table_id: StateHistoryTableId,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let table_name = table_id.sql_table();
        let object_id = format!("concurrent-{table_name}");

        let mut seed = sqlx::QueryBuilder::new("INSERT INTO ");
        seed.push(table_name);
        seed.push(" (object_id, state, state_version) SELECT ");
        seed.push_bind(&object_id);
        seed.push(", to_jsonb(sequence), ");
        seed.push_bind(config_version::ConfigVersion::new(1));
        seed.push(" FROM generate_series(1, 249) AS sequence");
        seed.build().execute(pool).await?;

        let mut first_txn = pool.begin().await?;
        persist(
            &mut first_txn,
            table_id,
            &object_id,
            &250_u32,
            config_version::ConfigVersion::new(250),
        )
        .await?;

        let (pid_sender, pid_receiver) = tokio::sync::oneshot::channel();
        let second_pool = pool.clone();
        let second_object_id = object_id.clone();
        let second_insert = tokio::spawn(async move {
            let mut txn = second_pool.begin().await.map_err(|err| err.to_string())?;
            let pid = sqlx::query_scalar::<_, i32>("SELECT pg_backend_pid()")
                .fetch_one(&mut *txn)
                .await
                .map_err(|err| err.to_string())?;
            pid_sender
                .send(pid)
                .map_err(|_| "could not report second writer PID".to_string())?;
            persist(
                &mut txn,
                table_id,
                &second_object_id,
                &251_u32,
                config_version::ConfigVersion::new(251),
            )
            .await
            .map_err(|err| err.to_string())?;
            txn.commit().await.map_err(|err| err.to_string())
        });

        let second_pid = pid_receiver.await?;
        let wait_result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let waiting: bool = sqlx::query_scalar(
                    "SELECT EXISTS (\
                         SELECT 1 FROM pg_locks \
                         WHERE pid = $1 AND locktype = 'advisory' AND NOT granted\
                     )",
                )
                .bind(second_pid)
                .fetch_one(pool)
                .await?;
                if waiting {
                    return Ok::<(), sqlx::Error>(());
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| {
            std::io::Error::other(format!(
                "second writer did not wait for {table_name} retention lock",
            ))
        });

        first_txn.commit().await?;
        let second_result = second_insert.await?.map_err(std::io::Error::other);
        wait_result??;
        second_result?;

        let mut retained_query = sqlx::QueryBuilder::new("SELECT state::TEXT FROM ");
        retained_query.push(table_name);
        retained_query.push(" WHERE object_id = ");
        retained_query.push_bind(&object_id);
        retained_query.push(" ORDER BY id ASC");
        let retained: Vec<String> = retained_query.build_query_scalar().fetch_all(pool).await?;
        assert_eq!(retained.len(), 250, "retention failed for {table_name}");
        assert_eq!(retained.first().unwrap(), "2");
        assert_eq!(retained.last().unwrap(), "251");

        Ok(())
    }

    #[crate::sqlx_test]
    async fn concurrent_inserts_are_serialized_per_object(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        for table_id in TABLES {
            assert_concurrent_retention(&pool, table_id).await?;
        }

        Ok(())
    }

    #[crate::sqlx_test]
    async fn state_history_tables_share_schema_and_retention_behavior(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = pool.acquire().await?;
        let expected_columns = [
            ("id", "bigint", "NO"),
            ("object_id", "text", "NO"),
            ("state", "jsonb", "NO"),
            ("state_version", "character varying", "NO"),
            ("timestamp", "timestamp with time zone", "NO"),
        ];

        for table_id in TABLES {
            let table_name = table_id.sql_table();
            let columns: Vec<(String, String, String)> = sqlx::query_as(
                "SELECT column_name, data_type, is_nullable \
                 FROM information_schema.columns \
                 WHERE table_schema = 'public' AND table_name = $1 \
                 ORDER BY ordinal_position",
            )
            .bind(table_name)
            .fetch_all(&mut *conn)
            .await?;
            assert_eq!(
                columns,
                expected_columns
                    .iter()
                    .map(|(name, data_type, nullable)| {
                        (
                            (*name).to_string(),
                            (*data_type).to_string(),
                            (*nullable).to_string(),
                        )
                    })
                    .collect::<Vec<_>>(),
                "unexpected schema for {table_name}",
            );

            let primary_key: String = sqlx::query_scalar(
                "SELECT key_column_usage.column_name \
                 FROM information_schema.table_constraints \
                 JOIN information_schema.key_column_usage \
                   ON table_constraints.constraint_name = key_column_usage.constraint_name \
                  AND table_constraints.constraint_schema = key_column_usage.constraint_schema \
                 WHERE table_constraints.table_schema = 'public' \
                   AND table_constraints.table_name = $1 \
                   AND table_constraints.constraint_type = 'PRIMARY KEY'",
            )
            .bind(table_name)
            .fetch_one(&mut *conn)
            .await?;
            assert_eq!(primary_key, "id", "unexpected primary key for {table_name}");

            let foreign_key_count: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) \
                 FROM information_schema.table_constraints \
                 WHERE table_schema = 'public' \
                   AND table_name = $1 \
                   AND constraint_type = 'FOREIGN KEY'",
            )
            .bind(table_name)
            .fetch_one(&mut *conn)
            .await?;
            assert_eq!(
                foreign_key_count, 0,
                "{table_name} must not reference the object table",
            );

            let timestamp_default: Option<String> = sqlx::query_scalar(
                "SELECT column_default \
                 FROM information_schema.columns \
                 WHERE table_schema = 'public' \
                   AND table_name = $1 \
                   AND column_name = 'timestamp'",
            )
            .bind(table_name)
            .fetch_one(&mut *conn)
            .await?;
            assert_eq!(
                timestamp_default.as_deref(),
                Some("now()"),
                "unexpected timestamp default for {table_name}",
            );

            let has_object_id_index: bool = sqlx::query_scalar(
                "SELECT EXISTS ( \
                    SELECT 1 FROM pg_indexes \
                    WHERE schemaname = 'public' \
                      AND tablename = $1 \
                      AND indexdef LIKE '% (object_id)%' \
                 )",
            )
            .bind(table_name)
            .fetch_one(&mut *conn)
            .await?;
            assert!(
                has_object_id_index,
                "{table_name} must index object_id lookups",
            );

            // An arbitrary ID proves both that the table no longer has a parent
            // foreign key and that every caller uses the common TEXT contract.
            let object_id = format!("orphaned-{table_name}-{}", "x".repeat(80));
            let renamed_object_id = format!("renamed-{object_id}");
            let version = config_version::ConfigVersion::new(1);
            let inserted = persist(&mut conn, table_id, &object_id, &1_u32, version).await?;
            assert_eq!(inserted.state, "1", "unexpected state for {table_name}");
            assert_eq!(inserted.state_version, version);
            assert!(
                inserted.time.is_some(),
                "missing timestamp for {table_name}"
            );

            let history = for_object(&mut conn, table_id, &object_id).await?;
            assert_eq!(history.len(), 1, "failed to read {table_name}");

            update_object_ids(&mut conn, table_id, &object_id, &renamed_object_id).await?;
            let histories = find_by_object_ids(
                &mut conn,
                table_id,
                &[renamed_object_id.as_str(), "missing-object"],
            )
            .await?;
            assert_eq!(
                histories.len(),
                1,
                "unexpected lookup result for {table_name}"
            );
            assert_eq!(
                histories[&renamed_object_id].len(),
                1,
                "renamed history missing from {table_name}",
            );

            // Exercise the row-level retention trigger in one bulk insert. The
            // original row is the oldest of 251 and must be evicted.
            let mut insert = sqlx::QueryBuilder::new("INSERT INTO ");
            insert.push(table_name);
            insert.push(" (object_id, state, state_version) SELECT ");
            insert.push_bind(&renamed_object_id);
            insert.push(", to_jsonb(sequence), ");
            insert.push_bind(config_version::ConfigVersion::new(2));
            insert.push(" FROM generate_series(2, 251) AS sequence");
            insert.build().execute(&mut *conn).await?;

            let retained = for_object(&mut conn, table_id, &renamed_object_id).await?;
            assert_eq!(retained.len(), 250, "retention failed for {table_name}");
            assert_eq!(retained.first().unwrap().state, "2");
            assert_eq!(retained.last().unwrap().state, "251");
        }

        Ok(())
    }
}
