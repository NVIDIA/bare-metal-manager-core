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
use model::rack_firmware::{RackFirmware, RackFirmwareApplyHistoryRecord};
use sqlx::Error::RowNotFound;
use sqlx::postgres::PgRow;
use sqlx::types::Json;
use sqlx::{FromRow, PgConnection, Row};

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

#[derive(Debug, Clone, FromRow)]
struct DbRackFirmwareApplyHistory {
    #[allow(dead_code)]
    id: i64,
    firmware_id: String,
    rack_id: String,
    firmware_type: String,
    applied_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct DbRackFirmwareApplyHistoryWithAvailability {
    history: DbRackFirmwareApplyHistory,
    firmware_available: bool,
}

impl<'r> FromRow<'r, PgRow> for DbRackFirmwareApplyHistoryWithAvailability {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(DbRackFirmwareApplyHistoryWithAvailability {
            history: DbRackFirmwareApplyHistory::from_row(row)?,
            firmware_available: row.try_get("firmware_available")?,
        })
    }
}

impl From<DbRackFirmwareApplyHistoryWithAvailability> for RackFirmwareApplyHistoryRecord {
    fn from(row: DbRackFirmwareApplyHistoryWithAvailability) -> Self {
        RackFirmwareApplyHistoryRecord {
            firmware_id: row.history.firmware_id,
            rack_id: row.history.rack_id,
            firmware_type: row.history.firmware_type,
            applied_at: row.history.applied_at,
            firmware_available: row.firmware_available,
        }
    }
}

pub async fn record_apply_history(
    txn: &mut PgConnection,
    firmware_id: &str,
    rack_id: &str,
    firmware_type: &str,
) -> DatabaseResult<()> {
    let query = "INSERT INTO rack_firmware_apply_history \
        (firmware_id, rack_id, firmware_type) \
        VALUES ($1, $2, $3)";

    sqlx::query(query)
        .bind(firmware_id)
        .bind(rack_id)
        .bind(firmware_type)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;
    Ok(())
}

/// List apply history, optionally filtered by firmware_id and/or rack_ids.
/// Joins against rack_firmware to report whether each firmware_id is still available.
pub async fn list_apply_history(
    txn: &mut PgConnection,
    firmware_id: Option<&str>,
    rack_ids: &[String],
) -> DatabaseResult<Vec<RackFirmwareApplyHistoryRecord>> {
    let mut query = "SELECT h.*, COALESCE(rf.available, false) AS firmware_available \
        FROM rack_firmware_apply_history h \
        LEFT JOIN rack_firmware rf ON rf.id = h.firmware_id"
        .to_string();

    let mut param_idx = 1;
    let mut conditions = Vec::new();

    if firmware_id.is_some() {
        conditions.push(format!("h.firmware_id = ${param_idx}"));
        param_idx += 1;
    }
    if !rack_ids.is_empty() {
        conditions.push(format!("h.rack_id = ANY(${param_idx})"));
    }
    if !conditions.is_empty() {
        query.push_str(" WHERE ");
        query.push_str(&conditions.join(" AND "));
    }
    query.push_str(" ORDER BY h.applied_at DESC");

    let mut q = sqlx::query_as(&query);
    if let Some(fid) = firmware_id {
        q = q.bind(fid);
    }
    if !rack_ids.is_empty() {
        q = q.bind(rack_ids);
    }

    let rows: Vec<DbRackFirmwareApplyHistoryWithAvailability> = q
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(&query, e))?;
    Ok(rows.into_iter().map(Into::into).collect())
}

pub async fn create(
    txn: &mut PgConnection,
    id: &str,
    config: serde_json::Value,
    parsed_components: Option<serde_json::Value>,
) -> DatabaseResult<RackFirmware> {
    let query = "INSERT INTO rack_firmware (id, config, parsed_components) VALUES ($1, $2::jsonb, $3::jsonb) RETURNING *";

    sqlx::query_as(query)
        .bind(id)
        .bind(Json(config))
        .bind(parsed_components.map(Json))
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))
}

pub async fn find_by_id(txn: impl DbReader<'_>, id: &str) -> DatabaseResult<RackFirmware> {
    let query = "SELECT * FROM rack_firmware WHERE id = $1";
    let ret = sqlx::query_as(query).bind(id).fetch_one(txn).await;
    ret.map_err(|e| match e {
        RowNotFound => DatabaseError::NotFoundError {
            kind: "rack firmware",
            id: format!("{id:?}"),
        },
        _ => DatabaseError::query(query, e),
    })
}

pub async fn list_all(
    txn: &mut PgConnection,
    only_available: bool,
) -> DatabaseResult<Vec<RackFirmware>> {
    let query = if only_available {
        "SELECT * FROM rack_firmware WHERE available = true ORDER BY created DESC"
    } else {
        "SELECT * FROM rack_firmware ORDER BY created DESC"
    };

    sqlx::query_as(query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn update_config(
    txn: &mut PgConnection,
    id: &str,
    config: serde_json::Value,
) -> DatabaseResult<RackFirmware> {
    let query =
        "UPDATE rack_firmware SET config = $2::jsonb, updated = NOW() WHERE id = $1 RETURNING *";

    sqlx::query_as(query)
        .bind(id)
        .bind(Json(config))
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))
}

pub async fn set_available(
    txn: &mut PgConnection,
    id: &str,
    available: bool,
) -> DatabaseResult<RackFirmware> {
    let query =
        "UPDATE rack_firmware SET available = $2, updated = NOW() WHERE id = $1 RETURNING *";

    sqlx::query_as(query)
        .bind(id)
        .bind(available)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))
}

pub async fn delete(txn: &mut PgConnection, id: &str) -> DatabaseResult<()> {
    let query = "DELETE FROM rack_firmware WHERE id = $1 RETURNING id";

    sqlx::query_as::<_, (String,)>(query)
        .bind(id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[crate::sqlx_test]
    async fn test_apply_history_record_and_list(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        // Create a firmware config so we can verify the availability join
        create(&mut txn, "fw-001", json!({"Id": "fw-001"}), None)
            .await
            .unwrap();
        set_available(&mut txn, "fw-001", true).await.unwrap();

        // Record two apply events for the same firmware
        record_apply_history(&mut txn, "fw-001", "rack-a", "prod")
            .await
            .unwrap();
        record_apply_history(&mut txn, "fw-001", "rack-b", "dev")
            .await
            .unwrap();

        // List all history — should return both, newest first
        let all = list_apply_history(&mut txn, None, &[]).await.unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].rack_id, "rack-b");
        assert_eq!(all[1].rack_id, "rack-a");
        assert!(all[0].firmware_available);
        assert!(all[1].firmware_available);

        // List filtered by firmware_id
        let filtered = list_apply_history(&mut txn, Some("fw-001"), &[])
            .await
            .unwrap();
        assert_eq!(filtered.len(), 2);

        // Filter by a non-existent firmware_id
        let empty = list_apply_history(&mut txn, Some("fw-999"), &[])
            .await
            .unwrap();
        assert!(empty.is_empty());

        // Filter by rack_id
        let by_rack = list_apply_history(&mut txn, None, &["rack-a".to_string()])
            .await
            .unwrap();
        assert_eq!(by_rack.len(), 1);
        assert_eq!(by_rack[0].rack_id, "rack-a");

        // Filter by both firmware_id and rack_ids
        let combined = list_apply_history(&mut txn, Some("fw-001"), &["rack-b".to_string()])
            .await
            .unwrap();
        assert_eq!(combined.len(), 1);
        assert_eq!(combined[0].rack_id, "rack-b");
    }

    #[crate::sqlx_test]
    async fn test_apply_history_firmware_available_reflects_deletion(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        // Create firmware and mark available
        create(&mut txn, "fw-002", json!({"Id": "fw-002"}), None)
            .await
            .unwrap();
        set_available(&mut txn, "fw-002", true).await.unwrap();

        // Record an apply
        record_apply_history(&mut txn, "fw-002", "rack-a", "prod")
            .await
            .unwrap();

        // Verify available = true
        let before = list_apply_history(&mut txn, Some("fw-002"), &[])
            .await
            .unwrap();
        assert_eq!(before.len(), 1);
        assert!(before[0].firmware_available);

        // Delete the firmware
        delete(&mut txn, "fw-002").await.unwrap();

        // History entry still exists but firmware_available is now false
        let after = list_apply_history(&mut txn, Some("fw-002"), &[])
            .await
            .unwrap();
        assert_eq!(after.len(), 1);
        assert!(!after[0].firmware_available);
    }

    #[crate::sqlx_test]
    async fn test_apply_history_unavailable_firmware(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        // Record history for a firmware_id that was never created
        record_apply_history(&mut txn, "fw-ghost", "rack-a", "prod")
            .await
            .unwrap();

        let history = list_apply_history(&mut txn, None, &[]).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].firmware_id, "fw-ghost");
        assert!(!history[0].firmware_available);
    }
}
