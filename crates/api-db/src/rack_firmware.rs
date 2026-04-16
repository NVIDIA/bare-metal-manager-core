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
use model::rack_type::RackHardwareType;
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
    rack_hardware_type: RackHardwareType,
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
            rack_hardware_type: row.history.rack_hardware_type,
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
    rack_hardware_type: RackHardwareType,
) -> DatabaseResult<()> {
    let query = "INSERT INTO rack_firmware_apply_history \
        (firmware_id, rack_id, firmware_type, rack_hardware_type) \
        VALUES ($1, $2, $3, $4)";

    sqlx::query(query)
        .bind(firmware_id)
        .bind(rack_id)
        .bind(firmware_type)
        .bind(rack_hardware_type)
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
    rack_hardware_type: RackHardwareType,
    config: serde_json::Value,
    parsed_components: Option<serde_json::Value>,
) -> DatabaseResult<RackFirmware> {
    let query = "INSERT INTO rack_firmware (id, rack_hardware_type, config, parsed_components) VALUES ($1, $2, $3::jsonb, $4::jsonb) RETURNING *";

    sqlx::query_as(query)
        .bind(id)
        .bind(rack_hardware_type)
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
    filter: model::rack_firmware::RackFirmwareSearchFilter,
) -> DatabaseResult<Vec<RackFirmware>> {
    let mut qb = sqlx::QueryBuilder::new("SELECT * FROM rack_firmware WHERE TRUE");

    if filter.only_available {
        qb.push(" AND available = true");
    }
    if let Some(hw_type) = filter.rack_hardware_type {
        qb.push(" AND rack_hardware_type = ");
        qb.push_bind(hw_type);
    }

    qb.push(" ORDER BY created DESC");

    qb.build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("rack_firmware::list_all", e))
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

/// Returns true if there is already a default firmware for the given rack_hardware_type.
pub async fn has_default(
    txn: &mut PgConnection,
    rack_hardware_type: &RackHardwareType,
) -> DatabaseResult<bool> {
    let query = "SELECT EXISTS(SELECT 1 FROM rack_firmware WHERE rack_hardware_type = $1 AND is_default = true)";
    let (exists,) = sqlx::query_as(query)
        .bind(rack_hardware_type)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;
    Ok(exists)
}

/// Finds the default firmware row for the given rack_hardware_type.
pub async fn find_default_by_rack_hardware_type(
    txn: impl DbReader<'_>,
    rack_hardware_type: &RackHardwareType,
) -> DatabaseResult<RackFirmware> {
    let query = "SELECT * FROM rack_firmware WHERE rack_hardware_type = $1 AND is_default = true ORDER BY created DESC LIMIT 1";
    let ret = sqlx::query_as(query)
        .bind(rack_hardware_type)
        .fetch_optional(txn)
        .await;
    ret.map_err(|e| DatabaseError::query(query, e))?
        .ok_or_else(|| DatabaseError::NotFoundError {
            kind: "default rack firmware",
            id: rack_hardware_type.to_string(),
        })
}

/// Sets the given firmware as the default for its rack_hardware_type.
/// Clears any previous default for the same rack_hardware_type.
pub async fn set_default(txn: &mut PgConnection, id: &str) -> DatabaseResult<RackFirmware> {
    // First, get the firmware to learn its rack_hardware_type.
    let fw = find_by_id(&mut *txn, id).await?;

    // Clear previous default for this rack_hardware_type.
    let clear_query = "UPDATE rack_firmware SET is_default = false WHERE rack_hardware_type = $1";
    sqlx::query(clear_query)
        .bind(&fw.rack_hardware_type)
        .execute(&mut *txn)
        .await
        .map_err(|e| DatabaseError::new(clear_query, e))?;

    // Set this one as default.
    let set_query =
        "UPDATE rack_firmware SET is_default = true, updated = NOW() WHERE id = $1 RETURNING *";
    sqlx::query_as(set_query)
        .bind(id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(set_query, e))
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
        create(
            &mut txn,
            "fw-001",
            RackHardwareType::any(),
            json!({"Id": "fw-001"}),
            None,
        )
        .await
        .unwrap();
        set_available(&mut txn, "fw-001", true).await.unwrap();

        // Record two apply events for the same firmware
        record_apply_history(
            &mut txn,
            "fw-001",
            "rack-a",
            "prod",
            RackHardwareType::any(),
        )
        .await
        .unwrap();
        record_apply_history(&mut txn, "fw-001", "rack-b", "dev", RackHardwareType::any())
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
        create(
            &mut txn,
            "fw-002",
            RackHardwareType::any(),
            json!({"Id": "fw-002"}),
            None,
        )
        .await
        .unwrap();
        set_available(&mut txn, "fw-002", true).await.unwrap();

        // Record an apply
        record_apply_history(
            &mut txn,
            "fw-002",
            "rack-a",
            "prod",
            RackHardwareType::any(),
        )
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
        record_apply_history(
            &mut txn,
            "fw-ghost",
            "rack-a",
            "prod",
            RackHardwareType::any(),
        )
        .await
        .unwrap();

        let history = list_apply_history(&mut txn, None, &[]).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].firmware_id, "fw-ghost");
        assert!(!history[0].firmware_available);
    }

    #[crate::sqlx_test]
    async fn test_create_firmware_defaults_to_not_default(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        let fw = create(
            &mut txn,
            "fw-010",
            RackHardwareType::any(),
            json!({"Id": "fw-010"}),
            None,
        )
        .await
        .unwrap();

        assert!(!fw.is_default);
    }

    #[crate::sqlx_test]
    async fn test_has_default_returns_false_when_none_set(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        create(
            &mut txn,
            "fw-011",
            RackHardwareType::any(),
            json!({"Id": "fw-011"}),
            None,
        )
        .await
        .unwrap();

        assert!(
            !has_default(&mut txn, &RackHardwareType::any())
                .await
                .unwrap()
        );
    }

    #[crate::sqlx_test]
    async fn test_set_default_and_has_default(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        create(
            &mut txn,
            "fw-012",
            RackHardwareType::any(),
            json!({"Id": "fw-012"}),
            None,
        )
        .await
        .unwrap();

        // Set as default.
        let fw = set_default(&mut txn, "fw-012").await.unwrap();
        assert!(fw.is_default);

        // has_default should now return true.
        assert!(
            has_default(&mut txn, &RackHardwareType::any())
                .await
                .unwrap()
        );

        let default_fw = find_default_by_rack_hardware_type(&mut *txn, &RackHardwareType::any())
            .await
            .unwrap();
        assert_eq!(default_fw.id, "fw-012");
        assert!(default_fw.is_default);
    }

    #[crate::sqlx_test]
    async fn test_set_default_clears_previous_default(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        let hw_type = RackHardwareType::from("test-type");

        create(
            &mut txn,
            "fw-a",
            hw_type.clone(),
            json!({"Id": "fw-a"}),
            None,
        )
        .await
        .unwrap();
        create(
            &mut txn,
            "fw-b",
            hw_type.clone(),
            json!({"Id": "fw-b"}),
            None,
        )
        .await
        .unwrap();

        // Set fw-a as default.
        set_default(&mut txn, "fw-a").await.unwrap();
        let a = find_by_id(&mut *txn, "fw-a").await.unwrap();
        assert!(a.is_default);

        // Set fw-b as default — fw-a should lose default.
        set_default(&mut txn, "fw-b").await.unwrap();
        let a = find_by_id(&mut *txn, "fw-a").await.unwrap();
        let b = find_by_id(&mut *txn, "fw-b").await.unwrap();
        assert!(!a.is_default);
        assert!(b.is_default);
    }

    #[crate::sqlx_test]
    async fn test_set_default_does_not_affect_other_hardware_types(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        let type_a = RackHardwareType::from("type-a");
        let type_b = RackHardwareType::from("type-b");

        create(
            &mut txn,
            "fw-x",
            type_a.clone(),
            json!({"Id": "fw-x"}),
            None,
        )
        .await
        .unwrap();
        create(
            &mut txn,
            "fw-y",
            type_b.clone(),
            json!({"Id": "fw-y"}),
            None,
        )
        .await
        .unwrap();

        // Set both as default for their respective types.
        set_default(&mut txn, "fw-x").await.unwrap();
        set_default(&mut txn, "fw-y").await.unwrap();

        // Both should be default (different hardware types).
        let x = find_by_id(&mut *txn, "fw-x").await.unwrap();
        let y = find_by_id(&mut *txn, "fw-y").await.unwrap();
        assert!(x.is_default);
        assert!(y.is_default);
    }

    #[crate::sqlx_test]
    async fn test_find_default_by_rack_hardware_type_not_found(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();

        create(
            &mut txn,
            "fw-z",
            RackHardwareType::from("type-z"),
            json!({"Id": "fw-z"}),
            None,
        )
        .await
        .unwrap();

        let err = find_default_by_rack_hardware_type(&mut *txn, &RackHardwareType::from("type-z"))
            .await
            .unwrap_err();
        assert!(matches!(err, DatabaseError::NotFoundError { .. }));
    }
}
