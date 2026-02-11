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

use carbide_uuid::rack::RackId;
use config_version::ConfigVersion;
use mac_address::MacAddress;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::rack::{Rack, RackConfig, RackState};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{
    ColumnInfo, DatabaseError, DatabaseResult, FilterableQueryBuilder, ObjectColumnFilter,
};

#[derive(Copy, Clone)]
pub struct IdColumn;
impl ColumnInfo<'_> for IdColumn {
    type TableType = Rack;
    type ColumnType = RackId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

pub async fn find_by<'a, C: ColumnInfo<'a, TableType = Rack>>(
    txn: &mut PgConnection,
    filter: ObjectColumnFilter<'a, C>,
) -> DatabaseResult<Vec<Rack>> {
    let mut query = FilterableQueryBuilder::new("SELECT * FROM racks").filter(&filter);

    query
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(query.sql(), e))
}

pub async fn list(txn: impl DbReader<'_>) -> DatabaseResult<Vec<Rack>> {
    let query = "SELECT * from racks where deleted IS NULL".to_string();
    sqlx::query_as(&query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("racks get", e))
}

pub async fn get(txn: impl DbReader<'_>, rack_id: RackId) -> DatabaseResult<Rack> {
    let query = "SELECT * from racks l WHERE l.id=$1".to_string();
    sqlx::query_as(&query)
        .bind(rack_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("racks get", e))
}

pub async fn create(
    txn: &mut PgConnection,
    rack_id: RackId,
    expected_compute_trays: Vec<MacAddress>,
    expected_nvlink_switches: Vec<MacAddress>,
    expected_power_shelves: Vec<MacAddress>,
) -> DatabaseResult<Rack> {
    if !expected_nvlink_switches.is_empty() {
        return Err(DatabaseError::new(
            "nvlink switch todo",
            sqlx::error::Error::ColumnNotFound("nvlink_switch".to_string()),
        ));
    }
    let config = RackConfig {
        compute_trays: Vec::new(),
        power_shelves: Vec::new(),
        expected_compute_trays,
        expected_power_shelves,
    };
    let controller_state = String::from("{\"state\":\"expected\"}");
    let controller_state_outcome = String::from("{}");
    let query = "INSERT INTO racks(id, config, controller_state, controller_state_outcome)
            VALUES($1, $2::json, $3::json, $4::json) RETURNING *";
    let rack: Rack = sqlx::query_as(query)
        .bind(rack_id)
        .bind(sqlx::types::Json(config))
        .bind(controller_state)
        .bind(controller_state_outcome)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(rack)
}

// only update the config
pub async fn update(
    txn: &mut PgConnection,
    rack_id: RackId,
    config: &RackConfig,
) -> DatabaseResult<Rack> {
    let query = "UPDATE racks SET config = $1::json, updated=NOW() WHERE id = $2 RETURNING *";
    let rack: Rack = sqlx::query_as(query)
        .bind(sqlx::types::Json(config))
        .bind(rack_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(rack)
}

pub async fn try_update_controller_state(
    txn: &mut PgConnection,
    rack_id: RackId,
    expected_version: ConfigVersion,
    new_state: &RackState,
) -> DatabaseResult<()> {
    let _query_result = sqlx::query_as::<_, Rack>(
            "UPDATE racks SET controller_state = $1, controller_state_version = $2 WHERE id = $3 AND controller_state_version = $4 RETURNING *",
        )
            .bind(sqlx::types::Json(new_state))
            .bind(expected_version)
            .bind(rack_id)
            .bind(expected_version)
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::new("try_update_controller_state", e))?;

    Ok(())
}

pub async fn update_controller_state_outcome(
    txn: &mut PgConnection,
    rack_id: RackId,
    outcome: PersistentStateHandlerOutcome,
) -> DatabaseResult<()> {
    sqlx::query("UPDATE racks SET controller_state_outcome = $1 WHERE id = $2")
        .bind(sqlx::types::Json(outcome))
        .bind(rack_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("update_controller_state_outcome", e))?;

    Ok(())
}

pub async fn mark_as_deleted(rack: &Rack, txn: &mut PgConnection) -> DatabaseResult<Rack> {
    let query = "UPDATE racks SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING *";
    let updated_rack = sqlx::query_as(query)
        .bind(rack.id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(updated_rack)
}

#[allow(dead_code)]
pub async fn final_delete(txn: &mut PgConnection, rack_id: RackId) -> DatabaseResult<()> {
    let query = "DELETE from racks WHERE id=$1";
    sqlx::query(query)
        .bind(rack_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}
