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
use health_report::{HealthReport, OverrideMode};
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

pub async fn get(txn: impl DbReader<'_>, rack_id: &RackId) -> DatabaseResult<Rack> {
    let query = "SELECT * from racks l WHERE l.id=$1".to_string();
    sqlx::query_as(&query)
        .bind(rack_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::new("racks get", e))?
        .ok_or_else(|| DatabaseError::NotFoundError {
            kind: "rack",
            id: rack_id.to_string(),
        })
}

pub async fn create(
    txn: &mut PgConnection,
    rack_id: &RackId,
    expected_compute_trays: Vec<MacAddress>,
    expected_nvlink_switches: Vec<MacAddress>,
    expected_power_shelves: Vec<MacAddress>,
) -> DatabaseResult<Rack> {
    let config = RackConfig {
        compute_trays: Vec::new(),
        power_shelves: Vec::new(),
        expected_compute_trays,
        expected_switches: expected_nvlink_switches,
        expected_power_shelves,
        rack_type: None,
        validation_run_id: None,
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
    rack_id: &RackId,
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

/// adopt_expected_switch adopts an expected switch into a rack's config by
/// adding its BMC MAC address to expected_switches. Returns Ok(false) if
/// the rack does not exist (the switch is not adopted).
pub async fn adopt_expected_switch(
    txn: &mut PgConnection,
    rack_id: &RackId,
    bmc_mac_address: MacAddress,
) -> DatabaseResult<bool> {
    match get(&mut *txn, rack_id).await {
        Ok(rack) => {
            let mut config = rack.config.clone();
            if !config.expected_switches.contains(&bmc_mac_address) {
                config.expected_switches.push(bmc_mac_address);
                update(&mut *txn, rack_id, &config).await?;
            }
            Ok(true)
        }
        Err(DatabaseError::NotFoundError { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// adopt_expected_machine adopts an expected machine into a rack's config by
/// adding its BMC MAC address to expected_compute_trays. Returns Ok(false) if
/// the rack does not exist (the machine is not adopted).
pub async fn adopt_expected_machine(
    txn: &mut PgConnection,
    rack_id: &RackId,
    bmc_mac_address: MacAddress,
) -> DatabaseResult<bool> {
    match get(&mut *txn, rack_id).await {
        Ok(rack) => {
            let mut config = rack.config.clone();
            if !config.expected_compute_trays.contains(&bmc_mac_address) {
                config.expected_compute_trays.push(bmc_mac_address);
                update(&mut *txn, rack_id, &config).await?;
            }
            Ok(true)
        }
        Err(DatabaseError::NotFoundError { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

/// adopt_expected_power_shelf adopts an expected power shelf into a rack's
/// config by adding its BMC MAC address to expected_power_shelves. Returns
/// Ok(false) if the rack does not exist (the power shelf is not adopted).
pub async fn adopt_expected_power_shelf(
    txn: &mut PgConnection,
    rack_id: &RackId,
    bmc_mac_address: MacAddress,
) -> DatabaseResult<bool> {
    match get(&mut *txn, rack_id).await {
        Ok(rack) => {
            let mut config = rack.config.clone();
            if !config.expected_power_shelves.contains(&bmc_mac_address) {
                config.expected_power_shelves.push(bmc_mac_address);
                update(&mut *txn, rack_id, &config).await?;
            }
            Ok(true)
        }
        Err(DatabaseError::NotFoundError { .. }) => Ok(false),
        Err(e) => Err(e),
    }
}

pub async fn try_update_controller_state(
    txn: &mut PgConnection,
    rack_id: &RackId,
    expected_version: ConfigVersion,
    new_state: &RackState,
) -> DatabaseResult<bool> {
    let query_result = sqlx::query_as::<_, Rack>(
            "UPDATE racks SET controller_state = $1, controller_state_version = $2 WHERE id = $3 AND controller_state_version = $4 RETURNING *",
        )
            .bind(sqlx::types::Json(new_state))
            .bind(expected_version)
            .bind(rack_id)
            .bind(expected_version)
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::new("try_update_controller_state", e))?;

    Ok(query_result.is_some())
}

pub async fn update_controller_state_outcome(
    txn: &mut PgConnection,
    rack_id: &RackId,
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
        .bind(&rack.id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(updated_rack)
}

pub async fn final_delete(txn: &mut PgConnection, rack_id: &RackId) -> DatabaseResult<()> {
    let query = "DELETE from racks WHERE id=$1";
    sqlx::query(query)
        .bind(rack_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn insert_health_report_override(
    txn: &mut PgConnection,
    rack_id: &RackId,
    mode: OverrideMode,
    health_report: &HealthReport,
) -> Result<(), DatabaseError> {
    let column_name = "health_report_overrides";
    let path = match mode {
        OverrideMode::Merge => format!("merges,\"{}\"", health_report.source),
        OverrideMode::Replace => "replace".to_string(),
    };

    let query = format!(
        "UPDATE racks SET {column_name} = jsonb_set(
            coalesce({column_name}, '{{\"merges\": {{}}}}'::jsonb),
            '{{{path}}}',
            $1::jsonb
        ) WHERE id = $2
        RETURNING id"
    );

    let _id: (RackId,) = sqlx::query_as(&query)
        .bind(sqlx::types::Json(health_report))
        .bind(rack_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("insert rack health report override", e))?;

    Ok(())
}

pub async fn remove_health_report_override(
    txn: &mut PgConnection,
    rack_id: &RackId,
    mode: OverrideMode,
    source: &str,
) -> Result<(), DatabaseError> {
    let column_name = "health_report_overrides";
    let path = match mode {
        OverrideMode::Merge => format!("merges,{source}"),
        OverrideMode::Replace => "replace".to_string(),
    };
    let query = format!(
        "UPDATE racks SET {column_name} = ({column_name} #- '{{{path}}}') WHERE id = $1
            RETURNING id"
    );

    let _id: (RackId,) = sqlx::query_as(&query)
        .bind(rack_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("remove rack health report override", e))?;

    Ok(())
}
