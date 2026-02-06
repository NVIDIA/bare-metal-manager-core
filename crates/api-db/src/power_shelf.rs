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

use carbide_uuid::power_shelf::PowerShelfId;
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use futures::StreamExt;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::power_shelf::{NewPowerShelf, PowerShelf, PowerShelfControllerState};
use sqlx::PgConnection;

use crate::{
    ColumnInfo, DatabaseError, DatabaseResult, FilterableQueryBuilder, ObjectColumnFilter,
};

#[derive(Debug, Clone, Default)]
pub struct PowerShelfSearchConfig {
    // pub include_history: bool, // unused
}

#[derive(Copy, Clone)]
pub struct IdColumn;
impl ColumnInfo<'_> for IdColumn {
    type TableType = PowerShelf;
    type ColumnType = PowerShelfId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Copy, Clone)]
pub struct NameColumn;
impl ColumnInfo<'_> for NameColumn {
    type TableType = PowerShelf;
    type ColumnType = String;

    fn column_name(&self) -> &'static str {
        "name"
    }
}

pub async fn create(
    txn: &mut PgConnection,
    new_power_shelf: &NewPowerShelf,
) -> Result<PowerShelf, DatabaseError> {
    let state = PowerShelfControllerState::Initializing;
    let version = ConfigVersion::initial();

    let query = sqlx::query_as::<_, PowerShelfId>(
        "INSERT INTO power_shelves (id, name, config, controller_state, controller_state_version) VALUES ($1, $2, $3, $4, $5) RETURNING id",
    );
    let _: PowerShelfId = query
        .bind(new_power_shelf.id)
        .bind(&new_power_shelf.config.name)
        .bind(sqlx::types::Json(&new_power_shelf.config))
        .bind(sqlx::types::Json(&state))
        .bind(version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("create power_shelf", e))?;

    Ok(PowerShelf {
        id: new_power_shelf.id,
        config: new_power_shelf.config.clone(),
        status: None,
        deleted: None,
        controller_state: Versioned {
            value: state,
            version,
        },
        controller_state_outcome: None,
    })
}

pub async fn find_by_name(
    txn: &mut PgConnection,
    name: &str,
) -> DatabaseResult<Option<PowerShelf>> {
    let mut power_shelves = find_by(
        txn,
        ObjectColumnFilter::One(NameColumn, &name.to_string()),
        PowerShelfSearchConfig::default(),
    )
    .await?;

    if power_shelves.is_empty() {
        Ok(None)
    } else if power_shelves.len() == 1 {
        Ok(Some(power_shelves.swap_remove(0)))
    } else {
        Err(DatabaseError::new(
            "PowerShelf::find_by_name",
            sqlx::Error::Decode(
                eyre::eyre!(
                    "Searching for PowerShelf {} returned multiple results",
                    name
                )
                .into(),
            ),
        ))
    }
}

pub async fn find_by_id(
    txn: &mut PgConnection,
    id: &PowerShelfId,
) -> DatabaseResult<Option<PowerShelf>> {
    let mut power_shelves = find_by(
        txn,
        ObjectColumnFilter::One(IdColumn, id),
        PowerShelfSearchConfig::default(),
    )
    .await?;

    if power_shelves.is_empty() {
        Ok(None)
    } else if power_shelves.len() == 1 {
        Ok(Some(power_shelves.swap_remove(0)))
    } else {
        Err(DatabaseError::new(
            "PowerShelf::find_by_id",
            sqlx::Error::Decode(
                eyre::eyre!("Searching for PowerShelf {} returned multiple results", id).into(),
            ),
        ))
    }
}

pub async fn list_segment_ids(txn: &mut PgConnection) -> DatabaseResult<Vec<PowerShelfId>> {
    let query =
        sqlx::query_as::<_, PowerShelfId>("SELECT id FROM power_shelves WHERE deleted IS NULL");

    let mut rows = query.fetch(txn);
    let mut ids = Vec::new();

    while let Some(row) = rows.next().await {
        ids.push(row.map_err(|e| DatabaseError::new("list_segment_ids power_shelf", e))?);
    }

    Ok(ids)
}

pub async fn find_by<'a, C: ColumnInfo<'a, TableType = PowerShelf>>(
    txn: &mut PgConnection,
    filter: ObjectColumnFilter<'a, C>,
    _search_config: PowerShelfSearchConfig,
) -> DatabaseResult<Vec<PowerShelf>> {
    let mut query = FilterableQueryBuilder::new("SELECT * FROM power_shelves").filter(&filter);

    query
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(query.sql(), e))
}

pub async fn try_update_controller_state(
    txn: &mut PgConnection,
    power_shelf_id: PowerShelfId,
    expected_version: ConfigVersion,
    new_state: &PowerShelfControllerState,
) -> DatabaseResult<()> {
    let _query_result = sqlx::query_as::<_, PowerShelfId>(
            "UPDATE power_shelves SET controller_state = $1, controller_state_version = $2 WHERE id = $3 AND controller_state_version = $4 RETURNING id",
        )
            .bind(sqlx::types::Json(new_state))
            .bind(expected_version)
            .bind(power_shelf_id)
            .bind(expected_version)
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::new("try_update_controller_state", e))?;

    Ok(())
}

pub async fn update_controller_state_outcome(
    txn: &mut PgConnection,
    power_shelf_id: PowerShelfId,
    outcome: PersistentStateHandlerOutcome,
) -> DatabaseResult<()> {
    sqlx::query("UPDATE power_shelves SET controller_state_outcome = $1 WHERE id = $2")
        .bind(sqlx::types::Json(outcome))
        .bind(power_shelf_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("update_controller_state_outcome", e))?;

    Ok(())
}

pub async fn mark_as_deleted<'a>(
    power_shelf: &'a mut PowerShelf,
    txn: &mut PgConnection,
) -> DatabaseResult<&'a mut PowerShelf> {
    let now = Utc::now();
    power_shelf.deleted = Some(now);

    sqlx::query("UPDATE power_shelves SET deleted = $1 WHERE id = $2")
        .bind(now)
        .bind(power_shelf.id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("mark_as_deleted", e))?;

    Ok(power_shelf)
}

pub async fn final_delete(
    power_shelf_id: PowerShelfId,
    txn: &mut PgConnection,
) -> DatabaseResult<PowerShelfId> {
    let query =
        sqlx::query_as::<_, PowerShelfId>("DELETE FROM power_shelves WHERE id = $1 RETURNING id");

    let power_shelf: PowerShelfId = query
        .bind(power_shelf_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("final_delete", e))?;

    Ok(power_shelf)
}

pub async fn update(
    power_shelf: &PowerShelf,
    txn: &mut PgConnection,
) -> DatabaseResult<PowerShelf> {
    sqlx::query("UPDATE power_shelves SET status = $1 WHERE id = $2")
        .bind(sqlx::types::Json(&power_shelf.status))
        .bind(power_shelf.id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("update", e))?;

    Ok(power_shelf.clone())
}
