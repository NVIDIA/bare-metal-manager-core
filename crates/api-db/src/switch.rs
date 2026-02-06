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

use std::net::IpAddr;

use carbide_uuid::switch::SwitchId;
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use futures::StreamExt;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::switch::{NewSwitch, Switch, SwitchControllerState};
use sqlx::PgConnection;

use crate::{
    ColumnInfo, DatabaseError, DatabaseResult, FilterableQueryBuilder, ObjectColumnFilter,
};

#[derive(Copy, Clone)]
pub struct IdColumn;
impl ColumnInfo<'_> for IdColumn {
    type TableType = Switch;
    type ColumnType = SwitchId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Copy, Clone)]
pub struct NameColumn;
impl ColumnInfo<'_> for NameColumn {
    type TableType = Switch;
    type ColumnType = String;

    fn column_name(&self) -> &'static str {
        "name"
    }
}
#[derive(Debug, Clone, Default)]
pub struct SwitchSearchConfig {
    // pub include_history: bool, // unused
}
pub async fn create(txn: &mut PgConnection, new_switch: &NewSwitch) -> DatabaseResult<Switch> {
    let state = SwitchControllerState::Initializing;
    let version = ConfigVersion::initial();

    let query = sqlx::query_as::<_, SwitchId>(
        "INSERT INTO switches (id, name, config, controller_state, controller_state_version) VALUES ($1, $2, $3, $4, $5) RETURNING id",
    );
    let id = query
        .bind(new_switch.id)
        .bind(&new_switch.config.name)
        .bind(sqlx::types::Json(&new_switch.config))
        .bind(sqlx::types::Json(&state))
        .bind(version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("create switch", e))?;

    Ok(Switch {
        id,
        config: new_switch.config.clone(),
        status: None,
        deleted: None,
        controller_state: Versioned {
            value: state,
            version,
        },
        controller_state_outcome: None,
    })
}

pub async fn find_by_name(txn: &mut PgConnection, name: &str) -> DatabaseResult<Option<Switch>> {
    let mut switches = find_by(
        txn,
        ObjectColumnFilter::One(NameColumn, &name.to_string()),
        SwitchSearchConfig::default(),
    )
    .await?;

    if switches.is_empty() {
        Ok(None)
    } else if switches.len() == 1 {
        Ok(Some(switches.swap_remove(0)))
    } else {
        Err(DatabaseError::new(
            "Switch::find_by_name",
            sqlx::Error::Decode(
                eyre::eyre!("Searching for Switch {} returned multiple results", name).into(),
            ),
        ))
    }
}

pub async fn find_by_id(txn: &mut PgConnection, id: &SwitchId) -> DatabaseResult<Option<Switch>> {
    let mut switches = find_by(
        txn,
        ObjectColumnFilter::One(IdColumn, id),
        SwitchSearchConfig::default(),
    )
    .await?;

    if switches.is_empty() {
        Ok(None)
    } else if switches.len() == 1 {
        Ok(Some(switches.swap_remove(0)))
    } else {
        Err(DatabaseError::new(
            "Switch::find_by_id",
            sqlx::Error::Decode(
                eyre::eyre!("Searching for Switch {} returned multiple results", id).into(),
            ),
        ))
    }
}

pub async fn find_all(txn: &mut PgConnection) -> DatabaseResult<Vec<SwitchId>> {
    let query = sqlx::query_as::<_, SwitchId>("SELECT id FROM switches WHERE deleted IS NULL");

    let mut rows = query.fetch(txn);
    let mut ids = Vec::new();

    while let Some(row) = rows.next().await {
        ids.push(row.map_err(|e| DatabaseError::new("find_all switch", e))?);
    }

    Ok(ids)
}

pub async fn list_sibling_ids(
    txn: &mut PgConnection,
    rack_id: &str,
) -> DatabaseResult<Vec<SwitchId>> {
    let query =
        sqlx::query_as::<_, SwitchId>("SELECT id FROM switches WHERE rack_id = $1").bind(rack_id);

    let mut rows = query.fetch(txn);
    let mut ids = Vec::new();

    while let Some(row) = rows.next().await {
        ids.push(row.map_err(|e| DatabaseError::new("list_sibling_ids switch", e))?);
    }

    Ok(ids)
}

pub async fn find_by<'a, C: ColumnInfo<'a, TableType = Switch>>(
    txn: &mut PgConnection,
    filter: ObjectColumnFilter<'a, C>,
    _search_config: SwitchSearchConfig,
) -> DatabaseResult<Vec<Switch>> {
    let mut query = FilterableQueryBuilder::new("SELECT * FROM switches").filter(&filter);

    query
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(query.sql(), e))
}

pub async fn try_update_controller_state(
    txn: &mut PgConnection,
    switch_id: SwitchId,
    expected_version: ConfigVersion,
    new_state: &SwitchControllerState,
) -> DatabaseResult<()> {
    let _query_result = sqlx::query_as::<_, SwitchId>(
            "UPDATE switches SET controller_state = $1, controller_state_version = $2 WHERE id = $3 AND controller_state_version = $4 RETURNING id",
        )
            .bind(sqlx::types::Json(new_state))
            .bind(expected_version)
            .bind(switch_id)
            .bind(expected_version)
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::new( "try_update_controller_state", e))?;

    Ok(())
}

pub async fn update_controller_state_outcome(
    txn: &mut PgConnection,
    switch_id: SwitchId,
    outcome: PersistentStateHandlerOutcome,
) -> DatabaseResult<()> {
    sqlx::query("UPDATE switches SET controller_state_outcome = $1 WHERE id = $2")
        .bind(sqlx::types::Json(outcome))
        .bind(switch_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("update_controller_state_outcome", e))?;

    Ok(())
}

pub async fn mark_as_deleted<'a>(
    switch: &'a mut Switch,
    txn: &mut PgConnection,
) -> DatabaseResult<&'a mut Switch> {
    let now = Utc::now();
    switch.deleted = Some(now);

    sqlx::query("UPDATE switches SET deleted = $1 WHERE id = $2")
        .bind(now)
        .bind(switch.id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("mark_as_deleted", e))?;

    Ok(switch)
}

pub async fn final_delete(switch_id: SwitchId, txn: &mut PgConnection) -> DatabaseResult<SwitchId> {
    let query = sqlx::query_as::<_, SwitchId>("DELETE FROM switches WHERE id = $1 RETURNING id");

    let switch: SwitchId = query
        .bind(switch_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("final_delete", e))?;

    Ok(switch)
}

pub async fn update(switch: &Switch, txn: &mut PgConnection) -> Result<Switch, DatabaseError> {
    sqlx::query("UPDATE switches SET status = $1 WHERE id = $2")
        .bind(sqlx::types::Json(&switch.status))
        .bind(switch.id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("update", e))?;

    Ok(switch.clone())
}

use mac_address::MacAddress;

#[derive(Debug, sqlx::FromRow)]
pub struct SwitchBmcInfoRow {
    pub serial_number: String,
    pub bmc_mac_address: MacAddress,
    pub ip_address: IpAddr,
}

pub async fn list_switch_bmc_info(txn: &mut PgConnection) -> DatabaseResult<Vec<SwitchBmcInfoRow>> {
    let sql = r#"
        SELECT 
            es.serial_number,
            es.bmc_mac_address,
            mia.address as ip_address
        FROM expected_switches es
        JOIN machine_interfaces mi ON mi.mac_address = es.bmc_mac_address
        JOIN machine_interface_addresses mia ON mia.interface_id = mi.id
        JOIN network_segments ns ON ns.id = mi.segment_id
        WHERE ns.network_segment_type = 'underlay'
    "#;

    sqlx::query_as(sql)
        .fetch_all(txn)
        .await
        .map_err(|err| DatabaseError::new("list_switch_bmc_info", err))
}
