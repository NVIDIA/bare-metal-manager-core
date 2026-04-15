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
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::metadata::Metadata;
use model::rack::RackFirmwareUpgradeStatus;
use model::switch::{NewSwitch, Switch, SwitchControllerState, SwitchReprovisionRequest};
use sqlx::PgConnection;

use crate::db_read::DbReader;
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
    pub controller_state: Option<String>,
    pub rack_id: Option<String>,
    pub bmc_mac_address: Option<MacAddress>,
}
pub async fn create(txn: &mut PgConnection, new_switch: &NewSwitch) -> DatabaseResult<Switch> {
    let state = SwitchControllerState::Created;
    let controller_state_version = ConfigVersion::initial();
    let version = ConfigVersion::initial();

    let default_metadata = Metadata::default();
    let expected_metadata = new_switch.metadata.as_ref().unwrap_or(&default_metadata);
    let metadata_name = match expected_metadata.name.as_str() {
        "" => new_switch.id.to_string(),
        name => name.to_string(),
    };
    let metadata = Metadata {
        name: metadata_name,
        description: expected_metadata.description.clone(),
        labels: expected_metadata.labels.clone(),
    };

    let query = sqlx::query_as::<_, SwitchId>(
        "INSERT INTO switches (id, name, config, controller_state, controller_state_version, bmc_mac_address, description, labels, version, rack_id, slot_number, tray_index) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10, $11, $12) RETURNING id",
    );
    let id = query
        .bind(new_switch.id)
        .bind(&metadata.name)
        .bind(sqlx::types::Json(&new_switch.config))
        .bind(sqlx::types::Json(&state))
        .bind(controller_state_version)
        .bind(new_switch.bmc_mac_address)
        .bind(&metadata.description)
        .bind(sqlx::types::Json(&metadata.labels))
        .bind(version)
        .bind(&new_switch.rack_id)
        .bind(new_switch.slot_number)
        .bind(new_switch.tray_index)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("create switch", e))?;

    Ok(Switch {
        id,
        config: new_switch.config.clone(),
        status: None,
        deleted: None,
        bmc_mac_address: new_switch.bmc_mac_address,
        controller_state: Versioned {
            value: state,
            version: controller_state_version,
        },
        controller_state_outcome: None,
        switch_reprovisioning_requested: None,
        firmware_upgrade_status: None,
        metadata,
        version,
        rack_id: new_switch.rack_id.clone(),
        slot_number: new_switch.slot_number,
        tray_index: new_switch.tray_index,
    })
}

pub async fn find_by_name(txn: &mut PgConnection, name: &str) -> DatabaseResult<Option<Switch>> {
    let mut switches = find_by(txn, ObjectColumnFilter::One(NameColumn, &name.to_string())).await?;

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
    let mut switches = find_by(txn, ObjectColumnFilter::One(IdColumn, id)).await?;

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

pub async fn find_ids(
    txn: impl DbReader<'_>,
    filter: model::switch::SwitchSearchFilter,
) -> Result<Vec<SwitchId>, DatabaseError> {
    let mut qb = sqlx::QueryBuilder::new("SELECT DISTINCT s.id FROM switches s");

    if filter.bmc_mac.is_some() {
        qb.push(" JOIN machine_interfaces mi ON mi.switch_id = s.id");
    }

    qb.push(" WHERE TRUE");

    if filter.rack_id.is_some() {
        qb.push(" AND s.rack_id = ");
        qb.push_bind(filter.rack_id.unwrap());
    }

    match filter.deleted {
        model::DeletedFilter::Exclude => qb.push(" AND s.deleted IS NULL"),
        model::DeletedFilter::Only => qb.push(" AND s.deleted IS NOT NULL"),
        model::DeletedFilter::Include => &mut qb,
    };

    if let Some(state) = &filter.controller_state {
        qb.push(" AND s.controller_state->>'state' = ");
        qb.push_bind(state.clone());
    }

    if let Some(mac) = filter.bmc_mac {
        qb.push(" AND mi.mac_address = ");
        qb.push_bind(mac);
    }

    qb.build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("switch::find_ids", e))
}

pub async fn find_by<'a, C: ColumnInfo<'a, TableType = Switch>>(
    txn: &mut PgConnection,
    filter: ObjectColumnFilter<'a, C>,
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
    new_version: ConfigVersion,
    new_state: &SwitchControllerState,
) -> DatabaseResult<bool> {
    let query_result = sqlx::query_as::<_, SwitchId>(
            "UPDATE switches SET controller_state = $1, controller_state_version = $2 WHERE id = $3 AND controller_state_version = $4 RETURNING id",
        )
            .bind(sqlx::types::Json(new_state))
            .bind(new_version)
            .bind(switch_id)
            .bind(expected_version)
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::new( "try_update_controller_state", e))?;

    Ok(query_result.is_some())
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

/// Sets switch_reprovisioning_requested on the switch. Can be called from any state machine or
/// service. When the switch is in Ready state, the switch state controller will observe the flag
/// and transition to ReProvisioning::Start.
pub async fn set_switch_reprovisioning_requested(
    txn: &mut PgConnection,
    switch_id: SwitchId,
    initiator: &str,
) -> DatabaseResult<()> {
    let req = SwitchReprovisionRequest {
        requested_at: Utc::now(),
        initiator: initiator.to_string(),
    };
    let query =
        "UPDATE switches SET switch_reprovisioning_requested = $1 WHERE id = $2 RETURNING id";
    sqlx::query_as::<_, SwitchId>(query)
        .bind(sqlx::types::Json(req))
        .bind(switch_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::new("set_switch_reprovisioning_requested", e))?;
    Ok(())
}

/// Clears switch_reprovisioning_requested. Typically called when reprovisioning completes or is
/// cancelled.
pub async fn clear_switch_reprovisioning_requested(
    txn: &mut PgConnection,
    switch_id: SwitchId,
) -> DatabaseResult<()> {
    let query =
        "UPDATE switches SET switch_reprovisioning_requested = NULL WHERE id = $1 RETURNING id";
    sqlx::query_as::<_, SwitchId>(query)
        .bind(switch_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::new("clear_switch_reprovisioning_requested", e))?;
    Ok(())
}

/// Sets firmware_upgrade_status on the switch. Call from any state machine or service to report
/// upgrade progress. WaitFirmwareUpdateCompletion reads this: Completed → Ready, Failed → Error.
pub async fn update_firmware_upgrade_status(
    txn: &mut PgConnection,
    switch_id: SwitchId,
    status: Option<&RackFirmwareUpgradeStatus>,
) -> DatabaseResult<()> {
    let query = "UPDATE switches SET firmware_upgrade_status = $1 WHERE id = $2 RETURNING id";
    sqlx::query_as::<_, SwitchId>(query)
        .bind(status.map(|s| sqlx::types::Json(s.clone())))
        .bind(switch_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::new("update_firmware_upgrade_status", e))?;
    Ok(())
}

pub async fn update_slot_and_tray(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
    slot_number: Option<i32>,
    tray_index: Option<i32>,
) -> DatabaseResult<()> {
    sqlx::query("UPDATE switches SET slot_number = $1, tray_index = $2 WHERE id = $3")
        .bind(slot_number)
        .bind(tray_index)
        .bind(switch_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("update_slot_and_tray", e))?;
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

/// Resolve SwitchIds to BMC IPs via the FK path:
///   switches.bmc_mac_address -> expected_switches.bmc_mac_address
///   -> machine_interfaces -> machine_interface_addresses (underlay) -> IP
pub async fn find_bmc_ips_by_switch_ids(
    db: impl crate::db_read::DbReader<'_>,
    switch_ids: &[SwitchId],
) -> DatabaseResult<Vec<(SwitchId, IpAddr)>> {
    let sql = r#"
        SELECT
            s.id,
            mia.address
        FROM switches s
        JOIN expected_switches es ON es.bmc_mac_address = s.bmc_mac_address
        JOIN machine_interfaces mi ON mi.mac_address = es.bmc_mac_address
        JOIN machine_interface_addresses mia ON mia.interface_id = mi.id
        JOIN network_segments ns ON ns.id = mi.segment_id
        WHERE s.id = ANY($1)
          AND ns.network_segment_type = 'underlay'
    "#;

    sqlx::query_as(sql)
        .bind(switch_ids)
        .fetch_all(db)
        .await
        .map_err(|err| DatabaseError::new("switch::find_bmc_ips_by_switch_ids", err))
}

/// Full endpoint info for a switch: BMC MAC/IP and optionally NVOS MAC/IP.
///
/// NVOS fields are nullable because `nvos_mac_addresses` may not be set on the
/// expected switch, or the corresponding `machine_interfaces` / addresses may
/// not exist yet.
#[derive(Debug, sqlx::FromRow)]
pub struct SwitchEndpointRow {
    pub switch_id: SwitchId,
    pub bmc_mac: MacAddress,
    pub bmc_ip: IpAddr,
    pub nvos_mac: Option<MacAddress>,
    pub nvos_ip: Option<IpAddr>,
}

/// Resolve SwitchIds to full endpoint info (BMC + NVOS MAC/IP).
///
/// Uses `DISTINCT ON (s.id)` to avoid duplicate rows when a MAC has multiple
/// addresses. NVOS resolution uses LEFT JOINs so switches without NVOS info
/// are still returned (with NULL nvos_mac / nvos_ip).
///
/// Path:
///   switches.bmc_mac_address -> expected_switches.bmc_mac_address (BMC MAC)
///   -> machine_interfaces (by bmc_mac) -> machine_interface_addresses (underlay) -> BMC IP
///   -> expected_switches.nvos_mac_addresses (NVOS MAC, nullable)
///   -> machine_interfaces (by nvos_mac) -> machine_interface_addresses -> NVOS IP
pub async fn find_switch_endpoints_by_ids(
    db: impl crate::db_read::DbReader<'_>,
    switch_ids: &[SwitchId],
) -> DatabaseResult<Vec<SwitchEndpointRow>> {
    let sql = r#"
        SELECT DISTINCT ON (s.id)
            s.id                 AS switch_id,
            es.bmc_mac_address   AS bmc_mac,
            bmc_mia.address      AS bmc_ip,
            nvos_mi.mac_address  AS nvos_mac,
            nvos_mia.address     AS nvos_ip
        FROM switches s
        JOIN expected_switches es
            ON es.bmc_mac_address = s.bmc_mac_address
        JOIN machine_interfaces bmc_mi
            ON bmc_mi.mac_address = es.bmc_mac_address
        JOIN machine_interface_addresses bmc_mia
            ON bmc_mia.interface_id = bmc_mi.id
        JOIN network_segments bmc_ns
            ON bmc_ns.id = bmc_mi.segment_id
        LEFT JOIN machine_interfaces nvos_mi
            ON es.nvos_mac_addresses IS NOT NULL
           AND nvos_mi.mac_address = ANY(es.nvos_mac_addresses)
        LEFT JOIN machine_interface_addresses nvos_mia
            ON nvos_mia.interface_id = nvos_mi.id
        WHERE s.id = ANY($1)
          AND bmc_ns.network_segment_type = 'underlay'
        ORDER BY s.id
    "#;

    sqlx::query_as(sql)
        .bind(switch_ids)
        .fetch_all(db)
        .await
        .map_err(|err| DatabaseError::new("switch::find_switch_endpoints_by_ids", err))
}

pub async fn update_metadata(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
    expected_version: ConfigVersion,
    metadata: Metadata,
) -> Result<(), DatabaseError> {
    let next_version = expected_version.increment();

    let query = "UPDATE switches SET
            version=$1,
            name=$2, description=$3, labels=$4::jsonb
            WHERE id=$5 AND version=$6
            RETURNING id";

    let query_result: Result<(SwitchId,), _> = sqlx::query_as(query)
        .bind(next_version)
        .bind(&metadata.name)
        .bind(&metadata.description)
        .bind(sqlx::types::Json(&metadata.labels))
        .bind(switch_id)
        .bind(expected_version)
        .fetch_one(txn)
        .await;

    match query_result {
        Ok((_id,)) => Ok(()),
        Err(e) => Err(match e {
            sqlx::Error::RowNotFound => {
                DatabaseError::ConcurrentModificationError("switch", expected_version.to_string())
            }
            e => DatabaseError::query(query, e),
        }),
    }
}

#[derive(Debug, sqlx::FromRow)]
pub struct SwitchBmcRow {
    pub switch_id: SwitchId,
    pub bmc_mac: MacAddress,
    pub bmc_ip: IpAddr,
}

/// Resolve SwitchIds to BMC MAC + IP via machine_interfaces.
pub async fn find_bmc_info_by_switch_ids(
    db: impl crate::db_read::DbReader<'_>,
    switch_ids: &[SwitchId],
) -> DatabaseResult<Vec<SwitchBmcRow>> {
    let sql = r#"
        SELECT DISTINCT ON (mi.switch_id)
            mi.switch_id,
            mi.mac_address   AS bmc_mac,
            mia.address      AS bmc_ip
        FROM machine_interfaces mi
        JOIN machine_interface_addresses mia ON mia.interface_id = mi.id
        JOIN network_segments ns ON ns.id = mi.segment_id
        WHERE mi.switch_id = ANY($1)
          AND ns.network_segment_type = 'underlay'
        ORDER BY mi.switch_id
    "#;

    sqlx::query_as(sql)
        .bind(switch_ids)
        .fetch_all(db)
        .await
        .map_err(|err| DatabaseError::new("switch::find_bmc_info_by_switch_ids", err))
}
