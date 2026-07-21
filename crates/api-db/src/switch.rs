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

use carbide_uuid::rack::{RackId, RackProfileId};
use carbide_uuid::switch::SwitchId;
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use health_report::{HealthReport, HealthReportApplyMode};
use mac_address::MacAddress;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::metadata::Metadata;
use model::rack::RackFirmwareUpgradeStatus;
use model::switch::{
    CONTROL_PLANE_STATE_CONFIGURED, FabricManagerState, FabricManagerStatus, NewSwitch,
    SWITCH_CONTROLLER_STATE_READY, Switch, SwitchControllerState, SwitchMaintenanceOperation,
    SwitchMaintenanceRequest, SwitchReprovisionRequest,
};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{
    ColumnInfo, DatabaseError, DatabaseResult, FilterableQueryBuilder, ObjectColumnFilter,
};

#[cfg(test)]
mod test_metadata;

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

#[derive(Copy, Clone)]
pub struct BmcMacAddressColumn;
impl ColumnInfo<'_> for BmcMacAddressColumn {
    type TableType = Switch;
    type ColumnType = mac_address::MacAddress;

    fn column_name(&self) -> &'static str {
        "bmc_mac_address"
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
        bmc_info: None,
        controller_state: Versioned {
            value: state,
            version: controller_state_version,
        },
        controller_state_outcome: None,
        switch_maintenance_requested: None,
        switch_reprovisioning_requested: None,
        firmware_upgrade_status: None,
        nvos_update_status: None,
        fabric_manager_status: None,
        metadata,
        version,
        is_primary: false,
        rack_id: new_switch.rack_id.clone(),
        slot_number: new_switch.slot_number,
        tray_index: new_switch.tray_index,
        health_reports: Default::default(),
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
                eyre::eyre!("searching for switch {} returned multiple results", name).into(),
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
                eyre::eyre!("searching for switch {} returned multiple results", id).into(),
            ),
        ))
    }
}

// TODO(chet): Per Issue #925, the goal is to link machines to BMCs via
// the machine_interfaces table, but for now this is going to be like
// this until I take care of the issue.
pub async fn find_by_bmc_mac_address(
    txn: &mut PgConnection,
    bmc_mac_address: mac_address::MacAddress,
) -> DatabaseResult<Option<Switch>> {
    let switches = find_by(
        txn,
        ObjectColumnFilter::One(BmcMacAddressColumn, &bmc_mac_address),
    )
    .await?;
    Ok(switches.into_iter().next())
}

pub async fn find_ids(
    txn: impl DbReader<'_>,
    filter: model::switch::SwitchSearchFilter,
) -> Result<Vec<SwitchId>, DatabaseError> {
    let mut qb = sqlx::QueryBuilder::new("SELECT DISTINCT s.id FROM switches s");

    if filter.bmc_mac.is_some() {
        qb.push(" JOIN machine_interfaces mi ON mi.switch_id = s.id");
    }

    if filter.nvos_mac.is_some() {
        qb.push(" JOIN expected_switches es_nvos ON es_nvos.bmc_mac_address = s.bmc_mac_address");
    }

    qb.push(" WHERE TRUE");

    if let Some(rack_id) = filter.rack_id {
        qb.push(" AND s.rack_id = ");
        qb.push_bind(rack_id);
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

    if let Some(mac) = filter.nvos_mac {
        qb.push(" AND ");
        qb.push_bind(mac);
        qb.push(" = ANY(es_nvos.nvos_mac_addresses)");
    }

    if let Some(ovrrd_str) = &filter.only_with_health_alert {
        qb.push(" AND health_reports->'merges' ? ");
        qb.push_bind(ovrrd_str.clone());
        qb.push(" AND jsonb_array_length(health_reports->'merges'->");
        qb.push_bind(ovrrd_str);
        qb.push("->'alerts') > 0");
    }

    qb.build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("switch::find_ids", e))
}

/// Returns non-deleted switches in `rack_id` whose controller state is Ready and whose
/// Fabric Manager status reports `fabric_manager_state = ok` with
/// `addition_info = CONTROL_PLANE_STATE_CONFIGURED`.
pub async fn find_ready_control_plane_configured_switch_ids_in_rack<DB>(
    txn: &mut DB,
    rack_id: &RackId,
) -> DatabaseResult<Vec<SwitchId>>
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    let query = r#"
        SELECT s.id
        FROM switches s
        WHERE s.rack_id = $1
          AND s.deleted IS NULL
          AND s.controller_state->>'state' = $2
          AND s.fabric_manager_status->>'fabric_manager_state' = $3
          AND s.fabric_manager_status->>'addition_info' = $4
    "#;

    sqlx::query_as::<_, SwitchId>(query)
        .bind(rack_id)
        .bind(SWITCH_CONTROLLER_STATE_READY)
        .bind(FabricManagerState::Ok.as_str())
        .bind(CONTROL_PLANE_STATE_CONFIGURED)
        .fetch_all(&mut *txn)
        .await
        .map_err(|e| {
            DatabaseError::new(
                "switch::find_ready_control_plane_configured_switch_ids_in_rack",
                e,
            )
        })
}

/// Base relation for loading switches. Wraps the `switches` table in a derived
/// table (aliased `switches`) that adds a `bmc_info` JSON column resolved from
/// the `Bmc` machine_interface linked back to the switch -- mirroring how the
/// machine snapshot query materializes `bmc_info` (see
/// `sql/machine_snapshots.sql.template`). Keeping the alias `switches` lets the
/// generic `FilterableQueryBuilder` filters reference unqualified columns.
const SWITCHES_WITH_BMC_INFO: &str = r#"SELECT * FROM (
    SELECT s.*, bmc.json AS bmc_info
    FROM switches s
    LEFT JOIN LATERAL (
        SELECT jsonb_strip_nulls(jsonb_build_object(
            'machine_interface_id', bmc_i.id,
            'ip', host(bmc_addr.address),
            'mac', bmc_i.mac_address::text
        )) AS json
        FROM machine_interfaces bmc_i
        LEFT JOIN LATERAL (
            SELECT a.address
            FROM machine_interface_addresses a
            WHERE a.interface_id = bmc_i.id
            ORDER BY family(a.address), a.address
            LIMIT 1
        ) AS bmc_addr ON true
        WHERE bmc_i.switch_id = s.id
          AND bmc_i.interface_type = 'Bmc'
        ORDER BY bmc_i.created ASC
        LIMIT 1
    ) AS bmc ON true
) AS switches"#;

pub async fn find_by<'a, C: ColumnInfo<'a, TableType = Switch>>(
    txn: &mut PgConnection,
    filter: ObjectColumnFilter<'a, C>,
) -> DatabaseResult<Vec<Switch>> {
    let mut query = FilterableQueryBuilder::new(SWITCHES_WITH_BMC_INFO).filter(&filter);

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
    set_switch_reprovisioning_requested_with_firmware_continuation(txn, switch_id, initiator, true)
        .await
}

pub async fn set_switch_reprovisioning_requested_with_firmware_continuation(
    txn: &mut PgConnection,
    switch_id: SwitchId,
    initiator: &str,
    continue_after_firmware_upgrade: bool,
) -> DatabaseResult<()> {
    let req = SwitchReprovisionRequest {
        requested_at: Utc::now(),
        initiator: initiator.to_string(),
        continue_after_firmware_upgrade,
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

pub async fn set_switch_maintenance_requested(
    txn: &mut PgConnection,
    switch_id: SwitchId,
    initiator: &str,
    operation: SwitchMaintenanceOperation,
) -> DatabaseResult<()> {
    let req = SwitchMaintenanceRequest {
        requested_at: Utc::now(),
        initiator: initiator.to_string(),
        operation,
    };
    let query = "UPDATE switches SET switch_maintenance_requested = $1 WHERE id = $2 RETURNING id";
    sqlx::query_as::<_, SwitchId>(query)
        .bind(sqlx::types::Json(req))
        .bind(switch_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("set_switch_maintenance_requested", e))?;
    Ok(())
}

pub async fn clear_switch_maintenance_requested(
    txn: &mut PgConnection,
    switch_id: SwitchId,
) -> DatabaseResult<()> {
    let query =
        "UPDATE switches SET switch_maintenance_requested = NULL WHERE id = $1 RETURNING id";
    sqlx::query_as::<_, SwitchId>(query)
        .bind(switch_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("clear_switch_maintenance_requested", e))?;
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

pub async fn update_nvos_update_status(
    txn: &mut PgConnection,
    switch_id: SwitchId,
    status: Option<&model::switch::SwitchNvosUpdateStatus>,
) -> DatabaseResult<()> {
    let query = "UPDATE switches SET nvos_update_status = $1 WHERE id = $2 RETURNING id";
    sqlx::query_as::<_, SwitchId>(query)
        .bind(status.map(|s| sqlx::types::Json(s.clone())))
        .bind(switch_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::new("update_nvos_update_status", e))?;
    Ok(())
}

pub async fn update_fabric_manager_status(
    txn: &mut PgConnection,
    switch_id: SwitchId,
    status: Option<&FabricManagerStatus>,
) -> DatabaseResult<()> {
    let query = "UPDATE switches SET fabric_manager_status = $1 WHERE id = $2 RETURNING id";
    sqlx::query_as::<_, SwitchId>(query)
        .bind(status.cloned().map(sqlx::types::Json))
        .bind(switch_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::new("update_fabric_manager_status", e))?;
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

pub async fn set_primary_switch_for_rack(
    txn: &mut PgConnection,
    rack_id: &RackId,
    primary_switch_id: &SwitchId,
) -> DatabaseResult<()> {
    sqlx::query("UPDATE switches SET is_primary = (id = $1) WHERE rack_id = $2")
        .bind(primary_switch_id)
        .bind(rack_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("set_primary_switch_for_rack", e))?;
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
    /// `machine_interfaces.hostname` plus domain for the NVOS interface (TLS SNI).
    pub nvos_hostname: Option<String>,
}

/// Ready switch endpoint selected for NMX-C rack-level operations.
#[derive(Debug, sqlx::FromRow)]
pub struct ReadyControlPlaneSwitchEndpointRow {
    pub switch_id: SwitchId,
    pub rack_id: RackId,
    pub rack_profile_id: Option<RackProfileId>,
    pub nvos_ip: IpAddr,
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
            nvos_mia.address     AS nvos_ip,
            CASE
                WHEN nvos_d.name IS NOT NULL AND nvos_d.name <> '' THEN
                    nvos_mi.hostname || '.' || nvos_d.name
                ELSE nvos_mi.hostname
            END                  AS nvos_hostname
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
        LEFT JOIN domains nvos_d
            ON nvos_d.id = nvos_mi.domain_id
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

/// Resolve one ready Fabric Manager control-plane switch endpoint per rack.
///
/// When several switches in a rack match, the primary switch is preferred.
pub async fn find_ready_control_plane_configured_switch_endpoints<DB>(
    db: &mut DB,
) -> DatabaseResult<Vec<ReadyControlPlaneSwitchEndpointRow>>
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    let sql = r#"
        SELECT DISTINCT ON (s.rack_id)
            s.id               AS switch_id,
            s.rack_id          AS rack_id,
            r.rack_profile_id  AS rack_profile_id,
            nvos_mia.address   AS nvos_ip
        FROM switches s
        LEFT JOIN racks r
            ON r.id = s.rack_id
        JOIN expected_switches es
            ON es.bmc_mac_address = s.bmc_mac_address
        JOIN machine_interfaces nvos_mi
            ON es.nvos_mac_addresses IS NOT NULL
           AND nvos_mi.mac_address = ANY(es.nvos_mac_addresses)
        JOIN machine_interface_addresses nvos_mia
            ON nvos_mia.interface_id = nvos_mi.id
        WHERE s.rack_id IS NOT NULL
          AND s.deleted IS NULL
          AND s.controller_state->>'state' = $1
          AND s.fabric_manager_status->>'fabric_manager_state' = $2
          AND s.fabric_manager_status->>'addition_info' = $3
        ORDER BY s.rack_id, s.is_primary DESC, s.id
    "#;

    sqlx::query_as(sql)
        .bind(SWITCH_CONTROLLER_STATE_READY)
        .bind(FabricManagerState::Ok.as_str())
        .bind(CONTROL_PLANE_STATE_CONFIGURED)
        .fetch_all(&mut *db)
        .await
        .map_err(|err| {
            DatabaseError::new(
                "switch::find_ready_control_plane_configured_switch_endpoints",
                err,
            )
        })
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

/// A switch resolved by its BMC MAC address, along with the rack it belongs
/// to. Used by the Component Manager state controller wrapper to build a
/// rack-level `MaintenanceScope` for the switches it's been asked to act on.
#[derive(Debug, sqlx::FromRow)]
pub struct SwitchIdByBmcMac {
    pub bmc_mac_address: MacAddress,
    pub id: SwitchId,
    pub rack_id: Option<RackId>,
}

/// Resolve BMC MAC addresses to `SwitchId`s + `rack_id`s.
pub async fn find_ids_by_bmc_macs(
    db: impl crate::db_read::DbReader<'_>,
    macs: &[MacAddress],
) -> DatabaseResult<Vec<SwitchIdByBmcMac>> {
    let sql = r#"
        SELECT s.bmc_mac_address, s.id, s.rack_id
        FROM switches s
        WHERE s.bmc_mac_address = ANY($1)
    "#;

    sqlx::query_as(sql)
        .bind(macs)
        .fetch_all(db)
        .await
        .map_err(|err| DatabaseError::new("switch::find_ids_by_bmc_macs", err))
}

/// RMS identity for a switch, including rack profile context for node type
/// resolution.
#[derive(Debug, sqlx::FromRow)]
pub struct SwitchRmsIdentity {
    pub id: String,
    pub bmc_mac_address: MacAddress,
    pub rack_id: Option<RackId>,
    pub rack_profile_id: Option<RackProfileId>,
}

/// Look up RMS identities and rack profile context for switches by their BMC
/// MAC addresses.
pub async fn find_rms_identities_by_macs(
    db: impl crate::db_read::DbReader<'_>,
    macs: &[MacAddress],
) -> DatabaseResult<Vec<SwitchRmsIdentity>> {
    let sql = r#"
        SELECT
            s.id::text,
            s.bmc_mac_address,
            s.rack_id,
            r.rack_profile_id
        FROM switches s
        LEFT JOIN racks r ON r.id = s.rack_id
        WHERE s.bmc_mac_address = ANY($1)
    "#;

    sqlx::query_as(sql)
        .bind(macs)
        .fetch_all(db)
        .await
        .map_err(|err| DatabaseError::new("switch::find_rms_identities_by_macs", err))
}

pub async fn insert_health_report(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
    mode: HealthReportApplyMode,
    health_report: &HealthReport,
) -> Result<(), DatabaseError> {
    crate::health_report::insert_health_report(txn, "switches", switch_id, mode, health_report)
        .await
}

pub async fn remove_health_report(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
    mode: HealthReportApplyMode,
    source: &str,
) -> Result<(), DatabaseError> {
    crate::health_report::remove_health_report(txn, "switches", switch_id, mode, source).await
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use carbide_uuid::machine::MachineInterfaceId;
    use carbide_uuid::network::NetworkSegmentId;
    use carbide_uuid::rack::{RackId, RackProfileId};
    use model::allocation_type::AllocationType;
    use model::rack::RackConfig;
    use model::switch::{
        CONTROL_PLANE_STATE_CONFIGURED, FabricManagerState, FabricManagerStatus, NewSwitch,
        SwitchConfig, SwitchControllerState,
    };

    use super::*;
    use crate::test_support::switch::create_seeded_discovered;

    /// The switch load query must surface `bmc_info` (MAC + IP +
    /// machine-interface id) resolved from the BMC machine_interface linked
    /// back to the switch (`switch_id` + `interface_type = 'Bmc'`), regardless
    /// of network segment. A non-BMC interface on the same switch must be
    /// ignored.
    #[crate::sqlx_test]
    async fn test_find_by_populates_bmc_info(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;

        let switch_id =
            SwitchId::from_str("sw100nsner0op5osl6n85t7772j010jmhafm934n7oej4mlome3okrn9b60")?;
        // `switches.bmc_mac_address` is an FK into `expected_switches`, so seed
        // the expected switch before creating the switch.
        sqlx::query(
            "INSERT INTO expected_switches (serial_number, bmc_mac_address, bmc_username, bmc_password)
             VALUES ('SW-SN-BMC', '02:00:00:00:0b:01'::macaddr, 'admin', 'pw')",
        )
        .execute(txn.as_mut())
        .await?;
        create(
            &mut txn,
            &NewSwitch {
                id: switch_id,
                config: SwitchConfig {
                    name: "BMC info switch".to_string(),
                    enable_nmxc: false,
                    fabric_manager_config: None,
                },
                bmc_mac_address: Some("02:00:00:00:0b:01".parse()?),
                metadata: None,
                rack_id: None,
                slot_number: None,
                tray_index: None,
            },
        )
        .await?;

        // A non-underlay segment on purpose: resolution must not depend on the
        // segment type, only on the BMC link back to the switch.
        let segment_id: NetworkSegmentId = sqlx::query_scalar(
            "INSERT INTO network_segments (name, version, network_segment_type)
             VALUES ($1, 'V1-T0', 'tenant') RETURNING id",
        )
        .bind("switch-bmc-info")
        .fetch_one(txn.as_mut())
        .await?;

        let bmc_mac = "02:00:00:00:0b:01";
        let bmc_ip: IpAddr = "10.30.40.50".parse()?;
        let bmc_interface_id: MachineInterfaceId = sqlx::query_scalar(
            "INSERT INTO machine_interfaces
                 (switch_id, association_type, segment_id, mac_address,
                  primary_interface, hostname, interface_type)
             VALUES ($1, 'Switch', $2, $3::macaddr, false, 'bmc', 'Bmc')
             RETURNING id",
        )
        .bind(switch_id)
        .bind(segment_id)
        .bind(bmc_mac)
        .fetch_one(txn.as_mut())
        .await?;
        crate::machine_interface_address::insert(
            txn.as_mut(),
            bmc_interface_id,
            bmc_ip,
            AllocationType::Dhcp,
        )
        .await?;

        // An NVOS 'Data' interface on the same switch must be ignored.
        let data_interface_id: MachineInterfaceId = sqlx::query_scalar(
            "INSERT INTO machine_interfaces
                 (switch_id, association_type, segment_id, mac_address,
                  primary_interface, hostname, interface_type)
             VALUES ($1, 'Switch', $2, $3::macaddr, false, 'nvos', 'Data')
             RETURNING id",
        )
        .bind(switch_id)
        .bind(segment_id)
        .bind("02:00:00:00:0b:02")
        .fetch_one(txn.as_mut())
        .await?;
        crate::machine_interface_address::insert(
            txn.as_mut(),
            data_interface_id,
            "10.30.40.51".parse::<IpAddr>()?,
            AllocationType::Dhcp,
        )
        .await?;

        let switch = find_by_id(&mut txn, &switch_id)
            .await?
            .expect("switch should exist");
        let bmc_info = switch
            .bmc_info
            .expect("switch load should populate bmc_info from the BMC interface");
        assert_eq!(bmc_info.machine_interface_id, Some(bmc_interface_id));
        assert_eq!(bmc_info.mac, Some(bmc_mac.parse()?));
        assert_eq!(bmc_info.ip, Some(bmc_ip));

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_find_ready_control_plane_configured_switch_ids_in_rack(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rack_id: RackId = "rack-sw-find".parse().unwrap();
        let other_rack_id: RackId = "rack-other".parse().unwrap();
        let rack_profile_id = RackProfileId::new("NVL72");
        let mut txn = pool.begin().await?;
        crate::rack::create(
            txn.as_mut(),
            &rack_id,
            Some(&rack_profile_id),
            &RackConfig::default(),
            None,
        )
        .await?;
        crate::rack::create(
            txn.as_mut(),
            &other_rack_id,
            Some(&rack_profile_id),
            &RackConfig::default(),
            None,
        )
        .await?;
        txn.commit().await?;

        let mut txn = pool.begin().await?;
        let matching_switch = create_seeded_discovered(txn.as_mut(), 1, "Switch1").await?;
        txn.commit().await?;
        let mut txn = pool.begin().await?;
        let wrong_fm_switch = create_seeded_discovered(txn.as_mut(), 2, "Switch2").await?;
        txn.commit().await?;
        let mut txn = pool.begin().await?;
        let other_rack_switch = create_seeded_discovered(txn.as_mut(), 4, "Switch4").await?;
        txn.commit().await?;

        let configured_status = FabricManagerStatus {
            fabric_manager_state: FabricManagerState::Ok,
            addition_info: Some(CONTROL_PLANE_STATE_CONFIGURED.to_string()),
            reason: None,
            error_message: None,
        };

        let mut txn = pool.begin().await?;
        for (switch_id, rack, fm_status) in [
            (matching_switch.id, &rack_id, Some(&configured_status)),
            (wrong_fm_switch.id, &rack_id, None),
            (
                other_rack_switch.id,
                &other_rack_id,
                Some(&configured_status),
            ),
        ] {
            sqlx::query("UPDATE switches SET rack_id = $1 WHERE id = $2")
                .bind(rack)
                .bind(switch_id)
                .execute(txn.as_mut())
                .await?;

            let switch = find_by_id(txn.as_mut(), &switch_id)
                .await?
                .expect("switch should exist");
            let updated = try_update_controller_state(
                txn.as_mut(),
                switch_id,
                switch.controller_state.version,
                switch.controller_state.version.increment(),
                &SwitchControllerState::Ready,
            )
            .await?;
            assert!(
                updated,
                "setup should update switch controller state with the current version"
            );

            if let Some(status) = fm_status {
                update_fabric_manager_status(txn.as_mut(), switch_id, Some(status)).await?;
            }
        }
        txn.commit().await?;

        let mut txn = pool.begin().await?;
        let found =
            find_ready_control_plane_configured_switch_ids_in_rack(txn.as_mut(), &rack_id).await?;
        assert_eq!(found, vec![matching_switch.id]);

        let found_other =
            find_ready_control_plane_configured_switch_ids_in_rack(txn.as_mut(), &other_rack_id)
                .await?;
        assert_eq!(found_other, vec![other_rack_switch.id]);
        txn.rollback().await?;

        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_find_ready_control_plane_configured_switch_endpoints_prefers_primary(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let rack_id: RackId = "rack-sw-endpoint".parse().unwrap();
        let rack_profile_id = RackProfileId::new("NVL72");
        let mut txn = pool.begin().await?;
        crate::rack::create(
            txn.as_mut(),
            &rack_id,
            Some(&rack_profile_id),
            &RackConfig::default(),
            None,
        )
        .await?;
        txn.commit().await?;

        let mut txn = pool.begin().await?;
        let secondary_switch = create_seeded_discovered(txn.as_mut(), 1, "Switch1").await?;
        txn.commit().await?;
        let mut txn = pool.begin().await?;
        let primary_switch = create_seeded_discovered(txn.as_mut(), 2, "Switch2").await?;
        txn.commit().await?;

        let configured_status = FabricManagerStatus {
            fabric_manager_state: FabricManagerState::Ok,
            addition_info: Some(CONTROL_PLANE_STATE_CONFIGURED.to_string()),
            reason: None,
            error_message: None,
        };

        let mut txn = pool.begin().await?;
        for switch_id in [secondary_switch.id, primary_switch.id] {
            sqlx::query("UPDATE switches SET rack_id = $1 WHERE id = $2")
                .bind(&rack_id)
                .bind(switch_id)
                .execute(txn.as_mut())
                .await?;

            let switch = find_by_id(txn.as_mut(), &switch_id)
                .await?
                .expect("switch should exist");
            let updated = try_update_controller_state(
                txn.as_mut(),
                switch_id,
                switch.controller_state.version,
                switch.controller_state.version.increment(),
                &SwitchControllerState::Ready,
            )
            .await?;
            assert!(
                updated,
                "setup should update switch controller state with the current version"
            );

            update_fabric_manager_status(txn.as_mut(), switch_id, Some(&configured_status)).await?;
        }
        set_primary_switch_for_rack(txn.as_mut(), &rack_id, &primary_switch.id).await?;

        let expected_nvos_ip = find_switch_endpoints_by_ids(txn.as_mut(), &[primary_switch.id])
            .await?
            .pop()
            .expect("primary switch endpoint")
            .nvos_ip
            .expect("primary switch nvos ip");

        let endpoints = find_ready_control_plane_configured_switch_endpoints(txn.as_mut()).await?;
        let rack_endpoints = endpoints
            .into_iter()
            .filter(|endpoint| endpoint.rack_id == rack_id)
            .collect::<Vec<_>>();

        assert_eq!(rack_endpoints.len(), 1);
        assert_eq!(rack_endpoints[0].switch_id, primary_switch.id);
        assert_eq!(rack_endpoints[0].rack_id, rack_id);
        assert_eq!(rack_endpoints[0].nvos_ip, expected_nvos_ip);
        txn.rollback().await?;

        Ok(())
    }
}
