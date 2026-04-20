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
use health_report::{HealthReport, HealthReportApplyMode};
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::metadata::Metadata;
use model::power_shelf::{NewPowerShelf, PowerShelf, PowerShelfControllerState};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{
    ColumnInfo, DatabaseError, DatabaseResult, FilterableQueryBuilder, ObjectColumnFilter,
};

#[derive(Debug, Clone, Default)]
pub struct PowerShelfSearchConfig {
    // pub include_history: bool, // unused
    pub controller_state: Option<String>,
    pub rack_id: Option<String>,
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
    let controller_state_version = ConfigVersion::initial();
    let version = ConfigVersion::initial();

    let default_metadata = Metadata::default();
    let expected_metadata = new_power_shelf
        .metadata
        .as_ref()
        .unwrap_or(&default_metadata);
    let metadata_name = match expected_metadata.name.as_str() {
        "" => new_power_shelf.id.to_string(),
        name => name.to_string(),
    };
    let metadata = Metadata {
        name: metadata_name,
        description: expected_metadata.description.clone(),
        labels: expected_metadata.labels.clone(),
    };

    let query = sqlx::query_as::<_, PowerShelfId>(
        "INSERT INTO power_shelves (id, name, config, controller_state, controller_state_version, description, labels, version, rack_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    );
    let _: PowerShelfId = query
        .bind(new_power_shelf.id)
        .bind(&metadata.name)
        .bind(sqlx::types::Json(&new_power_shelf.config))
        .bind(sqlx::types::Json(&state))
        .bind(controller_state_version)
        .bind(&metadata.description)
        .bind(sqlx::types::Json(&metadata.labels))
        .bind(version)
        .bind(&new_power_shelf.rack_id)
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
            version: controller_state_version,
        },
        controller_state_outcome: None,
        metadata,
        version,
        rack_id: new_power_shelf.rack_id.clone(),
        health_reports: Default::default(),
    })
}

pub async fn find_by_name(
    txn: &mut PgConnection,
    name: &str,
) -> DatabaseResult<Option<PowerShelf>> {
    let mut power_shelves =
        find_by(txn, ObjectColumnFilter::One(NameColumn, &name.to_string())).await?;

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
    let mut power_shelves = find_by(txn, ObjectColumnFilter::One(IdColumn, id)).await?;

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

pub async fn find_ids(
    txn: impl DbReader<'_>,
    filter: model::power_shelf::PowerShelfSearchFilter,
) -> Result<Vec<PowerShelfId>, DatabaseError> {
    let mut qb = sqlx::QueryBuilder::new("SELECT DISTINCT ps.id FROM power_shelves ps");

    if filter.bmc_mac.is_some() {
        qb.push(" JOIN machine_interfaces mi ON mi.power_shelf_id = ps.id");
    }

    qb.push(" WHERE TRUE");

    if filter.rack_id.is_some() {
        qb.push(" AND ps.rack_id = ");
        qb.push_bind(filter.rack_id.unwrap());
    }
    match filter.deleted {
        model::DeletedFilter::Exclude => qb.push(" AND ps.deleted IS NULL"),
        model::DeletedFilter::Only => qb.push(" AND ps.deleted IS NOT NULL"),
        model::DeletedFilter::Include => &mut qb,
    };

    if let Some(state) = &filter.controller_state {
        qb.push(" AND ps.controller_state->>'state' = ");
        qb.push_bind(state.clone());
    }

    if let Some(mac) = filter.bmc_mac {
        qb.push(" AND mi.mac_address = ");
        qb.push_bind(mac);
    }

    qb.build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("power_shelf::find_ids", e))
}

pub async fn find_by<'a, C: ColumnInfo<'a, TableType = PowerShelf>>(
    txn: &mut PgConnection,
    filter: ObjectColumnFilter<'a, C>,
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
    new_version: ConfigVersion,
    new_state: &PowerShelfControllerState,
) -> DatabaseResult<bool> {
    let query_result = sqlx::query_as::<_, PowerShelfId>(
            "UPDATE power_shelves SET controller_state = $1, controller_state_version = $2 WHERE id = $3 AND controller_state_version = $4 RETURNING id",
        )
            .bind(sqlx::types::Json(new_state))
            .bind(new_version)
            .bind(power_shelf_id)
            .bind(expected_version)
            .fetch_optional(txn)
            .await
            .map_err(|e| DatabaseError::new("try_update_controller_state", e))?;

    Ok(query_result.is_some())
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

use std::net::IpAddr;

use carbide_uuid::rack::RackId;
use mac_address::MacAddress;

/// Resolve PowerShelfIds to BMC/PMC IPs via the machine_interfaces path.
pub async fn find_bmc_ips_by_power_shelf_ids(
    db: impl crate::db_read::DbReader<'_>,
    power_shelf_ids: &[PowerShelfId],
) -> DatabaseResult<Vec<(PowerShelfId, IpAddr)>> {
    let sql = r#"
        SELECT DISTINCT ON (ps.id)
            ps.id,
            mia.address
        FROM power_shelves ps
        JOIN expected_power_shelves eps ON eps.serial_number = ps.config->>'name'
        JOIN machine_interfaces mi ON mi.mac_address = eps.bmc_mac_address
        JOIN machine_interface_addresses mia ON mia.interface_id = mi.id
        WHERE ps.id = ANY($1)
        ORDER BY ps.id
    "#;

    sqlx::query_as(sql)
        .bind(power_shelf_ids)
        .fetch_all(db)
        .await
        .map_err(|err| DatabaseError::new("power_shelf::find_bmc_ips_by_power_shelf_ids", err))
}

/// Full endpoint info for a power shelf: PMC MAC and PMC IP.
#[derive(Debug, sqlx::FromRow)]
pub struct PowerShelfEndpointRow {
    pub power_shelf_id: PowerShelfId,
    pub pmc_mac: MacAddress,
    pub pmc_ip: IpAddr,
}

/// Resolve PowerShelfIds to PMC MAC + IP.
pub async fn find_power_shelf_endpoints_by_ids(
    db: impl crate::db_read::DbReader<'_>,
    power_shelf_ids: &[PowerShelfId],
) -> DatabaseResult<Vec<PowerShelfEndpointRow>> {
    // DISTINCT ON guards against a machine_interface having multiple addresses
    let sql = r#"
        SELECT DISTINCT ON (ps.id)
            ps.id                AS power_shelf_id,
            eps.bmc_mac_address  AS pmc_mac,
            mia.address          AS pmc_ip
        FROM power_shelves ps
        JOIN expected_power_shelves eps ON eps.serial_number = ps.config->>'name'
        JOIN machine_interfaces mi ON mi.mac_address = eps.bmc_mac_address
        JOIN machine_interface_addresses mia ON mia.interface_id = mi.id
        WHERE ps.id = ANY($1)
        ORDER BY ps.id
    "#;

    sqlx::query_as(sql)
        .bind(power_shelf_ids)
        .fetch_all(db)
        .await
        .map_err(|err| DatabaseError::new("power_shelf::find_power_shelf_endpoints_by_ids", err))
}

pub async fn update_metadata(
    txn: &mut PgConnection,
    power_shelf_id: &PowerShelfId,
    expected_version: ConfigVersion,
    metadata: Metadata,
) -> Result<(), DatabaseError> {
    let next_version = expected_version.increment();

    let query = "UPDATE power_shelves SET
            version=$1,
            name=$2, description=$3, labels=$4::jsonb
            WHERE id=$5 AND version=$6
            RETURNING id";

    let query_result: Result<(PowerShelfId,), _> = sqlx::query_as(query)
        .bind(next_version)
        .bind(&metadata.name)
        .bind(&metadata.description)
        .bind(sqlx::types::Json(&metadata.labels))
        .bind(power_shelf_id)
        .bind(expected_version)
        .fetch_one(txn)
        .await;

    match query_result {
        Ok((_id,)) => Ok(()),
        Err(e) => Err(match e {
            sqlx::Error::RowNotFound => DatabaseError::ConcurrentModificationError(
                "power_shelf",
                expected_version.to_string(),
            ),
            e => DatabaseError::query(query, e),
        }),
    }
}

/// Resolve PowerShelfIds to BMC MAC + IP via machine_interfaces.
pub async fn find_bmc_info_by_power_shelf_ids(
    db: impl crate::db_read::DbReader<'_>,
    power_shelf_ids: &[PowerShelfId],
) -> DatabaseResult<Vec<PowerShelfEndpointRow>> {
    let sql = r#"
        SELECT DISTINCT ON (mi.power_shelf_id)
            mi.power_shelf_id  AS power_shelf_id,
            mi.mac_address     AS pmc_mac,
            mia.address        AS pmc_ip
        FROM machine_interfaces mi
        JOIN machine_interface_addresses mia ON mia.interface_id = mi.id
        JOIN network_segments ns ON ns.id = mi.segment_id
        WHERE mi.power_shelf_id = ANY($1)
          AND ns.network_segment_type = 'underlay'
        ORDER BY mi.power_shelf_id
    "#;

    sqlx::query_as(sql)
        .bind(power_shelf_ids)
        .fetch_all(db)
        .await
        .map_err(|err| DatabaseError::new("power_shelf::find_bmc_info_by_power_shelf_ids", err))
}

/// A power shelf resolved by its BMC MAC address, along with the rack it
/// belongs to. Used by the Component Manager state controller wrapper to
/// build a rack-level `MaintenanceScope` for the power shelves it's been
/// asked to act on.
#[derive(Debug, sqlx::FromRow)]
pub struct PowerShelfIdByBmcMac {
    pub bmc_mac_address: MacAddress,
    pub id: PowerShelfId,
    pub rack_id: Option<RackId>,
}

/// Resolve BMC MAC addresses to `PowerShelfId`s + `rack_id`s.
pub async fn find_ids_by_bmc_macs(
    db: impl crate::db_read::DbReader<'_>,
    macs: &[MacAddress],
) -> DatabaseResult<Vec<PowerShelfIdByBmcMac>> {
    let sql = r#"
        SELECT ps.bmc_mac_address, ps.id, ps.rack_id
        FROM power_shelves ps
        WHERE ps.bmc_mac_address = ANY($1)
    "#;

    sqlx::query_as(sql)
        .bind(macs)
        .fetch_all(db)
        .await
        .map_err(|err| DatabaseError::new("power_shelf::find_ids_by_bmc_macs", err))
}

/// RMS identity for a power shelf: the power shelf ID (used as the RMS
/// node_id), the BMC MAC address, and the rack_id.
#[derive(Debug, sqlx::FromRow)]
pub struct PowerShelfRmsIdentity {
    pub id: String,
    pub bmc_mac_address: MacAddress,
    pub rack_id: Option<RackId>,
}

/// Look up RMS identities (node_id, rack_id) for power shelves by their
/// BMC MAC addresses.
pub async fn find_rms_identities_by_macs(
    db: impl crate::db_read::DbReader<'_>,
    macs: &[MacAddress],
) -> DatabaseResult<Vec<PowerShelfRmsIdentity>> {
    let sql = r#"
        SELECT ps.id::text, ps.bmc_mac_address, ps.rack_id
        FROM power_shelves ps
        WHERE ps.bmc_mac_address = ANY($1)
    "#;

    sqlx::query_as(sql)
        .bind(macs)
        .fetch_all(db)
        .await
        .map_err(|err| DatabaseError::new("power_shelf::find_rms_identities_by_macs", err))
}

pub async fn insert_health_report(
    txn: &mut PgConnection,
    power_shelf_id: &PowerShelfId,
    mode: HealthReportApplyMode,
    health_report: &HealthReport,
) -> Result<(), DatabaseError> {
    crate::health_report::insert_health_report(
        txn,
        "power_shelves",
        power_shelf_id,
        mode,
        health_report,
    )
    .await
}

pub async fn remove_health_report(
    txn: &mut PgConnection,
    power_shelf_id: &PowerShelfId,
    mode: HealthReportApplyMode,
    source: &str,
) -> Result<(), DatabaseError> {
    crate::health_report::remove_health_report(txn, "power_shelves", power_shelf_id, mode, source)
        .await
}
