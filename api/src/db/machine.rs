/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
//!
//! Machine - represents a database-backed Machine object
//!

use std::collections::HashMap;
use std::fmt::Write;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

use ::rpc::forge::{self as rpc, DpuInfo};
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use forge_uuid::{
    instance_type::InstanceTypeId,
    machine::{MachineId, MachineType},
};
use health_report::{HealthReport, OverrideMode};
use itertools::Itertools;
use lazy_static::lazy_static;
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Pool, Postgres, Row, Transaction};
use uuid::Uuid;

use super::{DatabaseError, ObjectFilter};
use crate::db;
use crate::db::machine_interface::MACHINE_INTERFACE_SNAPSHOT_QUERY;
use crate::db::machine_topology::MachineTopology;
use crate::model::bmc_info::BmcInfo;
use crate::model::controller_outcome::PersistentStateHandlerOutcome;
use crate::model::hardware_info::MachineInventory;
use crate::model::machine::health_override::HealthReportOverrides;
use crate::model::machine::infiniband::MachineInfinibandStatusObservation;
use crate::model::machine::network::{MachineNetworkStatusObservation, ManagedHostNetworkConfig};
use crate::model::machine::upgrade_policy::AgentUpgradePolicy;
use crate::model::machine::{
    FailureDetails, HostReprovisionRequest, Machine, MachineInterfaceSnapshot,
    MachineLastRebootRequested, MachineLastRebootRequestedMode, MachineStateHistory,
    ManagedHostState, ReprovisionRequest, UpgradeDecision,
};
use crate::model::metadata::Metadata;
use crate::model::sku::SkuStatus;
use crate::resource_pool::common::CommonPools;
use crate::state_controller::machine::io::CURRENT_STATE_MODEL_VERSION;
use crate::{CarbideError, CarbideResult, resource_pool};

/// MachineSearchConfig: Search parameters
#[derive(Default, Debug, Copy, Clone)]
pub struct MachineSearchConfig {
    pub include_dpus: bool,
    pub include_history: bool,
    pub include_predicted_host: bool,
    /// Only include machines in maintenance mode
    pub only_maintenance: bool,
    pub exclude_hosts: bool,

    /// Whether the query results will be later
    /// used for updates in the same transaction.
    ///
    /// Triggers one or more locking behaviors in the DB.
    ///
    /// This applies *only* to the immediate machines records
    /// and any joined tables.  The value is *not*
    /// propagated to any additional underlying queries.
    pub for_update: bool,
}

impl From<rpc::MachineSearchConfig> for MachineSearchConfig {
    fn from(value: rpc::MachineSearchConfig) -> Self {
        MachineSearchConfig {
            include_dpus: value.include_dpus,
            include_history: value.include_history,
            include_predicted_host: value.include_predicted_host,
            only_maintenance: value.only_maintenance,
            exclude_hosts: value.exclude_hosts,
            for_update: false, // This isn't exposed to API callers
        }
    }
}

#[derive(Serialize)]
struct ReprovisionRequestRestart {
    pub update_firmware: bool,
    pub restart_reprovision_requested_at: DateTime<Utc>,
}

lazy_static! {
    // This is a denormalized view of a machine that includes its interfaces (including their
    // denormalized address/vendors), its most recent topology, and optionally its history, in a
    // single query, using CTE's and JSON_AGG.
    static ref MACHINE_SNAPSHOT_QUERY_TEMPLATE: String = r#"
        WITH
        interface_snapshots AS (__INTERFACE_SNAPSHOTS__),
        interfaces_agg AS (
            SELECT i.machine_id, JSON_AGG(i.*) AS json
            FROM interface_snapshots AS i
            GROUP BY i.machine_id
        ),
        partitioned_topologies AS (
            SELECT mt.*, ROW_NUMBER()
            OVER (PARTITION BY mt.machine_id ORDER BY mt.created DESC) as row_num
            FROM machine_topologies mt
        ),
        most_recent_topology AS (
            SELECT t.machine_id, t.topology, t.created, t.updated, t.topology_update_needed
            FROM partitioned_topologies t
            WHERE row_num = 1
        ),
        topology_agg AS (
            SELECT mt.machine_id, JSON_AGG(mt.*) AS json
            FROM most_recent_topology mt
            GROUP BY mt.machine_id
        )
        __HISTORY_AGG__
        SELECT
            m.*,
            COALESCE(interfaces_agg.json, '[]') AS interfaces,
            COALESCE(topology_agg.json, '[]') AS topology
            __HISTORY_SELECT__
        FROM machines m
        LEFT JOIN interfaces_agg ON interfaces_agg.machine_id = m.id
        LEFT JOIN topology_agg ON topology_agg.machine_id = m.id
        __HISTORY_JOIN__
    "#
    // MACHINE_INTERFACE_SNAPSHOT_QUERY is the query we use in machine_interfaces.rs to denormalize
    // the machine_interfaces table. Use that as a subquery for machine snapshots.
        .replace("__INTERFACE_SNAPSHOTS__", MACHINE_INTERFACE_SNAPSHOT_QUERY);

    pub static ref MACHINE_SNAPSHOT_WITH_HISTORY_QUERY: String = MACHINE_SNAPSHOT_QUERY_TEMPLATE
        .replace(
            "__HISTORY_AGG__",
            r#", history_agg AS (
                SELECT mh.machine_id, JSON_AGG(json_build_object('machine_id', mh.machine_id, 'state', mh.state::TEXT, 'state_version', mh.state_version)) AS json
                FROM machine_state_history mh
                GROUP BY machine_id
            )"#)
        .replace("__HISTORY_SELECT__", ", COALESCE(history_agg.json, '[]') AS history")
        .replace("__HISTORY_JOIN__", "LEFT JOIN history_agg ON history_agg.machine_id = m.id");

    pub static ref MACHINE_SNAPSHOT_QUERY: String = MACHINE_SNAPSHOT_QUERY_TEMPLATE
        .replace("__HISTORY_AGG__", "")
        .replace("__HISTORY_SELECT__", "")
        .replace("__HISTORY_JOIN__", "");

    pub static ref JSON_MACHINE_SNAPSHOT_WITH_HISTORY_QUERY: String = format!("WITH machine_snapshots AS ({}) SELECT row_to_json(m.*) FROM machine_snapshots m", MACHINE_SNAPSHOT_QUERY_TEMPLATE.deref())
        .replace(
            "__HISTORY_AGG__",
            r#", history_agg AS (
                SELECT mh.machine_id, JSON_AGG(json_build_object('machine_id', mh.machine_id, 'state', mh.state::TEXT, 'state_version', mh.state_version)) AS json
                FROM machine_state_history mh
                GROUP BY machine_id
            )"#)
        .replace("__HISTORY_SELECT__", ", COALESCE(history_agg.json, '[]') AS history")
        .replace("__HISTORY_JOIN__", "LEFT JOIN history_agg ON history_agg.machine_id = m.id");

    pub static ref JSON_MACHINE_SNAPSHOT_QUERY: String = format!("WITH machine_snapshots AS ({}) SELECT row_to_json(m.*) FROM machine_snapshots m", MACHINE_SNAPSHOT_QUERY_TEMPLATE.deref())
        .replace("__HISTORY_AGG__", "")
        .replace("__HISTORY_SELECT__", "")
        .replace("__HISTORY_JOIN__", "");
}

/// This represents the structure of a machine we get from postgres via the row_to_json or
/// JSONB_AGG functions. Its fields need to match the column names of the machine_snapshots query
/// exactly. It's expected that we read this directly from the JSON returned by the query, and then
/// convert it into a Machine.
#[derive(Serialize, Deserialize)]
pub struct MachineSnapshotPgJson {
    id: MachineId,
    created: DateTime<Utc>,
    updated: DateTime<Utc>,
    deployed: Option<DateTime<Utc>>,
    agent_reported_inventory: Option<MachineInventory>,
    network_config_version: String,
    network_config: ManagedHostNetworkConfig,
    network_status_observation: Option<MachineNetworkStatusObservation>,
    infiniband_status_observation: Option<MachineInfinibandStatusObservation>,
    controller_state_version: String,
    controller_state: ManagedHostState,
    last_discovery_time: Option<DateTime<Utc>>,
    last_reboot_time: Option<DateTime<Utc>>,
    last_reboot_requested: Option<MachineLastRebootRequested>,
    last_cleanup_time: Option<DateTime<Utc>>,
    maintenance_reference: Option<String>,
    maintenance_start_time: Option<DateTime<Utc>>,
    failure_details: FailureDetails,
    reprovisioning_requested: Option<ReprovisionRequest>,
    host_reprovisioning_requested: Option<HostReprovisionRequest>,
    bios_password_set_time: Option<DateTime<Utc>>,
    last_machine_validation_time: Option<DateTime<Utc>>,
    discovery_machine_validation_id: Option<uuid::Uuid>,
    cleanup_machine_validation_id: Option<uuid::Uuid>,
    dpu_agent_health_report: Option<HealthReport>,
    dpu_agent_upgrade_requested: Option<UpgradeDecision>,
    machine_validation_health_report: HealthReport,
    site_explorer_health_report: Option<HealthReport>,
    firmware_autoupdate: Option<bool>,
    hardware_health_report: Option<HealthReport>,
    health_report_overrides: Option<HealthReportOverrides>,
    on_demand_machine_validation_id: Option<uuid::Uuid>,
    on_demand_machine_validation_request: Option<bool>,
    asn: Option<u32>,
    controller_state_outcome: Option<PersistentStateHandlerOutcome>,
    current_machine_validation_id: Option<uuid::Uuid>,
    machine_state_model_version: i32,
    instance_type_id: Option<InstanceTypeId>,
    interfaces: Vec<MachineInterfaceSnapshot>,
    topology: Vec<MachineTopology>,
    log_parser_health_report: Option<HealthReport>,
    labels: HashMap<String, String>,
    name: String,
    description: String,
    #[serde(default)] // History is only brought in if the search config requested it
    history: Vec<MachineStateHistory>,
    version: String,
    hw_sku: Option<String>,
    hw_sku_status: Option<SkuStatus>,
    sku_validation_health_report: Option<HealthReport>,
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for Machine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let json: serde_json::value::Value = row.try_get(0)?;
        MachineSnapshotPgJson::deserialize(json)
            .map_err(|err| sqlx::Error::Decode(err.into()))?
            .try_into()
    }
}

impl TryFrom<MachineSnapshotPgJson> for Machine {
    type Error = sqlx::Error;

    fn try_from(value: MachineSnapshotPgJson) -> sqlx::Result<Self> {
        let (hardware_info, bmc_info) = value
            .topology
            .into_iter()
            .map(|t| {
                let topology = t.into_topology();
                (
                    Some(topology.discovery_data.info.clone()),
                    topology.bmc_info,
                )
            })
            .next()
            .unwrap_or((None, BmcInfo::default()));

        let metadata = Metadata {
            name: value.name,
            description: value.description,
            labels: value.labels,
        };

        let version: ConfigVersion =
            value
                .version
                .parse()
                .map_err(|e| sqlx::error::Error::ColumnDecode {
                    index: "version".to_string(),
                    source: Box::new(e),
                })?;

        let history = value
            .history
            .into_iter()
            .sorted_by(
                |s1: &crate::model::machine::MachineStateHistory,
                 s2: &crate::model::machine::MachineStateHistory| {
                    Ord::cmp(&s1.state_version.timestamp(), &s2.state_version.timestamp())
                },
            )
            .collect();

        Ok(Self {
            id: value.id,
            state: Versioned {
                value: value.controller_state,
                version: value.controller_state_version.parse().map_err(|e| {
                    sqlx::error::Error::ColumnDecode {
                        index: "controller_state_version".to_string(),
                        source: Box::new(e),
                    }
                })?,
            },
            network_config: Versioned {
                value: value.network_config,
                version: value.network_config_version.parse().map_err(|e| {
                    sqlx::error::Error::ColumnDecode {
                        index: "network_config_version".to_string(),
                        source: Box::new(e),
                    }
                })?,
            },
            network_status_observation: value.network_status_observation,
            infiniband_status_observation: value.infiniband_status_observation,
            history,
            interfaces: value.interfaces,
            hardware_info,
            bmc_info,
            maintenance_reference: value.maintenance_reference,
            maintenance_start_time: value.maintenance_start_time,
            last_reboot_time: value.last_reboot_time,
            last_cleanup_time: value.last_cleanup_time,
            last_discovery_time: value.last_discovery_time,
            failure_details: value.failure_details,
            reprovision_requested: value.reprovisioning_requested,
            host_reprovision_requested: value.host_reprovisioning_requested,
            dpu_agent_upgrade_requested: value.dpu_agent_upgrade_requested,
            dpu_agent_health_report: value.dpu_agent_health_report,
            hardware_health_report: value.hardware_health_report,
            machine_validation_health_report: value.machine_validation_health_report,
            site_explorer_health_report: value.site_explorer_health_report,
            health_report_overrides: value.health_report_overrides.unwrap_or_default(),
            inventory: value.agent_reported_inventory,
            last_reboot_requested: value.last_reboot_requested,
            controller_state_outcome: value.controller_state_outcome,
            bios_password_set_time: value.bios_password_set_time,
            last_machine_validation_time: value.last_machine_validation_time,
            discovery_machine_validation_id: value.discovery_machine_validation_id,
            cleanup_machine_validation_id: value.cleanup_machine_validation_id,
            firmware_autoupdate: value.firmware_autoupdate,
            on_demand_machine_validation_id: value.on_demand_machine_validation_id,
            on_demand_machine_validation_request: value.on_demand_machine_validation_request,
            asn: value.asn,
            metadata,
            instance_type_id: value.instance_type_id,
            log_parser_health_report: value.log_parser_health_report,
            version,
            // Columns for these exist, but are unused in rust code
            // deployed: value.deployed,
            // created: value.created,
            // updated: value.updated,
            hw_sku: value.hw_sku,
            hw_sku_status: value.hw_sku_status,
            sku_validation_health_report: value.sku_validation_health_report,
        })
    }
}

/// Load a Machine object matching an interface, creating it if not already present.
/// Returns a tuple of (Machine, bool did_we_just_create_it)
///
/// Arguments:
///
/// * `txn` - A reference to a currently open database transaction
/// * `interface` - Network interface of the machine
///
pub async fn get_or_create(
    txn: &mut Transaction<'_, Postgres>,
    common_pools: Option<&CommonPools>,
    stable_machine_id: &MachineId,
    interface: &MachineInterfaceSnapshot,
) -> CarbideResult<Machine> {
    let existing_machine =
        find_one(&mut *txn, stable_machine_id, MachineSearchConfig::default()).await?;
    if interface.machine_id.is_some() {
        let machine_id = interface.machine_id.as_ref().unwrap();
        if machine_id != stable_machine_id {
            return Err(CarbideError::internal(format!(
                "Database inconsistency: MachineId {} on interface {} does not match stable machine ID {} which now uses this interface",
                machine_id, interface.id, stable_machine_id
            )));
        }

        if existing_machine.is_none() {
            tracing::warn!(
                %machine_id,
                interface_id = %interface.id,
                "Interface ID refers to missing machine",
            );
            return Err(CarbideError::NotFoundError {
                kind: "machine",
                id: machine_id.to_string(),
            });
        }
    }

    // Get or create
    if let Some(machine) = existing_machine {
        // New site-explorer redfish discovery path.
        db::machine_interface::associate_interface_with_machine(&interface.id, &machine.id, txn)
            .await?;
        Ok(machine)
    } else {
        // Old manual discovery path.
        // Host and DPU machines are created in same `discover_machine` call. Update same
        // state in both machines.
        let state = ManagedHostState::Created;
        let machine = create(
            txn,
            common_pools,
            stable_machine_id,
            state,
            &Metadata::default(),
        )
        .await?;
        db::machine_interface::associate_interface_with_machine(&interface.id, &machine.id, txn)
            .await?;
        Ok(machine)
    }
}

pub async fn find_one(
    txn: &mut Transaction<'_, Postgres>,
    id: &MachineId,
    search_config: MachineSearchConfig,
) -> Result<Option<Machine>, DatabaseError> {
    Ok(find(txn, ObjectFilter::One(*id), search_config)
        .await?
        .pop())
}

pub async fn find_existing_machine(
    txn: &mut Transaction<'_, Postgres>,
    macaddr: MacAddress,
    relay: IpAddr,
) -> Result<Option<MachineId>, DatabaseError> {
    let query = "
    SELECT m.id FROM
    machines m
    INNER JOIN machine_interfaces mi
        ON m.id = mi.machine_id
    INNER JOIN network_segments ns
        ON mi.segment_id = ns.id
    INNER JOIN network_prefixes np
        ON np.segment_id = ns.id
    WHERE
        mi.mac_address = $1::macaddr
        AND
        $2::inet <<= np.prefix";

    let id: Option<MachineId> = sqlx::query_as(query)
        .bind(macaddr)
        .bind(relay)
        .fetch_optional(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(id)
}

/// Perform an arbitrary action to a Machine and advance it to the next state given the last
/// state.
///
/// Arguments:
///
/// * `txn` - A reference to a currently open database transaction
/// * `state` - A reference to a MachineState enum
///
// TODO: abhi, Make it private.
pub async fn advance(
    machine: &Machine,
    txn: &mut Transaction<'_, Postgres>,
    state: ManagedHostState,
    version: Option<ConfigVersion>,
) -> Result<bool, DatabaseError> {
    // Get current version
    let version = version.unwrap_or_else(|| machine.state.version.increment());

    // Store history of machine state changes.
    db::machine_state_history::persist(txn, &machine.id, state.clone(), version).await?;

    let _id: (String,) = sqlx::query_as(
            "UPDATE machines SET controller_state_version=$1, controller_state=$2 WHERE id=$3 RETURNING id",
        )
        .bind(version)
        .bind(sqlx::types::Json(state))
        .bind(machine.id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "update machines state", e))?;

    Ok(true)
}

/// Find machines given a set of criteria
///
/// Arguments:
///
/// * `txn`           - A reference to a currently open database transaction
/// * `filter`        - An ObjectFilter to control the size of the response set
/// * `search_config` - A MachineSearchConfig with search options to control the
///                     records selected
pub async fn find(
    txn: &mut Transaction<'_, Postgres>,
    filter: ObjectFilter<'_, MachineId>,
    search_config: MachineSearchConfig,
) -> Result<Vec<Machine>, DatabaseError> {
    // The TRUE will be optimized away by the query planner,
    // but it simplifies the rest of the building for us.
    lazy_static! {
        static ref query_no_history: String =
            format!("{} WHERE TRUE", JSON_MACHINE_SNAPSHOT_QUERY.deref());
        static ref query_with_history: String = format!(
            "{} WHERE TRUE",
            JSON_MACHINE_SNAPSHOT_WITH_HISTORY_QUERY.deref()
        );
    }

    let mut builder = sqlx::QueryBuilder::new(if search_config.include_history {
        query_with_history.deref()
    } else {
        query_no_history.deref()
    });

    match filter {
        ObjectFilter::All => {} // Nothing to add.
        ObjectFilter::One(id) => {
            builder.push(" AND m.id= ");
            builder.push_bind(id.to_string());
        }
        ObjectFilter::List(list) => {
            builder.push(" AND m.id=ANY( ");
            builder.push_bind(
                list.iter()
                    .map(|id| id.to_string())
                    .collect::<Vec<String>>(),
            );
            builder.push(" ) ");
        }
    }

    if search_config.only_maintenance {
        builder.push(" AND m.maintenance_reference IS NOT NULL ");
    }

    if search_config.for_update {
        builder.push(" FOR UPDATE ");
    };

    let all_machines: Vec<Machine> = builder
        .build_query_as()
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), builder.sql(), e))?;

    Ok(all_machines)
}

pub async fn find_by_ip(
    txn: &mut Transaction<'_, Postgres>,
    ip: &Ipv4Addr,
) -> Result<Option<Machine>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            r#"{}
                INNER JOIN machine_interfaces mi ON mi.machine_id = m.id
                INNER JOIN machine_interface_addresses mia on mia.interface_id=mi.id
                WHERE mia.address = $1::inet"#,
            JSON_MACHINE_SNAPSHOT_QUERY.deref()
        );
    }
    let machine = sqlx::query_as(&query)
        .bind(ip.to_string())
        .fetch_optional(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))?;

    Ok(machine)
}

pub async fn find_id_by_bmc_ip(
    txn: &mut Transaction<'_, Postgres>,
    bmc_ip: &IpAddr,
) -> Result<Option<MachineId>, DatabaseError> {
    MachineTopology::find_machine_id_by_bmc_ip(txn, &bmc_ip.to_string()).await
}

/// Finds machines associated with a specified instance type
///
/// * `txn`              - A reference to an active DB transaction
/// * `instance_type_id` - An reference to an InstanceTypeId to query for
/// * `for_update`       - A boolean flag to acquire DB locks for synchronization
pub async fn find_ids_by_instance_type_id(
    txn: &mut Transaction<'_, Postgres>,
    instance_type_id: &InstanceTypeId,
    for_update: bool,
) -> Result<Vec<MachineId>, DatabaseError> {
    let mut builder = sqlx::QueryBuilder::new("SELECT id FROM machines WHERE");

    builder.push(" instance_type_id = ");
    builder.push_bind(instance_type_id);

    if for_update {
        builder.push(" FOR UPDATE ");
    }

    builder
        .build_query_as()
        .bind(instance_type_id)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), builder.sql(), e))
}

/// Associates machines with an InstanceType.
///
/// * `txn`              - A reference to an active DB transaction
/// * `instance_type_id` - An reference to an InstanceTypeId to associate with a set of machines
/// * `machine_ids`      - A list of machine IDs to associate to the desired instance type
pub async fn associate_machines_with_instance_type(
    txn: &mut Transaction<'_, Postgres>,
    instance_type_id: &InstanceTypeId,
    machine_ids: &[MachineId],
) -> Result<Vec<MachineId>, DatabaseError> {
    let query = "UPDATE machines SET instance_type_id=$1::varchar WHERE id = ANY($2) RETURNING id";

    sqlx::query_as(query)
        .bind(instance_type_id)
        .bind(machine_ids)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
}

/// Removes multiple machine associations with an InstanceType.
/// This does *NOT* check if the machines are in use.
///
/// * `txn`         - A reference to an active DB transaction
/// * `machine_ids` - A slice of machine IDs to update
pub async fn remove_instance_type_associations(
    txn: &mut Transaction<'_, Postgres>,
    machine_ids: &[MachineId],
) -> Result<Vec<MachineId>, DatabaseError> {
    let query = "UPDATE machines SET instance_type_id=NULL WHERE id = ANY($1) RETURNING id";

    sqlx::query_as(query)
        .bind(machine_ids)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
}

pub async fn find_by_hostname(
    txn: &mut Transaction<'_, Postgres>,
    hostname: &str,
) -> Result<Option<Machine>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            "{} JOIN machine_interfaces mi ON m.id = mi.machine_id WHERE mi.hostname = $1",
            JSON_MACHINE_SNAPSHOT_QUERY.deref()
        );
    }

    let machine = sqlx::query_as(&query)
        .bind(hostname)
        .fetch_optional(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))?;

    Ok(machine)
}

pub async fn find_by_mac_address(
    txn: &mut Transaction<'_, Postgres>,
    mac_address: &MacAddress,
) -> Result<Option<Machine>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            "{} JOIN machine_interfaces mi ON m.id = mi.machine_id WHERE mi.mac_address = $1::macaddr",
            JSON_MACHINE_SNAPSHOT_QUERY.deref()
        );
    }
    let machine = sqlx::query_as(&query)
        .bind(mac_address)
        .fetch_optional(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))?;

    Ok(machine)
}

pub async fn find_by_loopback_ip(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    loopback_ip: &str,
) -> Result<Option<Machine>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            "{} WHERE m.network_config->>'loopback_ip' = $1",
            JSON_MACHINE_SNAPSHOT_QUERY.deref()
        );
    }
    let machine = sqlx::query_as(&query)
        .bind(loopback_ip)
        .fetch_optional(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))?;
    Ok(machine)
}

pub async fn find_id_by_fqdn(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    fqdn: &str,
) -> Result<Option<MachineId>, DatabaseError> {
    let query = "SELECT machine_id FROM machine_dhcp_records WHERE fqdn = $1";

    let machine_id: Option<MachineId> = sqlx::query_as(query)
        .bind(fqdn)
        .fetch_optional(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(machine_id)
}

/// Finds a machine by a query
///
/// - If the query looks like a MachineId, it will try to load the information based on the MachineId
/// - If the query looks like an IP address, it will try to look up the machine based on its admin IP address
/// - If the query looks like a MAC address, it will look up the machine by MAC address
/// - Otherwise, it will try to look up the Machine by hostname
pub async fn find_by_query(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    query: &str,
) -> Result<Option<Machine>, DatabaseError> {
    if let Ok(id) = MachineId::from_str(query) {
        return find_one(txn, &id, MachineSearchConfig::default()).await;
    }

    if let Ok(ip) = Ipv4Addr::from_str(query) {
        return find_by_ip(txn, &ip).await;
    }

    if let Ok(mac) = MacAddress::from_str(query) {
        return find_by_mac_address(txn, &mac).await;
    }

    find_by_hostname(txn, query).await
}

pub async fn update_reboot_time(
    machine: &Machine,
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET last_reboot_time=NOW() WHERE id=$1 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine.id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
    Ok(())
}

pub async fn update_reboot_requested_time(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, Postgres>,
    mode: MachineLastRebootRequestedMode,
) -> Result<(), DatabaseError> {
    let data = MachineLastRebootRequested {
        time: chrono::Utc::now(),
        mode,
    };

    let query = "UPDATE machines SET last_reboot_requested=$1 WHERE id=$2 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(sqlx::types::Json(&data))
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
    Ok(())
}

pub async fn update_cleanup_time(
    machine: &Machine,
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET last_cleanup_time=NOW() WHERE id=$1 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine.id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

pub async fn update_bios_password_set(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET bios_password_set_time=NOW() WHERE id=$1 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

pub async fn update_discovery_time(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET last_discovery_time=NOW() WHERE id=$1 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

pub async fn find_host_by_dpu_machine_id(
    txn: &mut Transaction<'_, Postgres>,
    dpu_machine_id: &MachineId,
) -> Result<Option<Machine>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            r#"{} INNER JOIN machine_interfaces mi ON m.id = mi.machine_id
                    WHERE mi.attached_dpu_machine_id=$1
                    AND mi.attached_dpu_machine_id != mi.machine_id"#,
            JSON_MACHINE_SNAPSHOT_QUERY.deref()
        );
    }
    let machine = sqlx::query_as(&query)
        .bind(dpu_machine_id.to_string())
        .fetch_optional(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))?;

    Ok(machine)
}

pub async fn find_dpus_by_host_machine_id(
    txn: &mut Transaction<'_, Postgres>,
    host_machine_id: &MachineId,
) -> Result<Vec<Machine>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            r#"{}
                    INNER JOIN machine_interfaces mi
                      ON m.id = mi.attached_dpu_machine_id
                    WHERE mi.machine_id=$1"#,
            JSON_MACHINE_SNAPSHOT_QUERY.deref()
        );
    }
    let machines = sqlx::query_as(&query)
        .bind(host_machine_id.to_string())
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))?;

    Ok(machines)
}

pub async fn update_metadata(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    expected_version: ConfigVersion,
    metadata: Metadata,
) -> Result<(), CarbideError> {
    let next_version = expected_version.increment();

    let query = "UPDATE machines SET
            version=$1,
            name=$2, description=$3, labels=$4::jsonb
            WHERE id=$5 AND version=$6
            RETURNING id";
    let query_result: Result<(MachineId,), _> = sqlx::query_as(query)
        .bind(next_version)
        .bind(&metadata.name)
        .bind(&metadata.description)
        .bind(sqlx::types::Json(&metadata.labels))
        .bind(machine_id.to_string())
        .bind(expected_version)
        .fetch_one(txn.deref_mut())
        .await;

    match query_result {
        Ok((_machine_id,)) => Ok(()),
        Err(e) => Err(match e {
            sqlx::Error::RowNotFound => {
                CarbideError::ConcurrentModificationError("machine", expected_version.to_string())
            }
            e => DatabaseError::new(file!(), line!(), query, e).into(),
        }),
    }
}

/// Only does the update if the passed observation is newer than any existing one
pub async fn update_network_status_observation(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    observation: &MachineNetworkStatusObservation,
) -> Result<(), DatabaseError> {
    let query =
            "UPDATE machines SET network_status_observation = $1::json WHERE id = $2 AND
             (network_status_observation IS NULL
                OR (network_status_observation ? 'observed_at' AND network_status_observation->>'observed_at' <= $3)
            ) RETURNING id";
    let _id: (MachineId,) = sqlx::query_as(query)
        .bind(sqlx::types::Json(&observation))
        .bind(machine_id.to_string())
        .bind(observation.observed_at.to_rfc3339())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

/// Only does the update if the passed observation is newer than any existing one
pub async fn update_infiniband_status_observation(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    observation: &MachineInfinibandStatusObservation,
) -> Result<(), DatabaseError> {
    let query =
            "UPDATE machines SET infiniband_status_observation = $1::json WHERE id = $2 AND
             (infiniband_status_observation IS NULL
                OR (infiniband_status_observation ? 'observed_at' AND infiniband_status_observation->>'observed_at' <= $3)
            ) RETURNING id";
    let _id: (MachineId,) = sqlx::query_as(query)
        .bind(sqlx::types::Json(&observation))
        .bind(machine_id.to_string())
        .bind(observation.observed_at.to_rfc3339())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

async fn update_health_report(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    column_name: &str,
    health_report: &HealthReport,
) -> Result<(), DatabaseError> {
    let query = format!(
        "UPDATE machines SET {column_name} = $1::json WHERE id = $2 AND
             ({column_name} IS NULL
                OR ({column_name} ? 'observed_at' AND {column_name}->>'observed_at' <= $3)
            ) RETURNING id"
    );
    let observed_at = health_report
        .observed_at
        .map(|o| o.to_rfc3339())
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
    let _id: (MachineId,) = sqlx::query_as(&query)
        .bind(sqlx::types::Json(&health_report))
        .bind(machine_id.to_string())
        .bind(observed_at)
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "update health report", e))?;

    Ok(())
}

pub async fn update_dpu_agent_health_report(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    health_report: &HealthReport,
) -> Result<(), DatabaseError> {
    update_health_report(txn, machine_id, "dpu_agent_health_report", health_report).await
}

pub async fn update_hardware_health_report(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    health_report: &HealthReport,
) -> Result<(), DatabaseError> {
    update_health_report(txn, machine_id, "hardware_health_report", health_report).await
}

pub async fn update_log_parser_health_report(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    health_report: &HealthReport,
) -> Result<(), DatabaseError> {
    let query = String::from(
        "UPDATE machines SET log_parser_health_report = $1::json WHERE id = $2
            RETURNING id",
    );
    let _id: (MachineId,) = sqlx::query_as(&query)
        .bind(sqlx::types::Json(&health_report))
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "update health report", e))?;

    Ok(())
}

pub async fn update_machine_validation_health_report(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    health_report: &HealthReport,
) -> Result<(), DatabaseError> {
    update_health_report(
        txn,
        machine_id,
        "machine_validation_health_report",
        health_report,
    )
    .await
}

pub async fn update_site_explorer_health_report(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    health_report: &HealthReport,
) -> Result<(), DatabaseError> {
    update_health_report(
        txn,
        machine_id,
        "site_explorer_health_report",
        health_report,
    )
    .await
}

pub async fn update_sku_validation_health_report(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    health_report: &HealthReport,
) -> Result<(), DatabaseError> {
    update_health_report(
        txn,
        machine_id,
        "sku_validation_health_report",
        health_report,
    )
    .await
}

pub async fn insert_health_report_override(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    mode: OverrideMode,
    health_report: &HealthReport,
) -> Result<(), DatabaseError> {
    let column_name = "health_report_overrides";
    let path = match mode {
        OverrideMode::Merge => format!("merges,\"{}\"", health_report.source),
        OverrideMode::Replace => "replace".to_string(),
    };
    let query = format!(
        "UPDATE machines SET {column_name} = jsonb_set(
                coalesce({column_name}, '{{\"merges\": {{}}}}'::jsonb),
                '{{{}}}',
                $1::jsonb
            ) WHERE id = $2
            RETURNING id",
        path
    );

    let _id: (MachineId,) = sqlx::query_as(&query)
        .bind(sqlx::types::Json(&health_report))
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "insert health report override", e))?;

    Ok(())
}

pub async fn remove_health_report_override(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    mode: OverrideMode,
    source: &str,
) -> Result<(), DatabaseError> {
    let column_name = "health_report_overrides";
    let path = match mode {
        OverrideMode::Merge => format!("merges,{}", source),
        OverrideMode::Replace => "replace".to_string(),
    };
    let query = format!(
        "UPDATE machines SET {column_name} = ({column_name} #- '{{{}}}') WHERE id = $1
            RETURNING id",
        path
    );

    let _id: (MachineId,) = sqlx::query_as(&query)
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "remove health report override", e))?;

    Ok(())
}

pub async fn update_agent_reported_inventory(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    inventory: &MachineInventory,
) -> Result<(), DatabaseError> {
    let query =
        "UPDATE machines SET agent_reported_inventory = $1::json WHERE id = $2 RETURNING id";
    tracing::debug!(machine_id = %machine_id, "Updating machine inventory");
    let _id: (MachineId,) = sqlx::query_as(query)
        .bind(sqlx::types::Json(&inventory))
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

pub async fn get_all_network_status_observation(
    txn: &mut Transaction<'_, Postgres>,
    limit: i64, // return at most this many rows
) -> Result<Vec<MachineNetworkStatusObservation>, DatabaseError> {
    let query = "SELECT network_status_observation FROM machines
            WHERE network_status_observation IS NOT NULL
            ORDER BY network_status_observation->'machine_id'
            LIMIT $1::integer";
    let rows = sqlx::query(query)
        .bind(limit)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
    let mut all = Vec::with_capacity(rows.len());
    for row in rows {
        let s: sqlx::types::Json<MachineNetworkStatusObservation> = row
            .try_get("network_status_observation")
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        all.push(s.0);
    }
    Ok(all)
}

/// Force cleans all tables related to a Machine - except MachineInterfaces
///
/// DO NOT USE OUTSIDE OF ADMIN CLI
pub async fn force_cleanup(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    // Note: It might be nicer to actually write the full query here so we can
    // report more results.
    // But this way we at least unit-test the stored procedure and make sure
    // it stays up to date.
    let query = r#"call cleanup_machine_by_id($1)"#;
    let _query_result = sqlx::query(query)
        .bind(machine_id.to_string())
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
    Ok(())
}

/// Updates the desired network configuration for a host
pub async fn try_update_network_config(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    expected_version: ConfigVersion,
    new_state: &ManagedHostNetworkConfig,
) -> Result<bool, DatabaseError> {
    // TODO: We currently need to persist the state on the DPU since it exists
    // earlier than the host. But we might want to replicate it to the host machine,
    // as we do with `controller_state`.

    let next_version = expected_version.increment();

    let query = "UPDATE machines SET network_config_version=$1, network_config=$2::json
            WHERE id=$3 AND network_config_version=$4
            RETURNING id";
    let query_result: Result<MachineId, _> = sqlx::query_as(query)
        .bind(next_version)
        .bind(sqlx::types::Json(new_state))
        .bind(machine_id.to_string())
        .bind(expected_version)
        .fetch_one(txn.deref_mut())
        .await;

    match query_result {
        Ok(_machine_id) => Ok(true),
        Err(sqlx::Error::RowNotFound) => Ok(false),
        Err(e) => Err(DatabaseError::new(file!(), line!(), query, e)),
    }
}

/// Replaces predicted host id with stable host id.
/// Once forge receives DiscoveryData from Host, forge can create StableMachineId.
/// This StableMachineId must replace existing PredictedHostId in db.
/// State machine does not act on receiving discoverydata, but discoverycompleted message,
/// so updating host id must not interfere state machine handling.
pub async fn try_sync_stable_id_with_current_machine_id_for_host(
    txn: &mut Transaction<'_, Postgres>,
    current_machine_id: &Option<MachineId>,
    stable_machine_id: &MachineId,
) -> Result<MachineId, CarbideError> {
    let Some(current_machine_id) = current_machine_id else {
        return Err(CarbideError::NotFoundError {
            kind: "machine_id",
            id: stable_machine_id.to_string(),
        });
    };

    // This is repeated call. Machine is already updated with stable ID.
    if !current_machine_id.machine_type().is_predicted_host() {
        return match find_one(txn, current_machine_id, MachineSearchConfig::default()).await? {
            Some(machine) => Ok(machine.id),
            None => Err(CarbideError::NotFoundError {
                kind: "machine",
                id: current_machine_id.to_string(),
            }),
        };
    }

    // Update the machine history to account for the rename
    db::machine_state_history::update_machine_ids(txn, current_machine_id, stable_machine_id)
        .await?;

    // Table machine_interfaces has a FK ON UPDATE CASCADE so machine_interfaces.machine_id will
    // also change.
    let query = "UPDATE machines SET id=$1 WHERE id=$2 RETURNING id";
    let machine_id = sqlx::query_as(query)
        .bind(stable_machine_id.to_string())
        .bind(current_machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    // If the Machines name in Metadata matched the predicted machine id,
    // then update it to the new ID.
    // If someone changed the name manually then don't bother
    let query = "UPDATE machines SET name=$1 WHERE id=$2 AND name=$3";
    sqlx::query(query)
        .bind(stable_machine_id.to_string())
        .bind(stable_machine_id.to_string())
        .bind(current_machine_id.to_string())
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(machine_id)
}

pub async fn update_failure_details(
    machine: &Machine,
    txn: &mut Transaction<'_, Postgres>,
    failure: FailureDetails,
) -> Result<(), DatabaseError> {
    update_failure_details_by_machine_id(&machine.id, txn, failure).await
}

pub async fn clear_failure_details(
    machine_id: &MachineId,
    txn: &mut Transaction<'_, Postgres>,
) -> Result<(), DatabaseError> {
    let failure_details = FailureDetails {
        cause: crate::model::machine::FailureCause::NoError,
        failed_at: chrono::Utc::now(),
        source: crate::model::machine::FailureSource::NoError,
    };

    let query = "UPDATE machines SET failure_details = $1::json WHERE id = $2 RETURNING id";
    let _id: (MachineId,) = sqlx::query_as(query)
        .bind(sqlx::types::Json(failure_details))
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

pub async fn set_maintenance_mode(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    mode: &MaintenanceMode,
) -> Result<(), DatabaseError> {
    set_maintenance_mode_with_condition(txn, machine_id, mode, None).await
}

pub async fn set_maintenance_mode_with_condition(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    mode: &MaintenanceMode,
    condition: Option<String>,
) -> Result<(), DatabaseError> {
    match mode {
        MaintenanceMode::On { reference } => {
            let mut query = "UPDATE machines SET maintenance_reference=$1, maintenance_start_time=NOW() WHERE id=$2".to_string();
            if let Some(condition) = condition {
                write!(&mut query, " AND {condition}").unwrap();
            }
            sqlx::query(&query)
                .bind(reference)
                .bind(machine_id.to_string())
                .execute(txn.deref_mut())
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))?;
        }
        MaintenanceMode::Off => {
            let mut query = "UPDATE machines SET maintenance_reference=NULL, maintenance_start_time=NULL WHERE id=$1".to_string();
            if let Some(condition) = condition {
                write!(&mut query, " AND {condition}").unwrap();
            }
            sqlx::query(&query)
                .bind(machine_id.to_string())
                .execute(txn.deref_mut())
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))?;
        }
    }
    Ok(())
}

pub async fn create(
    txn: &mut Transaction<'_, Postgres>,
    common_pools: Option<&CommonPools>,
    stable_machine_id: &MachineId,
    state: ManagedHostState,
    metadata: &Metadata,
) -> CarbideResult<Machine> {
    let stable_machine_id_string = stable_machine_id.to_string();
    // Host and DPU machines are created in same `discover_machine` call. Update same
    // state in both machines.
    let state_version = ConfigVersion::initial();
    let version = ConfigVersion::initial();

    let network_config_version = ConfigVersion::initial();
    let network_config = ManagedHostNetworkConfig::default();
    let asn: Option<i64> = if stable_machine_id.machine_type() == MachineType::Dpu {
        if let Some(common_pools) = common_pools {
            match common_pools
                .ethernet
                .pool_fnn_asn
                .allocate(
                    txn,
                    resource_pool::OwnerType::Machine,
                    &stable_machine_id_string,
                )
                .await
            {
                Ok(asn) => Some(asn as i64),
                Err(e) => {
                    tracing::info!("Failed to allocate asn for dpu {stable_machine_id}: {e}");
                    None
                }
            }
        } else {
            None
        }
    } else {
        None
    };

    let query = r#"INSERT INTO machines(
                            id, controller_state_version, controller_state, network_config_version, network_config, machine_state_model_version, asn, version, name, description, labels)
                            VALUES($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11::json) RETURNING id"#;
    let machine_id: MachineId = sqlx::query_as(query)
        .bind(&stable_machine_id_string)
        .bind(state_version)
        .bind(sqlx::types::Json(&state))
        .bind(network_config_version)
        .bind(sqlx::types::Json(&network_config))
        .bind(CURRENT_STATE_MODEL_VERSION)
        .bind(asn)
        .bind(version)
        .bind(&metadata.name)
        .bind(&metadata.description)
        .bind(sqlx::types::Json(&metadata.labels))
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

    if machine_id != *stable_machine_id {
        return Err(CarbideError::internal(format!(
            "Mmachine {stable_machine_id} was just created, but database failed to return any rows"
        )));
    }

    let machine = find_one(txn, stable_machine_id, MachineSearchConfig::default())
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "machine",
            id: stable_machine_id.to_string(),
        })?;
    advance(&machine, txn, state, None).await?;
    Ok(machine)
}

// Trigger DPU reprovisioning. For machine assigned to user, needs user approval to start
// reprovisioning.
pub async fn trigger_dpu_reprovisioning_request(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, Postgres>,
    initiator: &str,
    update_firmware: bool,
) -> Result<(), DatabaseError> {
    let reprovision_time = chrono::Utc::now();
    let req = ReprovisionRequest {
        requested_at: reprovision_time,
        initiator: initiator.to_string(),
        update_firmware,
        started_at: None,
        user_approval_received: false,
        restart_reprovision_requested_at: reprovision_time,
    };

    let query = "UPDATE machines SET reprovisioning_requested=$2 WHERE id=$1 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .bind(sqlx::types::Json(req))
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

// Update reprovision start time.
pub async fn update_dpu_reprovision_start_time(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<(), DatabaseError> {
    let current_time = chrono::Utc::now();
    let query = r#"UPDATE machines
                        SET reprovisioning_requested=
                                    jsonb_set(reprovisioning_requested,
                                                '{started_at}', $2, true)
                       WHERE id=$1 RETURNING id"#;
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .bind(sqlx::types::Json(current_time))
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

pub async fn update_host_reprovision_start_time(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<(), DatabaseError> {
    let current_time = chrono::Utc::now();
    let query = r#"UPDATE machines
                        SET host_reprovisioning_requested=
                                    jsonb_set(host_reprovisioning_requested,
                                                '{started_at}', $2, true)
                       WHERE id=$1 RETURNING id"#;
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .bind(sqlx::types::Json(current_time))
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

pub async fn trigger_host_reprovisioning_request(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    initiator: &str,
    machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    let req = HostReprovisionRequest {
        requested_at: chrono::Utc::now(),
        started_at: None,
        initiator: initiator.to_string(),
        user_approval_received: false,
    };

    let query = "UPDATE machines SET host_reprovisioning_requested=$2 WHERE id=$1 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .bind(sqlx::types::Json(req))
        .fetch_one(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

pub async fn clear_host_reprovisioning_request(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    machine_id: &MachineId,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET host_reprovisioning_requested = NULL WHERE id=$1 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .fetch_one(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

pub async fn get_host_reprovisioning_machines(
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<Vec<Machine>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            "{}
                WHERE m.host_reprovisioning_requested IS NOT NULL",
            JSON_MACHINE_SNAPSHOT_QUERY.deref()
        );
    }
    sqlx::query_as(&query)
        .fetch_all(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))
}

pub async fn update_controller_state_outcome(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    machine_id: &MachineId,
    outcome: PersistentStateHandlerOutcome,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET controller_state_outcome=$1 WHERE id=$2";
    sqlx::query(query)
        .bind(sqlx::types::Json(outcome))
        .bind(machine_id.to_string())
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
    Ok(())
}

// Update user's approval status in db.
pub async fn approve_dpu_reprovision_request(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<(), DatabaseError> {
    let query = r#"UPDATE machines
                        SET reprovisioning_requested=
                                    jsonb_set(reprovisioning_requested,
                                                '{user_approval_received}', $2, true)
                       WHERE id=$1 RETURNING id"#;
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .bind(sqlx::types::Json(true))
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

pub async fn approve_host_reprovision_request(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<(), DatabaseError> {
    let query = r#"UPDATE machines
                        SET host_reprovisioning_requested=
                                    jsonb_set(host_reprovisioning_requested,
                                                '{user_approval_received}', $2, true)
                       WHERE id=$1 RETURNING id"#;
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .bind(sqlx::types::Json(true))
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

/// This will reset the dpu_reprov request.
pub async fn restart_dpu_reprovisioning(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    machine_ids: &[&MachineId],
    update_firmware: bool,
) -> Result<(), DatabaseError> {
    let restart_request = ReprovisionRequestRestart {
        update_firmware,
        restart_reprovision_requested_at: chrono::Utc::now(),
    };
    let query = r#"UPDATE machines
                                SET reprovisioning_requested=reprovisioning_requested || $1
                        WHERE id=ANY($2) RETURNING id"#
        .to_string();

    let str_list: Vec<String> = machine_ids.iter().map(|id| id.to_string()).collect();
    let _id = sqlx::query_as::<_, MachineId>(&query)
        .bind(sqlx::types::Json(restart_request))
        .bind(str_list)
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "restart reprovisioning_requested", e))?;

    Ok(())
}

/// This will fail if reprovisioning is already started.
pub async fn clear_dpu_reprovisioning_request(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    machine_id: &MachineId,
    validate_started_time: bool,
) -> Result<(), DatabaseError> {
    let query = r#"UPDATE machines SET reprovisioning_requested=NULL
                        WHERE id=$1 {validate_started} RETURNING id"#
        .to_string();

    let query = if validate_started_time {
        query.replace(
            "{validate_started}",
            "AND reprovisioning_requested->'started_at' = 'null'::jsonb",
        )
    } else {
        query.replace("{validate_started}", "")
    };

    let _id = sqlx::query_as::<_, MachineId>(&query)
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "clear reprovisioning_requested", e))?;

    Ok(())
}

pub async fn list_machines_requested_for_reprovisioning(
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<Vec<Machine>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            "{} WHERE m.reprovisioning_requested IS NOT NULL",
            JSON_MACHINE_SNAPSHOT_QUERY.deref()
        );
    }
    sqlx::query_as(&query)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))
}

pub async fn list_machines_requested_for_host_reprovisioning(
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<Vec<Machine>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            "{} WHERE m.host_reprovisioning_requested IS NOT NULL",
            JSON_MACHINE_SNAPSHOT_QUERY.deref()
        );
    }
    sqlx::query_as(&query)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))
}

/// Apply dpu agent upgrade policy to a single DPU.
/// Returns Ok(true) if it needs upgrading, Ok(false) otherwise.
pub async fn apply_agent_upgrade_policy(
    txn: &mut Transaction<'_, Postgres>,
    policy: AgentUpgradePolicy,
    machine_id: &MachineId,
) -> Result<bool, CarbideError> {
    if policy == AgentUpgradePolicy::Off {
        return Ok(false);
    }
    let machine = find_one(txn, machine_id, MachineSearchConfig::default())
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "dpu_machine",
            id: machine_id.to_string(),
        })?;
    match machine.network_status_observation.as_ref() {
        None => Ok(false),
        Some(obs) => {
            let carbide_api_version = forge_version::v!(build_version);
            if obs.agent_version.is_none() {
                return Ok(false);
            }
            let agent_version = obs.agent_version.as_ref().cloned().unwrap();
            let should_upgrade = policy.should_upgrade(&agent_version, carbide_api_version);
            if should_upgrade != machine.needs_agent_upgrade() {
                set_dpu_agent_upgrade_requested(
                    txn,
                    machine_id,
                    should_upgrade,
                    carbide_api_version,
                )
                .await?;
            }

            Ok(true)
        }
    }
}

pub async fn set_dpu_agent_upgrade_requested(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    should_upgrade: bool,
    to_version: &str,
) -> Result<(), DatabaseError> {
    let decision = UpgradeDecision {
        should_upgrade,
        to_version: to_version.to_string(),
        last_updated: chrono::Utc::now(),
    };
    let query = "UPDATE machines SET dpu_agent_upgrade_requested = $1::json WHERE id = $2";
    sqlx::query(query)
        .bind(sqlx::types::Json(decision))
        .bind(machine_id.to_string())
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
    Ok(())
}

pub async fn find_machine_ids(
    txn: &mut Transaction<'_, Postgres>,
    search_config: MachineSearchConfig,
) -> Result<Vec<MachineId>, DatabaseError> {
    let mut qb = sqlx::QueryBuilder::new("SELECT id FROM machines");
    let mut has_where = false;

    if search_config.only_maintenance {
        qb.push(" WHERE maintenance_reference IS NOT NULL");
        has_where = true;
    }

    if !search_config.include_dpus {
        if has_where {
            qb.push(" AND ");
        } else {
            qb.push(" WHERE ");
        }

        qb.push("NOT starts_with(id, 'fm100d')");
        has_where = true;
    }

    if search_config.exclude_hosts {
        if has_where {
            qb.push(" AND ");
        } else {
            qb.push(" WHERE ");
        }

        qb.push("NOT starts_with(id, 'fm100h')");
        has_where = true;
    }

    if !search_config.include_predicted_host {
        if has_where {
            qb.push(" AND ");
        } else {
            qb.push(" WHERE ");
        }
        qb.push("NOT starts_with(id, 'fm100p')");
    }

    if search_config.for_update {
        qb.push(" FOR UPDATE ");
    }

    let q = qb.build_query_as();
    let machine_ids: Vec<MachineId> = q
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "find_machine_ids", e))?;

    Ok(machine_ids)
}

pub async fn update_state(
    txn: &mut Transaction<'_, Postgres>,
    host_id: &MachineId,
    new_state: ManagedHostState,
) -> Result<(), DatabaseError> {
    let host = find_one(
        txn,
        host_id,
        // TODO(?): Should we be using for_update/row-level locks here?
        // This is a select that's later used for an update on both version
        // and state below with the calls to `advance`.
        crate::db::machine::MachineSearchConfig::default(),
    )
    .await?
    .ok_or_else(|| {
        DatabaseError::new(
            file!(),
            line!(),
            "db::machine::find_one",
            sqlx::Error::RowNotFound,
        )
    })?;

    let version = host.current_version().increment();
    tracing::info!(machine_id = %host.id, ?new_state, "Updating host state");
    advance(&host, txn, new_state.clone(), Some(version)).await?;

    // Keep both host and dpu's states in sync.
    let dpus = find_dpus_by_host_machine_id(txn, host_id).await?;

    for dpu in dpus {
        advance(&dpu, txn, new_state.clone(), Some(version)).await?;
    }
    Ok(())
}

pub async fn update_machine_validation_time(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET last_machine_validation_time=NOW() WHERE id=$1 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}
pub async fn update_machine_validation_id(
    machine_id: &MachineId,
    validation_id: uuid::Uuid,
    context_column_name: String,
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> Result<MachineId, DatabaseError> {
    let base_query = "UPDATE machines SET {column}=$1 WHERE id=$2 RETURNING id".to_owned();
    sqlx::query_as(&base_query.replace("{column}", context_column_name.as_str()))
        .bind(validation_id)
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "UPDATE machines ", e))
}

pub async fn update_failure_details_by_machine_id(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, Postgres>,
    failure: FailureDetails,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET failure_details = $1::json WHERE id = $2 RETURNING id";
    let _id: (MachineId,) = sqlx::query_as(query)
        .bind(sqlx::types::Json(failure))
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

/// Find a list of dpu information
///
/// Returns: `Vec<DpuInfo>` - A list of DPU information of DPU id and loopback Ip addresses
///
/// Arguments
///
/// * `txn` - A reference to currently open database transaction
///
pub async fn find_dpu_ids_and_loopback_ips(
    txn: &mut Transaction<'_, Postgres>,
) -> Result<Vec<DpuInfo>, DatabaseError> {
    // Get all DPU IP addresses except the requester DPU machine
    let query = "
        SELECT id, network_config->>'loopback_ip' AS loopback_ip
        FROM machines
        WHERE network_config->>'loopback_ip' IS NOT NULL";

    let dpu_infos: Vec<DpuInfo> = sqlx::query_as(query)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        .into_iter()
        .map(|(id, loopback_ip)| DpuInfo { id, loopback_ip })
        .collect();

    Ok(dpu_infos)
}

/// Allocate a value from the loopback IP resource pool.
///
/// If the pool exists but is empty or has en error, return that.
pub async fn allocate_loopback_ip(
    common_pools: &CommonPools,
    txn: &mut Transaction<'_, Postgres>,
    owner_id: &str,
) -> Result<Ipv4Addr, CarbideError> {
    match common_pools
        .ethernet
        .pool_loopback_ip
        .allocate(txn, resource_pool::OwnerType::Machine, owner_id)
        .await
    {
        Ok(val) => Ok(val),
        Err(resource_pool::ResourcePoolError::Empty) => {
            tracing::error!(owner_id, pool = "lo-ip", "Pool exhausted, cannot allocate");
            Err(CarbideError::ResourceExhausted("pool lo-ip".to_string()))
        }
        Err(err) => {
            tracing::error!(owner_id, error = %err, pool = "lo-ip", "Error allocating from resource pool");
            Err(err.into())
        }
    }
}

/// Allocate a value from the loopback IP resource pool.
///
/// If the pool exists but is empty or has en error, return that.
pub async fn allocate_vpc_dpu_loopback(
    common_pools: &CommonPools,
    txn: &mut Transaction<'_, Postgres>,
    owner_id: &str,
) -> Result<Ipv4Addr, CarbideError> {
    match common_pools
        .ethernet
        .pool_vpc_dpu_loopback_ip
        .allocate(txn, resource_pool::OwnerType::Machine, owner_id)
        .await
    {
        Ok(val) => Ok(val),
        Err(resource_pool::ResourcePoolError::Empty) => {
            tracing::error!(
                owner_id,
                pool = "vpc-dpu-lo-ip",
                "Pool exhausted, cannot allocate"
            );
            Err(CarbideError::ResourceExhausted(
                "pool vpc-dpu-lo-ip".to_string(),
            ))
        }
        Err(err) => {
            tracing::error!(owner_id, error = %err, pool = "lo-ip", "Error allocating from resource pool");
            Err(err.into())
        }
    }
}

pub async fn find_by_validation_id(
    txn: &mut Transaction<'_, Postgres>,
    validation_id: &Uuid,
) -> Result<Option<Machine>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            r#"{}
                WHERE m.discovery_machine_validation_id = $1
                OR m.cleanup_machine_validation_id = $1
                OR m.on_demand_machine_validation_id = $1"#,
            JSON_MACHINE_SNAPSHOT_QUERY.deref()
        );
    }
    let machine = sqlx::query_as(&query)
        .bind(validation_id)
        .fetch_optional(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))?;

    Ok(machine)
}

/// set_firmware_autoupdate flags a machine ID as explicitly having firmware upgrade enabled or disabled, or use config files if None.
pub async fn set_firmware_autoupdate(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    state: Option<bool>,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET firmware_autoupdate = $1 WHERE id = $2";
    sqlx::query(query)
        .bind(state)
        .bind(machine_id)
        .execute(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
    Ok(())
}

pub async fn set_machine_validation_request(
    txn: &mut sqlx::Transaction<'_, Postgres>,
    machine_id: &MachineId,
    machine_validation_request: bool,
) -> Result<(), DatabaseError> {
    let query =
        "UPDATE machines SET on_demand_machine_validation_request=$2 WHERE id=$1 RETURNING id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id.to_string())
        .bind(machine_validation_request)
        .fetch_one(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

pub async fn update_dpu_asns(
    db_pool: &Pool<Postgres>,
    common_pools: &CommonPools,
) -> Result<(), CarbideError> {
    let mut txn = db_pool
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin agent upgrade policy", e))?;

    if common_pools
        .ethernet
        .pool_fnn_asn
        .stats(db_pool)
        .await?
        .free
        == 0
    {
        tracing::info!(
            "Skipping update of DPU ASNs.  FNN ASN pool not configured or fully allocated"
        );
        return Ok(());
    }
    // Get all DPU IP addresses except the requester DPU machine
    let query = "SELECT id FROM machines WHERE starts_with(id, 'fm100d') AND asn IS NULL";

    let dpu_ids: Vec<MachineId> = sqlx::query_as(query)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    if !dpu_ids.is_empty() {
        tracing::info!(dpu_count = dpu_ids.len(), "Updating missing ASN of DPUs");
    }

    for dpu_machine_id in dpu_ids.iter() {
        let asn: i64 = common_pools
            .ethernet
            .pool_fnn_asn
            .allocate(
                &mut txn,
                resource_pool::OwnerType::Machine,
                &dpu_machine_id.to_string(),
            )
            .await? as i64;

        let query = "UPDATE machines set asn=$1 WHERE id=$2 and asn is null";

        sqlx::query(query)
            .bind(asn)
            .bind(dpu_machine_id)
            .execute(&mut *txn)
            .await
            .map_err(|e: sqlx::Error| DatabaseError::new(file!(), line!(), query, e))?;
    }

    txn.commit()
        .await
        .map_err(|e: sqlx::Error| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(())
}

pub async fn assign_sku(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    sku_id: &str,
) -> Result<MachineId, DatabaseError> {
    let query = "UPDATE machines SET hw_sku=$1 WHERE id=$2 and hw_sku is null RETURNING id";

    let id = sqlx::query_as(query)
        .bind(sku_id)
        .bind(machine_id)
        .fetch_one(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "assign sku to machine", e))?;

    Ok(id)
}

pub async fn unassign_sku(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
) -> Result<MachineId, DatabaseError> {
    let query = "UPDATE machines SET hw_sku=NULL WHERE id=$1 RETURNING id";

    let id = sqlx::query_as(query)
        .bind(machine_id)
        .fetch_one(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "assign sku to machine", e))?;

    Ok(id)
}

pub async fn update_sku_status(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    sku_status: SkuStatus,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machines SET hw_sku_status=$1 WHERE id=$2 RETURNING id";

    let _: () = sqlx::query_as(query)
        .bind(sqlx::types::Json(sku_status))
        .bind(machine_id)
        .fetch_one(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "assign sku to machine", e))?;

    Ok(())
}

#[derive(Debug, Clone, PartialEq)]
pub enum MaintenanceMode {
    Off,
    On { reference: String },
}

#[cfg(test)]
mod test {
    use crate::model::{machine::ManagedHostState, metadata::Metadata};
    use forge_uuid::machine::MachineId;
    use std::str::FromStr;

    #[crate::sqlx_test]

    async fn test_set_firmware_autoupdate(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await.unwrap();
        let id =
            MachineId::from_str("fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30")?;
        super::create(
            &mut txn,
            None,
            &id,
            ManagedHostState::Ready,
            &Metadata::default(),
        )
        .await?;
        super::set_firmware_autoupdate(&mut txn, &id, Some(true)).await?;
        super::set_firmware_autoupdate(&mut txn, &id, None).await?;
        Ok(())
    }
}
