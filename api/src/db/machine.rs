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
use std::net::{IpAddr, Ipv4Addr};
use std::ops::DerefMut;
use std::str::FromStr;

use ::rpc::forge::{self as rpc, DpuInfo};
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use forge_uuid::instance_type::InstanceTypeId;
use health_report::{HealthReport, OverrideMode};
use mac_address::MacAddress;
use serde::Serialize;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Pool, Postgres, Row, Transaction};
use uuid::Uuid;

use super::{DatabaseError, ObjectFilter};
use crate::db;
use crate::db::machine_topology::MachineTopology;
use crate::model::bmc_info::BmcInfo;
use crate::model::controller_outcome::PersistentStateHandlerOutcome;
use crate::model::hardware_info::{HardwareInfo, MachineInventory};
use crate::model::machine::health_override::HealthReportOverrides;
use crate::model::machine::infiniband::MachineInfinibandStatusObservation;
use crate::model::machine::network::{MachineNetworkStatusObservation, ManagedHostNetworkConfig};
use crate::model::machine::upgrade_policy::AgentUpgradePolicy;
use crate::model::machine::{
    CurrentMachineState, FailureDetails, HostReprovisionRequest, MachineInterfaceSnapshot,
    MachineLastRebootRequested, MachineLastRebootRequestedMode, MachineSnapshot,
    MachineStateHistory, ManagedHostState, ReprovisionRequest, UpgradeDecision,
};
use crate::resource_pool::common::CommonPools;
use crate::state_controller::machine::io::CURRENT_STATE_MODEL_VERSION;
use crate::{resource_pool, CarbideError, CarbideResult};
use forge_uuid::machine::{MachineId, MachineType};

/// MachineSearchConfig: Search parameters
#[derive(Default, Debug, Copy, Clone)]
pub struct MachineSearchConfig {
    pub include_dpus: bool,
    pub include_history: bool,
    pub include_predicted_host: bool,
    /// Only include machines in maintenance mode
    pub only_maintenance: bool,
    pub exclude_hosts: bool,
}

impl From<rpc::MachineSearchConfig> for MachineSearchConfig {
    fn from(value: rpc::MachineSearchConfig) -> Self {
        MachineSearchConfig {
            include_dpus: value.include_dpus,
            include_history: value.include_history,
            include_predicted_host: value.include_predicted_host,
            only_maintenance: value.only_maintenance,
            exclude_hosts: value.exclude_hosts,
        }
    }
}

#[derive(Serialize)]
struct ReprovisionRequestRestart {
    pub update_firmware: bool,
    pub restart_reprovision_requested_at: DateTime<Utc>,
}

///
/// A machine is a standalone system that performs network booting via normal DHCP processes.
///
#[derive(Debug, Clone)]
pub struct Machine {
    /// The ID of the machine, this is an internal identifier in the database that's unique for
    /// all machines managed by this instance of carbide.
    id: MachineId,

    /// When this machine record was created
    created: DateTime<Utc>,

    /// When the machine record was last modified
    updated: DateTime<Utc>,

    /// When the machine was last deployed
    _deployed: Option<DateTime<Utc>>,

    /// The current state of the machine.
    state: Versioned<ManagedHostState>,

    /// The current network state of the machine, excluding the tenant related
    /// configuration. The latter will be tracked as part of the InstanceNetworkConfig.
    network_config: Versioned<ManagedHostNetworkConfig>,

    /// The most recent status forge-dpu-agent observed. Tells us if network_config has been
    /// applied yet, and other useful things.
    network_status_observation: Option<MachineNetworkStatusObservation>,

    /// The most recent status of infiniband interfaces.
    infiniband_status_observation: Option<MachineInfinibandStatusObservation>,

    /// A list of [MachineStateHistory] that this machine has experienced
    history: Vec<MachineStateHistory>,

    /// A list of [MachineInterfaceSnapshot]s that this machine owns
    interfaces: Vec<MachineInterfaceSnapshot>,

    /// The Hardware information that was discovered for this machine
    hardware_info: Option<HardwareInfo>,

    /// The BMC info for this machine
    bmc_info: BmcInfo,

    /// URL of the reference tracking this machine's maintenance (e.g. JIRA)
    /// Some(_) means the machine is in maintenance mode.
    /// None means not in maintenance mode.
    maintenance_reference: Option<String>,

    /// What time was this machine set into maintenance mode?
    maintenance_start_time: Option<DateTime<Utc>>,

    /// Last time when machine came up.
    last_reboot_time: Option<DateTime<Utc>>,

    /// Last time when cleanup was performed successfully.
    last_cleanup_time: Option<DateTime<Utc>>,

    /// Last time when discovery finished.
    last_discovery_time: Option<DateTime<Utc>>,

    /// Failure cause. If failure cause is critical, machine will move into Failed state.
    failure_details: FailureDetails,

    /// Last time when machine reprovisioning_requested.
    reprovisioning_requested: Option<ReprovisionRequest>,

    /// Last time when host reprovisioning requested
    host_reprovisioning_requested: Option<HostReprovisionRequest>,

    /// Does the forge-dpu-agent on this DPU need upgrading?
    dpu_agent_upgrade_requested: Option<UpgradeDecision>,

    /// Latest health report received by forge-dpu-agent
    dpu_agent_health_report: Option<HealthReport>,

    /// Latest health report received by hardware-health
    hardware_health_report: Option<HealthReport>,

    /// Latest health report generated by validation tests
    machine_validation_health_report: HealthReport,

    /// Latest health report submitted by site-explorer
    site_explorer_health_report: Option<HealthReport>,

    /// All health report overrides
    health_report_overrides: HealthReportOverrides,

    // Inventory related to a DPU machine as reported by the agent there.
    // Software and versions installed on the machine.
    inventory: Option<MachineInventory>,

    /// Last time when machine reboot was requested.
    /// This field takes care of reboot requested from state machine only.
    last_reboot_requested: Option<MachineLastRebootRequested>,

    /// The result of the last attempt to change state
    controller_state_outcome: Option<PersistentStateHandlerOutcome>,

    // Is the bios password set on the machine
    bios_password_set_time: Option<DateTime<Utc>>,

    /// Last host validation finished.
    last_machine_validation_time: Option<DateTime<Utc>>,

    /// current discovery validation id.
    discovery_machine_validation_id: Option<uuid::Uuid>,

    /// current cleanup validation id.
    cleanup_machine_validation_id: Option<uuid::Uuid>,

    /// Override to enable or disable firmware auto update
    firmware_autoupdate: Option<bool>,

    /// current on demand validation id.
    on_demand_machine_validation_id: Option<uuid::Uuid>,

    on_demand_machine_validation_request: Option<bool>,

    asn: Option<u32>,
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for Machine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state: sqlx::types::Json<ManagedHostState> =
            row.try_get("controller_state")?;

        let stable_string: String = row.try_get("id")?;
        let id = MachineId::from_str(&stable_string).unwrap();

        let network_config: sqlx::types::Json<ManagedHostNetworkConfig> =
            row.try_get("network_config")?;

        let network_status_observation: Option<sqlx::types::Json<MachineNetworkStatusObservation>> =
            row.try_get("network_status_observation")?;
        let network_status_observation = network_status_observation.map(|n| n.0);

        let infiniband_status_observation: Option<
            sqlx::types::Json<MachineInfinibandStatusObservation>,
        > = row.try_get("infiniband_status_observation")?;
        let infiniband_status_observation = infiniband_status_observation.map(|n| n.0);

        let failure_details: sqlx::types::Json<FailureDetails> = row.try_get("failure_details")?;
        let reprovision_req: Option<sqlx::types::Json<ReprovisionRequest>> =
            row.try_get("reprovisioning_requested")?;
        let host_reprovision_req: Option<sqlx::types::Json<HostReprovisionRequest>> =
            row.try_get("host_reprovisioning_requested")?;

        let dpu_agent_health_report = row
            .try_get::<Option<sqlx::types::Json<HealthReport>>, _>("dpu_agent_health_report")?
            .map(|j| j.0);

        let hardware_health_report = row
            .try_get::<Option<sqlx::types::Json<HealthReport>>, _>("hardware_health_report")?
            .map(|j| j.0);

        let machine_validation_health_report = row
            .try_get::<sqlx::types::Json<HealthReport>, _>("machine_validation_health_report")?
            .0;

        let site_explorer_health_report = row
            .try_get::<Option<sqlx::types::Json<HealthReport>>, _>("site_explorer_health_report")?
            .map(|j| j.0);

        let health_report_overrides = row
            .try_get::<Option<sqlx::types::Json<HealthReportOverrides>>, _>(
                "health_report_overrides",
            )?
            .map(|os| os.0)
            .unwrap_or_default();

        let dpu_agent_upgrade_requested: Option<sqlx::types::Json<UpgradeDecision>> =
            row.try_get("dpu_agent_upgrade_requested")?;
        let last_reboot_requested: Option<sqlx::types::Json<MachineLastRebootRequested>> =
            row.try_get("last_reboot_requested")?;

        let machine_inventory: Option<sqlx::types::Json<MachineInventory>> =
            row.try_get("agent_reported_inventory")?;

        let state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome")?;

        let asn: Option<u32> = row.try_get::<Option<i64>, _>("asn")?.map(|v| v as u32);

        Ok(Machine {
            id,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            _deployed: row.try_get("deployed")?,
            state: Versioned::new(controller_state.0, row.try_get("controller_state_version")?),
            network_config: Versioned::new(
                network_config.0,
                row.try_get("network_config_version")?,
            ),
            network_status_observation,
            infiniband_status_observation,
            history: Vec::new(),
            interfaces: Vec::new(),
            hardware_info: None,
            bmc_info: BmcInfo {
                ip: None,
                port: None,
                mac: None,
                version: None,
                firmware_version: None,
            },
            maintenance_reference: row.try_get("maintenance_reference")?,
            maintenance_start_time: row.try_get("maintenance_start_time")?,
            last_reboot_time: row.try_get("last_reboot_time")?,
            last_reboot_requested: last_reboot_requested.map(|x| x.0),
            last_cleanup_time: row.try_get("last_cleanup_time")?,
            last_discovery_time: row.try_get("last_discovery_time")?,
            failure_details: failure_details.0,
            reprovisioning_requested: reprovision_req.map(|x| x.0),
            host_reprovisioning_requested: host_reprovision_req.map(|x| x.0),
            dpu_agent_health_report,
            hardware_health_report,
            machine_validation_health_report,
            site_explorer_health_report,
            health_report_overrides,
            dpu_agent_upgrade_requested: dpu_agent_upgrade_requested.map(|x| x.0),
            inventory: machine_inventory.map(|x| x.0),
            controller_state_outcome: state_outcome.map(|x| x.0),
            bios_password_set_time: row.try_get("bios_password_set_time")?,
            last_machine_validation_time: row.try_get("last_machine_validation_time")?,
            discovery_machine_validation_id: row.try_get("discovery_machine_validation_id")?,
            cleanup_machine_validation_id: row.try_get("cleanup_machine_validation_id")?,
            firmware_autoupdate: row.try_get("firmware_autoupdate")?,
            on_demand_machine_validation_id: row.try_get("on_demand_machine_validation_id")?,
            on_demand_machine_validation_request: row
                .try_get("on_demand_machine_validation_request")?,
            asn,
        })
    }
}

impl From<Machine> for MachineSnapshot {
    fn from(machine: Machine) -> Self {
        MachineSnapshot {
            machine_id: machine.id().clone(),
            bmc_info: machine.bmc_info().clone(),
            bmc_vendor: machine.bmc_vendor(),
            hardware_info: machine.hardware_info().cloned(),
            agent_reported_inventory: machine.inventory().cloned().unwrap_or_default(),
            network_config: machine.network_config().clone(),
            interfaces: machine.interfaces().clone(),
            network_status_observation: machine.network_status_observation().cloned(),
            infiniband_status_observation: machine.infiniband_status_observation().cloned(),
            current: CurrentMachineState {
                state: machine.current_state(),
                version: machine.current_version(),
                outcome: machine.controller_state_outcome.clone(),
            },
            last_discovery_time: machine.last_discovery_time(),
            last_reboot_time: machine.last_reboot_time(),
            last_cleanup_time: machine.last_cleanup_time(),
            maintenance_reference: machine.maintenance_reference(),
            maintenance_start_time: machine.maintenance_start_time(),
            failure_details: machine.failure_details(),
            reprovision_requested: machine.reprovisioning_requested(),
            last_reboot_requested: machine.last_reboot_requested(),
            bios_password_set_time: machine.bios_password_set_time(),
            last_machine_validation_time: machine.last_machine_validation_time(),
            discovery_machine_validation_id: machine.discovery_machine_validation_id(),
            cleanup_machine_validation_id: machine.cleanup_machine_validation_id(),
            on_demand_machine_validation_id: machine.on_demand_machine_validation_id(),
            on_demand_machine_validation_request: machine.on_demand_machine_validation_request(),
            reprovisioning_requested: machine.reprovisioning_requested().clone(),
            host_reprovision_requested: machine.host_reprovisioning_requested().clone(),
            dpu_agent_health_report: machine.dpu_agent_health_report,
            site_explorer_health_report: machine.site_explorer_health_report,
            firmware_autoupdate: machine.firmware_autoupdate,
            hardware_health_report: machine.hardware_health_report,
            machine_validation_health_report: machine.machine_validation_health_report,
            history: machine.history.into_iter().map(Into::into).collect(),
            health_report_overrides: machine.health_report_overrides,
            asn: machine.asn,
        }
    }
}

impl Machine {
    /// Returns whether the Machine is a DPU, based on the HardwareInfo that
    /// was available when the Machine was discovered
    pub fn is_dpu(&self) -> bool {
        self.id.machine_type().is_dpu()
    }

    /// BMC related information
    pub fn bmc_info(&self) -> &BmcInfo {
        &self.bmc_info
    }

    pub fn bmc_vendor(&self) -> bmc_vendor::BMCVendor {
        match self.hardware_info() {
            Some(hw) => hw.bmc_vendor(),
            None => bmc_vendor::BMCVendor::Unknown,
        }
    }

    pub fn model(&self) -> String {
        match self.hardware_info() {
            Some(hw) => hw.model().unwrap_or("Unknown".to_string()),
            None => "Unknown".to_string(),
        }
    }

    pub fn inventory(&self) -> Option<&MachineInventory> {
        self.inventory.as_ref()
    }

    /// Hardware information
    pub fn hardware_info(&self) -> Option<&HardwareInfo> {
        self.hardware_info.as_ref()
    }

    /// The current network state of the machine, excluding the tenant related
    /// configuration. The latter will be tracked as part of the InstanceNetworkConfig.
    pub fn network_config(&self) -> &Versioned<ManagedHostNetworkConfig> {
        &self.network_config
    }

    /// Returns failure cause of machine.
    pub fn failure_details(&self) -> FailureDetails {
        self.failure_details.clone()
    }

    /// Returns the HealthReport submitted by forge-dpu-agent
    pub fn dpu_agent_health_report(&self) -> Option<&HealthReport> {
        self.dpu_agent_health_report.as_ref()
    }

    /// Returns the HealthReport submitted by hardware health
    pub fn hardware_health_report(&self) -> Option<&HealthReport> {
        self.hardware_health_report.as_ref()
    }

    /// Returns the HealthReport created by Machine Validation
    pub fn machine_validation_health_report(&self) -> &HealthReport {
        &self.machine_validation_health_report
    }

    /// Returns the HealthReport submitted by Site Explorer
    pub fn site_explorer_health_report(&self) -> Option<&HealthReport> {
        self.site_explorer_health_report.as_ref()
    }

    /// Returns the HealthReport overrides
    pub fn health_report_overrides(&self) -> &HealthReportOverrides {
        &self.health_report_overrides
    }

    /// Actual network info from machine
    pub fn network_status_observation(&self) -> Option<&MachineNetworkStatusObservation> {
        self.network_status_observation.as_ref()
    }

    /// Actual infiniband info from machine
    pub fn infiniband_status_observation(&self) -> Option<&MachineInfinibandStatusObservation> {
        self.infiniband_status_observation.as_ref()
    }

    pub fn loopback_ip(&self) -> Option<Ipv4Addr> {
        self.network_config().loopback_ip
    }

    pub fn use_admin_network(&self) -> bool {
        self.network_config().use_admin_network.unwrap_or(true)
    }

    /// Does the forge-dpu-agent on this DPU need upgrading?
    pub fn needs_agent_upgrade(&self) -> bool {
        self.dpu_agent_upgrade_requested
            .as_ref()
            .map(|d| d.should_upgrade)
            .unwrap_or(false)
    }

    pub fn asn(&self) -> Option<u32> {
        self.asn
    }

    pub async fn exists(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> Result<bool, DatabaseError> {
        let machine =
            Machine::find_one(&mut *txn, machine_id, MachineSearchConfig::default()).await?;
        match machine {
            None => Ok(false),
            Some(_) => Ok(true),
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
    ) -> CarbideResult<Self> {
        let existing_machine =
            Machine::find_one(&mut *txn, stable_machine_id, MachineSearchConfig::default()).await?;
        if interface.machine_id.is_some() {
            let machine_id = interface.machine_id.as_ref().unwrap();
            if machine_id != stable_machine_id {
                return Err(CarbideError::internal(format!(
                    "Database inconsistency: MachineId {} on interface {} does not match stable machine ID {} which now uses this interface",
                    machine_id, interface.id,
                    stable_machine_id)));
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
            db::machine_interface::associate_interface_with_machine(
                &interface.id,
                &machine.id,
                txn,
            )
            .await?;
            Ok(machine)
        } else {
            // Old manual discovery path.
            // Host and DPU machines are created in same `discover_machine` call. Update same
            // state in both machines.
            let state = ManagedHostState::Created;
            let machine = Self::create(txn, common_pools, stable_machine_id, state).await?;
            db::machine_interface::associate_interface_with_machine(
                &interface.id,
                &machine.id,
                txn,
            )
            .await?;
            Ok(machine)
        }
    }

    pub async fn find_one(
        txn: &mut Transaction<'_, Postgres>,
        id: &MachineId,
        search_config: MachineSearchConfig,
    ) -> Result<Option<Self>, DatabaseError> {
        Ok(
            Machine::find(txn, ObjectFilter::One(id.clone()), search_config)
                .await?
                .pop(),
        )
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

    /// Returns the ID of the machine object
    pub fn id(&self) -> &MachineId {
        &self.id
    }

    /// Returns the std::time::SystemTime for when the machine was initially discovered
    pub fn created(&self) -> chrono::DateTime<Utc> {
        self.created
    }

    /// Returns the std::time::SystemTime for when the machine was last updated
    pub fn updated(&self) -> chrono::DateTime<Utc> {
        self.updated
    }

    /// Returns the list of History Events the machine has experienced
    pub fn history(&self) -> &Vec<MachineStateHistory> {
        &self.history
    }

    /// Returns the list of Interfaces this machine owns
    /// Includes the admin interface.
    pub fn interfaces(&self) -> &Vec<MachineInterfaceSnapshot> {
        &self.interfaces
    }

    /// Return the current state of the machine.
    pub fn current_state(&self) -> ManagedHostState {
        self.state.value.clone()
    }

    /// The result of the last state controller iteration, if any
    pub fn current_state_iteration_outcome(&self) -> Option<PersistentStateHandlerOutcome> {
        self.controller_state_outcome.clone()
    }

    /// Return the current version of state of the machine.
    pub fn current_version(&self) -> ConfigVersion {
        self.state.version
    }

    /// Does this host have an instance assigned to it?
    pub fn has_instance(&self) -> bool {
        matches!(self.state.value, ManagedHostState::Assigned { .. })
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
        &self,
        txn: &mut Transaction<'_, Postgres>,
        state: ManagedHostState,
        version: Option<ConfigVersion>,
    ) -> Result<bool, DatabaseError> {
        // Get current version
        let version = version.unwrap_or_else(|| self.state.version.increment());

        // Store history of machine state changes.
        db::machine_state_history::persist(txn, self.id(), state.clone(), version).await?;

        let _id: (String,) = sqlx::query_as(
            "UPDATE machines SET controller_state_version=$1, controller_state=$2 WHERE id=$3 RETURNING id",
        )
        .bind(version)
        .bind(sqlx::types::Json(state))
        .bind(self.id().to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "update machines state", e))?;

        Ok(true)
    }

    /// Find machines given a set of criteria, right now just returns all machines because there's
    /// no way to filter the machines.
    ///
    /// TODO(ajf): write a query language???
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    ///
    pub async fn find(
        txn: &mut Transaction<'_, Postgres>,
        filter: ObjectFilter<'_, MachineId>,
        search_config: MachineSearchConfig,
    ) -> Result<Vec<Machine>, DatabaseError> {
        let base_query = "SELECT * FROM machines m {where} GROUP BY m.id".to_owned();

        let mut all_machines: Vec<Machine> = match filter {
            ObjectFilter::All => {
                let where_clause = if search_config.only_maintenance {
                    "WHERE maintenance_reference IS NOT NULL"
                } else {
                    ""
                };
                sqlx::query_as(&base_query.replace("{where}", where_clause))
                    .fetch_all(txn.deref_mut())
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "machines All", e))?
            }
            ObjectFilter::One(id) => {
                let mut where_clause = "WHERE m.id=$1".to_string();
                if search_config.only_maintenance {
                    where_clause += " AND maintenance_reference IS NOT NULL";
                }
                sqlx::query_as(&base_query.replace("{where}", &where_clause))
                    .bind(id.to_string())
                    .fetch_all(txn.deref_mut())
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "machines One", e))?
            }
            ObjectFilter::List(list) => {
                let mut where_clause = "WHERE m.id=ANY($1)".to_string();
                if search_config.only_maintenance {
                    where_clause += " AND maintenance_reference IS NOT NULL";
                }
                let str_list: Vec<String> = list.iter().map(|id| id.to_string()).collect();
                sqlx::query_as(&base_query.replace("{where}", &where_clause))
                    .bind(str_list)
                    .fetch_all(txn.deref_mut())
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "machines List", e))?
            }
        };

        // If we didn't find anything, we don't have to invest more queries for
        // fetching related data
        if all_machines.is_empty() {
            return Ok(all_machines);
        }

        let all_ids = all_machines
            .iter()
            .map(|m| m.id.clone())
            .collect::<Vec<MachineId>>();

        let mut history_for_machine = if search_config.include_history {
            db::machine_state_history::find_by_machine_ids(&mut *txn, &all_ids).await?
        } else {
            HashMap::new()
        };

        let mut interfaces_for_machine =
            db::machine_interface::find_by_machine_ids(&mut *txn, &all_ids).await?;

        let topologies_for_machine =
            MachineTopology::find_latest_by_machine_ids(&mut *txn, &all_ids).await?;

        for machine in all_machines.iter_mut() {
            if search_config.include_history {
                if let Some(history) = history_for_machine.remove(&machine.id) {
                    machine.history = history;
                }
            }

            if let Some(interfaces) = interfaces_for_machine.remove(&machine.id) {
                machine.interfaces = interfaces;
            }

            if let Some(topo) = topologies_for_machine.get(&machine.id) {
                machine.hardware_info = Some(topo.topology().discovery_data.info.clone());
                machine.bmc_info = topo.topology().bmc_info.clone();
                if machine.bmc_info.ip.is_some() && machine.bmc_info.mac.is_none() {
                    // In older versions of Forge, host machines never had their BMC mac addresses set in machine_topologies
                    // Set the mac address of the host BMC in the machine_topologies table here

                    // the conversion from carbide error to db error is not elegant.
                    // but, this code is to handle legacy hosts who did not have their mac address setup
                    // TODO (spyda): remove this once we've handled all the legacy hosts
                    db::bmc_metadata::enrich_mac_address(
                        &mut machine.bmc_info,
                        "Machine::find".to_string(),
                        txn,
                        &machine.id,
                        true,
                    )
                    .await
                    .map_err(|e| {
                        DatabaseError::new(
                            file!(),
                            line!(),
                            "enrich_mac_address",
                            sqlx::Error::Protocol(e.to_string()),
                        )
                    })?;
                }
            }

            if !machine.id().machine_type().is_predicted_host() && machine.hardware_info.is_none() {
                tracing::warn!(
                    machine_id = %machine.id,
                    "Machine has no associated discovery data",
                );
            }
        }

        Ok(all_machines)
    }

    async fn load_related_data(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let history = db::machine_state_history::for_machine(&mut *txn, &self.id).await?;
        if !history.is_empty() {
            self.history = history;
        }

        let mut interfaces =
            db::machine_interface::find_by_machine_ids(&mut *txn, &[self.id.clone()]).await?;
        if let Some(interfaces) = interfaces.remove(&self.id) {
            self.interfaces = interfaces;
        }

        let mut topologies =
            MachineTopology::find_latest_by_machine_ids(&mut *txn, &[self.id.clone()]).await?;
        if let Some(topology) = topologies.remove(&self.id) {
            self.hardware_info = Some(topology.topology().discovery_data.info.clone());
            self.bmc_info = topology.topology().bmc_info.clone();
        }

        Ok(())
    }

    pub async fn find_by_ip(
        txn: &mut Transaction<'_, Postgres>,
        ip: &Ipv4Addr,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = r#"SELECT m.* FROM machines m
            JOIN machine_interfaces mi ON m.id = mi.machine_id
            INNER JOIN machine_interface_addresses mia on mia.interface_id=mi.id
            WHERE mia.address = $1::inet"#;
        let machine: Option<Self> = sqlx::query_as(query)
            .bind(ip.to_string())
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        let mut machine = match machine {
            Some(machine) => machine,
            None => return Ok(None),
        };

        machine.load_related_data(txn).await?;
        Ok(Some(machine))
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
        let query =
            "UPDATE machines SET instance_type_id=$1::varchar WHERE id = ANY($2) RETURNING id";

        sqlx::query_as(query)
            .bind(instance_type_id)
            .bind(machine_ids)
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    /// Removes a machine's association with an InstanceType.
    ///
    /// * `txn`        - A reference to an active DB transaction
    /// * `machine_id` - A reference to a machine ID to update
    pub async fn remove_instance_type_association(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> Result<MachineId, DatabaseError> {
        let query = "UPDATE machines SET instance_type_id=NULL WHERE id = $1::varchar RETURNING id";

        sqlx::query_as(query)
            .bind(machine_id)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_hostname(
        txn: &mut Transaction<'_, Postgres>,
        hostname: &str,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = r#"SELECT m.* FROM machines m
            JOIN machine_interfaces mi ON m.id = mi.machine_id
            WHERE mi.hostname = $1"#;
        let machine: Option<Self> = sqlx::query_as(query)
            .bind(hostname)
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        let mut machine = match machine {
            Some(machine) => machine,
            None => return Ok(None),
        };

        machine.load_related_data(txn).await?;
        Ok(Some(machine))
    }

    pub async fn find_by_mac_address(
        txn: &mut Transaction<'_, Postgres>,
        mac_address: &MacAddress,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = r#"SELECT m.* FROM machines m
            JOIN machine_interfaces mi ON m.id = mi.machine_id
            WHERE mi.mac_address = $1::macaddr"#;
        let machine: Option<Self> = sqlx::query_as(query)
            .bind(mac_address)
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        let mut machine = match machine {
            Some(machine) => machine,
            None => return Ok(None),
        };

        machine.load_related_data(txn).await?;
        Ok(Some(machine))
    }

    pub async fn find_by_loopback_ip(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        loopback_ip: &str,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = "SELECT * FROM machines WHERE network_config->>'loopback_ip' = $1";
        let machine: Option<Self> = sqlx::query_as(query)
            .bind(loopback_ip)
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        let mut machine = match machine {
            Some(machine) => machine,
            None => return Ok(None),
        };
        machine.load_related_data(txn).await?;
        Ok(Some(machine))
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
    ) -> Result<Option<Self>, DatabaseError> {
        if let Ok(id) = MachineId::from_str(query) {
            return Self::find_one(txn, &id, MachineSearchConfig::default()).await;
        }

        if let Ok(ip) = Ipv4Addr::from_str(query) {
            return Self::find_by_ip(txn, &ip).await;
        }

        if let Ok(mac) = MacAddress::from_str(query) {
            return Self::find_by_mac_address(txn, &mac).await;
        }

        Self::find_by_hostname(txn, query).await
    }

    pub fn is_maintenance_mode(&self) -> bool {
        self.maintenance_reference.is_some()
    }

    pub fn maintenance_reference(&self) -> Option<String> {
        self.maintenance_reference.clone()
    }

    pub fn maintenance_start_time(&self) -> Option<DateTime<Utc>> {
        self.maintenance_start_time
    }

    pub fn last_reboot_time(&self) -> Option<DateTime<Utc>> {
        self.last_reboot_time
    }

    pub fn last_reboot_requested(&self) -> Option<MachineLastRebootRequested> {
        self.last_reboot_requested.clone()
    }

    pub fn last_cleanup_time(&self) -> Option<DateTime<Utc>> {
        self.last_cleanup_time
    }

    pub fn last_discovery_time(&self) -> Option<DateTime<Utc>> {
        self.last_discovery_time
    }

    pub fn reprovisioning_requested(&self) -> Option<ReprovisionRequest> {
        self.reprovisioning_requested.clone()
    }

    pub fn host_reprovisioning_requested(&self) -> Option<HostReprovisionRequest> {
        self.host_reprovisioning_requested.clone()
    }

    pub fn bios_password_set_time(&self) -> Option<DateTime<Utc>> {
        self.bios_password_set_time
    }

    pub fn last_machine_validation_time(&self) -> Option<DateTime<Utc>> {
        self.last_machine_validation_time
    }

    pub fn discovery_machine_validation_id(&self) -> Option<uuid::Uuid> {
        self.discovery_machine_validation_id
    }

    pub fn cleanup_machine_validation_id(&self) -> Option<uuid::Uuid> {
        self.cleanup_machine_validation_id
    }

    pub fn firmware_autoupdate(&self) -> Option<bool> {
        self.firmware_autoupdate
    }

    pub fn on_demand_machine_validation_id(&self) -> Option<uuid::Uuid> {
        self.on_demand_machine_validation_id
    }

    pub fn on_demand_machine_validation_request(&self) -> Option<bool> {
        self.on_demand_machine_validation_request
    }

    pub async fn update_reboot_time(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE machines SET last_reboot_time=NOW() WHERE id=$1 RETURNING id";
        let _id = sqlx::query_as::<_, MachineId>(query)
            .bind(self.id().to_string())
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
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE machines SET last_cleanup_time=NOW() WHERE id=$1 RETURNING id";
        let _id = sqlx::query_as::<_, MachineId>(query)
            .bind(self.id().to_string())
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
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE machines SET last_discovery_time=NOW() WHERE id=$1 RETURNING id";
        let _id = sqlx::query_as::<_, MachineId>(query)
            .bind(self.id().to_string())
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    pub async fn find_host_machine_id_by_dpu_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        dpu_machine_id: &MachineId,
    ) -> Result<Option<MachineId>, DatabaseError> {
        let query = r#"SELECT machine_id FROM machine_interfaces
                WHERE attached_dpu_machine_id=$1
                AND attached_dpu_machine_id != machine_id"#;

        let machine_id: Option<MachineId> = sqlx::query_as(query)
            .bind(dpu_machine_id.to_string())
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(machine_id)
    }

    pub async fn find_host_by_dpu_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        dpu_machine_id: &MachineId,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = r#"SELECT m.* From machines m
                INNER JOIN machine_interfaces mi
                  ON m.id = mi.machine_id
                WHERE mi.attached_dpu_machine_id=$1
                    AND mi.attached_dpu_machine_id != mi.machine_id"#;
        let machine: Option<Self> = sqlx::query_as(query)
            .bind(dpu_machine_id.to_string())
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        let mut machine = match machine {
            Some(machine) => machine,
            None => return Ok(None),
        };

        machine.load_related_data(txn).await?;

        Ok(Some(machine))
    }

    pub async fn find_dpus_by_host_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        host_machine_id: &MachineId,
    ) -> Result<Vec<Self>, DatabaseError> {
        let query = r#"SELECT m.* From machines m
                INNER JOIN machine_interfaces mi
                  ON m.id = mi.attached_dpu_machine_id
                WHERE mi.machine_id=$1"#;
        let mut machines: Vec<Self> = sqlx::query_as(query)
            .bind(host_machine_id.to_string())
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        for m in &mut machines {
            m.load_related_data(txn).await?;
        }

        Ok(machines)
    }

    pub async fn find_dpu_machine_ids_by_host_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        host_machine_id: &MachineId,
    ) -> Result<Vec<MachineId>, DatabaseError> {
        let query = r#"SELECT m.id From machines m
                INNER JOIN machine_interfaces mi
                  ON m.id = mi.attached_dpu_machine_id
                WHERE mi.machine_id=$1"#;

        let machine_ids: Vec<MachineId> = sqlx::query_as(query)
            .bind(host_machine_id.to_string())
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(machine_ids)
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
        Self::update_health_report(txn, machine_id, "dpu_agent_health_report", health_report).await
    }

    pub async fn update_hardware_health_report(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        health_report: &HealthReport,
    ) -> Result<(), DatabaseError> {
        Self::update_health_report(txn, machine_id, "hardware_health_report", health_report).await
    }

    pub async fn update_machine_validation_health_report(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        health_report: &HealthReport,
    ) -> Result<(), DatabaseError> {
        Self::update_health_report(
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
        Self::update_health_report(
            txn,
            machine_id,
            "site_explorer_health_report",
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
            .map_err(|e| {
                DatabaseError::new(file!(), line!(), "insert health report override", e)
            })?;

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
            .map_err(|e| {
                DatabaseError::new(file!(), line!(), "remove health report override", e)
            })?;

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

    /// Returns the MachineType based on hardware info.
    pub fn machine_type(&self) -> MachineType {
        self.id.machine_type()
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
    ) -> Result<Self, CarbideError> {
        let Some(current_machine_id) = current_machine_id else {
            return Err(CarbideError::NotFoundError {
                kind: "machine_id",
                id: stable_machine_id.to_string(),
            });
        };

        // This is repeated call. Machine is already updated with stable ID.
        if !current_machine_id.machine_type().is_predicted_host() {
            return match Self::find_one(txn, current_machine_id, MachineSearchConfig::default())
                .await?
            {
                Some(machine) => Ok(machine),
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
        let query = "UPDATE machines SET id=$1 WHERE id=$2 RETURNING *";
        Ok(sqlx::query_as(query)
            .bind(stable_machine_id.to_string())
            .bind(current_machine_id.to_string())
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?)
    }

    pub async fn update_failure_details(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        failure: FailureDetails,
    ) -> Result<(), DatabaseError> {
        Machine::update_failure_details_by_machine_id(&self.id, txn, failure).await
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
        match mode {
            MaintenanceMode::On { reference } => {
                let query = "UPDATE machines SET maintenance_reference=$1, maintenance_start_time=NOW() WHERE id=$2";
                sqlx::query(query)
                    .bind(reference)
                    .bind(machine_id.to_string())
                    .execute(txn.deref_mut())
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
            }
            MaintenanceMode::Off => {
                let query = "UPDATE machines SET maintenance_reference=NULL, maintenance_start_time=NULL WHERE id=$1";
                sqlx::query(query)
                    .bind(machine_id.to_string())
                    .execute(txn.deref_mut())
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
            }
        }
        Ok(())
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        common_pools: Option<&CommonPools>,
        stable_machine_id: &MachineId,
        state: ManagedHostState,
    ) -> CarbideResult<Self> {
        let stable_machine_id_string = stable_machine_id.to_string();
        // Host and DPU machines are created in same `discover_machine` call. Update same
        // state in both machines.
        let state_version = ConfigVersion::initial();

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

        let query = r#"INSERT INTO machines(id, controller_state_version, controller_state, network_config_version, network_config, machine_state_model_version, asn) 
                                VALUES($1, $2, $3, $4, $5, $6, $7) RETURNING id"#;
        let machine_id: MachineId = sqlx::query_as(query)
            .bind(&stable_machine_id_string)
            .bind(state_version)
            .bind(sqlx::types::Json(&state))
            .bind(network_config_version)
            .bind(sqlx::types::Json(&network_config))
            .bind(CURRENT_STATE_MODEL_VERSION)
            .bind(asn)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        if machine_id != *stable_machine_id {
            return Err(CarbideError::internal(
                format!("Mmachine {stable_machine_id} was just created, but database failed to return any rows")
            ));
        }

        let machine = Machine::find_one(txn, stable_machine_id, MachineSearchConfig::default())
            .await?
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "machine",
                id: stable_machine_id.to_string(),
            })?;
        machine.advance(txn, state, None).await?;
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

    pub async fn trigger_host_reprovisioning_request(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> Result<(), DatabaseError> {
        let req = HostReprovisionRequest {
            requested_at: chrono::Utc::now(),
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
        let query =
            "UPDATE machines SET host_reprovisioning_requested = NULL WHERE id=$1 RETURNING id";
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
        let query = "SELECT * FROM machines
            WHERE host_reprovisioning_requested IS NOT NULL";
        sqlx::query_as(query)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
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
            .map_err(|e| {
                DatabaseError::new(file!(), line!(), "restart reprovisioning_requested", e)
            })?;

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
            .map_err(|e| {
                DatabaseError::new(file!(), line!(), "clear reprovisioning_requested", e)
            })?;

        Ok(())
    }

    pub async fn list_machines_requested_for_reprovisioning(
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<Vec<Self>, DatabaseError> {
        let query = "SELECT * FROM machines WHERE reprovisioning_requested IS NOT NULL";
        sqlx::query_as(query)
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
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
        let machine = Machine::find_one(txn, machine_id, MachineSearchConfig::default())
            .await?
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "dpu_machine",
                id: machine_id.to_string(),
            })?;
        match machine.network_status_observation() {
            None => Ok(false),
            Some(obs) => {
                let carbide_api_version = forge_version::v!(build_version);
                if obs.agent_version.is_none() {
                    return Ok(false);
                }
                let agent_version = obs.agent_version.as_ref().cloned().unwrap();
                let should_upgrade = policy.should_upgrade(&agent_version, carbide_api_version);
                if should_upgrade != machine.needs_agent_upgrade() {
                    Machine::set_dpu_agent_upgrade_requested(
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

        let q = qb.build_query_as();
        let machine_ids: Vec<MachineId> = q
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "find_machine_ids", e))?;

        Ok(machine_ids)
    }

    pub async fn get_host_machine_ids_for_state_model_version(
        txn: &mut Transaction<'_, Postgres>,
        version: i16,
    ) -> Result<Vec<MachineId>, CarbideError> {
        let query = r#"SELECT id FROM machines WHERE 
                               (starts_with(id, 'fm100h') OR starts_with(id, 'fm100p')) 
                               AND machine_state_model_version=$1"#;
        let machine_ids: Vec<MachineId> = sqlx::query_as(query)
            .bind(version)
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| {
                DatabaseError::new(
                    file!(),
                    line!(),
                    "get_host_machine_ids_with_model_version",
                    e,
                )
            })?;

        Ok(machine_ids)
    }

    pub async fn update_state(
        txn: &mut Transaction<'_, Postgres>,
        host_id: &MachineId,
        new_state: ManagedHostState,
    ) -> Result<(), DatabaseError> {
        let host = Machine::find_one(
            txn,
            host_id,
            crate::db::machine::MachineSearchConfig::default(),
        )
        .await?
        .ok_or_else(|| {
            DatabaseError::new(
                file!(),
                line!(),
                "Machine::find_one",
                sqlx::Error::RowNotFound,
            )
        })?;

        let version = host.current_version().increment();
        tracing::info!(machine_id = %host.id(), ?new_state, "Updating host state");
        host.advance(txn, new_state.clone(), Some(version)).await?;

        // Keep both host and dpu's states in sync.
        let dpus = Machine::find_dpus_by_host_machine_id(txn, host_id).await?;

        for dpu in dpus {
            dpu.advance(txn, new_state.clone(), Some(version)).await?;
        }
        Ok(())
    }

    pub async fn update_state_with_state_model_version_update(
        txn: &mut Transaction<'_, Postgres>,
        host_id: &MachineId,
        dpu_ids: &[MachineId],
        new_state: ManagedHostState,
        state_model_version: i16,
    ) -> CarbideResult<()> {
        tracing::info!(machine_id = %host_id, %new_state, "Updating host state (no version update, state model version update)");
        // Keep both host and dpus's states in sync.

        let all_machines = {
            let mut all = dpu_ids.to_vec();
            all.push(host_id.clone());
            all
        };

        let ids: Vec<(String,)> =
            sqlx::query_as("UPDATE machines SET controller_state=$1, machine_state_model_version=$2 WHERE id=ANY($3) RETURNING id")
                .bind(sqlx::types::Json(new_state))
                .bind(state_model_version)
                .bind(all_machines.clone())
                .fetch_all(txn.deref_mut())
                .await
                .map_err(|e| {
                    DatabaseError::new(file!(), line!(), "update machines state no version", e)
                })?;

        if ids.len() != all_machines.len() {
            return Err(CarbideError::internal(format!(
                "Expected updates: {:?}, Actual updates: {:?}",
                all_machines, ids,
            )));
        }

        Ok(())
    }

    pub async fn update_machine_validation_time(
        machine_id: &MachineId,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query =
            "UPDATE machines SET last_machine_validation_time=NOW() WHERE id=$1 RETURNING id";
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
    ) -> Result<(), DatabaseError> {
        let base_query = "UPDATE machines SET {column}=$1 WHERE id=$2 RETURNING *".to_owned();
        // let query = base_query.replace("{column}", context_column_name.as_str());
        let _id = sqlx::query_as::<_, Self>(
            &base_query.replace("{column}", context_column_name.as_str()),
        )
        .bind(validation_id)
        .bind(machine_id.to_string())
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "UPDATE machines ", e))?;

        Ok(())
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
    pub async fn find_by_validation_id(
        txn: &mut Transaction<'_, Postgres>,
        validation_id: &Uuid,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = r#"SELECT * FROM machines 
            WHERE discovery_machine_validation_id = $1 OR cleanup_machine_validation_id = $1 OR on_demand_machine_validation_id = $1"#;
        let machine: Option<Self> = sqlx::query_as(query)
            .bind(validation_id)
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        let mut machine = match machine {
            Some(machine) => machine,
            None => return Ok(None),
        };

        machine.load_related_data(txn).await?;
        Ok(Some(machine))
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

#[derive(Debug, Clone, PartialEq)]
pub enum MaintenanceMode {
    Off,
    On { reference: String },
}

#[cfg(test)]
mod test {
    use super::Machine;
    use crate::model::machine::ManagedHostState;
    use forge_uuid::machine::MachineId;
    use std::str::FromStr;

    #[crate::sqlx_test]

    async fn test_set_firmware_autoupdate(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await.unwrap();
        let id =
            MachineId::from_str("fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30")?;
        Machine::create(&mut txn, None, &id, ManagedHostState::Ready).await?;
        Machine::set_firmware_autoupdate(&mut txn, &id, Some(true)).await?;
        Machine::set_firmware_autoupdate(&mut txn, &id, None).await?;
        Ok(())
    }
}
