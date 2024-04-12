/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::str::FromStr;

use ::rpc::forge as rpc;
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use mac_address::MacAddress;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

use super::{DatabaseError, ObjectFilter};
use crate::db::machine_interface::MachineInterface;
use crate::db::machine_state_history::MachineStateHistory;
use crate::db::machine_topology::MachineTopology;
use crate::human_hash;
use crate::model::bmc_info::BmcInfo;
use crate::model::hardware_info::{BMCVendor, HardwareInfo, MachineInventory};
use crate::model::machine::machine_id::MachineId;
use crate::model::machine::machine_id::{MachineType, RpcMachineTypeWrapper};
use crate::model::machine::network::{MachineNetworkStatusObservation, ManagedHostNetworkConfig};
use crate::model::machine::upgrade_policy::AgentUpgradePolicy;
use crate::model::machine::{
    FailureDetails, MachineLastRebootRequested, MachineLastRebootRequestedMode, MachineState,
    ManagedHostState, ReprovisionRequest, UpgradeDecision,
};
use crate::state_controller::io::PersistentStateHandlerOutcome;
use crate::{CarbideError, CarbideResult};

/// MachineSearchConfig: Search parameters
#[derive(Default, Debug)]
pub struct MachineSearchConfig {
    pub include_dpus: bool,
    pub include_history: bool,
    pub include_predicted_host: bool,
    /// Only include machines in maintenance mode
    pub only_maintenance: bool,
    pub include_associated_machine_id: bool,
    pub exclude_hosts: bool,
}

impl From<rpc::MachineSearchConfig> for MachineSearchConfig {
    fn from(value: rpc::MachineSearchConfig) -> Self {
        MachineSearchConfig {
            include_dpus: value.include_dpus,
            include_history: value.include_history,
            include_predicted_host: value.include_predicted_host,
            only_maintenance: value.only_maintenance,
            include_associated_machine_id: value.include_associated_machine_id,
            exclude_hosts: value.exclude_hosts,
        }
    }
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

    /// A list of [MachineStateHistory] that this machine has experienced
    history: Vec<MachineStateHistory>,

    /// A list of [MachineInterface][interface]s that this machine owns
    interfaces: Vec<MachineInterface>,

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

    /// Does the forge-dpu-agent on this DPU need upgrading?
    dpu_agent_upgrade_requested: Option<UpgradeDecision>,

    // Other machine ids associated with this machine
    associated_host_machine_id: Option<MachineId>,
    associated_dpu_machine_id: Option<MachineId>,

    // Inventory related to a machine.
    // Software and versions installed on the machine.
    inventory: Option<MachineInventory>,

    /// Last time when machine reboot was requested.
    /// This field takes care of reboot requested from state machine only.
    last_reboot_requested: Option<MachineLastRebootRequested>,

    /// The result of the last attempt to change state
    controller_state_outcome: Option<PersistentStateHandlerOutcome>,
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for Machine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state_version_str: &str = row.try_get("controller_state_version")?;
        let controller_state_version = controller_state_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let controller_state: sqlx::types::Json<ManagedHostState> =
            row.try_get("controller_state")?;

        let stable_string: String = row.try_get("id")?;
        let id = MachineId::from_str(&stable_string).unwrap();

        let network_config_version_str: &str = row.try_get("network_config_version")?;
        let network_config_version = network_config_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let network_config: sqlx::types::Json<ManagedHostNetworkConfig> =
            row.try_get("network_config")?;

        let network_status_observation: Option<sqlx::types::Json<MachineNetworkStatusObservation>> =
            row.try_get("network_status_observation")?;
        let network_status_observation = network_status_observation.map(|n| n.0);

        let failure_details: sqlx::types::Json<FailureDetails> = row.try_get("failure_details")?;
        let reprovision_req: Option<sqlx::types::Json<ReprovisionRequest>> =
            row.try_get("reprovisioning_requested")?;

        let dpu_agent_upgrade_requested: Option<sqlx::types::Json<UpgradeDecision>> =
            row.try_get("dpu_agent_upgrade_requested")?;
        let last_reboot_requested: Option<sqlx::types::Json<MachineLastRebootRequested>> =
            row.try_get("last_reboot_requested")?;

        let machine_inventory: Option<sqlx::types::Json<MachineInventory>> =
            row.try_get("agent_reported_inventory")?;

        let state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome")?;

        Ok(Machine {
            id,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            _deployed: row.try_get("deployed")?,
            state: Versioned::new(controller_state.0, controller_state_version),
            network_config: Versioned::new(network_config.0, network_config_version),
            network_status_observation,
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
            dpu_agent_upgrade_requested: dpu_agent_upgrade_requested.map(|x| x.0),
            associated_host_machine_id: None,
            associated_dpu_machine_id: None,
            inventory: machine_inventory.map(|x| x.0),
            controller_state_outcome: state_outcome.map(|x| x.0),
        })
    }
}

/// A wrapper around `MachineId` that implements `sqlx::Decode` and `sqlx::FromRow`
#[derive(Debug, Clone)]
pub struct DbMachineId(MachineId);

impl DbMachineId {
    pub fn into_inner(self) -> MachineId {
        self.0
    }
}

impl From<DbMachineId> for MachineId {
    fn from(value: DbMachineId) -> Self {
        value.0
    }
}

impl<DB> sqlx::Type<DB> for DbMachineId
where
    DB: sqlx::Database,
    String: sqlx::Type<DB>,
{
    fn type_info() -> <DB as sqlx::Database>::TypeInfo {
        String::type_info()
    }

    fn compatible(ty: &DB::TypeInfo) -> bool {
        String::compatible(ty)
    }
}

impl<'r, DB> sqlx::Decode<'r, DB> for DbMachineId
where
    DB: sqlx::Database,
    String: sqlx::Decode<'r, DB>,
{
    fn decode(
        value: <DB as sqlx::database::HasValueRef<'r>>::ValueRef,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        // We first read the MachineId as a String. The function for this already
        // exists and we delegate
        let str_id: String = String::decode(value)?;
        // Then we parse the ID
        let id = MachineId::from_str(&str_id).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        Ok(DbMachineId(id))
    }
}

impl<'r> sqlx::FromRow<'r, PgRow> for DbMachineId {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let id: DbMachineId = row.try_get(0)?;
        Ok(id)
    }
}

///
/// Implements conversion from a database-backed `Machine` to a Protobuf representation of the
/// Machine.
///
impl From<Machine> for rpc::Machine {
    fn from(machine: Machine) -> Self {
        rpc::Machine {
            id: Some(machine.id.to_string().into()),
            state: machine.state.value.to_string(),
            state_version: machine.state.version.version_string(),
            machine_type: *RpcMachineTypeWrapper::from(machine.machine_type()) as i32,
            events: machine
                .history
                .into_iter()
                .map(|event| event.into())
                .collect(),
            interfaces: machine
                .interfaces
                .into_iter()
                .map(|interface| interface.into())
                .collect(),
            discovery_info: machine
                .hardware_info
                .and_then(|hw_info| match hw_info.try_into() {
                    Ok(di) => Some(di),
                    Err(e) => {
                        tracing::warn!(
                            machine_id = %machine.id,
                            error = %e,
                            "Hardware information couldn't be parsed into discovery info",
                        );
                        None
                    }
                }),
            bmc_info: Some(machine.bmc_info.into()),
            last_reboot_time: machine.last_reboot_time.map(|t| t.into()),
            network_health: machine
                .network_status_observation
                .as_ref()
                .map(|obs| obs.health_status.clone().into()),
            last_observation_time: machine
                .network_status_observation
                .as_ref()
                .map(|obs| obs.observed_at.into()),
            dpu_agent_version: machine
                .network_status_observation
                .as_ref()
                .and_then(|obs| obs.agent_version.clone()),
            maintenance_reference: machine.maintenance_reference,
            maintenance_start_time: machine.maintenance_start_time.map(|t| t.into()),
            associated_host_machine_id: machine
                .associated_host_machine_id
                .map(|id| id.to_string().into()),
            associated_dpu_machine_id: machine
                .associated_dpu_machine_id
                .map(|id| id.to_string().into()),
            inventory: machine.inventory.clone().map(|i| i.into()),
            last_reboot_requested_time: machine
                .last_reboot_requested
                .as_ref()
                .map(|x| x.time.into()),
            last_reboot_requested_mode: machine
                .last_reboot_requested
                .as_ref()
                .map(|x| x.mode.to_string()),
            state_reason: machine.controller_state_outcome.map(|r| r.into()),
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

    pub fn bmc_vendor(&self) -> BMCVendor {
        match self.hardware_info() {
            Some(hw) => hw.bmc_vendor(),
            None => BMCVendor::Unknown,
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

    /// Actual network info from machine
    pub fn network_status_observation(&self) -> Option<&MachineNetworkStatusObservation> {
        self.network_status_observation.as_ref()
    }

    /// Is the HBN on this machine's DPU healthy and working?
    /// Only for DPU machines.
    pub fn has_healthy_network(&self) -> Result<bool, eyre::Report> {
        if !self.is_dpu() {
            eyre::bail!("has_healthy_network can only be called on a DPU");
        }
        Ok(match &self.network_status_observation {
            None => false,
            Some(obs) => obs.health_status.is_healthy,
        })
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
        stable_machine_id: &MachineId,
        interface: &MachineInterface,
    ) -> CarbideResult<(Self, bool)> {
        let existing_machine = Machine::find_one(
            &mut *txn,
            stable_machine_id,
            MachineSearchConfig {
                include_associated_machine_id: true,
                ..Default::default()
            },
        )
        .await?;
        if interface.machine_id.is_some() {
            let machine_id = interface.machine_id.as_ref().unwrap();
            if machine_id != stable_machine_id {
                return Err(CarbideError::GenericError(format!(
                    "Database inconsistency: MachineId {} on interface {} does not match stable machine ID {} which now uses this interface",
                    machine_id, interface.id(),
                    stable_machine_id)));
            }

            if existing_machine.is_none() {
                tracing::warn!(
                    %machine_id,
                    interface_id = %interface.id(),
                    "Interface ID refers to missing machine",
                );
                return Err(CarbideError::NotFoundError {
                    kind: "machine",
                    id: machine_id.to_string(),
                });
            }
        }

        // Get or create
        if existing_machine.is_some() {
            // New site-explorer redfish discovery path.
            let machine = existing_machine.unwrap();
            interface
                .associate_interface_with_machine(txn, &machine.id)
                .await?;
            // Machine that is discovered via redfish, still considered as new for api to configure network.
            let is_new = machine.network_config().loopback_ip.is_none();

            Ok((machine, is_new))
        } else {
            // Old manual discovery path.
            // Host and DPU machines are created in same `discover_machine` call. Update same
            // state in both machines.
            let state = ManagedHostState::DPUNotReady {
                machine_state: MachineState::Init,
            };
            let machine = Self::create(txn, stable_machine_id, state).await?;
            interface
                .associate_interface_with_machine(txn, &machine.id)
                .await?;
            Ok((machine, true))
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

    pub fn generate_hostname_from_uuid(uuid: &uuid::Uuid) -> String {
        human_hash::humanize(uuid, 2)
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

        let id: Option<DbMachineId> = sqlx::query_as(query)
            .bind(macaddr)
            .bind(relay)
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(id.map(|id| id.into_inner()))
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
    pub fn interfaces(&self) -> &Vec<MachineInterface> {
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
        MachineStateHistory::persist(txn, self.id(), state.clone(), version).await?;

        let _id: (String,) = sqlx::query_as(
            "UPDATE machines SET controller_state_version=$1, controller_state=$2 WHERE id=$3 RETURNING id",
        )
        .bind(version.version_string())
        .bind(sqlx::types::Json(state))
        .bind(self.id().to_string())
        .fetch_one(&mut **txn)
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
                sqlx::query_as::<_, Machine>(&base_query.replace("{where}", where_clause))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "machines All", e))?
            }
            ObjectFilter::One(id) => {
                let mut where_clause = "WHERE m.id=$1".to_string();
                if search_config.only_maintenance {
                    where_clause += " AND maintenance_reference IS NOT NULL";
                }
                sqlx::query_as::<_, Machine>(&base_query.replace("{where}", &where_clause))
                    .bind(id.to_string())
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "machines One", e))?
            }
            ObjectFilter::List(list) => {
                let mut where_clause = "WHERE m.id=ANY($1)".to_string();
                if search_config.only_maintenance {
                    where_clause += " AND maintenance_reference IS NOT NULL";
                }
                let str_list: Vec<String> = list.iter().map(|id| id.to_string()).collect();
                sqlx::query_as::<_, Machine>(&base_query.replace("{where}", &where_clause))
                    .bind(str_list)
                    .fetch_all(&mut **txn)
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
            MachineStateHistory::find_by_machine_ids(&mut *txn, &all_ids).await?
        } else {
            HashMap::new()
        };

        let mut interfaces_for_machine =
            MachineInterface::find_by_machine_ids(&mut *txn, &all_ids).await?;

        let topologies_for_machine =
            MachineTopology::find_latest_by_machine_ids(&mut *txn, &all_ids).await?;

        for machine in all_machines.iter_mut() {
            if search_config.include_history {
                if let Some(history) = history_for_machine.remove(&machine.id) {
                    machine.history = history;
                }
            }

            if search_config.include_associated_machine_id {
                if machine.is_dpu() {
                    machine.associated_host_machine_id =
                        Machine::find_host_machine_id_by_dpu_machine_id(txn, &machine.id).await?;
                } else {
                    machine.associated_dpu_machine_id = interfaces_for_machine
                        .get(&machine.id)
                        .and_then(|i| i.first())
                        .and_then(|i| i.attached_dpu_machine_id().clone());
                }
            }

            if let Some(interfaces) = interfaces_for_machine.remove(&machine.id) {
                machine.interfaces = interfaces;
            }

            if let Some(topo) = topologies_for_machine.get(&machine.id) {
                machine.hardware_info = Some(topo.topology().discovery_data.info.clone());
                machine.bmc_info = topo.topology().bmc_info.clone();
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
        let history = MachineStateHistory::for_machine(&mut *txn, &self.id).await?;
        if !history.is_empty() {
            self.history = history;
        }

        let mut interfaces =
            MachineInterface::find_by_machine_ids(&mut *txn, &[self.id.clone()]).await?;
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
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        let mut machine = match machine {
            Some(machine) => machine,
            None => return Ok(None),
        };

        machine.load_related_data(txn).await?;
        Ok(Some(machine))
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
            .fetch_optional(&mut **txn)
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
            .fetch_optional(&mut **txn)
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
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        let mut machine = match machine {
            Some(machine) => machine,
            None => return Ok(None),
        };
        machine.load_related_data(txn).await?;
        Ok(Some(machine))
    }

    pub async fn find_by_fqdn(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        fqdn: &str,
        search_config: MachineSearchConfig,
    ) -> Result<Vec<Machine>, DatabaseError> {
        let query = "SELECT machine_id FROM machine_dhcp_records WHERE fqdn = $1";

        let machine_id: Option<DbMachineId> = sqlx::query_as(query)
            .bind(fqdn)
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        let machine_id = match machine_id {
            Some(id) => id.into_inner(),
            None => return Ok(Vec::new()),
        };

        match Self::find_one(txn, &machine_id, search_config).await? {
            Some(machine) => Ok(vec![machine]),
            None => Ok(vec![]),
        }
    }

    /// Finds a machine by a query
    ///
    /// - If the query looks like a MachineId, it will try to load the information based on the MachineId
    /// - If the query looks like an IP address, it will try to look up the machine based on it's admin IP address
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

    pub async fn update_reboot_time(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE machines SET last_reboot_time=NOW() WHERE id=$1 RETURNING *";
        let _id = sqlx::query_as::<_, Self>(query)
            .bind(self.id().to_string())
            .fetch_one(&mut **txn)
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

        let query = "UPDATE machines SET last_reboot_requested=$1 WHERE id=$2 RETURNING *";
        let _id = sqlx::query_as::<_, Self>(query)
            .bind(sqlx::types::Json(&data))
            .bind(machine_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn update_cleanup_time(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE machines SET last_cleanup_time=NOW() WHERE id=$1 RETURNING *";
        let _id = sqlx::query_as::<_, Self>(query)
            .bind(self.id().to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    pub async fn update_discovery_time(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE machines SET last_discovery_time=NOW() WHERE id=$1 RETURNING *";
        let _id = sqlx::query_as::<_, Self>(query)
            .bind(self.id().to_string())
            .fetch_one(&mut **txn)
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

        let machine_id: Option<DbMachineId> = sqlx::query_as(query)
            .bind(dpu_machine_id.to_string())
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(machine_id.map(MachineId::from))
    }

    pub async fn find_host_by_dpu_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        dpu_machine_id: &MachineId,
    ) -> CarbideResult<Option<Self>> {
        let query = r#"SELECT m.* From machines m
                INNER JOIN machine_interfaces mi
                  ON m.id = mi.machine_id
                WHERE mi.attached_dpu_machine_id=$1
                    AND mi.attached_dpu_machine_id != mi.machine_id"#;
        let machine: Option<Self> = sqlx::query_as(query)
            .bind(dpu_machine_id.to_string())
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        let mut machine = match machine {
            Some(machine) => machine,
            None => return Ok(None),
        };

        machine.load_related_data(txn).await?;

        Ok(Some(machine))
    }

    pub async fn find_dpu_by_host_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        host_machine_id: &MachineId,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = r#"SELECT m.* From machines m
                INNER JOIN machine_interfaces mi
                  ON m.id = mi.attached_dpu_machine_id
                WHERE mi.machine_id=$1"#;
        let machine: Option<Self> = sqlx::query_as(query)
            .bind(host_machine_id.to_string())
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        let mut machine = match machine {
            Some(machine) => machine,
            None => return Ok(None),
        };

        machine.load_related_data(txn).await?;

        Ok(Some(machine))
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
        let _id: (DbMachineId,) = sqlx::query_as(query)
            .bind(sqlx::types::Json(&observation))
            .bind(machine_id.to_string())
            .bind(observation.observed_at.to_rfc3339())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

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
        let _id: (DbMachineId,) = sqlx::query_as(query)
            .bind(sqlx::types::Json(&inventory))
            .bind(machine_id.to_string())
            .fetch_one(&mut **txn)
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
            .fetch_all(&mut **txn)
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
            .execute(&mut **txn)
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

        let expected_version_str = expected_version.version_string();
        let next_version = expected_version.increment();
        let next_version_str = next_version.version_string();

        let query = "UPDATE machines SET network_config_version=$1, network_config=$2::json
            WHERE id=$3 AND network_config_version=$4
            RETURNING id";
        let query_result: Result<DbMachineId, _> = sqlx::query_as(query)
            .bind(&next_version_str)
            .bind(sqlx::types::Json(new_state))
            .bind(machine_id.to_string())
            .bind(&expected_version_str)
            .fetch_one(&mut **txn)
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

        // Table machine_interfaces has a FK ON UPDATE CASCADE so machine_interfaces.machine_id will
        // also change.
        let query = "UPDATE machines SET id=$1 WHERE id=$2 RETURNING *";
        let res = sqlx::query_as::<_, Machine>(query)
            .bind(stable_machine_id.to_string())
            .bind(current_machine_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(res)
    }

    pub async fn update_failure_details(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        failure: FailureDetails,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE machines SET failure_details = $1::json WHERE id = $2 RETURNING id";
        let _id: (DbMachineId,) = sqlx::query_as(query)
            .bind(sqlx::types::Json(failure))
            .bind(self.id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
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
        let _id: (DbMachineId,) = sqlx::query_as(query)
            .bind(sqlx::types::Json(failure_details))
            .bind(machine_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    pub async fn set_maintenance_mode(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        mode: MaintenanceMode,
    ) -> Result<(), DatabaseError> {
        match mode {
            MaintenanceMode::On { reference } => {
                let query = "UPDATE machines SET maintenance_reference=$1, maintenance_start_time=NOW() WHERE id=$2";
                sqlx::query(query)
                    .bind(reference)
                    .bind(machine_id.to_string())
                    .execute(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
            }
            MaintenanceMode::Off => {
                let query = "UPDATE machines SET maintenance_reference=NULL, maintenance_start_time=NULL WHERE id=$1";
                sqlx::query(query)
                    .bind(machine_id.to_string())
                    .execute(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
            }
        }
        Ok(())
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        stable_machine_id: &MachineId,
        state: ManagedHostState,
    ) -> CarbideResult<Self> {
        let stable_machine_id_string = stable_machine_id.to_string();
        // Host and DPU machines are created in same `discover_machine` call. Update same
        // state in both machines.
        let state_version = ConfigVersion::initial();

        let network_config_version = ConfigVersion::initial();
        let network_config = ManagedHostNetworkConfig::default();

        let query = "INSERT INTO machines(id, controller_state_version, controller_state, network_config_version, network_config) VALUES($1, $2, $3, $4, $5) RETURNING id";
        let row: (DbMachineId,) = sqlx::query_as(query)
            .bind(&stable_machine_id_string)
            .bind(state_version.version_string())
            .bind(sqlx::types::Json(&state))
            .bind(network_config_version.version_string())
            .bind(sqlx::types::Json(&network_config))
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        let machine_id = row.0.into_inner();
        if machine_id != *stable_machine_id {
            return Err(CarbideError::DatabaseInconsistencyOnMachineCreate(
                stable_machine_id.clone(),
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
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
        initiator: &str,
        update_firmware: bool,
    ) -> Result<(), DatabaseError> {
        let req = ReprovisionRequest {
            requested_at: chrono::Utc::now(),
            initiator: initiator.to_string(),
            update_firmware,
            started_at: None,
            user_approval_received: false,
        };

        let query = "UPDATE machines SET reprovisioning_requested=$2 WHERE id=$1 RETURNING id";
        let _id = sqlx::query_as::<_, DbMachineId>(query)
            .bind(self.id().to_string())
            .bind(sqlx::types::Json(req))
            .fetch_one(&mut **txn)
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
        let _id = sqlx::query_as::<_, DbMachineId>(query)
            .bind(machine_id.to_string())
            .bind(sqlx::types::Json(current_time))
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
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
            .execute(&mut **txn)
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
        let _id = sqlx::query_as::<_, DbMachineId>(query)
            .bind(machine_id.to_string())
            .bind(sqlx::types::Json(true))
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

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
                "AND reprovisioning_requested->'started_at' IS NOT NULL",
            )
        } else {
            query.replace("{validate_started}", "")
        };

        let _id = sqlx::query_as::<_, DbMachineId>(&query)
            .bind(machine_id.to_string())
            .fetch_one(&mut **txn)
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
        sqlx::query_as::<_, Self>(query)
            .fetch_all(&mut **txn)
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
            .execute(&mut **txn)
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

        tracing::info!("sql: {}", qb.sql());
        let q = qb.build_query_as();
        let machine_ids: Vec<DbMachineId> = q
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "find_machine_ids", e))?;

        Ok(machine_ids.into_iter().map(MachineId::from).collect())
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum MaintenanceMode {
    Off,
    On { reference: String },
}

#[cfg(test)]
mod test {}
