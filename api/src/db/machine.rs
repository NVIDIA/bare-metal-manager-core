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
use std::convert::From;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use ::rpc::forge::{self as rpc};
use chrono::prelude::*;
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

use super::{DatabaseError, ObjectFilter};
use crate::db::machine_interface::MachineInterface;
use crate::db::machine_state_history::MachineStateHistory;
use crate::db::machine_topology::MachineTopology;
use crate::human_hash;
use crate::model::config_version::{ConfigVersion, Versioned};
use crate::model::hardware_info::HardwareInfo;
use crate::model::machine::machine_id::MachineId;
use crate::model::machine::machine_id::{MachineType, RpcMachineTypeWrapper};
use crate::model::machine::network::MachineNetworkStatus;
use crate::model::machine::{BmcInfo, MachineState, ManagedHostState};
use crate::{CarbideError, CarbideResult};

/// MachineSearchConfig: Search parameters
#[derive(Default, Debug)]
pub struct MachineSearchConfig {
    pub include_history: bool,
}

impl From<rpc::MachineSearchConfig> for MachineSearchConfig {
    fn from(value: rpc::MachineSearchConfig) -> Self {
        MachineSearchConfig {
            include_history: value.include_history,
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

    /// References the entry in the vpc_resource_leafs table
    ///
    /// This is a MachineId, because the table is indexed by the MachineId of the DPU
    vpc_leaf_id: Option<MachineId>,

    /// When this machine record was created
    created: DateTime<Utc>,

    /// When the machine record was last modified
    updated: DateTime<Utc>,

    /// When the machine was last deployed
    deployed: Option<DateTime<Utc>>,

    /// The current state of the machine.
    state: Versioned<ManagedHostState>,

    /// A list of [MachineStateHistory] that this machine has experienced
    history: Vec<MachineStateHistory>,

    /// A list of [MachineInterface][interface]s that this machine owns
    interfaces: Vec<MachineInterface>,

    /// The Hardware information that was discoverd for this machine
    hardware_info: Option<HardwareInfo>,

    /// The BMC info for this machine
    bmc_info: BmcInfo,

    /// Last time when machine came up.
    last_reboot_time: Option<DateTime<Utc>>,

    /// Last time when cleanup was performed successfully.
    last_cleanup_time: Option<DateTime<Utc>>,

    /// Last time when discovery finished.
    last_discovery_time: Option<DateTime<Utc>>,
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

        let vpc_leaf_id: Option<DbMachineId> = row.try_get("vpc_leaf_id")?;

        Ok(Machine {
            id,
            vpc_leaf_id: vpc_leaf_id.map(|id| id.0),
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deployed: row.try_get("deployed")?,
            state: Versioned::new(controller_state.0, controller_state_version),
            history: Vec::new(),
            interfaces: Vec::new(),
            hardware_info: None,
            bmc_info: BmcInfo {
                ip: None,
                mac: None,
            },
            last_reboot_time: row.try_get("last_reboot_time")?,
            last_cleanup_time: row.try_get("last_cleanup_time")?,
            last_discovery_time: row.try_get("last_discovery_time")?,
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
            created: Some(machine.created.into()),
            updated: Some(machine.updated.into()),
            deployed: machine.deployed.map(|ts| ts.into()),
            state: machine.state.value.to_string(),
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
            discovery_info: machine.hardware_info.and_then(|hw_info| {
                match hw_info.try_into() {
                    Ok(di) => Some(di),
                    Err(e) => {
                        log::warn!(
                            "Hardware information for machine {} couldn't be parsed into discovery info: {}",
                            &machine.id,
                            e,
                        );
                        None
                    }
                }
            }),
            bmc_info: Some(rpc::BmcInfo{ip: machine.bmc_info.ip, mac: machine.bmc_info.mac}),
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

    /// Hardware information
    pub fn hardware_info(&self) -> Option<&HardwareInfo> {
        self.hardware_info.as_ref()
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
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    /// * `interface` - Network interface of the machine
    ///
    pub async fn get_or_create(
        txn: &mut Transaction<'_, Postgres>,
        stable_machine_id: &MachineId,
        mut interface: MachineInterface,
        is_dpu: bool,
    ) -> CarbideResult<Self> {
        let stable_machine_id_string = stable_machine_id.to_string();

        match &interface.machine_id {
            // GET
            Some(machine_id) => {
                if machine_id != stable_machine_id {
                    return Err(CarbideError::GenericError(format!(
                        "Database inconsistency: MachineId {} on interface {} does not match stable machine ID {} which now uses this interface",
                        machine_id, interface.id(),
                        stable_machine_id)));
                }

                match Machine::find_one(&mut *txn, machine_id, MachineSearchConfig::default())
                    .await?
                {
                    Some(machine) => Ok(machine),
                    None => {
                        log::warn!(
                            "Interface ID {} refers to missing machine {machine_id}",
                            interface.id()
                        );
                        Err(CarbideError::NotFoundError {
                            kind: "machine",
                            id: machine_id.to_string(),
                        })
                    }
                }
            }
            // CREATE
            None => {
                // Choose appropriate state based on machine type dpu or host.
                let state = if is_dpu {
                    ManagedHostState::DPUNotReady {
                        machine_state: MachineState::Init,
                    }
                } else {
                    // At this time, this should be same state of DPU. Even if not, it will be
                    // synced in next state change.
                    ManagedHostState::Created
                };
                let state_version = ConfigVersion::initial();

                let query = "INSERT INTO machines(id, controller_state_version, controller_state) VALUES($1, $2, $3) RETURNING id";
                let row: (DbMachineId,) = sqlx::query_as(query)
                    .bind(&stable_machine_id_string)
                    .bind(state_version.to_version_string())
                    .bind(sqlx::types::Json(&state))
                    .fetch_one(&mut *txn)
                    .await
                    .map_err(|e| {
                        CarbideError::from(DatabaseError::new(file!(), line!(), query, e))
                    })?;
                let machine_id = row.0.into_inner();
                if machine_id != *stable_machine_id {
                    return Err(CarbideError::DatabaseInconsistencyOnMachineCreate(
                        stable_machine_id.clone(),
                    ));
                }

                let machine =
                    Machine::find_one(txn, stable_machine_id, MachineSearchConfig::default())
                        .await?
                        .ok_or_else(|| CarbideError::NotFoundError {
                            kind: "machine",
                            id: stable_machine_id.to_string(),
                        })?;
                machine.advance(txn, state, None).await?;

                interface
                    .associate_interface_with_machine(txn, &machine.id)
                    .await?;
                Ok(machine)
            }
        }
    }

    pub async fn associate_vpc_leaf_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        vpc_leaf_id: &MachineId,
    ) -> Result<Machine, DatabaseError> {
        let query = "UPDATE machines SET vpc_leaf_id=$1 where id=$2 RETURNING *";
        sqlx::query_as(query)
            .bind(vpc_leaf_id.to_string())
            .bind(machine_id.to_string())
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
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
            .bind(IpNetwork::from(relay))
            .fetch_optional(&mut *txn)
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
    pub fn interfaces(&self) -> &Vec<MachineInterface> {
        &self.interfaces
    }

    pub fn vpc_leaf_id(&self) -> &Option<MachineId> {
        &self.vpc_leaf_id
    }

    /// Return the current state of the machine.
    ///
    /// Arguments:
    /// None
    ///
    pub fn current_state(&self) -> ManagedHostState {
        self.state.value.clone()
    }

    /// Return the current version of state of the machine.
    ///
    /// Arguments:
    /// None
    ///
    pub fn current_version(&self) -> ConfigVersion {
        self.state.version
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
    ) -> CarbideResult<bool> {
        // Get current version
        let version = version.unwrap_or_else(|| self.state.version.increment());

        // Store history of machine state changes.
        MachineStateHistory::persist(txn, self.id(), state.clone(), version).await?;

        let _id: (String,) = sqlx::query_as(
            "UPDATE machines SET controller_state_version=$1, controller_state=$2 WHERE id=$3 RETURNING id",
        )
        .bind(version.to_version_string())
        .bind(sqlx::types::Json(state))
        .bind(self.id().to_string())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "update machines state", e))?;

        Ok(true)
    }

    /// Find machines given a set of criteria, right now just returns all machines because there's
    /// no way to filter the machines.
    ///
    /// TODO(ajf): write a query langauge???
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
            ObjectFilter::All => sqlx::query_as::<_, Machine>(&base_query.replace("{where}", ""))
                .fetch_all(&mut *txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), "machines All", e))?,
            ObjectFilter::One(id) => {
                sqlx::query_as::<_, Machine>(&base_query.replace("{where}", "WHERE m.id=$1"))
                    .bind(id.to_string())
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "machines One", e))?
            }
            ObjectFilter::List(list) => {
                let str_list: Vec<String> = list.iter().map(|id| id.to_string()).collect();
                sqlx::query_as::<_, Machine>(&base_query.replace("{where}", "WHERE m.id=ANY($1)"))
                    .bind(str_list)
                    .fetch_all(&mut *txn)
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

        all_machines.iter_mut().for_each(|machine| {
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
                machine.bmc_info.ip = topo.topology().ipmi_ip.clone();
                machine.bmc_info.mac = topo.topology().ipmi_mac.clone();
            }

            if machine.hardware_info.is_none() {
                log::warn!("Machine {0} has no associated discovery data", &machine.id);
            }
        });

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
            self.bmc_info.ip = topology.topology().ipmi_ip.clone();
            self.bmc_info.mac = topology.topology().ipmi_mac.clone();
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
            .fetch_optional(&mut *txn)
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
            .fetch_optional(&mut *txn)
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
            .fetch_optional(&mut *txn)
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
            .fetch_optional(&mut *txn)
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

    pub fn last_reboot_time(&self) -> Option<DateTime<Utc>> {
        self.last_reboot_time
    }

    pub fn last_cleanup_time(&self) -> Option<DateTime<Utc>> {
        self.last_cleanup_time
    }

    pub fn last_discovery_time(&self) -> Option<DateTime<Utc>> {
        self.last_discovery_time
    }

    pub async fn update_reboot_time(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<()> {
        let query = "UPDATE machines SET last_reboot_time=NOW() WHERE id=$1 RETURNING *";
        let _id = sqlx::query_as::<_, Self>(query)
            .bind(self.id().to_string())
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn update_cleanup_time(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<()> {
        let query = "UPDATE machines SET last_cleanup_time=NOW() WHERE id=$1 RETURNING *";
        let _id = sqlx::query_as::<_, Self>(query)
            .bind(self.id().to_string())
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    pub async fn update_discovery_time(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<()> {
        let query = "UPDATE machines SET last_discovery_time=NOW() WHERE id=$1 RETURNING *";
        let _id = sqlx::query_as::<_, Self>(query)
            .bind(self.id().to_string())
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
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
            .fetch_optional(&mut *txn)
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
    ) -> CarbideResult<Option<Self>> {
        let query = r#"SELECT m.* From machines m
                INNER JOIN machine_interfaces mi
                  ON m.id = mi.attached_dpu_machine_id
                WHERE mi.machine_id=$1"#;
        let machine: Option<Self> = sqlx::query_as(query)
            .bind(host_machine_id.to_string())
            .fetch_optional(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        let mut machine = match machine {
            Some(machine) => machine,
            None => return Ok(None),
        };

        machine.load_related_data(txn).await?;

        Ok(Some(machine))
    }

    pub async fn update_network_status_observation(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        observation: MachineNetworkStatus,
    ) -> CarbideResult<()> {
        let query =
            "UPDATE machines SET network_status_observation = $1::json WHERE id = $2 RETURNING id";
        let _id: (DbMachineId,) = sqlx::query_as(query)
            .bind(sqlx::types::Json(observation))
            .bind(machine_id.to_string())
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    pub async fn get_all_network_status(
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<Vec<MachineNetworkStatus>> {
        let query = "SELECT network_status_observation FROM machines
            WHERE network_status_observation IS NOT NULL
            ORDER BY network_status_observation->'machine_id'
            LIMIT 1000";
        let rows = sqlx::query(query)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        let mut all = Vec::with_capacity(rows.len());
        for row in rows {
            let s: sqlx::types::Json<MachineNetworkStatus> = row
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
            .execute(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    /// Returns the MachineType based on hardware info.
    pub fn machine_type(&self) -> MachineType {
        self.id.machine_type()
    }
}

#[cfg(test)]
mod test {}
