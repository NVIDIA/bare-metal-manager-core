/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use std::convert::From;
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;

use ::rpc::forge as rpc;
use chrono::prelude::*;
use futures::StreamExt;
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use super::{DatabaseError, UuidKeyedObjectFilter};
use crate::db::machine_interface::MachineInterface;
use crate::db::machine_state_history::MachineStateHistory;
use crate::db::machine_topology::MachineTopology;
use crate::human_hash;
use crate::model::config_version::{ConfigVersion, Versioned};
use crate::model::hardware_info::HardwareInfo;
use crate::model::machine::{machine_id::MachineId as StableMachineId, MachineState};
use crate::{CarbideError, CarbideResult};

///
/// A machine is a standalone system that performs network booting via normal DHCP processes.
///
#[derive(Debug)]
pub struct Machine {
    ///
    /// The UUID of the machine, this is an internal identifier in the database that's unique for
    /// all machines managed by this instance of carbide.
    ///
    id: uuid::Uuid,

    vpc_leaf_id: Option<uuid::Uuid>,

    /// When this machine record was created
    created: DateTime<Utc>,

    /// When the machine record was last modified
    updated: DateTime<Utc>,

    /// When the machine was last deployed
    deployed: Option<DateTime<Utc>>,

    /// The current state of the machine
    state: Versioned<MachineState>,

    /// A list of [MachineEvent][event]s that this machine has experienced
    ///
    /// [event]: crate::db::MachineEvent
    history: Vec<MachineStateHistory>,

    /// A list of [MachineInterface][interface]s that this machine owns
    ///
    /// [event]: crate::db::MachineInterface
    interfaces: Vec<MachineInterface>,

    /// The Hardware information that was discoverd for this machine
    hardware_info: Option<HardwareInfo>,

    /// The BMC IP for this machine
    bmc_ip: Option<String>,

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
        let controller_state: sqlx::types::Json<MachineState> = row.try_get("controller_state")?;

        Ok(Machine {
            id: row.try_get("id")?,
            vpc_leaf_id: row.try_get("vpc_leaf_id")?,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deployed: row.try_get("deployed")?,
            state: Versioned::new(controller_state.0, controller_state_version),
            history: Vec::new(),
            interfaces: Vec::new(),
            hardware_info: None,
            bmc_ip: None,
            last_reboot_time: row.try_get("last_reboot_time")?,
            last_cleanup_time: row.try_get("last_cleanup_time")?,
            last_discovery_time: row.try_get("last_discovery_time")?,
        })
    }
}

#[derive(Debug, Clone, Copy, FromRow)]
pub struct MachineId(uuid::Uuid);

impl From<MachineId> for uuid::Uuid {
    fn from(id: MachineId) -> Self {
        id.0
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
        }
    }
}

impl Machine {
    /// Returns whether the Machine is a DPU, based on the attached HardwareInfo
    ///
    /// If no HardwareInfo is loaded, this will return `false` even if the Machine is a DPU
    pub fn is_dpu(&self) -> bool {
        // TODO: With new MachineIds, this can just check the ID
        // Another appraoch is also to check the `attached_dpu_machine_id` - but this
        // requires interface information being loaded
        match &self.hardware_info {
            Some(info) => info.is_dpu(),
            None => false,
        }
    }

    /// The BMC IP for this machine
    pub fn bmc_ip(&self) -> Option<&str> {
        self.bmc_ip.as_deref()
    }

    pub async fn exists(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: uuid::Uuid,
    ) -> Result<bool, DatabaseError> {
        let machine = Machine::find_one(&mut *txn, machine_id).await?;
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
        stable_machine_id: Option<StableMachineId>,
        mut interface: MachineInterface,
    ) -> CarbideResult<Self> {
        let stable_machine_id_string = stable_machine_id.map(|id| id.to_string());

        match interface.machine_id {
            // GET
            Some(machine_id) => match Machine::find_one(&mut *txn, machine_id).await? {
                Some(machine) => {
                    // TODO: Verify that the Stable Machine ID matches?
                    Ok(machine)
                }
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
            },
            // CREATE
            None => {
                let query = "INSERT INTO machines(stable_id) VALUES($1) RETURNING id";
                let row: (Uuid,) = sqlx::query_as(query)
                    .bind(&stable_machine_id_string)
                    .fetch_one(&mut *txn)
                    .await
                    .map_err(|e| {
                        CarbideError::from(DatabaseError::new(file!(), line!(), query, e))
                    })?;
                let machine = match Machine::find_one(&mut *txn, row.0).await {
                    Ok(Some(x)) => Ok(x),
                    Ok(None) => Err(CarbideError::DatabaseInconsistencyOnMachineCreate(row.0)),
                    Err(x) => Err(x.into()),
                }?;
                match machine.current_state() {
                    MachineState::Init => {
                        interface
                            .associate_interface_with_machine(txn, &machine.id)
                            .await?;
                    }
                    rest => {
                        return Err(CarbideError::GenericError(format!(
                            "Discover call received in Invalid {} state for machine: {}",
                            rest,
                            machine.id()
                        )));
                    }
                }
                Ok(machine)
            }
        }
    }

    pub async fn associate_vpc_leaf_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: uuid::Uuid,
        vpc_leaf_id: uuid::Uuid,
    ) -> Result<Machine, DatabaseError> {
        let query = "UPDATE machines SET vpc_leaf_id=$1::uuid where id=$2::uuid RETURNING *";
        sqlx::query_as(query)
            .bind(vpc_leaf_id)
            .bind(machine_id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_one(
        txn: &mut Transaction<'_, Postgres>,
        uuid: uuid::Uuid,
    ) -> Result<Option<Self>, DatabaseError> {
        Ok(Machine::find(txn, UuidKeyedObjectFilter::One(uuid))
            .await?
            .pop())
    }

    pub fn generate_hostname_from_uuid(uuid: &uuid::Uuid) -> String {
        human_hash::humanize(uuid, 2)
    }

    pub async fn find_existing_machine(
        txn: &mut Transaction<'_, Postgres>,
        macaddr: MacAddress,
        relay: IpAddr,
    ) -> Result<Option<(Uuid,)>, DatabaseError> {
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

        sqlx::query_as(query)
            .bind(macaddr)
            .bind(IpNetwork::from(relay))
            .fetch_optional(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    /// Returns the ID of the machine object
    pub fn id(&self) -> &uuid::Uuid {
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

    pub fn vpc_leaf_id(&self) -> &Option<uuid::Uuid> {
        &self.vpc_leaf_id
    }

    /// Return the current state of the machine.
    ///
    /// Arguments:
    /// None
    ///
    pub fn current_state(&self) -> MachineState {
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
    pub async fn advance(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        state: MachineState,
    ) -> Result<bool, DatabaseError> {
        // Get current version
        let version = self.state.version;
        let new_version = version.increment();

        // Store history of machine state changes.
        MachineStateHistory::persist(txn, self.id(), state.clone(), new_version).await?;

        let query = "UPDATE machines SET controller_state_version=$1, controller_state=$2 WHERE id=$3 RETURNING id";
        let _id: (uuid::Uuid,) = sqlx::query_as(query)
            .bind(new_version.to_version_string())
            .bind(sqlx::types::Json(state))
            .bind(self.id())
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(true)
    }

    /// Retrieves the IDs of all active Machines - which are machines that are not in
    /// the final state.
    ///
    /// * `txn` - A reference to a currently open database transaction
    ///
    pub async fn list_active_machine_ids(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<Uuid>, DatabaseError> {
        // TODO: Since the state is not directly part of the database and might move,
        // we currently assume all machines as active

        let query = "SELECT id FROM machines";
        let mut results = Vec::new();
        let mut machine_id_stream = sqlx::query_as::<_, MachineId>(query).fetch(txn);
        while let Some(maybe_id) = machine_id_stream.next().await {
            let id = maybe_id.map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
            results.push(id.into());
        }

        Ok(results)
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
        filter: UuidKeyedObjectFilter<'_>,
    ) -> Result<Vec<Machine>, DatabaseError> {
        let base_query = "SELECT * FROM machines m {where} GROUP BY m.id".to_owned();

        let mut all_machines: Vec<Machine> = match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, Machine>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "machines All", e))?
            }
            UuidKeyedObjectFilter::One(uuid) => {
                sqlx::query_as::<_, Machine>(&base_query.replace("{where}", "WHERE m.id=$1"))
                    .bind(uuid)
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "machines One", e))?
            }
            UuidKeyedObjectFilter::List(list) => {
                sqlx::query_as::<_, Machine>(&base_query.replace("{where}", "WHERE m.id=ANY($1)"))
                    .bind(list)
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "machines List", e))?
            }
        };

        let all_uuids = all_machines.iter().map(|m| m.id).collect::<Vec<Uuid>>();

        let mut history_for_machine =
            MachineStateHistory::find_by_machine_ids(&mut *txn, &all_uuids).await?;

        let mut interfaces_for_machine =
            MachineInterface::find_by_machine_ids(&mut *txn, &all_uuids).await?;

        let topologies_for_machine =
            MachineTopology::find_latest_by_machine_ids(&mut *txn, &all_uuids).await?;

        all_machines.iter_mut().for_each(|machine| {
            if let Some(history) = history_for_machine.remove(&machine.id) {
                machine.history = history;
            } else {
                log::warn!("Machine {0} () has no events", machine.id);
            }

            if let Some(interfaces) = interfaces_for_machine.remove(&machine.id) {
                machine.interfaces = interfaces;
            } else {
                log::warn!("Machine {0} () has no interfaces", machine.id);
            }

            if let Some(topo) = topologies_for_machine.get(&machine.id) {
                machine.hardware_info = Some(topo.topology().discovery_data.info.clone());
                machine.bmc_ip = topo.topology().ipmi_ip.clone();
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

        let mut interfaces = MachineInterface::find_by_machine_ids(&mut *txn, &[self.id]).await?;
        if let Some(interfaces) = interfaces.remove(&self.id) {
            self.interfaces = interfaces;
        }

        let mut topologies =
            MachineTopology::find_latest_by_machine_ids(&mut *txn, &[self.id]).await?;
        if let Some(topology) = topologies.remove(&self.id) {
            self.hardware_info = Some(topology.topology().discovery_data.info.clone());
            self.bmc_ip = topology.topology().ipmi_ip.clone();
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
    ) -> Result<Vec<Machine>, DatabaseError> {
        let query = "SELECT machine_id FROM machine_dhcp_records WHERE fqdn = $1";

        let machine_id: Option<MachineId> = sqlx::query_as(query)
            .bind(fqdn)
            .fetch_optional(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        let machine_id = match machine_id {
            Some(id) => id,
            None => return Ok(Vec::new()),
        };

        match Self::find_one(txn, machine_id.0).await? {
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
        if let Ok(uuid) = Uuid::parse_str(query) {
            return Self::find_one(txn, uuid).await;
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
            .bind(self.id())
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
            .bind(self.id())
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
            .bind(self.id())
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    pub async fn find_host_by_dpu_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        dpu_machine_id: &uuid::Uuid,
    ) -> CarbideResult<Option<Self>> {
        let query = r#"SELECT m.* From machines m 
                INNER JOIN machine_interfaces mi 
                  ON m.id = mi.machine_id 
                WHERE mi.attached_dpu_machine_id=$1::uuid 
                    AND mi.attached_dpu_machine_id != mi.machine_id"#;
        let machine: Option<Self> = sqlx::query_as(query)
            .bind(dpu_machine_id)
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
        host_machine_id: &uuid::Uuid,
    ) -> CarbideResult<Option<Self>> {
        let query = r#"SELECT m.* From machines m 
                INNER JOIN machine_interfaces mi 
                  ON m.id = mi.attached_dpu_machine_id 
                WHERE mi.machine_id=$1::uuid"#;
        let machine: Option<Self> = sqlx::query_as(query)
            .bind(host_machine_id)
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

    /// Force cleans all tables related to a Machine - except MachineInterfaces
    ///
    /// DO NOT USE OUTSIDE OF ADMIN CLI
    pub async fn force_cleanup(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: uuid::Uuid,
    ) -> Result<(), DatabaseError> {
        // Note: It might be nicer to actually write the full query here so we can
        // report more results.
        // But this way we at least unit-test the stored procedure and make sure
        // it stays up to date.
        let query = r#"call cleanup_machine_by_id($1)"#;
        let _query_result = sqlx::query(query)
            .bind(machine_id)
            .execute(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }
}

#[cfg(test)]
mod test {}
