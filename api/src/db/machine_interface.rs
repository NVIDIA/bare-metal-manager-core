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
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};

use ::rpc::forge as rpc;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use mac_address::MacAddress;
use sqlx::{postgres::PgRow, Acquire, FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use super::machine::{DbMachineId, MachineSearchConfig};
use super::{DatabaseError, ObjectFilter, UuidKeyedObjectFilter};
use crate::db::address_selection_strategy::AddressSelectionStrategy;
use crate::db::machine::Machine;
use crate::db::machine_interface_address::MachineInterfaceAddress;
use crate::db::network_segment::NetworkSegment;
use crate::dhcp::allocation::{IpAllocator, UsedIpResolver};
use crate::model::hardware_info::HardwareInfo;
use crate::model::machine::machine_id::MachineId;
use crate::{CarbideError, CarbideResult};

const SQL_VIOLATION_DUPLICATE_MAC: &str = "machine_interfaces_segment_id_mac_address_key";
const SQL_VIOLATION_ONE_PRIMARY_INTERFACE: &str = "one_primary_interface_per_machine";

#[derive(Debug, Clone)]
pub struct MachineInterface {
    pub id: uuid::Uuid,
    attached_dpu_machine_id: Option<MachineId>,
    pub domain_id: Option<uuid::Uuid>,
    pub machine_id: Option<MachineId>,
    segment_id: uuid::Uuid,
    pub mac_address: MacAddress,
    hostname: String,
    primary_interface: bool,
    addresses: Vec<MachineInterfaceAddress>,
}

struct UsedAdminNetworkIpResolver {
    segment_id: uuid::Uuid,
}

impl<'r> FromRow<'r, PgRow> for MachineInterface {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let machine_id: Option<DbMachineId> = row.try_get("machine_id")?;
        let attached_dpu_machine_id: Option<DbMachineId> =
            row.try_get("attached_dpu_machine_id")?;

        Ok(MachineInterface {
            id: row.try_get("id")?,
            attached_dpu_machine_id: attached_dpu_machine_id.map(|id| id.into_inner()),
            machine_id: machine_id.map(|id| id.into_inner()),
            segment_id: row.try_get("segment_id")?,
            domain_id: row.try_get("domain_id")?,
            hostname: row.try_get("hostname")?,
            mac_address: row.try_get("mac_address")?,
            primary_interface: row.try_get("primary_interface")?,
            addresses: Vec::new(),
        })
    }
}

impl From<MachineInterface> for rpc::MachineInterface {
    fn from(machine_interface: MachineInterface) -> rpc::MachineInterface {
        rpc::MachineInterface {
            id: Some(machine_interface.id.into()),
            attached_dpu_machine_id: machine_interface
                .attached_dpu_machine_id
                .map(|id| id.to_string().into()),
            machine_id: machine_interface.machine_id.map(|id| id.to_string().into()),
            segment_id: Some(machine_interface.segment_id.into()),
            hostname: machine_interface.hostname,
            domain_id: machine_interface.domain_id.map(|d| d.into()),
            mac_address: machine_interface.mac_address.to_string(),
            primary_interface: machine_interface.primary_interface,
            address: machine_interface
                .addresses
                .iter()
                .map(|addr| addr.address.to_string())
                .collect(),
        }
    }
}

impl MachineInterface {
    /// Update machine interface hostname
    ///
    /// This updates the machine_interfaces hostname which will render the old name in-accessible after the DNS
    /// TTL expires on recursive resolvers.  The authoritative resolver is updated immediately.
    ///
    /// Arguments:
    ///
    /// * `txn` - A reference to a currently open database transaction
    /// * `new_hostname` - The new hostname, which is subject to DNS validation rules (todo!())
    pub async fn update_hostname(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
        new_hostname: &str,
    ) -> Result<&MachineInterface, DatabaseError> {
        let query = "UPDATE machine_interfaces SET hostname=$1 WHERE id=$2 RETURNING hostname";
        let (hostname,) = sqlx::query_as(query)
            .bind(new_hostname)
            .bind(self.id())
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        self.hostname = hostname;

        Ok(self)
    }

    pub async fn associate_interface_with_dpu_machine(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        dpu_machine_id: &MachineId,
    ) -> Result<Self, DatabaseError> {
        let query =
            "UPDATE machine_interfaces SET attached_dpu_machine_id=$1 where id=$2::uuid RETURNING *";
        sqlx::query_as(query)
            .bind(dpu_machine_id.to_string())
            .bind(self.id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn associate_interface_with_machine(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> CarbideResult<Self> {
        let query = "UPDATE machine_interfaces SET machine_id=$1 where id=$2::uuid RETURNING *";
        sqlx::query_as(query)
            .bind(machine_id.to_string())
            .bind(self.id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                sqlx::Error::Database(e)
                    if e.constraint() == Some(SQL_VIOLATION_ONE_PRIMARY_INTERFACE) =>
                {
                    CarbideError::OnePrimaryInterface
                }
                _ => CarbideError::from(DatabaseError::new(file!(), line!(), query, err)),
            })
    }

    /// Returns the ID of the MachineInterface object
    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub fn addresses(&self) -> &Vec<MachineInterfaceAddress> {
        &self.addresses
    }

    pub fn attached_dpu_machine_id(&self) -> &Option<MachineId> {
        &self.attached_dpu_machine_id
    }

    pub async fn find_by_mac_address(
        txn: &mut Transaction<'_, Postgres>,
        macaddr: MacAddress,
    ) -> Result<Vec<MachineInterface>, DatabaseError> {
        MachineInterface::find_by(txn, ObjectFilter::One(macaddr.to_string()), "mac_address").await
    }

    pub async fn find_by_ip(
        txn: &mut Transaction<'_, Postgres>,
        ip: &Ipv4Addr,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = r#"SELECT mi.* FROM machine_interfaces mi
            INNER JOIN machine_interface_addresses mia on mia.interface_id=mi.id
            WHERE mia.address = $1::inet"#;
        let interface: Option<Self> = sqlx::query_as(query)
            .bind(ip.to_string())
            .fetch_optional(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(interface)
    }

    pub async fn find_by_machine_ids(
        txn: &mut Transaction<'_, Postgres>,
        machine_ids: &[MachineId],
    ) -> Result<HashMap<MachineId, Vec<MachineInterface>>, DatabaseError> {
        // The .unwrap() in the `group_map_by` call is ok - because we are only
        // searching for Machines which have associated MachineIds
        let str_ids: Vec<String> = machine_ids.iter().map(|id| id.to_string()).collect();
        Ok(
            MachineInterface::find_by(txn, ObjectFilter::List(&str_ids), "machine_id")
                .await?
                .into_iter()
                .into_group_map_by(|interface| interface.machine_id.clone().unwrap()),
        )
    }

    pub async fn find_host_primary_interface_by_dpu_id(
        txn: &mut Transaction<'_, Postgres>,
        dpu_machine_id: &MachineId,
    ) -> Result<Option<MachineInterface>, DatabaseError> {
        let query =
            "SELECT * FROM machine_interfaces WHERE attached_dpu_machine_id = $1 AND primary_interface=TRUE AND (machine_id!=attached_dpu_machine_id OR machine_id IS NULL)";
        let Some(mut machine_interface) = sqlx::query_as::<_, MachineInterface>(query)
            .bind(dpu_machine_id.to_string())
            .fetch_optional(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))? else {
            return Ok(None);
        };

        let mut addresses_for_interfaces = MachineInterfaceAddress::find_for_interface(
            &mut *txn,
            UuidKeyedObjectFilter::List(&[machine_interface.id]),
        )
        .await?;

        if let Some(addresses) = addresses_for_interfaces.remove(&machine_interface.id) {
            machine_interface.addresses = addresses;
        } else {
            tracing::warn!("Interface {0} has no addresses", &machine_interface.id);
        }

        Ok(Some(machine_interface))
    }

    pub async fn count_by_segment_id(
        txn: &mut Transaction<'_, Postgres>,
        segment_id: &uuid::Uuid,
    ) -> Result<usize, DatabaseError> {
        let query = "SELECT count(*) FROM machine_interfaces WHERE segment_id = $1";
        let (address_count,): (i64,) = sqlx::query_as(query)
            .bind(segment_id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(address_count.max(0) as usize)
    }

    pub async fn find_one(
        txn: &mut Transaction<'_, Postgres>,
        interface_id: uuid::Uuid,
    ) -> CarbideResult<MachineInterface> {
        let mut interfaces =
            MachineInterface::find_by(txn, ObjectFilter::One(interface_id.to_string()), "id")
                .await
                .map_err(CarbideError::from)?;
        match interfaces.len() {
            0 => Err(CarbideError::FindOneReturnedNoResultsError(interface_id)),
            1 => Ok(interfaces.remove(0)),
            _ => Err(CarbideError::FindOneReturnedManyResultsError(interface_id)),
        }
    }

    // Returns (MachineInterface, newly_created_interface).
    // newly_created_interface indicates that we couldn't find a MachineInterface so created new
    // one.
    pub async fn find_or_create_machine_interface(
        txn: &mut Transaction<'_, Postgres>,
        machines: Option<MachineId>,
        mac_address: MacAddress,
        relay: IpAddr,
    ) -> CarbideResult<Self> {
        match machines {
            None => {
                tracing::info!(
                    "Found no existing machine with mac address {} using network with relay: {}",
                    mac_address,
                    relay
                );
                Ok(MachineInterface::validate_existing_mac_and_create(
                    &mut *txn,
                    mac_address,
                    relay,
                )
                .await?)
            }
            Some(_) => {
                let mut ifcs =
                    MachineInterface::find_by_mac_address(&mut *txn, mac_address).await?;
                match ifcs.len() {
                    1 => Ok(ifcs.remove(0)),
                    n => {
                        tracing::warn!(
                            "{0} existing mac address ({1}) for network segment (relay ip: {2})",
                            n,
                            &mac_address,
                            &relay
                        );
                        Err(CarbideError::NetworkSegmentDuplicateMacAddress(mac_address))
                    }
                }
            }
        }
    }

    /// Do basic validating on existing macs and create the interface if it does not exist
    pub async fn validate_existing_mac_and_create(
        txn: &mut Transaction<'_, Postgres>,
        mac_address: MacAddress,
        relay: IpAddr,
    ) -> CarbideResult<Self> {
        let mut existing_mac = MachineInterface::find_by_mac_address(txn, mac_address).await?;
        match &existing_mac.len() {
            0 => {
                tracing::debug!(
                    "No existing machine_interface with mac address[{0}] exists yet, creating one.",
                    mac_address
                );
                match NetworkSegment::for_relay(txn, relay).await? {
                    None => Err(CarbideError::NoNetworkSegmentsForRelay(relay)),
                    Some(segment) => {
                        // actually create the interface
                        let v = MachineInterface::create(
                            txn,
                            &segment,
                            &mac_address,
                            segment.subdomain_id,
                            Machine::generate_hostname_from_uuid(&uuid::Uuid::new_v4()),
                            true,
                            AddressSelectionStrategy::Automatic,
                        )
                        .await?;
                        Ok(v)
                    }
                }
            }
            1 => {
                tracing::debug!("An existing mac address[{0}] exists yet, validating the relay and returning it.", mac_address);
                let mac = existing_mac.remove(0);
                // Ensure the relay segment exists before blindly giving the mac address back out
                match NetworkSegment::for_relay(txn, relay).await? {
                    None => Err(CarbideError::NoNetworkSegmentsForRelay(relay)),
                    Some(_) => Ok(mac),
                }
            }
            _ => {
                tracing::warn!(
                    "More than existing mac address ({0}) for network segment (relay ip: {1})",
                    &mac_address,
                    &relay
                );
                Err(CarbideError::NetworkSegmentDuplicateMacAddress(mac_address))
            }
        }
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        segment: &NetworkSegment,
        macaddr: &MacAddress,
        domain_id: Option<uuid::Uuid>,
        hostname: String,
        primary_interface: bool,
        addresses: AddressSelectionStrategy<'_>,
    ) -> CarbideResult<Self> {
        // We're potentially about to insert a couple rows, so create a savepoint.
        let mut inner_txn = txn
            .begin()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "begin", e))?;
        let query = "LOCK TABLE machine_interfaces IN ACCESS EXCLUSIVE MODE";
        sqlx::query(query)
            .execute(&mut *inner_txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        let dhcp_handler = UsedAdminNetworkIpResolver {
            segment_id: segment.id,
        };

        // If either requested addresses are auto-generated, we lock the entire table.
        let allocated_addresses =
            IpAllocator::new(&mut inner_txn, segment, &dhcp_handler, addresses).await?;

        let query = "INSERT INTO machine_interfaces
            (segment_id, mac_address, hostname, domain_id, primary_interface)
            VALUES
            ($1::uuid, $2::macaddr, $3::varchar, $4::uuid, $5::bool) RETURNING id";
        let interface_id: (Uuid,) = sqlx::query_as(query)
            .bind(segment.id())
            .bind(macaddr)
            .bind(hostname)
            .bind(domain_id)
            .bind(primary_interface)
            .fetch_one(&mut *inner_txn)
            .await
            .map_err(|err: sqlx::Error| match err {
                sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_DUPLICATE_MAC) => {
                    CarbideError::NetworkSegmentDuplicateMacAddress(*macaddr)
                }
                sqlx::Error::Database(e)
                    if e.constraint() == Some(SQL_VIOLATION_ONE_PRIMARY_INTERFACE) =>
                {
                    CarbideError::OnePrimaryInterface
                }
                _ => CarbideError::from(DatabaseError::new(file!(), line!(), query, err)),
            })?;

        let query = "INSERT INTO machine_interface_addresses (interface_id, address) VALUES ($1::uuid, $2::inet)";
        for (_prefix_id, address) in allocated_addresses {
            sqlx::query(query)
                .bind(interface_id.0)
                .bind(address?)
                .fetch_all(&mut *inner_txn)
                .await
                .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;
        }

        inner_txn
            .commit()
            .await
            .map_err(|e| CarbideError::DatabaseError(file!(), "commit", e))?;

        Ok(
            MachineInterface::find_by(txn, ObjectFilter::One(interface_id.0.to_string()), "id")
                .await?
                .remove(0),
        )
    }

    /// Get a reference to the machine interface's segment id.
    pub fn segment_id(&self) -> Uuid {
        self.segment_id
    }

    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    pub fn primary_interface(&self) -> bool {
        self.primary_interface
    }

    // Convenience function to load the machine which owns this interface
    pub async fn load_machine(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Option<Machine>, DatabaseError> {
        match &self.machine_id {
            Some(machine_id) => {
                Machine::find_one(txn, machine_id, MachineSearchConfig::default()).await
            }
            None => Ok(None),
        }
    }

    async fn find_by<'a>(
        txn: &mut Transaction<'_, Postgres>,
        filter: ObjectFilter<'_, String>,
        column: &'a str,
    ) -> Result<Vec<MachineInterface>, DatabaseError> {
        let base_query = "SELECT * FROM machine_interfaces mi {where}".to_owned();

        let mut interfaces = match filter {
            ObjectFilter::All => {
                sqlx::query_as::<_, MachineInterface>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| {
                        DatabaseError::new(file!(), line!(), "machine_interfaces All", e)
                    })?
            }
            ObjectFilter::One(id) => {
                let query = base_query
                    .replace("{where}", &format!("WHERE mi.{column}='{}'", id))
                    .replace("{column}", column);
                sqlx::query_as::<_, MachineInterface>(&query)
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| {
                        DatabaseError::new(file!(), line!(), "machine_interfaces One", e)
                    })?
            }
            ObjectFilter::List(list) => {
                if list.is_empty() {
                    return Ok(Vec::new());
                }

                let mut columns = String::new();
                for item in list {
                    if !columns.is_empty() {
                        columns.push(',');
                    }
                    columns.push('\'');
                    columns.push_str(item);
                    columns.push('\'');
                }
                let query = base_query
                    .replace("{where}", &format!("WHERE mi.{column} IN ({})", columns))
                    .replace("{column}", column);

                sqlx::query_as::<_, MachineInterface>(&query)
                    .fetch_all(&mut *txn)
                    .await
                    .map_err(|e| {
                        DatabaseError::new(file!(), line!(), "machine_interfaces List", e)
                    })?
            }
        };

        let mut addresses_for_interfaces = MachineInterfaceAddress::find_for_interface(
            &mut *txn,
            UuidKeyedObjectFilter::List(
                interfaces
                    .iter()
                    .map(|interface| interface.id)
                    .collect::<Vec<Uuid>>()
                    .as_slice(),
            ),
        )
        .await?;

        interfaces.iter_mut().for_each(|interface| {
            if let Some(addresses) = addresses_for_interfaces.remove(&interface.id) {
                interface.addresses = addresses;
            } else {
                tracing::warn!("Interface {0} has no addresses", &interface.id);
            }
        });

        Ok(interfaces)
    }

    pub async fn get_machine_interface_primary(
        machine_id: &MachineId,
        txn: &mut sqlx::Transaction<'_, Postgres>,
    ) -> CarbideResult<MachineInterface> {
        MachineInterface::find_by_machine_ids(txn, &[machine_id.clone()])
            .await?
            .remove(machine_id)
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "interface",
                id: machine_id.to_string(),
            })?
            .into_iter()
            .filter(|m_intf| m_intf.primary_interface())
            .collect::<Vec<MachineInterface>>()
            .pop()
            .ok_or_else(|| {
                CarbideError::GenericError(format!(
                    "Couldn't find primary interface for {}.",
                    machine_id
                ))
            })
    }

    /// This function creates Proactive Host Machine Interface with all available information.
    /// Parsed Mac: Found in DPU's topology data
    /// Relay IP: Taken from fixed Admin network segment. Relay IP is used only to identify related
    /// segment.
    /// Retunrs: Machine Interface, True if new interface is created.
    pub async fn create_host_machine_interface_proactively(
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        hardware_info: Option<&HardwareInfo>,
        dpu_id: &MachineId,
    ) -> Result<Self, CarbideError> {
        let admin_network = NetworkSegment::admin(txn).await?;

        // Using gateway IP as relay IP. This is just to enable next algorithm to find related network
        // segment.
        let prefix = admin_network
            .prefixes
            .iter()
            .filter(|x| x.prefix.is_ipv4())
            .last()
            .ok_or(CarbideError::AdminNetworkNotConfigured)?;

        let Some(gateway) = prefix.gateway.map(|x|x.ip()) else {
            return Err(CarbideError::AdminNetworkNotConfigured);
        };

        // Host mac is stored at DPU topology data.
        let host_mac = hardware_info
            .map(|x| x.factory_mac_address())
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "Hardware Info",
                id: dpu_id.to_string(),
            })??;

        let existing_machine = Machine::find_existing_machine(txn, host_mac, gateway)
            .await
            .map_err(CarbideError::from)?;

        let machine_interface =
            Self::find_or_create_machine_interface(txn, existing_machine, host_mac, gateway)
                .await?;
        machine_interface
            .associate_interface_with_dpu_machine(txn, dpu_id)
            .await?;

        Ok(machine_interface)
    }

    pub async fn find_by_machine_and_segment(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        segment_id: uuid::Uuid,
    ) -> Result<Self, DatabaseError> {
        let query =
            "SELECT * FROM machine_interfaces WHERE machine_id = $1 AND segment_id = $2::uuid";
        sqlx::query_as(query)
            .bind(machine_id.to_string())
            .bind(segment_id)
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}

#[async_trait::async_trait]
impl UsedIpResolver for UsedAdminNetworkIpResolver {
    async fn used_ips(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<(IpNetwork,)>, DatabaseError> {
        let query = "
SELECT address FROM machine_interface_addresses
INNER JOIN machine_interfaces ON machine_interfaces.id = machine_interface_addresses.interface_id
INNER JOIN network_segments ON machine_interfaces.segment_id = network_segments.id
WHERE network_segments.id = $1::uuid";

        sqlx::query_as(query)
            .bind(self.segment_id)
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}
