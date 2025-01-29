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

use std::net::IpAddr;
use std::ops::DerefMut;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use mac_address::MacAddress;
use sqlx::postgres::PgRow;
use sqlx::{Acquire, FromRow, Postgres, Row, Transaction};

use super::dhcp_entry::DhcpEntry;
use super::{ColumnInfo, DatabaseError, FilterableQueryBuilder, ObjectColumnFilter};
use crate::db::address_selection_strategy::AddressSelectionStrategy;
use crate::db::machine::Machine;
use crate::db::machine_interface_address::MachineInterfaceAddress;
use crate::db::network_segment::NetworkSegment;
use crate::db::predicted_machine_interface::PredictedMachineInterface;
use crate::dhcp::allocation::{IpAllocator, UsedIpResolver};
use crate::model::hardware_info::HardwareInfo;
use crate::model::machine::MachineInterfaceSnapshot;
use crate::{CarbideError, CarbideResult};
use forge_uuid::machine::MachineId;
use forge_uuid::{domain::DomainId, machine::MachineInterfaceId, network::NetworkSegmentId};

const SQL_VIOLATION_DUPLICATE_MAC: &str = "machine_interfaces_segment_id_mac_address_key";
const SQL_VIOLATION_ONE_PRIMARY_INTERFACE: &str = "one_primary_interface_per_machine";

pub struct UsedAdminNetworkIpResolver {
    pub segment_id: NetworkSegmentId,
}

#[derive(Clone, Copy)]
pub struct IdColumn;
impl ColumnInfo<'_> for IdColumn {
    type TableType = MachineInterfaceSnapshot;
    type ColumnType = MachineInterfaceId;
    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Clone, Copy)]
pub struct MacAddressColumn;
impl ColumnInfo<'_> for MacAddressColumn {
    type TableType = MachineInterfaceSnapshot;
    type ColumnType = MacAddress;
    fn column_name(&self) -> &'static str {
        "mac_address"
    }
}

#[derive(Clone, Copy)]
pub struct MachineIdColumn;
impl ColumnInfo<'_> for MachineIdColumn {
    type TableType = MachineInterfaceSnapshot;
    type ColumnType = MachineId;
    fn column_name(&self) -> &'static str {
        "machine_id"
    }
}

/// A denormalized view on machine_interfaces that aggregates the addresses and vendors using
/// JSON_AGG. This query is also used by machines.rs as a subquery when collecting machine
/// snapshots.
pub const MACHINE_INTERFACE_SNAPSHOT_QUERY: &str = r#"
    WITH addresses_agg AS (
        SELECT a.interface_id,
            json_agg(a.address) AS json
        FROM machine_interface_addresses a
        GROUP BY a.interface_id
    ),
    vendors_agg AS (
        SELECT d.machine_interface_id,
            json_agg(d.vendor_string) AS json
        FROM dhcp_entries d
        GROUP BY d.machine_interface_id
    )
    SELECT mi.*,
        COALESCE(addresses_agg.json, '[]'::json) AS addresses,
        COALESCE(vendors_agg.json, '[]'::json) AS vendors,
        ns.network_segment_type
    FROM machine_interfaces mi
    JOIN network_segments ns ON ns.id = mi.segment_id
    LEFT JOIN addresses_agg ON addresses_agg.interface_id = mi.id
    LEFT JOIN vendors_agg ON vendors_agg.machine_interface_id = mi.id
"#;

impl<'r> FromRow<'r, PgRow> for MachineInterfaceSnapshot {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        // Note: Make sure to use the MACHINE_INTERFACE_SNAPSHOT_QUERY when querying, or these
        // columns will not be present in the result.
        let addrs_json: sqlx::types::Json<Vec<Option<IpAddr>>> = row.try_get("addresses")?;
        let vendors_json: sqlx::types::Json<Vec<Option<String>>> = row.try_get("vendors")?;

        Ok(MachineInterfaceSnapshot {
            id: row.try_get("id")?,
            attached_dpu_machine_id: row.try_get("attached_dpu_machine_id")?,
            machine_id: row.try_get("machine_id")?,
            segment_id: row.try_get("segment_id")?,
            domain_id: row.try_get("domain_id")?,
            hostname: row.try_get("hostname")?,
            mac_address: row.try_get("mac_address")?,
            primary_interface: row.try_get("primary_interface")?,
            created: row.try_get("created")?,
            last_dhcp: row.try_get("last_dhcp")?,
            network_segment_type: row.try_get("network_segment_type")?,
            addresses: addrs_json.0.into_iter().flatten().collect(),
            vendors: vendors_json.0.into_iter().flatten().collect(),
        })
    }
}

/// Sets current machine interface primary attribute to provided value.
pub async fn set_primary_interface(
    interface_id: &MachineInterfaceId,
    primary: bool,
    txn: &mut Transaction<'_, Postgres>,
) -> Result<MachineInterfaceId, DatabaseError> {
    let query = "UPDATE machine_interfaces SET primary_interface=$1 where id=$2::uuid RETURNING id";
    sqlx::query_as(query)
        .bind(primary)
        .bind(*interface_id)
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
}

pub async fn associate_interface_with_dpu_machine(
    interface_id: &MachineInterfaceId,
    dpu_machine_id: &MachineId,
    txn: &mut Transaction<'_, Postgres>,
) -> Result<MachineInterfaceId, DatabaseError> {
    let query =
        "UPDATE machine_interfaces SET attached_dpu_machine_id=$1 where id=$2::uuid RETURNING id";
    sqlx::query_as(query)
        .bind(dpu_machine_id.to_string())
        .bind(*interface_id)
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
}

pub async fn associate_interface_with_machine(
    interface_id: &MachineInterfaceId,
    machine_id: &MachineId,
    txn: &mut Transaction<'_, Postgres>,
) -> CarbideResult<MachineInterfaceId> {
    let query = "UPDATE machine_interfaces SET machine_id=$1 where id=$2::uuid RETURNING id";
    sqlx::query_as(query)
        .bind(machine_id.to_string())
        .bind(*interface_id)
        .fetch_one(txn.deref_mut())
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

pub async fn find_by_mac_address(
    txn: &mut Transaction<'_, Postgres>,
    macaddr: MacAddress,
) -> Result<Vec<MachineInterfaceSnapshot>, DatabaseError> {
    find_by(txn, ObjectColumnFilter::One(MacAddressColumn, &macaddr)).await
}

pub async fn find_by_ip(
    txn: &mut Transaction<'_, Postgres>,
    ip: IpAddr,
) -> Result<Option<MachineInterfaceSnapshot>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            r#"{}
            INNER JOIN machine_interface_addresses mia on mia.interface_id=mi.id
            WHERE mia.address = $1::inet"#,
            MACHINE_INTERFACE_SNAPSHOT_QUERY
        );
    }
    sqlx::query_as(&query)
        .bind(ip)
        .fetch_optional(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))
}

pub async fn find_all(
    txn: &mut Transaction<'_, Postgres>,
) -> CarbideResult<Vec<MachineInterfaceSnapshot>> {
    find_by(txn, ObjectColumnFilter::All::<IdColumn>)
        .await
        .map_err(CarbideError::from)
}

#[cfg(test)] // only used in tests today
pub async fn find_by_machine_ids(
    txn: &mut Transaction<'_, Postgres>,
    machine_ids: &[MachineId],
) -> Result<std::collections::HashMap<MachineId, Vec<MachineInterfaceSnapshot>>, DatabaseError> {
    use itertools::Itertools;
    // The .unwrap() in the `group_map_by` call is ok - because we are only
    // searching for Machines which have associated MachineIds
    Ok(
        find_by(txn, ObjectColumnFilter::List(MachineIdColumn, machine_ids))
            .await?
            .into_iter()
            .into_group_map_by(|interface| interface.machine_id.clone().unwrap()),
    )
}

pub async fn count_by_segment_id(
    txn: &mut Transaction<'_, Postgres>,
    segment_id: &NetworkSegmentId,
) -> Result<usize, DatabaseError> {
    let query = "SELECT count(*) FROM machine_interfaces WHERE segment_id = $1";
    let (address_count,): (i64,) = sqlx::query_as(query)
        .bind(segment_id)
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    Ok(address_count.max(0) as usize)
}

pub async fn find_one(
    txn: &mut Transaction<'_, Postgres>,
    interface_id: MachineInterfaceId,
) -> CarbideResult<MachineInterfaceSnapshot> {
    let mut interfaces = find_by(txn, ObjectColumnFilter::One(IdColumn, &interface_id))
        .await
        .map_err(CarbideError::from)?;
    match interfaces.len() {
        0 => Err(CarbideError::FindOneReturnedNoResultsError(interface_id.0)),
        1 => Ok(interfaces.remove(0)),
        _ => Err(CarbideError::FindOneReturnedManyResultsError(
            interface_id.0,
        )),
    }
}

// Returns (MachineInterface, newly_created_interface).
// newly_created_interface indicates that we couldn't find a MachineInterface so created new
// one.
pub async fn find_or_create_machine_interface(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: Option<MachineId>,
    mac_address: MacAddress,
    relay: IpAddr,
) -> CarbideResult<MachineInterfaceSnapshot> {
    match machine_id {
        None => {
            tracing::info!(
                %mac_address,
                %relay,
                "Found no existing machine with mac address {mac_address} using network with relay {relay}",
            );
            Ok(validate_existing_mac_and_create(&mut *txn, mac_address, relay).await?)
        }
        Some(_) => {
            let mut ifcs = find_by_mac_address(&mut *txn, mac_address).await?;
            match ifcs.len() {
                1 => Ok(ifcs.remove(0)),
                n => {
                    tracing::warn!(
                        %mac_address,
                        relay_ip = %relay,
                        num_mac_address = n,
                        "Duplicate mac address for network segment",
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
) -> CarbideResult<MachineInterfaceSnapshot> {
    let mut existing_mac = find_by_mac_address(txn, mac_address).await?;
    match &existing_mac.len() {
        0 => {
            tracing::debug!(
                %mac_address,
                "No existing machine_interface with mac address exists yet, creating one",
            );
            match NetworkSegment::for_relay(txn, relay).await? {
                None => Err(CarbideError::internal(format!(
                    "No network segment defined for relay address: {relay}"
                ))),
                Some(segment) => {
                    // actually create the interface
                    let v = create(
                        txn,
                        &segment,
                        &mac_address,
                        segment.subdomain_id,
                        true,
                        AddressSelectionStrategy::Automatic,
                    )
                    .await?;
                    Ok(v)
                }
            }
        }
        1 => {
            tracing::debug!(
                %mac_address,
                "Mac address exists, validating the relay and returning it",
            );
            let mac = existing_mac.remove(0);
            // Ensure the relay segment exists before blindly giving the mac address back out
            match NetworkSegment::for_relay(txn, relay).await? {
                Some(ifc) if ifc.id == mac.segment_id => Ok(mac),
                Some(ifc) => Err(CarbideError::internal(format!(
                    "Network segment mismatch for existing mac address: {0} expected: {1} actual from network switch: {2}",
                    mac.mac_address,
                    mac.segment_id,
                    ifc.id,
                ))),
                None => Err(CarbideError::internal(format!("No network segment defined for relay address: {relay}"))),
            }
        }
        _ => {
            tracing::warn!(
                %mac_address,
                %relay,
                "More than one existing mac address for network segment",
            );
            Err(CarbideError::NetworkSegmentDuplicateMacAddress(mac_address))
        }
    }
}

pub async fn create(
    txn: &mut Transaction<'_, Postgres>,
    segment: &NetworkSegment,
    macaddr: &MacAddress,
    domain_id: Option<DomainId>,
    primary_interface: bool,
    addresses: AddressSelectionStrategy,
) -> CarbideResult<MachineInterfaceSnapshot> {
    // We're potentially about to insert a couple rows, so create a savepoint.
    let mut inner_txn = txn
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin", e))?;

    // If either requested addresses are auto-generated, we lock the entire table
    // by way of the inner_txn.
    let query = "LOCK TABLE machine_interfaces_lock IN ACCESS EXCLUSIVE MODE";
    sqlx::query(query)
        .execute(&mut *inner_txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    // Use the UsedAdminNetworkIpResolver, which specifically looks at
    // the machine interface addresses table in the database for finding
    // the next available IP.
    let dhcp_handler: Box<dyn UsedIpResolver + Send> = Box::new(UsedAdminNetworkIpResolver {
        segment_id: segment.id,
    });

    // In the case of machine interfaces, the IpAllocator is going to remain
    // a hard-coded /32 allocation prefix. This is in constrast to tenant
    // instances, which may be a /32, or in the case of FNN, a /30 or otherwise.
    let prefix_length = 32;
    let addresses_allocator = IpAllocator::new(
        &mut inner_txn,
        segment,
        dhcp_handler,
        addresses,
        prefix_length,
    )
    .await?;

    let mut hostname: String = "".to_string();
    let mut allocated_addresses = Vec::new();
    for (_, maybe_address) in addresses_allocator {
        let address = maybe_address?;
        if address.prefix() != prefix_length {
            return Err(
                CarbideError::internal(
                    format!(
                        "received allocated address candidate with mismatched prefix length (expected: {}, got: {}",
                        prefix_length, address.prefix())));
        }
        allocated_addresses.push(address.ip());
        if hostname.is_empty() && address.is_ipv4() {
            hostname = address_to_hostname(&address.ip())?;
        }
    }
    if hostname.is_empty() {
        return Err(CarbideError::internal(
            "Could not generate hostname".to_string(),
        ));
    }

    let interface_id = insert_machine_interface(
        &mut inner_txn,
        segment.id(),
        macaddr,
        hostname,
        domain_id,
        primary_interface,
    )
    .await?;

    for address in allocated_addresses {
        insert_machine_interface_address(&mut inner_txn, &interface_id, &address).await?;
    }

    inner_txn
        .commit()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "commit", e))?;

    Ok(
        find_by(txn, ObjectColumnFilter::One(IdColumn, &interface_id))
            .await?
            .remove(0),
    )
}

// Support dpu-agent/scout transition from machine_interface_id to source IP.
// Allow either for now.
pub async fn find_by_ip_or_id(
    txn: &mut Transaction<'_, Postgres>,
    remote_ip: Option<IpAddr>,
    interface_id: Option<MachineInterfaceId>,
) -> Result<MachineInterfaceSnapshot, CarbideError> {
    if let Some(remote_ip) = remote_ip {
        if let Some(interface) = find_by_ip(txn, remote_ip)
            .await
            .map_err(CarbideError::from)?
        {
            // remove debug message by Apr 2024
            tracing::debug!(
                interface_id = %interface.id,
                %remote_ip,
                "Loaded interface by remote IP"
            );
            return Ok(interface);
        }
    }
    match interface_id {
        Some(interface_id) => find_one(txn, interface_id).await,
        None => Err(CarbideError::NotFoundError {
            kind: "machine_interface",
            id: format!("remote_ip={remote_ip:?},interface_id={interface_id:?}"),
        }),
    }
}

/// insert_machine_interface inserts a new machine interface record
/// into the database, returning the newly minted MachineInterfaceId
/// for the corresponding record.
async fn insert_machine_interface(
    txn: &mut Transaction<'_, Postgres>,
    segment_id: &NetworkSegmentId,
    mac_address: &MacAddress,
    hostname: String,
    domain_id: Option<DomainId>,
    is_primary_interface: bool,
) -> CarbideResult<MachineInterfaceId> {
    let query = "INSERT INTO machine_interfaces
        (segment_id, mac_address, hostname, domain_id, primary_interface)
        VALUES
        ($1::uuid, $2::macaddr, $3::varchar, $4::uuid, $5::bool) RETURNING id";

    let (interface_id,): (MachineInterfaceId,) = sqlx::query_as(query)
        .bind(segment_id)
        .bind(mac_address)
        .bind(hostname)
        .bind(domain_id)
        .bind(is_primary_interface)
        .fetch_one(txn.deref_mut())
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_DUPLICATE_MAC) => {
                CarbideError::NetworkSegmentDuplicateMacAddress(*mac_address)
            }
            sqlx::Error::Database(e)
                if e.constraint() == Some(SQL_VIOLATION_ONE_PRIMARY_INTERFACE) =>
            {
                CarbideError::OnePrimaryInterface
            }
            _ => DatabaseError::new(file!(), line!(), query, err).into(),
        })?;

    Ok(interface_id)
}

/// insert_machine_interface_address inserts a new machine interface
/// address entry into the database. In the case of machine interfaces,
/// this explicitly takes an `IpAddr`, since machine interfaces are
/// always going to be a /32. It is up to the caller to ensure a possible
/// IpNetwork returned from the IpAllocator is of the correct size.
async fn insert_machine_interface_address(
    txn: &mut Transaction<'_, Postgres>,
    interface_id: &MachineInterfaceId,
    address: &IpAddr,
) -> CarbideResult<()> {
    let query = "INSERT INTO machine_interface_addresses (interface_id, address) VALUES ($1::uuid, $2::inet)";
    sqlx::query(query)
        .bind(interface_id)
        .bind(address)
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
    Ok(())
}

/// address_to_hostname converts an IpAddr address to a hostname,
/// verifying the resulting hostname is actually a valid DNS name
/// before returning it.
fn address_to_hostname(address: &IpAddr) -> CarbideResult<String> {
    let hostname = address.to_string().replace('.', "-");
    match domain::base::Name::<octseq::array::Array<255>>::from_str(hostname.as_str()).is_ok() {
        true => Ok(hostname),
        false => Err(CarbideError::internal(format!(
            "invalid address to hostname: {}",
            hostname
        ))),
    }
}

async fn find_by<'a, C: ColumnInfo<'a, TableType = MachineInterfaceSnapshot>>(
    txn: &mut Transaction<'_, Postgres>,
    filter: ObjectColumnFilter<'a, C>,
) -> Result<Vec<MachineInterfaceSnapshot>, DatabaseError> {
    let mut query = FilterableQueryBuilder::new(MACHINE_INTERFACE_SNAPSHOT_QUERY)
        .filter_relation(&filter, Some("mi"));
    let interfaces = query
        .build_query_as::<MachineInterfaceSnapshot>()
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query.sql(), e))?;
    Ok(interfaces)
}

#[cfg(test)] // currently only used by tests
pub async fn get_machine_interface_primary(
    machine_id: &MachineId,
    txn: &mut sqlx::Transaction<'_, Postgres>,
) -> CarbideResult<MachineInterfaceSnapshot> {
    find_by_machine_ids(txn, &[machine_id.clone()])
        .await?
        .remove(machine_id)
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "interface",
            id: machine_id.to_string(),
        })?
        .into_iter()
        .filter(|m_intf| m_intf.primary_interface)
        .collect::<Vec<MachineInterfaceSnapshot>>()
        .pop()
        .ok_or_else(|| {
            CarbideError::internal(format!(
                "Couldn't find primary interface for {}.",
                machine_id
            ))
        })
}

/// Move an entry from predicted_machine_interfaces to machine_interfaces, using the given relay IP
/// to know what network segment to assign.
pub async fn move_predicted_machine_interface_to_machine(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    predicted_machine_interface: &PredictedMachineInterface,
    relay_ip: IpAddr,
) -> Result<(), CarbideError> {
    tracing::info!(
        machine_id=%predicted_machine_interface.machine_id,
        mac_address=%predicted_machine_interface.mac_address,
        %relay_ip,
        "Got DHCP from predicted machine interface, moving to machine"
    );
    let Some(network_segment) = NetworkSegment::for_relay(txn, relay_ip).await? else {
        return Err(CarbideError::internal(format!(
            "No network segment defined for relay address: {relay_ip}"
        )));
    };

    if network_segment.segment_type != predicted_machine_interface.expected_network_segment_type {
        return Err(CarbideError::internal(format!(
            "Got DHCP for predicted host with MAC address {0} on network segment {1}, which is not of the expected type {2}",
            predicted_machine_interface.mac_address,
            network_segment.id,
            predicted_machine_interface.expected_network_segment_type,
        )));
    }

    let machine_interface_id = match self::find_by_mac_address(
        txn,
        predicted_machine_interface.mac_address,
    )
    .await?
    .into_iter()
    .find(|machine_interface| machine_interface.segment_id == network_segment.id)
    {
        Some(machine_interface_snapshot) => {
            match machine_interface_snapshot.machine_id.as_ref() {
                None => {
                    // This host has already DHCP'd once and created an anonymous machine_interface,
                    // we will migrate it below.
                    machine_interface_snapshot.id
                }
                Some(machine_id) => {
                    if machine_id.ne(&predicted_machine_interface.machine_id) {
                        tracing::error!(
                            %machine_id,
                            "Can't migrate predicted_machine_interface to machine_interface: one already exists with this MAC address"
                        );
                        return Err(CarbideError::NetworkSegmentDuplicateMacAddress(
                            predicted_machine_interface.mac_address,
                        ));
                    } else {
                        tracing::warn!(
                            %machine_id,
                            "Bug: trying to move predicted_machine_interface to machine_interface, but it's already a part of this machine? Will proceed anyway."
                        );
                        machine_interface_snapshot.id
                    }
                }
            }
        }
        None => {
            // This host has never DHCP'd before, create a new machine_interface for it
            let machine_interface = create(
                txn,
                &network_segment,
                &predicted_machine_interface.mac_address,
                network_segment.subdomain_id,
                false,
                AddressSelectionStrategy::Automatic,
            )
            .await?;
            machine_interface.id
        }
    };

    // Take either the newly-created interface or the anonymous one we found, and associate it with
    // this machine.
    associate_interface_with_machine(
        &machine_interface_id,
        &predicted_machine_interface.machine_id,
        txn,
    )
    .await?;

    predicted_machine_interface.delete(txn).await?;
    Ok(())
}

/// This function creates Proactive Host Machine Interface with all available information.
/// Parsed Mac: Found in DPU's topology data
/// Relay IP: Taken from fixed Admin network segment. Relay IP is used only to identify related
/// segment.
/// Returns: Machine Interface, True if new interface is created.
pub async fn create_host_machine_dpu_interface_proactively(
    txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    hardware_info: Option<&HardwareInfo>,
    dpu_id: &MachineId,
) -> Result<MachineInterfaceSnapshot, CarbideError> {
    let admin_network = NetworkSegment::admin(txn).await?;

    // Using gateway IP as relay IP. This is just to enable next algorithm to find related network
    // segment.
    let prefix = admin_network
        .prefixes
        .iter()
        .filter(|x| x.prefix.is_ipv4())
        .last()
        .ok_or(CarbideError::AdminNetworkNotConfigured)?;

    let Some(gateway) = prefix.gateway else {
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
        find_or_create_machine_interface(txn, existing_machine, host_mac, gateway).await?;
    associate_interface_with_dpu_machine(&machine_interface.id, dpu_id, txn).await?;

    Ok(machine_interface)
}

pub async fn find_by_machine_and_segment(
    txn: &mut Transaction<'_, Postgres>,
    machine_id: &MachineId,
    segment_id: NetworkSegmentId,
) -> Result<Vec<MachineInterfaceSnapshot>, DatabaseError> {
    lazy_static! {
        static ref query: String = format!(
            "{} WHERE mi.machine_id = $1 AND mi.segment_id = $2::uuid",
            MACHINE_INTERFACE_SNAPSHOT_QUERY
        );
    }
    sqlx::query_as::<_, MachineInterfaceSnapshot>(&query)
        .bind(machine_id.to_string())
        .bind(segment_id)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), &query, e))
        .map(|interfaces| {
            interfaces
                .into_iter()
                .map(MachineInterfaceSnapshot::from)
                .collect()
        })
}

/// Record that this interface just DHCPed, so it must still exist
pub async fn update_last_dhcp(
    txn: &mut Transaction<'_, Postgres>,
    interface_id: MachineInterfaceId,
    timestamp: Option<DateTime<Utc>>,
) -> Result<(), DatabaseError> {
    let query_timestamp = match timestamp {
        Some(t) => t,
        None => Utc::now(),
    };
    let query = "UPDATE machine_interfaces SET last_dhcp = $1::TIMESTAMPTZ WHERE id=$2::uuid";
    sqlx::query(query)
        .bind(query_timestamp.to_rfc3339())
        .bind(interface_id)
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
    Ok(())
}

pub async fn delete(
    interface_id: &MachineInterfaceId,
    txn: &mut Transaction<'_, Postgres>,
) -> Result<(), DatabaseError> {
    let query = "DELETE FROM machine_interfaces WHERE id=$1";
    MachineInterfaceAddress::delete(txn, interface_id).await?;
    DhcpEntry::delete(txn, interface_id).await?;
    sqlx::query(query)
        .bind(*interface_id)
        .execute(txn.deref_mut())
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

    let query = "UPDATE machine_interfaces_deletion SET last_deletion=NOW() WHERE id = 1";
    sqlx::query(query)
        .bind(*interface_id)
        .execute(txn.deref_mut())
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
}

pub async fn delete_by_ip(
    txn: &mut Transaction<'_, Postgres>,
    ip: IpAddr,
) -> Result<Option<()>, DatabaseError> {
    let interface = find_by_ip(txn, ip).await?;

    let Some(interface) = interface else {
        return Ok(None);
    };

    delete(&interface.id, txn).await?;

    Ok(Some(()))
}

#[async_trait::async_trait]
impl UsedIpResolver for UsedAdminNetworkIpResolver {
    // DEPRECATED
    // With the introduction of `used_prefixes()` this is no
    // longer an accurate approach for finding all allocated
    // IPs in a segment, since used_ips() completely ignores
    // the fact wider prefixes may have been allocated, even
    // though in the case of machine interfaces, its probably
    // always going to just be a /32.
    //
    // used_ips returns the used (or allocated) IPs for machine
    // interfaces in a given network segment.
    //
    // More specifically, this is intended to specifically
    // target the `address` column of the `machine_interface_addresses`
    // table, in which a single /32 is stored (although, as an
    // `inet`, it could techincally also have a prefix length).
    async fn used_ips(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<IpAddr>, DatabaseError> {
        // IpAddrContainer is a small private struct used
        // for binding the result of the subsequent SQL
        // query, so we can implement FromRow and return
        // a Vec<IpAddr> a bit more easily.
        #[derive(FromRow)]
        struct IpAddrContainer {
            address: IpAddr,
        }

        let query = "
SELECT address FROM machine_interface_addresses
INNER JOIN machine_interfaces ON machine_interfaces.id = machine_interface_addresses.interface_id
INNER JOIN network_segments ON machine_interfaces.segment_id = network_segments.id
WHERE network_segments.id = $1::uuid";

        let containers: Vec<IpAddrContainer> = sqlx::query_as(query)
            .bind(self.segment_id)
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(containers.iter().map(|c| c.address).collect())
    }

    // used_prefixes returns the used (or allocated) prefixes
    // for machine interfaces in a given network segment.
    //
    // NOTE(Chet): This is kind of a hack! Machine interfaces
    // aren't allocated prefixes other than a /32, and I think
    // it might be confusing if we added a `prefix` column to the
    // machine_interface_addresses table (since it's always
    // just going to be a /32 anyway).
    //
    // So, instead of database schema changes, this just gets all
    // of the used IPs and turns them into IpNetworks.
    //
    // This could also potentially just always return an error
    // saying its not implemented for machine_interfaces, BUT,
    // it keeps it cleaner knowing the IpAllocator works via
    // calling used_prefixes() regardless of who is using it.
    async fn used_prefixes(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<IpNetwork>, DatabaseError> {
        let used_ips = self.used_ips(txn).await?;
        let mut ip_networks: Vec<IpNetwork> = Vec::new();
        for used_ip in used_ips {
            let network = IpNetwork::new(used_ip, 32).map_err(|e| {
                DatabaseError::new(
                    file!(),
                    line!(),
                    "machine_interface.used_prefixes",
                    sqlx::Error::Io(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        e.to_string(),
                    )),
                )
            })?;
            ip_networks.push(network);
        }
        Ok(ip_networks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_address_to_hostname() {
        let address: IpAddr = "192.168.1.0".parse().unwrap();
        let hostname = address_to_hostname(&address).unwrap();
        assert_eq!("192-168-1-0", hostname);
    }
}
