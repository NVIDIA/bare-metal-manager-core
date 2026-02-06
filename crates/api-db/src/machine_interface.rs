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
use std::ops::DerefMut;
use std::str::FromStr;

use carbide_uuid::domain::DomainId;
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use carbide_uuid::network::{NetworkPrefixId, NetworkSegmentId};
use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::switch::SwitchId;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use lazy_static::lazy_static;
use mac_address::MacAddress;
use model::address_selection_strategy::AddressSelectionStrategy;
use model::expected_machine::ExpectedHostNic;
use model::hardware_info::HardwareInfo;
use model::machine::MachineInterfaceSnapshot;
use model::machine_interface_address::MachineInterfaceAssociation;
use model::network_segment::{NetworkSegment, NetworkSegmentType};
use model::predicted_machine_interface::PredictedMachineInterface;
use sqlx::{FromRow, PgConnection, PgTransaction};

use super::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter};
use crate::ip_allocator::{IpAllocator, UsedIpResolver, next_machine_interface_v4_ip};
use crate::{DatabaseError, DatabaseResult, Transaction, network_segment as db_network_segment};

const SQL_VIOLATION_DUPLICATE_MAC: &str = "machine_interfaces_segment_id_mac_address_key";
const SQL_VIOLATION_ONE_PRIMARY_INTERFACE: &str = "one_primary_interface_per_machine";
const SQL_VIOLATION_MAX_ONE_ASSOCIATION: &str = "chk_max_one_association";

pub struct UsedAdminNetworkIpResolver {
    pub segment_id: NetworkSegmentId,
    // All the IPs which can not be allocated, e.g. SVI IP.
    pub busy_ips: Vec<IpAddr>,
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

#[derive(Clone, Copy)]
pub struct PowerShelfIdColumn;

impl ColumnInfo<'_> for PowerShelfIdColumn {
    type TableType = MachineInterfaceSnapshot;
    type ColumnType = PowerShelfId;
    fn column_name(&self) -> &'static str {
        "power_shelf_id"
    }
}

#[derive(Clone, Copy)]
pub struct SwitchIdColumn;

impl ColumnInfo<'_> for SwitchIdColumn {
    type TableType = MachineInterfaceSnapshot;
    type ColumnType = SwitchId;
    fn column_name(&self) -> &'static str {
        "switch_id"
    }
}

/// A denormalized view on machine_interfaces that aggregates the addresses and vendors using
/// JSON_AGG. This query is also used by machines.rs as a subquery when collecting machine
/// snapshots.
pub const MACHINE_INTERFACE_SNAPSHOT_QUERY: &str = r#"
    SELECT mi.*,
        COALESCE(addresses_agg.json, '[]'::json) AS addresses,
        COALESCE(vendors_agg.json, '[]'::json) AS vendors,
        ns.network_segment_type
    FROM machine_interfaces mi
    JOIN network_segments ns ON ns.id = mi.segment_id
    LEFT JOIN LATERAL (
        SELECT a.interface_id,
            json_agg(a.address) AS json
        FROM machine_interface_addresses a
        WHERE a.interface_id = mi.id
        GROUP BY a.interface_id
    ) AS addresses_agg ON true
    LEFT JOIN LATERAL (
        SELECT d.machine_interface_id,
            json_agg(d.vendor_string) AS json
        FROM dhcp_entries d
        WHERE d.machine_interface_id = mi.id
        GROUP BY d.machine_interface_id
    ) AS vendors_agg ON true
"#;

/// Sets current machine interface primary attribute to provided value.
pub async fn set_primary_interface(
    interface_id: &MachineInterfaceId,
    primary: bool,
    txn: &mut PgConnection,
) -> Result<MachineInterfaceId, DatabaseError> {
    let query = "UPDATE machine_interfaces SET primary_interface=$1 where id=$2::uuid RETURNING id";
    sqlx::query_as(query)
        .bind(primary)
        .bind(*interface_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn associate_interface_with_dpu_machine(
    interface_id: &MachineInterfaceId,
    dpu_machine_id: &MachineId,
    txn: &mut PgConnection,
) -> Result<MachineInterfaceId, DatabaseError> {
    let query =
        "UPDATE machine_interfaces SET attached_dpu_machine_id=$1 where id=$2::uuid RETURNING id";
    sqlx::query_as(query)
        .bind(dpu_machine_id)
        .bind(*interface_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn associate_interface_with_machine(
    interface_id: &MachineInterfaceId,
    association: MachineInterfaceAssociation,
    txn: &mut PgConnection,
) -> DatabaseResult<MachineInterfaceId> {
    let (column_name, association_type, id_value) = match association {
        MachineInterfaceAssociation::Machine(id) => ("machine_id", "Machine", id.to_string()),
        MachineInterfaceAssociation::Switch(id) => ("switch_id", "Switch", id.to_string()),
        MachineInterfaceAssociation::PowerShelf(id) => {
            ("power_shelf_id", "PowerShelf", id.to_string())
        }
    };
    let query = format!(
        "UPDATE machine_interfaces SET {}=$1, association_type=$2::association_type where id=$3::uuid RETURNING id",
        column_name
    );
    sqlx::query_as(&query)
        .bind(id_value)
        .bind(association_type)
        .bind(*interface_id)
        .fetch_one(txn)
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::Database(e)
                if e.constraint() == Some(SQL_VIOLATION_ONE_PRIMARY_INTERFACE) =>
            {
                DatabaseError::OnePrimaryInterface
            }
            sqlx::Error::Database(e)
                if e.constraint() == Some(SQL_VIOLATION_MAX_ONE_ASSOCIATION) =>
            {
                DatabaseError::MaxOneInterfaceAssociation
            }
            _ => DatabaseError::query(&query, err),
        })
}

pub async fn find_by_mac_address(
    txn: &mut PgConnection,
    macaddr: MacAddress,
) -> Result<Vec<MachineInterfaceSnapshot>, DatabaseError> {
    find_by(txn, ObjectColumnFilter::One(MacAddressColumn, &macaddr)).await
}

pub async fn find_by_ip(
    txn: &mut PgConnection,
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
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(&query, e))
}

pub async fn find_all(txn: &mut PgConnection) -> DatabaseResult<Vec<MachineInterfaceSnapshot>> {
    find_by(txn, ObjectColumnFilter::All::<IdColumn>).await
}

pub async fn find_by_machine_ids(
    txn: &mut PgConnection,
    machine_ids: &[MachineId],
) -> Result<std::collections::HashMap<MachineId, Vec<MachineInterfaceSnapshot>>, DatabaseError> {
    use itertools::Itertools;
    // The .unwrap() in the `group_map_by` call is ok - because we are only
    // searching for Machines which have associated MachineIds
    Ok(
        find_by(txn, ObjectColumnFilter::List(MachineIdColumn, machine_ids))
            .await?
            .into_iter()
            .into_group_map_by(|interface| interface.machine_id.unwrap()),
    )
}

pub async fn count_by_segment_id(
    txn: &mut PgConnection,
    segment_id: &NetworkSegmentId,
) -> Result<usize, DatabaseError> {
    let query = "SELECT count(*) FROM machine_interfaces WHERE segment_id = $1";
    let (address_count,): (i64,) = sqlx::query_as(query)
        .bind(segment_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(address_count.max(0) as usize)
}

pub async fn find_one(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    let mut interfaces = find_by(txn, ObjectColumnFilter::One(IdColumn, &interface_id)).await?;
    match interfaces.len() {
        0 => Err(DatabaseError::FindOneReturnedNoResultsError(
            interface_id.into(),
        )),
        1 => Ok(interfaces.remove(0)),
        _ => Err(DatabaseError::FindOneReturnedManyResultsError(
            interface_id.into(),
        )),
    }
}

// Returns (MachineInterface, newly_created_interface).
// newly_created_interface indicates that we couldn't find a MachineInterface so created new
// one.
pub async fn find_or_create_machine_interface(
    txn: &mut PgConnection,
    machine_id: Option<MachineId>,
    mac_address: MacAddress,
    relay: IpAddr,
    host_nic: Option<ExpectedHostNic>,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    match machine_id {
        None => {
            tracing::info!(
                %mac_address,
                %relay,
                "Found no existing machine with mac address {mac_address} using network with relay {relay}",
            );
            Ok(validate_existing_mac_and_create(&mut *txn, mac_address, relay, host_nic).await?)
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
                    Err(DatabaseError::NetworkSegmentDuplicateMacAddress(
                        mac_address,
                    ))
                }
            }
        }
    }
}

/// Do basic validating on existing macs and create the interface if it does not exist
pub async fn validate_existing_mac_and_create(
    txn: &mut PgConnection,
    mac_address: MacAddress,
    relay: IpAddr,
    host_nic: Option<ExpectedHostNic>,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    let mut existing_mac = find_by_mac_address(txn, mac_address).await?;
    match &existing_mac.len() {
        0 => {
            tracing::debug!(
                %mac_address,
                "No existing machine_interface with mac address exists yet, creating one",
            );

            let segment_type = if let Some(nic) = host_nic.clone() {
                if let Some(nic_type) = nic.nic_type {
                    match nic_type.to_ascii_lowercase().as_str() {
                        "bf3" => Some(NetworkSegmentType::Admin),
                        "dpu" => Some(NetworkSegmentType::Admin),
                        "bmc" => Some(NetworkSegmentType::Underlay),
                        "oob" => Some(NetworkSegmentType::Underlay),
                        "onboard" => Some(NetworkSegmentType::Admin),
                        &_ => None, // (default) use the relay ip if not forcing a segment type
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let network_segment = if let Some(network_segment_type) = segment_type {
                // only if forcing a segment type
                db_network_segment::for_segment_type(txn, relay, network_segment_type).await?
            } else {
                db_network_segment::for_relay(txn, relay).await?
            };

            if let Some(segment) = network_segment {
                // TODO: add fixed_ip handling
                if let Some(expected_nic) = host_nic.clone()
                    && let Some(ipaddr) = expected_nic.fixed_ip
                {
                    return Err(DatabaseError::internal(format!(
                        "IP reservation per MAC address not implemented yet for {ipaddr}, {mac_address}"
                    )));
                }

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
            } else {
                Err(DatabaseError::internal(format!(
                    "No network segment defined for relay address: {relay}"
                )))
            }
        }
        1 => {
            tracing::debug!(
                %mac_address,
                "Mac address exists, validating the relay and returning it",
            );
            let mac = existing_mac.remove(0);
            // Ensure the relay segment exists before blindly giving the mac address back out
            match crate::network_segment::for_relay(txn, relay).await? {
                Some(ifc) if ifc.id == mac.segment_id => Ok(mac),
                Some(ifc) => Err(DatabaseError::internal(format!(
                    "Network segment mismatch for existing mac address: {0} expected: {1} actual from network switch: {2}",
                    mac.mac_address, mac.segment_id, ifc.id,
                ))),
                None => Err(DatabaseError::internal(format!(
                    "No network segment defined for relay address: {relay}"
                ))),
            }
        }
        _ => {
            tracing::warn!(
                %mac_address,
                %relay,
                "More than one existing mac address for network segment",
            );
            Err(DatabaseError::NetworkSegmentDuplicateMacAddress(
                mac_address,
            ))
        }
    }
}

#[allow(txn_held_across_await)]
pub async fn create(
    txn: &mut PgConnection,
    segment: &NetworkSegment,
    macaddr: &MacAddress,
    domain_id: Option<DomainId>,
    primary_interface: bool,
    _addresses: AddressSelectionStrategy,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    // We're potentially about to insert a couple rows, so create a savepoint.
    let mut inner_txn = Transaction::begin_inner(txn).await?;

    // If either requested addresses are auto-generated, we lock the entire table
    // by way of the inner_txn.
    let query = "LOCK TABLE machine_interfaces_lock IN ACCESS EXCLUSIVE MODE";
    sqlx::query(query)
        .execute(inner_txn.as_pgconn())
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    // In the case of machine interfaces, we always use a hard-coded /32 allocation prefix.
    // In the case of machine interfaces, the IpAllocator is going to remain
    // a hard-coded /32 allocation prefix.
    let mut allocated_address = None;
    for prefix in &segment.prefixes {
        if let Some(address) = next_machine_interface_v4_ip(&mut inner_txn, prefix).await? {
            allocated_address = Some(address);
            break;
        }
    }
    let Some(allocated_address) = allocated_address else {
        return Err(crate::DatabaseError::ResourceExhausted(
            "No IP addresses left in network segment".to_string(),
        ));
    };

    let hostname = address_to_hostname(&allocated_address)?;
    let interface_id = insert_machine_interface(
        &mut inner_txn,
        &segment.id,
        macaddr,
        hostname,
        domain_id,
        primary_interface,
    )
    .await?;

    insert_machine_interface_address(&mut inner_txn, &interface_id, &allocated_address).await?;

    inner_txn.commit().await?;

    Ok(
        find_by(txn, ObjectColumnFilter::One(IdColumn, &interface_id))
            .await?
            .remove(0),
    )
}

pub async fn allocate_svi_ip(
    txn: &mut PgTransaction<'_>,
    segment: &NetworkSegment,
) -> DatabaseResult<(NetworkPrefixId, IpAddr)> {
    let dhcp_handler: Box<dyn UsedIpResolver + Send> = Box::new(UsedAdminNetworkIpResolver {
        segment_id: segment.id,
        busy_ips: vec![],
    });

    // If either requested addresses are auto-generated, we lock the entire table
    let query = "LOCK TABLE machine_interfaces_lock IN ACCESS EXCLUSIVE MODE";
    sqlx::query(query)
        .execute(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    let mut addresses_allocator = IpAllocator::new(
        txn,
        segment,
        dhcp_handler,
        AddressSelectionStrategy::Automatic,
        32,
    )
    .await?;

    // Carbide supports only one prefix with Ipv4.
    match addresses_allocator.next() {
        Some((id, Ok(address))) => Ok((id, address.ip())),
        Some((_, Err(err))) => Err(err),
        _ => Err(DatabaseError::ResourceExhausted(format!(
            "SVI IP not found for {}.",
            segment.id
        ))),
    }
}

// Support dpu-agent/scout transition from machine_interface_id to source IP.
// Allow either for now.
pub async fn find_by_ip_or_id(
    txn: &mut PgConnection,
    remote_ip: Option<IpAddr>,
    interface_id: Option<MachineInterfaceId>,
) -> Result<MachineInterfaceSnapshot, DatabaseError> {
    if let Some(remote_ip) = remote_ip
        && let Some(interface) = find_by_ip(txn, remote_ip).await?
    {
        // remove debug message by Apr 2024
        tracing::debug!(
            interface_id = %interface.id,
            %remote_ip,
            "Loaded interface by remote IP"
        );
        return Ok(interface);
    }
    match interface_id {
        Some(interface_id) => find_one(txn, interface_id).await,
        None => Err(DatabaseError::NotFoundError {
            kind: "machine_interface",
            id: format!("remote_ip={remote_ip:?},interface_id={interface_id:?}"),
        }),
    }
}

/// insert_machine_interface inserts a new machine interface record
/// into the database, returning the newly minted MachineInterfaceId
/// for the corresponding record.
async fn insert_machine_interface(
    txn: &mut PgConnection,
    segment_id: &NetworkSegmentId,
    mac_address: &MacAddress,
    hostname: String,
    domain_id: Option<DomainId>,
    is_primary_interface: bool,
) -> DatabaseResult<MachineInterfaceId> {
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
        .fetch_one(txn)
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::Database(e) if e.constraint() == Some(SQL_VIOLATION_DUPLICATE_MAC) => {
                DatabaseError::NetworkSegmentDuplicateMacAddress(*mac_address)
            }
            sqlx::Error::Database(e)
                if e.constraint() == Some(SQL_VIOLATION_ONE_PRIMARY_INTERFACE) =>
            {
                DatabaseError::OnePrimaryInterface
            }
            _ => DatabaseError::query(query, err),
        })?;

    Ok(interface_id)
}

/// insert_machine_interface_address inserts a new machine interface
/// address entry into the database. In the case of machine interfaces,
/// this explicitly takes an `IpAddr`, since machine interfaces are
/// always going to be a /32. It is up to the caller to ensure a possible
/// IpNetwork returned from the IpAllocator is of the correct size.
async fn insert_machine_interface_address(
    txn: &mut PgConnection,
    interface_id: &MachineInterfaceId,
    address: &IpAddr,
) -> DatabaseResult<()> {
    let query = "INSERT INTO machine_interface_addresses (interface_id, address) VALUES ($1::uuid, $2::inet)";
    sqlx::query(query)
        .bind(interface_id)
        .bind(address)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

/// address_to_hostname converts an IpAddr address to a hostname,
/// verifying the resulting hostname is actually a valid DNS name
/// before returning it.
fn address_to_hostname(address: &IpAddr) -> DatabaseResult<String> {
    let hostname = address.to_string().replace('.', "-");
    match domain::base::Name::<octseq::array::Array<255>>::from_str(hostname.as_str()).is_ok() {
        true => Ok(hostname),
        false => Err(DatabaseError::internal(format!(
            "invalid address to hostname: {hostname}"
        ))),
    }
}

async fn find_by<'a, C: ColumnInfo<'a, TableType = MachineInterfaceSnapshot>>(
    txn: &mut PgConnection,
    filter: ObjectColumnFilter<'a, C>,
) -> Result<Vec<MachineInterfaceSnapshot>, DatabaseError> {
    let mut query = FilterableQueryBuilder::new(MACHINE_INTERFACE_SNAPSHOT_QUERY)
        .filter_relation(&filter, Some("mi"));
    let interfaces = query
        .build_query_as::<MachineInterfaceSnapshot>()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))?;
    Ok(interfaces)
}

pub async fn get_machine_interface_primary(
    machine_id: &MachineId,
    txn: &mut PgConnection,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    find_by_machine_ids(txn, &[*machine_id])
        .await?
        .remove(machine_id)
        .ok_or_else(|| DatabaseError::NotFoundError {
            kind: "interface",
            id: machine_id.to_string(),
        })?
        .into_iter()
        .filter(|m_intf| m_intf.primary_interface)
        .collect::<Vec<MachineInterfaceSnapshot>>()
        .pop()
        .ok_or_else(|| {
            DatabaseError::internal(format!("Couldn't find primary interface for {machine_id}."))
        })
}

/// Move an entry from predicted_machine_interfaces to machine_interfaces, using the given relay IP
/// to know what network segment to assign.
pub async fn move_predicted_machine_interface_to_machine(
    txn: &mut PgConnection,
    predicted_machine_interface: &PredictedMachineInterface,
    relay_ip: IpAddr,
) -> Result<(), DatabaseError> {
    tracing::info!(
        machine_id=%predicted_machine_interface.machine_id,
        mac_address=%predicted_machine_interface.mac_address,
        %relay_ip,
        "Got DHCP from predicted machine interface, moving to machine"
    );
    let Some(network_segment) = crate::network_segment::for_relay(txn, relay_ip).await? else {
        return Err(DatabaseError::internal(format!(
            "No network segment defined for relay address: {relay_ip}"
        )));
    };

    if network_segment.segment_type != predicted_machine_interface.expected_network_segment_type {
        return Err(DatabaseError::internal(format!(
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
                        return Err(DatabaseError::NetworkSegmentDuplicateMacAddress(
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
        MachineInterfaceAssociation::Machine(predicted_machine_interface.machine_id),
        txn,
    )
    .await?;

    crate::predicted_machine_interface::delete(predicted_machine_interface, txn).await?;
    Ok(())
}

/// This function creates Proactive Host Machine Interface with all available information.
/// Parsed Mac: Found in DPU's topology data
/// Relay IP: Taken from fixed Admin network segment. Relay IP is used only to identify related
/// segment.
/// Returns: Machine Interface, True if new interface is created.
pub async fn create_host_machine_dpu_interface_proactively(
    txn: &mut PgConnection,
    hardware_info: Option<&HardwareInfo>,
    dpu_id: &MachineId,
) -> Result<MachineInterfaceSnapshot, DatabaseError> {
    let admin_network = crate::network_segment::admin(txn).await?;

    // Using gateway IP as relay IP. This is just to enable next algorithm to find related network
    // segment.
    let prefix = admin_network
        .prefixes
        .iter()
        .filter(|x| x.prefix.is_ipv4())
        .next_back()
        .ok_or(DatabaseError::AdminNetworkNotConfigured)?;

    let Some(gateway) = prefix.gateway else {
        return Err(DatabaseError::AdminNetworkNotConfigured);
    };

    // Host mac is stored at DPU topology data.
    let host_mac = hardware_info
        .map(|x| x.factory_mac_address())
        .ok_or_else(|| DatabaseError::NotFoundError {
            kind: "Hardware Info",
            id: dpu_id.to_string(),
        })??;

    let existing_machine = crate::machine::find_existing_machine(txn, host_mac, gateway).await?;

    let machine_interface =
        find_or_create_machine_interface(txn, existing_machine, host_mac, gateway, None).await?;
    associate_interface_with_dpu_machine(&machine_interface.id, dpu_id, txn).await?;

    Ok(machine_interface)
}

pub async fn find_by_machine_and_segment(
    txn: &mut PgConnection,
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
        .bind(machine_id)
        .bind(segment_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(&query, e))
        .map(|interfaces| interfaces.into_iter().collect())
}

/// Record that this interface just DHCPed, so it must still exist
pub async fn update_last_dhcp(
    txn: &mut PgConnection,
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
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn delete(
    interface_id: &MachineInterfaceId,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "DELETE FROM machine_interfaces WHERE id=$1";
    crate::machine_interface_address::delete(txn, interface_id).await?;
    crate::dhcp_entry::delete(txn, interface_id).await?;
    sqlx::query(query)
        .bind(*interface_id)
        .execute(&mut *txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))?;

    let query = "UPDATE machine_interfaces_deletion SET last_deletion=NOW() WHERE id = 1";
    sqlx::query(query)
        .bind(*interface_id)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn delete_by_ip(txn: &mut PgConnection, ip: IpAddr) -> Result<Option<()>, DatabaseError> {
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
    async fn used_ips(&self, txn: &mut PgConnection) -> Result<Vec<IpAddr>, DatabaseError> {
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
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        let mut ips: Vec<IpAddr> = containers.iter().map(|c| c.address).collect();
        ips.extend(self.busy_ips.iter());
        Ok(ips)
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
    async fn used_prefixes(&self, txn: &mut PgConnection) -> Result<Vec<IpNetwork>, DatabaseError> {
        let used_ips = self.used_ips(txn).await?;
        let mut ip_networks: Vec<IpNetwork> = Vec::new();
        for used_ip in used_ips {
            let network = IpNetwork::new(used_ip, 32).map_err(|e| {
                DatabaseError::new(
                    "machine_interface.used_prefixes",
                    sqlx::Error::Io(std::io::Error::other(e.to_string())),
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
