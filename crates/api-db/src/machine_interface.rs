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

use std::collections::HashMap;
use std::net::IpAddr;

use carbide_network::ip::{IdentifyAddressFamily, IpAddressFamily};
use carbide_utils::redfish::BmcAccessInfo;
use carbide_uuid::domain::DomainId;
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use carbide_uuid::network::{NetworkPrefixId, NetworkSegmentId};
use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::switch::SwitchId;
use chrono::{DateTime, Utc};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use mac_address::MacAddress;
use model::address_selection_strategy::AddressSelectionStrategy;
use model::allocation_type::AllocationType;
use model::expected_machine::ExpectedHostNic;
use model::hardware_info::HardwareInfo;
use model::machine::MachineInterfaceSnapshot;
use model::machine_interface::InterfaceType;
use model::machine_interface_address::MachineInterfaceAssociation;
use model::network_prefix::NetworkPrefix;
use model::network_segment::{AllocationStrategy, NetworkSegment, NetworkSegmentType};
use model::predicted_machine_interface::PredictedMachineInterface;
use sqlx::{FromRow, PgConnection, PgTransaction};

use super::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter};
use crate::db_read::DbReader;
use crate::host_naming::{self, NamingContext};
use crate::ip_allocator::{DhcpError, IpAllocator, UsedIpResolver};
use crate::machine_interface_address::{AddressAlreadyInUseError, MachineInterfaceAddressWithType};
use crate::{DatabaseError, DatabaseResult, Transaction, network_segment as db_network_segment};

const SQL_VIOLATION_DUPLICATE_MAC: &str = "machine_interfaces_segment_id_mac_address_key";
const SQL_VIOLATION_ONE_PRIMARY_INTERFACE: &str = "one_primary_interface_per_machine";
const SQL_VIOLATION_MAX_ONE_ASSOCIATION: &str = "chk_max_one_association";
const FAST_PATH_MAX_RETRIES: usize = 128;
const FAST_PATH_CANDIDATE_BATCH: i64 = 32;

pub struct UsedAdminNetworkIpResolver {
    pub segment_id: NetworkSegmentId,
    // All the IPs which can not be allocated, e.g. SVI IP.
    pub busy_ips: Vec<IpAddr>,
}

#[derive(Debug)]
struct AdminInterfaceForReconcile {
    id: MachineInterfaceId,
    segment_id: NetworkSegmentId,
    hostname: String,
    domain_id: Option<DomainId>,
    primary_interface: bool,
    is_dpu_backed_host_link: bool,
    mac_address: MacAddress,
    addresses: Vec<MachineInterfaceAddressWithType>,
}

#[derive(FromRow)]
struct AdminInterfaceForReconcileRow {
    id: MachineInterfaceId,
    segment_id: NetworkSegmentId,
    hostname: String,
    domain_id: Option<DomainId>,
    primary_interface: bool,
    is_dpu_backed_host_link: bool,
    mac_address: MacAddress,
    address: Option<IpAddr>,
    allocation_type: Option<AllocationType>,
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

#[cfg(test)]
mod ip_allocator;
#[cfg(test)]
mod test_duplicate_mac;
#[cfg(test)]
mod tests;

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
macro_rules! machine_interface_snapshot_query {
    () => {
        r#"
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
    ) AS vendors_agg ON true"#
    };
}

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

/// Clears `primary_interface` on every interface a machine currently owns.
///
/// Used when a new interface takes over as the machine's sole primary -- e.g. a
/// declared integrated host NIC promoted ahead of the DPU admin link it replaces
/// on a managed-DPU host -- so the incoming primary never collides with the outgoing
/// one on the `one_primary_interface_per_machine` index.
pub async fn demote_primary_interfaces_for_machine(
    machine_id: &MachineId,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machine_interfaces SET primary_interface=false WHERE machine_id=$1 AND primary_interface=true";
    sqlx::query(query)
        .bind(machine_id)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Whether a machine owns any interface flagged `primary_interface`, in any segment.
///
/// Lets admin-address reconciliation distinguish a genuinely broken host (no
/// primary at all) from one that legitimately boots from a non-admin primary --
/// a HostInband integrated NIC on a managed-DPU host -- whose DPU admin links are
/// then all dormant.
pub async fn machine_has_primary_interface(
    machine_id: &MachineId,
    txn: &mut PgConnection,
) -> Result<bool, DatabaseError> {
    let query = "SELECT EXISTS(SELECT 1 FROM machine_interfaces WHERE machine_id=$1 AND primary_interface=true)";
    let (exists,): (bool,) = sqlx::query_as(query)
        .bind(machine_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(exists)
}

/// Records the vendor-native Redfish `EthernetInterface.Id` on the machine_interface
/// row(s) with the given MAC. Captured by site-explorer per exploration; callers only
/// invoke this when the id resolves from the current report, so a wiped MAC leaves the
/// last-known-good id in place.
pub async fn set_boot_interface_id(
    mac_address: MacAddress,
    boot_interface_id: &str,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machine_interfaces SET boot_interface_id=$1 WHERE mac_address=$2";
    sqlx::query(query)
        .bind(boot_interface_id)
        .bind(mac_address)
        .execute(txn)
        .await
        .map(|_| ())
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

/// Link an interface as the BMC of its owning entity in one statement:
/// associate it with the machine / switch / power shelf (per `association`),
/// annotate it as `Bmc`, and demote it from primary (a BMC is a management
/// interface, never the primary data interface).
///
/// Mirrors [`associate_interface_with_machine`] but additionally forces
/// `interface_type='Bmc'` and `primary_interface=false`.
pub async fn associate_bmc_interface(
    interface_id: &MachineInterfaceId,
    association: MachineInterfaceAssociation,
    txn: &mut PgConnection,
) -> DatabaseResult<MachineInterfaceId> {
    let (query, association_type, id_value) = match association {
        MachineInterfaceAssociation::Machine(id) => (
            "UPDATE machine_interfaces SET machine_id=$1, association_type=$2::association_type, \
             interface_type='Bmc'::interface_type, primary_interface=false \
             WHERE id=$3::uuid RETURNING id",
            "Machine",
            id.to_string(),
        ),
        MachineInterfaceAssociation::Switch(id) => (
            "UPDATE machine_interfaces SET switch_id=$1, association_type=$2::association_type, \
             interface_type='Bmc'::interface_type, primary_interface=false \
             WHERE id=$3::uuid RETURNING id",
            "Switch",
            id.to_string(),
        ),
        MachineInterfaceAssociation::PowerShelf(id) => (
            "UPDATE machine_interfaces SET power_shelf_id=$1, association_type=$2::association_type, \
             interface_type='Bmc'::interface_type, primary_interface=false \
             WHERE id=$3::uuid RETURNING id",
            "PowerShelf",
            id.to_string(),
        ),
    };
    // `primary_interface` is always forced to false here, so the one-primary
    // constraint cannot fire -- only the single-association one is relevant.
    sqlx::query_as(query)
        .bind(id_value)
        .bind(association_type)
        .bind(*interface_id)
        .fetch_one(txn)
        .await
        .map_err(|err: sqlx::Error| match err {
            sqlx::Error::Database(e)
                if e.constraint() == Some(SQL_VIOLATION_MAX_ONE_ASSOCIATION) =>
            {
                DatabaseError::MaxOneInterfaceAssociation
            }
            _ => DatabaseError::query(query, err),
        })
}

pub async fn set_interface_type(
    interface_id: &MachineInterfaceId,
    interface_type: InterfaceType,
    txn: &mut PgConnection,
) -> DatabaseResult<MachineInterfaceId> {
    let query = "UPDATE machine_interfaces SET interface_type=$1 WHERE id=$2::uuid RETURNING id";
    sqlx::query_as(query)
        .bind(interface_type)
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
    let (query, association_type, id_value) = match association {
        MachineInterfaceAssociation::Machine(id) => (
            "UPDATE machine_interfaces SET machine_id=$1, association_type=$2::association_type where id=$3::uuid RETURNING id",
            "Machine",
            id.to_string(),
        ),
        MachineInterfaceAssociation::Switch(id) => (
            "UPDATE machine_interfaces SET switch_id=$1, association_type=$2::association_type where id=$3::uuid RETURNING id",
            "Switch",
            id.to_string(),
        ),
        MachineInterfaceAssociation::PowerShelf(id) => (
            "UPDATE machine_interfaces SET power_shelf_id=$1, association_type=$2::association_type where id=$3::uuid RETURNING id",
            "PowerShelf",
            id.to_string(),
        ),
    };
    sqlx::query_as(query)
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
            _ => DatabaseError::query(query, err),
        })
}

pub async fn find_by_mac_address(
    txn: impl DbReader<'_>,
    macaddr: MacAddress,
) -> Result<Vec<MachineInterfaceSnapshot>, DatabaseError> {
    find_by(txn, ObjectColumnFilter::One(MacAddressColumn, &macaddr)).await
}

/// This function returns only an IP for efficiency, we don't need to fetch/deserialize the entire
/// MachineInterfaceSnapshot
pub async fn lookup_bmc_ip_by_mac_address(
    db: impl DbReader<'_>,
    mac_address: MacAddress,
) -> DatabaseResult<Vec<IpAddr>> {
    let query = r"SELECT mia.address FROM machine_interfaces mi
        INNER JOIN machine_interface_addresses mia ON (mia.interface_id = mi.id)
        WHERE mi.mac_address = $1";
    sqlx::query_scalar(query)
        .bind(mac_address)
        .fetch_all(db)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Returns the fully qualified hostname (`hostname.domain`) for each requested
/// MAC address, using `machine_interfaces.hostname` and the associated
/// `domains.name` when present.
pub async fn find_hostnames_by_mac_addresses(
    db: impl DbReader<'_>,
    mac_addresses: &[MacAddress],
) -> DatabaseResult<HashMap<MacAddress, String>> {
    if mac_addresses.is_empty() {
        return Ok(HashMap::new());
    }

    let query = r#"
        SELECT
            mi.mac_address,
            CASE
                WHEN d.name IS NOT NULL AND d.name <> '' THEN mi.hostname || '.' || d.name
                ELSE mi.hostname
            END AS hostname
        FROM machine_interfaces mi
        LEFT JOIN domains d ON d.id = mi.domain_id
        WHERE mi.mac_address = ANY($1)
          AND mi.hostname <> ''
    "#;
    let rows: Vec<(MacAddress, String)> = sqlx::query_as(query)
        .bind(mac_addresses)
        .fetch_all(db)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(rows
        .into_iter()
        .filter(|(_, hostname)| !hostname.is_empty())
        .collect())
}

pub async fn lookup_bmc_access_info(
    db: impl DbReader<'_>,
    ip: IpAddr,
    port: Option<u16>,
) -> DatabaseResult<BmcAccessInfo> {
    let mac_address = find_by_ip(db, ip)
        .await?
        .ok_or_else(|| DatabaseError::NotFoundError {
            kind: "Machine Interface",
            id: ip.to_string(),
        })?
        .mac_address;
    Ok(BmcAccessInfo {
        host: ip.to_string(),
        port,
        mac_address,
    })
}

pub async fn find_by_ip(
    txn: impl DbReader<'_>,
    ip: IpAddr,
) -> Result<Option<MachineInterfaceSnapshot>, DatabaseError> {
    static QUERY: &str = concat!(
        machine_interface_snapshot_query!(),
        r#" INNER JOIN machine_interface_addresses mia on mia.interface_id=mi.id
        WHERE mia.address = $1::inet"#,
    );
    sqlx::query_as(QUERY)
        .bind(ip)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
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
            .filter(|interface| interface.interface_type != InterfaceType::Bmc)
            .into_group_map_by(|interface| interface.machine_id.unwrap()),
    )
}

/// Counts the machine interfaces bound to a given segment.
///
/// Keep this predicate in sync with
/// [`crate::instance_address::segment_has_allocations`] (used by the
/// segment-drain reconcile).
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
    txn: impl DbReader<'_>,
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
// newly_created_interface indicates that we couldn't find a
// MachineInterface, so created new one.
//
// DHCPv4 and DHCPv6 for the same NIC intentionally converge on the same
// machine_interfaces row through the `(segment_id, mac_address)` invariant.
//
// `is_primary` carries the declared `ExpectedHostNic.primary` for this MAC:
// `Some(true)` -- this NIC is the host's declared boot interface, `Some(false)`
// -- a different NIC is, `None` -- nothing was declared. On a newly created (and
// thus still machine-less) row we make that declaration stick, promoting to or
// demoting from the creation default as needed, so the boot interface is right
// from the first lease. `None` keeps the creation default.
//
// If we're not making a new interface, then existing interfaces
// are returned untouched.
/// Optional metadata used while finding or creating a DHCP machine interface.
pub struct FindOrCreateMachineInterfaceOptions {
    pub host_nic: Option<ExpectedHostNic>,
    pub is_primary: Option<bool>,
    pub retained_window: Option<chrono::Duration>,
}

pub async fn find_or_create_machine_interface(
    txn: &mut PgConnection,
    machine_id: Option<MachineId>,
    mac_address: MacAddress,
    relays: &[IpAddr],
    host_nic: Option<ExpectedHostNic>,
    is_primary: Option<bool>,
    retained_window: Option<chrono::Duration>,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    find_or_create_machine_interface_inner(
        txn,
        machine_id,
        mac_address,
        relays,
        FindOrCreateMachineInterfaceOptions {
            host_nic,
            is_primary,
            retained_window,
        },
        None,
    )
    .await
}

/// Find or create a DHCP interface, allocating only the requested family for a
/// brand-new dynamic row.
pub async fn find_or_create_machine_interface_for_family(
    txn: &mut PgConnection,
    machine_id: Option<MachineId>,
    mac_address: MacAddress,
    relays: &[IpAddr],
    options: FindOrCreateMachineInterfaceOptions,
    address_family: IpAddressFamily,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    find_or_create_machine_interface_inner(
        txn,
        machine_id,
        mac_address,
        relays,
        options,
        Some(address_family),
    )
    .await
}

async fn find_or_create_machine_interface_inner(
    txn: &mut PgConnection,
    machine_id: Option<MachineId>,
    mac_address: MacAddress,
    relays: &[IpAddr],
    options: FindOrCreateMachineInterfaceOptions,
    address_family: Option<IpAddressFamily>,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    let FindOrCreateMachineInterfaceOptions {
        host_nic,
        is_primary,
        retained_window,
    } = options;
    let relaystr = relays
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>()
        .join(", ");
    match machine_id {
        None => {
            tracing::info!(
                %mac_address,
                relays = ?relays,
                "No existing machine found",
            );
            let mut interface = validate_existing_mac_and_create_inner(
                &mut *txn,
                mac_address,
                relays,
                host_nic,
                retained_window,
                address_family,
            )
            .await?;
            apply_primary_declaration(&mut *txn, &mut interface, is_primary).await?;
            Ok(interface)
        }
        Some(_) => {
            let mut ifcs = find_by_mac_address(&mut *txn, mac_address).await?;
            match ifcs.len() {
                1 => Ok(ifcs.remove(0)),
                n => {
                    tracing::warn!(
                        %mac_address,
                        relay_ip_addresses = %relaystr,
                        matching_interface_count = n,
                        expected_interface_count = 1,
                        "Unexpected number of machine interfaces for MAC while machine is already known",
                    );
                    Err(DatabaseError::NetworkSegmentDuplicateMacAddress(
                        mac_address,
                    ))
                }
            }
        }
    }
}

/// Find or create a DHCP-seen interface without allocating any addresses.
///
/// This is used before family-specific DHCP allocation and by DHCPv6
/// information-request handling, where the packet proves interface presence but
/// must not consume a DHCP lease.
pub async fn find_or_create_observed_machine_interface(
    txn: &mut PgConnection,
    machine_id: Option<MachineId>,
    mac_address: MacAddress,
    relays: &[IpAddr],
    host_nic: Option<ExpectedHostNic>,
    is_primary: Option<bool>,
    retained_window: Option<chrono::Duration>,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    let relaystr = relays
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<String>>()
        .join(", ");
    match machine_id {
        None => {
            tracing::info!(
                %mac_address,
                relays = ?relays,
                "No existing machine found",
            );

            // Return an existing row when the MAC is already known on this segment.
            let mut interface_snapshot = find_by_mac_address(&mut *txn, mac_address).await?;
            let mut interface = match interface_snapshot.len() {
                0 => {
                    tracing::debug!(
                        %mac_address,
                        "No existing machine_interface with mac address exists yet, creating observed row",
                    );
                    let network_segments =
                        network_segments_for_dhcp_relays(txn, relays, host_nic.as_ref()).await?;

                    if network_segments.is_empty() {
                        return Err(DatabaseError::internal(format!(
                            "No network segment defined for relay addresses: {:?}",
                            relays
                        )));
                    }

                    // Observed-only rows are specific to DHCPv6 INFORMATION-REQUEST.
                    // Use the already ordered first candidate; exact DHCPv6
                    // link-address matches are returned before prefix fallback candidates.
                    let segment = &network_segments[0];

                    // Only the selected segment may veto observed-row creation. With one
                    // relay, later candidates are fallback matches and must not block it.
                    if segment.config.allocation_strategy == AllocationStrategy::Reserved {
                        return Err(DatabaseError::internal(format!(
                            "segment {} configured for static DHCP leases only; no static reservation for MAC {mac_address}",
                            segment.config.name,
                        )));
                    }

                    create_without_addresses(txn, segment, &mac_address, true, retained_window)
                        .await?
                }
                1 => {
                    tracing::debug!(
                        %mac_address,
                        "Mac address exists, validating the relay and returning it",
                    );
                    let mut existing_interface = interface_snapshot.remove(0);
                    reconcile_interface_segment(txn, &mut existing_interface, relays).await?;
                    existing_interface
                }
                n => {
                    tracing::warn!(
                        %mac_address,
                        matching_interface_count = n,
                        expected_interface_count = 1,
                        "Unexpected number of existing machine interfaces for observed MAC",
                    );
                    return Err(DatabaseError::NetworkSegmentDuplicateMacAddress(
                        mac_address,
                    ));
                }
            };

            apply_primary_declaration(txn, &mut interface, is_primary).await?;
            Ok(interface)
        }
        Some(_) => {
            let mut ifcs = find_by_mac_address(&mut *txn, mac_address).await?;
            match ifcs.len() {
                1 => Ok(ifcs.remove(0)),
                n => {
                    tracing::warn!(
                        %mac_address,
                        relay_ip_addresses = %relaystr,
                        matching_interface_count = n,
                        expected_interface_count = 1,
                        "Unexpected number of machine interfaces for MAC while machine is already known",
                    );
                    Err(DatabaseError::NetworkSegmentDuplicateMacAddress(
                        mac_address,
                    ))
                }
            }
        }
    }
}

/// Apply the expected-host primary declaration to an anonymous interface row.
async fn apply_primary_declaration(
    txn: &mut PgConnection,
    interface: &mut MachineInterfaceSnapshot,
    is_primary: Option<bool>,
) -> DatabaseResult<()> {
    // The declaration is safe on NULL-machine rows because the primary-interface
    // uniqueness index does not constrain them.
    match is_primary {
        Some(false) if interface.primary_interface => {
            set_primary_interface(&interface.id, false, &mut *txn).await?;
            interface.primary_interface = false;
        }
        Some(true) if !interface.primary_interface => {
            set_primary_interface(&interface.id, true, &mut *txn).await?;
            interface.primary_interface = true;
        }
        _ => {}
    }
    Ok(())
}

/// Resolve DHCP candidate network segments for a relay list and optional NIC type.
pub async fn network_segments_for_dhcp_relays(
    txn: &mut PgConnection,
    relays: &[IpAddr],
    host_nic: Option<&ExpectedHostNic>,
) -> DatabaseResult<Vec<NetworkSegment>> {
    let expected_network_segment_type =
        host_nic.and_then(ExpectedHostNic::resolved_network_segment_type);
    let network_segments = db_network_segment::for_relay_all(txn, relays).await?;
    let exact_segment_ids = exact_dhcpv6_link_address_segment_ids(&network_segments, relays);
    if !exact_segment_ids.is_empty() {
        // DHCPv6 link-address is authoritative relay metadata, so exact
        // matches win even when ExpectedHostNic suggests a different type.
        let exact_segments = network_segments
            .into_iter()
            .filter(|segment| exact_segment_ids.contains(&segment.id))
            .collect::<Vec<_>>();

        if let Some(network_segment_type) = expected_network_segment_type
            && exact_segments
                .iter()
                .any(|segment| segment.config.segment_type != network_segment_type)
        {
            tracing::warn!(
                relay_ip_addresses = %relays.iter().join(", "),
                expected_network_segment_type = %network_segment_type,
                exact_segment_ids = %exact_segments.iter().map(|segment| segment.id.to_string()).join(", "),
                exact_segment_types = %exact_segments
                    .iter()
                    .map(|segment| segment.config.segment_type.to_string())
                    .join(", "),
                "DHCPv6 exact link-address segment type differs from ExpectedHostNic segment type; using authoritative exact link-address segment"
            );
        }

        return Ok(exact_segments);
    }

    // With no exact link-address match, a declared NIC may narrow prefix-based
    // candidates to the expected segment type.
    if let Some(network_segment_type) = expected_network_segment_type {
        Ok(network_segments
            .into_iter()
            .filter(|segment| segment.config.segment_type == network_segment_type)
            .collect())
    } else {
        Ok(network_segments)
    }
}

/// Returns relay candidate IDs that exactly match a DHCPv6 link-address.
///
/// `network_prefixes.dhcpv6_link_address` is unique at the DB layer, so a
/// single relay/link-address can produce at most one exact segment. Multiple
/// IDs here mean the caller supplied multiple distinct relay inputs.
fn exact_dhcpv6_link_address_segment_ids(
    network_segments: &[NetworkSegment],
    relays: &[IpAddr],
) -> Vec<NetworkSegmentId> {
    network_segments
        .iter()
        .filter(|segment| {
            segment.prefixes.iter().any(|prefix| {
                prefix
                    .dhcpv6_link_address
                    .is_some_and(|link_address| relays.contains(&link_address))
            })
        })
        .map(|segment| segment.id)
        .collect()
}

/// Do basic validating on existing MACs and create the interface if it does not exist.
pub async fn validate_existing_mac_and_create(
    txn: &mut PgConnection,
    mac_address: MacAddress,
    relays: &[IpAddr],
    host_nic: Option<ExpectedHostNic>,
    retained_window: Option<chrono::Duration>,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    validate_existing_mac_and_create_inner(
        txn,
        mac_address,
        relays,
        host_nic,
        retained_window,
        None,
    )
    .await
}

/// If `address_family` is provided, it is applied only when this call creates
/// a new dynamic interface: candidate segment snapshots are filtered to that
/// family before `create` runs. Existing MAC reconciliation ignores the filter.
async fn validate_existing_mac_and_create_inner(
    txn: &mut PgConnection,
    mac_address: MacAddress,
    relays: &[IpAddr],
    host_nic: Option<ExpectedHostNic>,
    retained_window: Option<chrono::Duration>,
    address_family: Option<IpAddressFamily>,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    let mut interface_snapshot = find_by_mac_address(&mut *txn, mac_address).await?;
    match &interface_snapshot.len() {
        0 => {
            tracing::debug!(
                %mac_address,
                "No existing machine_interface with mac address exists yet, creating one",
            );

            let mut network_segments =
                network_segments_for_dhcp_relays(txn, relays, host_nic.as_ref()).await?;

            if !network_segments.is_empty() {
                let exact_segment_ids =
                    exact_dhcpv6_link_address_segment_ids(&network_segments, relays);
                let authoritative_segment_ids = if exact_segment_ids.is_empty() {
                    network_segments
                        .iter()
                        .map(|segment| segment.id)
                        .collect::<Vec<_>>()
                } else {
                    exact_segment_ids.clone()
                };

                // IPv4 relay resolution has only prefix candidates, so the legacy
                // "any reserved candidate vetoes dynamic DHCP" behavior remains.
                // DHCPv6 link-address can be authoritative while a later prefix
                // fallback is reserved; only authoritative candidates may veto.
                for segment in network_segments
                    .iter()
                    .filter(|segment| authoritative_segment_ids.contains(&segment.id))
                {
                    if segment.config.allocation_strategy == AllocationStrategy::Reserved {
                        return Err(DatabaseError::internal(format!(
                            "segment {} configured for static DHCP leases only; no static reservation for MAC {mac_address}",
                            segment.config.name,
                        )));
                    }
                }

                if !exact_segment_ids.is_empty() {
                    // Exact DHCPv6 link-address is a segment selector. IPv4 has
                    // only prefix candidates and keeps fallback behavior; exact
                    // DHCPv6 fails on that segment if it is v6-disabled or exhausted.
                    network_segments.retain(|segment| exact_segment_ids.contains(&segment.id));
                }

                if let Some(address_family) = address_family {
                    let candidate_segment_ids = network_segments
                        .iter()
                        .map(|segment| segment.id.to_string())
                        .join(", ");

                    // Reuse the existing dynamic create path unchanged: each
                    // candidate snapshot now exposes only the requested family,
                    // so its normal retry and lock strategy stays correct.
                    network_segments.retain_mut(|segment| {
                        segment
                            .prefixes
                            .retain(|prefix| prefix.prefix.is_address_family(address_family));
                        !segment.prefixes.is_empty()
                    });

                    if network_segments.is_empty() {
                        let family_label = match address_family {
                            IpAddressFamily::Ipv4 => "IPv4",
                            IpAddressFamily::Ipv6 => "IPv6",
                        };
                        return Err(DatabaseError::FailedPrecondition(format!(
                            "DHCP request received for candidate network segments {candidate_segment_ids} without an {family_label} prefix",
                        )));
                    }
                }

                // Dynamic-pool allocation.
                // Any AddressSelectionStrategy::StaticIp flows will have happened as part of
                // preallocate_machine_interface or preallocate_bmc_machine_interface.
                // (`create` recovers any retained boot interface id onto the new row.)
                let v = create(
                    txn,
                    &network_segments,
                    &mac_address,
                    true,
                    AddressSelectionStrategy::NextAvailableIp,
                    retained_window,
                )
                .await?;
                Ok(v)
            } else {
                Err(DatabaseError::internal(format!(
                    "No network segment defined for relay addresses: {:?}",
                    relays
                )))
            }
        }
        1 => {
            tracing::debug!(
                %mac_address,
                "Mac address exists, validating the relay and returning it",
            );

            // TODO(chet): I don't like that it's mut here, but this seems to be
            // a pattern in this module in general, especially since we may or may
            // not update the interface. Consider having reconcile_interface_segment
            // just return the interface, which would probably look a lot better.
            let mut existing_interface = interface_snapshot.remove(0);
            reconcile_interface_segment(txn, &mut existing_interface, relays).await?;
            Ok(existing_interface)
        }
        n => {
            tracing::warn!(
                %mac_address,
                matching_interface_count = n,
                expected_interface_count = 1,
                "Unexpected number of existing machine interfaces for MAC during DHCP validation",
            );
            Err(DatabaseError::NetworkSegmentDuplicateMacAddress(
                mac_address,
            ))
        }
    }
}

/// Ensure a a `machine_interface` exists for the `mac_address` with its
/// reserved allocation, either falling into a Carbide-managed segment (when
/// there is a match within a managed prefix), or into the `static_assignments`
/// segment for IPs that are outside of managed networks.
///
/// Calls are idempotent on the input `(mac_address, static_ip)`, meaning
/// repeat calls return `Ok(())` if/once the end state matches the request.
///
/// Errors on conflicts that need operator attention, e.g.
/// - The interface for this MAC exists but carries different addresses, or,
/// - The IP is already allocated to a different MAC.
///
/// Called as part of site-explorer iterations (when an ExpectedMachine has a
/// static assignment/reservation configured), and from the DHCP `discover()`
/// path (when a client whose configuration expects a static address) to ensure
/// the fixed-address is returned.
pub async fn preallocate_machine_interface(
    txn: &mut PgConnection,
    mac_address: MacAddress,
    static_ip: IpAddr,
    retained_window: Option<chrono::Duration>,
) -> DatabaseResult<()> {
    preallocate_machine_interface_with_type(
        txn,
        mac_address,
        static_ip,
        InterfaceType::Data,
        retained_window,
    )
    .await
}

pub async fn preallocate_bmc_machine_interface(
    txn: &mut PgConnection,
    mac_address: MacAddress,
    static_ip: IpAddr,
    retained_window: Option<chrono::Duration>,
) -> DatabaseResult<()> {
    preallocate_machine_interface_with_type(
        txn,
        mac_address,
        static_ip,
        InterfaceType::Bmc,
        retained_window,
    )
    .await
}

/// Pin a BMC interface's dynamic (DHCP) address as `Static` so lease expiry can't
/// reap it. Idempotent no-op if the BMC interface has no DHCP address. Honors a
/// `Retained` bmc_ip_allocation for BMCs with no operator-specified address.
pub async fn retain_bmc_address_by_mac(
    txn: &mut PgConnection,
    bmc_mac: MacAddress,
) -> DatabaseResult<()> {
    let query = "UPDATE machine_interface_addresses
        SET allocation_type = 'static'
        WHERE allocation_type = 'dhcp'
          AND interface_id IN (
              SELECT id FROM machine_interfaces
              WHERE mac_address = $1 AND interface_type = 'Bmc'
          )";
    sqlx::query(query)
        .bind(bmc_mac)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|err| DatabaseError::query(query, err))
}

/// If a machine interface row already exists for `mac_address`, reconcile it against the
/// requested (`static_ip`, `interface_type`):
///   - Returns `Ok(true)` when an existing row can carry `static_ip`. Promotes
///     `interface_type` (and clears `primary_interface` for Bmc) if those don't already match.
///     Existing DHCP/SLAAC rows for the same address family are replaced by the static
///     reservation.
///   - Returns `Ok(false)` when no row exists for `mac_address` — caller should create.
///   - Returns `Err(InvalidArgument)` when a row exists but carries a different static address
///     for the requested address family.
async fn reconcile_existing_preallocation(
    txn: &mut PgConnection,
    mac_address: MacAddress,
    static_ip: IpAddr,
    interface_type: InterfaceType,
) -> DatabaseResult<bool> {
    let existing = find_by_mac_address(&mut *txn, mac_address).await?;
    let Some(iface) = existing.first() else {
        return Ok(false);
    };

    let family = static_ip.address_family();
    let addresses =
        crate::machine_interface_address::find_for_interface(&mut *txn, iface.id).await?;
    let same_family = addresses
        .iter()
        .find(|address| address.address.is_address_family(family));
    match same_family {
        // An existing static reservation for this family is authoritative:
        // callers must use update to change it.
        Some(address)
            if address.address != static_ip
                && address.allocation_type == AllocationType::Static =>
        {
            return Err(DatabaseError::InvalidArgument(format!(
                "a machine interface already exists for MAC {mac_address} with addresses {:?}; use update to change the IP address",
                iface.addresses,
            )));
        }
        // The requested static reservation is already present; reconciliation
        // still continues below to align interface type/primary flags.
        Some(address)
            if address.address == static_ip
                && address.allocation_type == AllocationType::Static => {}
        // No same-family static reservation exists. DHCP/SLAAC rows for this
        // family may be replaced, but only after proving the target IP and
        // target segment are safe for this interface.
        _ => {
            if let Some(existing_addr) =
                crate::machine_interface_address::find_by_address(&mut *txn, static_ip).await?
                && existing_addr.id != iface.id
            {
                return Err(DatabaseError::InvalidArgument(format!(
                    "IP address {static_ip} is already allocated to interface {} on segment {}; use 'machine-interfaces assign-address' to reassign it",
                    existing_addr.id, existing_addr.name,
                )));
            }
            let target_segment =
                match db_network_segment::for_prefix_containing_address(&mut *txn, static_ip)
                    .await?
                {
                    Some(segment) => segment,
                    None => db_network_segment::static_assignments(&mut *txn).await?,
                };
            // Do not silently move an existing preallocated interface; changing
            // segment ownership is an explicit update operation.
            if iface.segment_id != target_segment.id {
                return Err(DatabaseError::InvalidArgument(format!(
                    "a machine interface already exists for MAC {mac_address} on segment {}; fixed IP {static_ip} belongs to segment {}; use update to change the segment",
                    iface.segment_id, target_segment.id,
                )));
            }
            // Safe replacement point: same interface, same segment, and no
            // conflicting owner for the requested IP.
            crate::machine_interface_address::assign_static(&mut *txn, iface.id, static_ip).await?;
            sync_hostname_after_address_assignment(
                &mut *txn,
                iface.id,
                target_segment.config.subdomain_id,
            )
            .await?;
        }
    }

    if iface.interface_type != interface_type {
        set_interface_type(&iface.id, interface_type, txn).await?;
    }
    if interface_type == InterfaceType::Bmc && iface.primary_interface {
        set_primary_interface(&iface.id, false, txn).await?;
    }
    Ok(true)
}

async fn preallocate_machine_interface_with_type(
    txn: &mut PgConnection,
    mac_address: MacAddress,
    static_ip: IpAddr,
    interface_type: InterfaceType,
    retained_window: Option<chrono::Duration>,
) -> DatabaseResult<()> {
    // If there's already a matching record for (ip, mac), just return Ok,
    // instead of attempting to insert, getting a duplicate error, and then
    // handling.
    if reconcile_existing_preallocation(txn, mac_address, static_ip, interface_type).await? {
        return Ok(());
    }

    if let Some(existing_addr) =
        crate::machine_interface_address::find_by_address(&mut *txn, static_ip).await?
    {
        return Err(DatabaseError::InvalidArgument(format!(
            "IP address {static_ip} is already allocated to interface {} on segment {}; use 'machine-interfaces assign-address' to reassign it",
            existing_addr.id, existing_addr.name,
        )));
    }

    let segment =
        match db_network_segment::for_prefix_containing_address(&mut *txn, static_ip).await? {
            Some(seg) => seg,
            None => db_network_segment::static_assignments(&mut *txn).await?,
        };

    match create_with_type(
        txn,
        std::slice::from_ref(&segment),
        &mac_address,
        interface_type != InterfaceType::Bmc,
        AddressSelectionStrategy::StaticAddress(static_ip),
        interface_type,
        retained_window,
    )
    .await
    {
        Ok(_) => {
            tracing::info!(
                %mac_address,
                static_ip_address = %static_ip,
                network_segment_id = %segment.id,
                "Pre-allocated static machine interface"
            );
            Ok(())
        }
        Err(DatabaseError::NetworkSegmentDuplicateMacAddress(_)) => {
            // Looks like we might have lost a race with anohter inserter. Try to
            // uphold our idempotency by re-fetching to reconcile. If the conflicting
            // row carries our `static_ip`, our work is already done!
            // Otherwise return an error.
            if reconcile_existing_preallocation(txn, mac_address, static_ip, interface_type).await?
            {
                Ok(())
            } else {
                Err(DatabaseError::internal(format!(
                    "duplicate-MAC error for {mac_address}, but could not reconcile",
                )))
            }
        }
        Err(e) => Err(e),
    }
}

pub async fn create(
    txn: &mut PgConnection,
    segments: &[NetworkSegment],
    macaddr: &MacAddress,
    primary_interface: bool,
    address_strategy: AddressSelectionStrategy,
    retained_window: Option<chrono::Duration>,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    create_with_type(
        txn,
        segments,
        macaddr,
        primary_interface,
        address_strategy,
        InterfaceType::Data,
        retained_window,
    )
    .await
}

pub async fn create_with_type(
    txn: &mut PgConnection,
    segments: &[NetworkSegment],
    macaddr: &MacAddress,
    primary_interface: bool,
    address_strategy: AddressSelectionStrategy,
    interface_type: InterfaceType,
    retained_window: Option<chrono::Duration>,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    let mut snapshot = match address_strategy {
        AddressSelectionStrategy::NextAvailableIp | AddressSelectionStrategy::Automatic => {
            create_fast_path(txn, segments, macaddr, primary_interface, interface_type).await
        }
        AddressSelectionStrategy::StaticAddress(addr) => {
            create_static_path(
                txn,
                segments,
                macaddr,
                primary_interface,
                addr,
                interface_type,
            )
            .await
        }
        //
        AddressSelectionStrategy::NextAvailablePrefix(_) => {
            let [segment] = segments else {
                return Err(DatabaseError::InvalidArgument(
                    "NextAvailablePrefix allocation requires exactly one candidate segment"
                        .to_string(),
                ));
            };

            create_slow_path(
                txn,
                segment,
                macaddr,
                primary_interface,
                address_strategy,
                interface_type,
            )
            .await
        }
    }?;

    // Every brand-new row passes through here, whatever created it --
    // dynamic DHCP, a static preallocation, or predicted-interface
    // promotion. A prior row for this MAC may have been deleted with its
    // boot interface id retained; recover the pair onto the new row and
    // consume the retention record.
    if snapshot.boot_interface_id.is_none()
        && let Some(boot_interface_id) =
            crate::retained_boot_interface::take_by_mac(&mut *txn, *macaddr, retained_window)
                .await?
    {
        set_boot_interface_id(*macaddr, &boot_interface_id, &mut *txn).await?;
        snapshot.boot_interface_id = Some(boot_interface_id);
    }
    Ok(snapshot)
}

#[allow(txn_held_across_await)]
async fn create_fast_path(
    txn: &mut PgConnection,
    segments: &[NetworkSegment],
    macaddr: &MacAddress,
    primary_interface: bool,
    interface_type: InterfaceType,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    for segments_idx in 0..segments.len() {
        let segment = &segments[segments_idx];
        for _ in 0..FAST_PATH_MAX_RETRIES {
            let mut fast_txn = Transaction::begin_inner(txn).await?;

            // Keep IPv4-only allocation concurrent, but serialize any segment
            // containing IPv6 because the Rust allocator reads used addresses
            // without taking per-IP candidate locks.
            if segment
                .prefixes
                .iter()
                .any(|prefix| prefix.prefix.is_ipv6())
            {
                lock_network_segment_exclusive(&mut fast_txn, segment).await?;
            } else {
                lock_network_segment_shared(&mut fast_txn, segment).await?;
            }

            let segment_exhausted = match try_create_fast_path(
                &mut fast_txn,
                segment,
                macaddr,
                primary_interface,
                interface_type,
            )
            .await
            {
                Ok(interface_id) => {
                    fast_txn.commit().await?;
                    return Ok(
                        find_by(txn, ObjectColumnFilter::One(IdColumn, &interface_id))
                            .await?
                            .remove(0),
                    );
                }
                Err(err) if err.is_fqdn_conflict() => {
                    // Another simultaneous create got the same FQDN, try again.
                    false
                }
                Err(DatabaseError::TryAgain) => {
                    // All the IP's in the batch we grabbed from the database got taken by other
                    // concurrent calls to create_fast_path. Try again.
                    false
                }
                Err(DatabaseError::ResourceExhausted(_)) if segments_idx < segments.len() - 1 => {
                    // If there are more segments to check, we just need to signal that this one was exhausted.
                    true
                }
                Err(err) => {
                    // Some other error, roll back the inner transaction
                    fast_txn.rollback().await?;
                    return Err(err);
                }
            };

            fast_txn.rollback().await?;
            tokio::task::yield_now().await;

            // If this segment is exhausted, go to the next segment.
            if segment_exhausted {
                break;
            }
        }
    }

    Err(DatabaseError::internal(format!(
        "unable to create machine interface in fast path out of segments {:?} after {} retries",
        segments, FAST_PATH_MAX_RETRIES
    )))
}

/// Create a machine interface with a specific static IP address.
/// A perfect compliment to create_fast_path and create_slow_path.
///
/// If the target IP is already allocated to an interface with
/// same MAC, just return the existing interface snapshot.
///
/// Otherwise, if the target IP is allocated to a different MAC,
/// return with an AddressAlreadyInUse error.
async fn create_static_path(
    txn: &mut PgConnection,
    segments: &[NetworkSegment],
    macaddr: &MacAddress,
    primary_interface: bool,
    address: IpAddr,
    interface_type: InterfaceType,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    // For the staic path, we need to be a little forgiving since
    // we expect to allow static assignment even if the requested
    // assignment is outside any network segment as long as
    // there is a "static assignment segment".
    // To identify the owning segment:
    //  - pick a segment whose prefix contains the static IP (we guard against overlap so there could be at most 1)
    //  - otherwise allow the special static-assignments segment
    //  - otherwise return an error
    let segment = segments
                .iter()
                .find(|s| s.prefixes.iter().any(|p| p.prefix.contains(address)))
                .or_else(|| segments.iter().find(|s| s.config.name == crate::network_segment::STATIC_ASSIGNMENTS_SEGMENT_NAME))
                .ok_or_else(|| DatabaseError::internal(format!(
                    "unable to find network segment that contains requested IP {address} in network segments: {}",
                    segments.iter().map(|s| s.id.to_string()).join(", "),
                ))
    )?;

    if let Some(existing) = find_by_ip(&mut *txn, address).await? {
        if existing.mac_address == *macaddr {
            return Ok(existing);
        }
        return Err(AddressAlreadyInUseError(
            address,
            existing.mac_address,
            existing.segment_id,
            existing.id,
        )
        .into());
    }

    let interface_id = create_inner(
        txn,
        segment,
        macaddr,
        segment.config.subdomain_id,
        primary_interface,
        &[address],
        AllocationType::Static,
        interface_type,
    )
    .await?;

    Ok(
        find_by(txn, ObjectColumnFilter::One(IdColumn, &interface_id))
            .await?
            .remove(0),
    )
}

/// Create a machine interface and allocate IP addresses, slow path for whole-prefix allocation.
///
/// This uses [`crate::IpAllocator`], which requires:
///
/// - Locking the machine_interfaces_lock table
/// - Reading all used IP's from the database for the given segment
/// - Selecting a batch of IP's according to the selection strategy
#[allow(txn_held_across_await)]
pub async fn create_slow_path(
    txn: &mut PgConnection,
    segment: &NetworkSegment,
    macaddr: &MacAddress,
    primary_interface: bool,
    address_strategy: AddressSelectionStrategy,
    interface_type: InterfaceType,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    // We're potentially about to insert a couple rows, so create a savepoint.
    let mut inner_txn = Transaction::begin_inner(txn).await?;

    // If either requested addresses are auto-generated, we lock the entire table
    // by way of the inner_txn.
    lock_network_segment_exclusive(&mut inner_txn, segment).await?;

    // Collect SVI IPs so the allocator knows they're already reserved.
    let mut reserved_ips = vec![];
    for prefix in &segment.prefixes {
        if let Some(svi_ip) = prefix.svi_ip {
            reserved_ips.push(svi_ip);
        }
    }

    let dhcp_handler: Box<dyn UsedIpResolver<PgConnection> + Send> =
        Box::new(UsedAdminNetworkIpResolver {
            segment_id: segment.id,
            busy_ips: reserved_ips,
        });

    // Allocate an address from each prefix in the segment. For dual-stack
    // segments this means one IPv4 address and one IPv6 address.
    let allocator = IpAllocator::new(
        inner_txn.as_pgconn(),
        segment,
        dhcp_handler,
        address_strategy,
    )
    .await?;

    let mut allocated_addresses = Vec::new();
    for (_, maybe_address) in allocator {
        let address = maybe_address?;
        allocated_addresses.push(address.ip());
    }

    let interface_id = create_inner(
        inner_txn.as_pgconn(),
        segment,
        macaddr,
        segment.config.subdomain_id,
        primary_interface,
        &allocated_addresses,
        AllocationType::Dhcp,
        interface_type,
    )
    .await?;
    inner_txn.commit().await?;

    Ok(
        find_by(txn, ObjectColumnFilter::One(IdColumn, &interface_id))
            .await?
            .remove(0),
    )
}

/// Fast path for single-IP allocation.
///
/// This allocates a single candidate IP per prefix entirely in the database, without having to read
/// all the used IP's.
async fn try_create_fast_path(
    // Note: Must be a transaction since we're doing locks
    txn: &mut PgTransaction<'_>,
    segment: &NetworkSegment,
    macaddr: &MacAddress,
    primary_interface: bool,
    interface_type: InterfaceType,
) -> DatabaseResult<MachineInterfaceId> {
    let allocated_addresses = allocate_addresses_from_segment(txn, segment).await?;

    create_inner(
        txn,
        segment,
        macaddr,
        segment.config.subdomain_id,
        primary_interface,
        &allocated_addresses,
        AllocationType::Dhcp,
        interface_type,
    )
    .await
}

/// Allocate one IP address from each prefix in the segment.
///
/// For dual-stack segments this means one IPv4 and one IPv6 address. Callers
/// must already hold the segment's exclusive lock when the segment contains
/// IPv6 prefixes.
async fn allocate_addresses_from_segment(
    txn: &mut PgTransaction<'_>,
    segment: &NetworkSegment,
) -> DatabaseResult<Vec<IpAddr>> {
    let mut addresses = Vec::with_capacity(segment.prefixes.len());
    for prefix in &segment.prefixes {
        if prefix.prefix.is_ipv6() {
            // Use a single-prefix segment view so v6 allocation cannot consume
            // or reason about unrelated prefixes on a dual-stack segment.
            let single_prefix_segment = NetworkSegment {
                prefixes: vec![prefix.clone()],
                ..segment.clone()
            };
            addresses
                .extend(allocate_v6_addresses_via_ip_allocator(txn, &single_prefix_segment).await?);
        } else {
            // IPv4 stays on the SQL fast path for its existing concurrency and
            // allocation-order behavior.
            let address = allocate_next_ip_with_retry(txn, segment, prefix).await?;
            addresses.push(address);
        }
    }
    Ok(addresses)
}

/// Allocates IPv6 DHCP addresses using the Rust `IpAllocator`.
///
/// The caller must hold the segment's exclusive advisory lock because
/// `IpAllocator` reads the used-address set instead of taking per-IP advisory
/// locks for each candidate.
async fn allocate_v6_addresses_via_ip_allocator(
    txn: &mut PgTransaction<'_>,
    segment: &NetworkSegment,
) -> DatabaseResult<Vec<IpAddr>> {
    // Collect SVI IPs so the allocator treats those addresses as unavailable.
    let reserved_ips = segment
        .prefixes
        .iter()
        .filter_map(|prefix| prefix.svi_ip)
        .collect();

    let dhcp_handler: Box<dyn UsedIpResolver<PgConnection> + Send> =
        Box::new(UsedAdminNetworkIpResolver {
            segment_id: segment.id,
            busy_ips: reserved_ips,
        });

    // Limit the allocator input to IPv6 prefixes; IPv4 remains on the SQL fast
    // path even when the original segment is dual-stack.
    let ipv6_segment = NetworkSegment {
        prefixes: segment
            .prefixes
            .iter()
            .filter(|prefix| prefix.prefix.is_ipv6())
            .cloned()
            .collect(),
        ..segment.clone()
    };

    let allocator = IpAllocator::new(
        txn.as_mut(),
        &ipv6_segment,
        dhcp_handler,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await?;

    let mut allocated_addresses = Vec::with_capacity(ipv6_segment.prefixes.len());
    for (prefix_id, maybe_address) in allocator {
        let address = match maybe_address {
            Ok(address) => address,
            Err(DatabaseError::DhcpError(DhcpError::PrefixExhausted(_))) => {
                let prefix = ipv6_segment
                    .prefixes
                    .iter()
                    .find(|prefix| prefix.id == prefix_id)
                    .map_or_else(|| prefix_id.to_string(), |prefix| prefix.prefix.to_string());
                return Err(DatabaseError::ResourceExhausted(format!(
                    "No IP addresses left in prefix {prefix}"
                )));
            }
            Err(err) => return Err(err),
        };
        allocated_addresses.push(address.ip());
    }

    Ok(allocated_addresses)
}

/// Create a machine interface row without inserting address rows.
///
/// This preserves the normal hostname and retained boot-interface behavior for
/// observation-only DHCPv6 paths that must not consume a DHCP allocation.
async fn create_without_addresses(
    txn: &mut PgConnection,
    segment: &NetworkSegment,
    macaddr: &MacAddress,
    primary_interface: bool,
    retained_window: Option<chrono::Duration>,
) -> DatabaseResult<MachineInterfaceSnapshot> {
    // A brand-new observed row has no address yet, so naming uses the dormant placeholder.
    let ctx = NamingContext {
        mac_address: *macaddr,
        addresses: &[],
        current_hostname: None,
        machine_id: None,
        is_primary: primary_interface,
        interface_type: InterfaceType::Data,
        interface_id: None,
        domain_id: segment.config.subdomain_id,
    };
    let hostname = host_naming::hostname_for(txn, &ctx).await?;

    // Insert only the interface identity; address observation/allocation happens later.
    let interface_id = insert_machine_interface(
        txn,
        &segment.id,
        macaddr,
        hostname,
        segment.config.subdomain_id,
        primary_interface,
        InterfaceType::Data,
    )
    .await?;

    let mut snapshot = find_by(&mut *txn, ObjectColumnFilter::One(IdColumn, &interface_id))
        .await?
        .remove(0);
    if snapshot.boot_interface_id.is_none()
        && let Some(boot_interface_id) =
            crate::retained_boot_interface::take_by_mac(&mut *txn, *macaddr, retained_window)
                .await?
    {
        set_boot_interface_id(*macaddr, &boot_interface_id, &mut *txn).await?;
        snapshot.boot_interface_id = Some(boot_interface_id);
    }

    Ok(snapshot)
}

/// Create the actual machine interface once we know what addresses we want.
#[allow(clippy::too_many_arguments)]
async fn create_inner(
    txn: &mut PgConnection,
    segment: &NetworkSegment,
    macaddr: &MacAddress,
    domain_id: Option<DomainId>,
    primary_interface: bool,
    allocated_addresses: &[IpAddr],
    allocation_type: AllocationType,
    interface_type: InterfaceType,
) -> DatabaseResult<MachineInterfaceId> {
    // Allocation must have produced at least one address for the new interface.
    if allocated_addresses.is_empty() {
        let prefixes: Vec<_> = segment
            .prefixes
            .iter()
            .map(|p| p.prefix.to_string())
            .collect();
        return Err(crate::DatabaseError::ResourceExhausted(format!(
            "No IP addresses left in network segment (prefixes: {})",
            prefixes.join(", ")
        )));
    }
    // A brand-new interface has no stored name yet, so the configured strategy
    // assigns one (IP-derived, a new fun name, etc.).
    let ctx = NamingContext {
        mac_address: *macaddr,
        addresses: allocated_addresses,
        current_hostname: None,
        // Brand-new interface: not yet bound to a machine, so serial naming
        // (if configured) uses a temporary IP-based name and switches later.
        machine_id: None,
        is_primary: primary_interface,
        interface_type,
        // The row doesn't exist yet.
        interface_id: None,
        domain_id,
    };
    let hostname = host_naming::hostname_for(txn, &ctx).await?;

    let interface_id = insert_machine_interface(
        txn,
        &segment.id,
        macaddr,
        hostname,
        domain_id,
        primary_interface,
        interface_type,
    )
    .await?;

    for address in allocated_addresses {
        insert_machine_interface_address(txn, &interface_id, address, allocation_type).await?;
    }

    Ok(interface_id)
}

/// Retries allocation for a single prefix which may be under contention.
///
/// Each iteration fetches a small free-IP batch, tries to take an advisory lock
/// on each candidate, and returns once one lock is acquired.
///
/// This is for eliminating a big shared lock when we have lots of machines DHCP'ing for the first
/// time simultaneously: By requesting a batch of free IP's at once and trying locks on each one, we
/// can process roughly [`FAST_PATH_CANDIDATE_BATCH`] initial DHCP requests concurrently.
async fn allocate_next_ip_with_retry(
    // Note: Must be a transaction since we're doing locks
    txn: &mut PgTransaction<'_>,
    segment: &NetworkSegment,
    prefix: &NetworkPrefix,
) -> DatabaseResult<IpAddr> {
    // The SQL fast path is IPv4-only. IPv6 host-space math needs the Rust
    // allocator's u128 arithmetic instead of PostgreSQL int4 shifts.
    if prefix.prefix.is_ipv6() {
        return Err(DatabaseError::internal(format!(
            "IPv6 prefix {} cannot use the SQL fast-path allocator",
            prefix.prefix
        )));
    }

    let reserved = if prefix.gateway.is_none() {
        prefix.num_reserved.max(2)
    } else {
        prefix.num_reserved.max(1)
    };

    let host_bits = 32 - prefix.prefix.prefix() as i32;

    for _ in 0..FAST_PATH_MAX_RETRIES {
        // Grab FAST_PATH_CANDIDATE_BATCH IP's at once
        let query = r#"
SELECT ($1::inet + ip_series.n)::inet AS ip
FROM generate_series($3, (1 << $2) - 2) AS ip_series(n)
LEFT JOIN machine_interface_addresses AS mia
  ON mia.address = ($1::inet + ip_series.n)::inet
WHERE mia.address IS NULL
  AND ($4::inet IS NULL OR ($1::inet + ip_series.n)::inet <> $4::inet)
  AND ($5::inet IS NULL OR ($1::inet + ip_series.n)::inet <> $5::inet)
ORDER BY ip
LIMIT $6;
    "#;
        let candidates = sqlx::query_scalar::<_, IpAddr>(query)
            .bind(prefix.prefix.ip())
            .bind(host_bits)
            .bind(reserved)
            .bind(prefix.gateway)
            .bind(prefix.svi_ip)
            .bind(FAST_PATH_CANDIDATE_BATCH)
            .fetch_all(txn.as_mut())
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        if candidates.is_empty() {
            return Err(DatabaseError::ResourceExhausted(format!(
                "No IP addresses left in prefix {}",
                prefix.prefix
            )));
        }

        // Try to lock an IP (in case multiple allocation requests are happening at once)
        for candidate in candidates {
            if try_lock_ip_candidate(txn, segment, candidate).await? {
                return Ok(candidate);
            }
        }
    }

    Err(DatabaseError::TryAgain)
}

/// Attempts to acquire a transaction-scoped advisory lock for one IP candidate.
///
/// A successful lock means this transaction "owns" that candidate for the current attempt, which
/// avoids same-IP races across concurrent allocations.
async fn try_lock_ip_candidate(
    // Note: Must be a transaction since we're doing locks
    txn: &mut PgTransaction<'_>,
    segment: &NetworkSegment,
    ip: IpAddr,
) -> DatabaseResult<bool> {
    let query = "SELECT pg_try_advisory_xact_lock(hashtextextended($1::text, 0))";
    sqlx::query_scalar::<_, bool>(query)
        .bind(format!("{}:{}", segment.id, ip))
        .fetch_one(txn.as_mut())
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

async fn lock_network_segment_shared(
    // Note: Must be a transaction since we're doing locks
    txn: &mut PgTransaction<'_>,
    segment: &NetworkSegment,
) -> DatabaseResult<()> {
    let query = "SELECT pg_advisory_xact_lock_shared(hashtextextended($1::text, 0))";
    sqlx::query_scalar(query)
        .bind(format!("network_segment.{}", segment.id))
        .fetch_one(txn.as_mut())
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

async fn lock_network_segment_exclusive(
    // Note: Must be a transaction since we're doing locks
    txn: &mut PgTransaction<'_>,
    segment: &NetworkSegment,
) -> DatabaseResult<()> {
    lock_network_segments_exclusive(txn.as_mut(), std::slice::from_ref(&segment.id)).await
}

/// Advisory-lock every segment in `segment_ids`, in ascending id order --
/// the allocator convention: segment advisory lock first, then machine
/// interface/address row locks. This is the one home for the lock key and
/// ordering; every segment-lock helper funnels through it. Must run inside a
/// transaction: the locks are `pg_advisory_xact_lock`-scoped and release on
/// commit or rollback.
pub async fn lock_network_segments_exclusive(
    txn: &mut PgConnection,
    segment_ids: &[NetworkSegmentId],
) -> DatabaseResult<()> {
    let mut ids = segment_ids.to_vec();
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        let query = "SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))";
        sqlx::query_scalar::<_, ()>(query)
            .bind(format!("network_segment.{id}"))
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;
    }
    Ok(())
}

/// Advisory-lock every admin segment, in ascending id order. Transactions
/// that touch machine-interface rows before their segment locks -- the flows
/// that end in `reconcile_admin_addresses_for_host`, and machine teardown,
/// which deletes interface rows wholesale -- call this right after opening
/// the transaction so the whole transaction follows the allocator order.
/// Later acquisitions of the same locks in the same transaction (reconcile's
/// own pass) are no-ops.
pub async fn lock_all_admin_segments(txn: &mut PgConnection) -> DatabaseResult<()> {
    let segment_ids =
        db_network_segment::list_segment_ids(&mut *txn, Some(NetworkSegmentType::Admin)).await?;
    lock_network_segments_exclusive(txn, &segment_ids).await
}

pub async fn allocate_svi_ip(
    txn: &mut PgTransaction<'_>,
    segment: &NetworkSegment,
) -> DatabaseResult<(NetworkPrefixId, IpAddr)> {
    let dhcp_handler: Box<dyn UsedIpResolver<PgConnection> + Send> =
        Box::new(UsedAdminNetworkIpResolver {
            segment_id: segment.id,
            busy_ips: vec![],
        });

    // Prevent other allocations from happening concurrently in this network segment
    lock_network_segment_exclusive(txn, segment).await?;

    let mut addresses_allocator = IpAllocator::new(
        txn.as_mut(),
        segment,
        dhcp_handler,
        AddressSelectionStrategy::NextAvailableIp,
    )
    .await?;
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
        && let Some(interface) = find_by_ip(&mut *txn, remote_ip).await?
    {
        // remove debug message by Apr 2024
        tracing::debug!(
            machine_interface_id = %interface.id,
            remote_ip_address = %remote_ip,
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
    interface_type: InterfaceType,
) -> DatabaseResult<MachineInterfaceId> {
    let query = "INSERT INTO machine_interfaces
        (segment_id, mac_address, hostname, domain_id, primary_interface, interface_type)
        VALUES
        ($1::uuid, $2::macaddr, $3::varchar, $4::uuid, $5::bool, $6::interface_type) RETURNING id";

    let (interface_id,): (MachineInterfaceId,) = sqlx::query_as(query)
        .bind(segment_id)
        .bind(mac_address)
        .bind(hostname)
        .bind(domain_id)
        .bind(is_primary_interface)
        .bind(interface_type)
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
    allocation_type: model::allocation_type::AllocationType,
) -> DatabaseResult<()> {
    let query = "INSERT INTO machine_interface_addresses (interface_id, address, allocation_type) VALUES ($1::uuid, $2::inet, $3)";
    sqlx::query(query)
        .bind(interface_id)
        .bind(address)
        .bind(allocation_type)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

async fn find_by<'a, C: ColumnInfo<'a, TableType = MachineInterfaceSnapshot>>(
    txn: impl DbReader<'_>,
    filter: ObjectColumnFilter<'a, C>,
) -> Result<Vec<MachineInterfaceSnapshot>, DatabaseError> {
    let mut query = FilterableQueryBuilder::new(machine_interface_snapshot_query!())
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
    retained_window: Option<chrono::Duration>,
) -> Result<(), DatabaseError> {
    tracing::info!(
        machine_id=%predicted_machine_interface.machine_id,
        mac_address=%predicted_machine_interface.mac_address,
        relay_ip_address = %relay_ip,
        "Got DHCP from predicted machine interface, moving to machine"
    );
    let Some(network_segment) = crate::network_segment::for_relay(txn, relay_ip).await? else {
        return Err(DatabaseError::internal(format!(
            "No network segment defined for relay address: {relay_ip}"
        )));
    };

    if network_segment.config.segment_type
        != predicted_machine_interface.expected_network_segment_type
    {
        return Err(DatabaseError::internal(format!(
            "Got DHCP for predicted host with MAC address {0} on network segment {1}, which is not of the expected type {2}",
            predicted_machine_interface.mac_address,
            network_segment.id,
            predicted_machine_interface.expected_network_segment_type,
        )));
    }

    let existing_row =
        self::find_by_mac_address(&mut *txn, predicted_machine_interface.mac_address)
            .await?
            .into_iter()
            .find(|machine_interface| machine_interface.segment_id == network_segment.id);

    if let Some(machine_id) = existing_row
        .as_ref()
        .and_then(|machine_interface| machine_interface.machine_id.as_ref())
    {
        if machine_id.ne(&predicted_machine_interface.machine_id) {
            tracing::error!(
                %machine_id,
                "Can't migrate predicted_machine_interface to machine_interface: one already exists with this MAC address"
            );
            return Err(DatabaseError::NetworkSegmentDuplicateMacAddress(
                predicted_machine_interface.mac_address,
            ));
        }
        // To even get here, the interface must have been attached to the
        // machine through some path that didn't clean up the prediction --
        // think a concurrent DHCP for the same MAC, or an attach flow that
        // doesn't know predictions exist. There's nothing left to migrate,
        // so just finish the bookkeeping below and remove the prediction.
        tracing::warn!(
            %machine_id,
            "Bug: trying to move predicted_machine_interface to machine_interface, but it's already a part of this machine? Will proceed anyway."
        );
    }

    let (machine_interface_id, current_boot_interface_id, current_primary, row_created_here) =
        match existing_row {
            // This host has already DHCP'd once and created a machine_interface;
            // we will migrate it below.
            Some(machine_interface_snapshot) => (
                machine_interface_snapshot.id,
                machine_interface_snapshot.boot_interface_id,
                machine_interface_snapshot.primary_interface,
                false,
            ),
            None => {
                // This host has never DHCP'd before, create only the interface
                // identity. The DHCP handler allocates the requested address
                // family after promotion.
                let machine_interface = create_without_addresses(
                    txn,
                    &network_segment,
                    &predicted_machine_interface.mac_address,
                    predicted_machine_interface.primary_interface,
                    retained_window,
                )
                .await?;
                (
                    machine_interface.id,
                    machine_interface.boot_interface_id,
                    machine_interface.primary_interface,
                    true,
                )
            }
        };

    // Land the declared boot interface as we promote: the prediction holds the
    // host's declared `ExpectedHostNic.primary`, so a promoted interface is primary
    // exactly when it was declared. (An anonymous row found here keeps whatever
    // flag DHCP set, so reconcile it to the declaration.) Done before association
    // so a row reaches its machine already carrying the right flag.
    if current_primary != predicted_machine_interface.primary_interface {
        set_primary_interface(
            &machine_interface_id,
            predicted_machine_interface.primary_interface,
            &mut *txn,
        )
        .await?;
    }

    // A primary prediction takes over as the host's sole primary: demote any
    // current primary (e.g. the DPU admin link on a managed-DPU host that boots from
    // a declared integrated NIC) before this row joins the machine, so the two
    // never collide on `one_primary_interface_per_machine`.
    if predicted_machine_interface.primary_interface {
        demote_primary_interfaces_for_machine(&predicted_machine_interface.machine_id, txn).await?;
    }

    // Take either the newly-created interface or the anonymous one we found, and associate it with
    // this machine.
    associate_interface_with_machine(
        &machine_interface_id,
        MachineInterfaceAssociation::Machine(predicted_machine_interface.machine_id),
        txn,
    )
    .await?;

    // Resolve the promoted row's boot interface id. The prediction's value
    // comes from the live report and outranks an existing row value: that
    // row may have been created from a static preallocation (an
    // ExpectedMachine `fixed_ip` recorded while the prediction was pending)
    // and recovered an older retained id. The retention record is consumed
    // either way (creation already consumed it, or the take here does):
    // from here on the MAC has a `machine_interfaces` row for explorations
    // to keep up to date.
    let retained_boot_interface_id = if row_created_here {
        // Creation already consumed the record; any recovered value is on
        // the row (`current_boot_interface_id`).
        None
    } else {
        crate::retained_boot_interface::take_by_mac(
            &mut *txn,
            predicted_machine_interface.mac_address,
            retained_window,
        )
        .await?
    };
    let predicted_boot_interface_id = predicted_machine_interface.boot_interface_id.clone();
    let resolved_boot_interface_id = predicted_boot_interface_id
        .or(current_boot_interface_id.clone())
        .or(retained_boot_interface_id);
    if let Some(boot_interface_id) = resolved_boot_interface_id
        && current_boot_interface_id.as_deref() != Some(boot_interface_id.as_str())
    {
        set_boot_interface_id(
            predicted_machine_interface.mac_address,
            &boot_interface_id,
            &mut *txn,
        )
        .await?;
    }

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
    retained_window: Option<chrono::Duration>,
) -> Result<MachineInterfaceSnapshot, DatabaseError> {
    let admin_networks = crate::network_segment::admin(txn).await?;

    // Using gateway IP as relay IP. This is just to enable next algorithm to find related network
    // segment.
    let mut gateways = vec![];
    let mut existing_machine = None;

    for admin_network in admin_networks {
        for prefix in admin_network.prefixes {
            if let Some(gateway) = prefix.gateway {
                gateways.push(gateway);
            }
        }
    }

    if gateways.is_empty() {
        return Err(DatabaseError::AdminNetworkNotConfigured);
    };

    // Host mac is stored at DPU topology data.
    let host_mac = hardware_info
        .map(|x| x.factory_mac_address())
        .ok_or_else(|| DatabaseError::NotFoundError {
            kind: "Hardware Info",
            id: dpu_id.to_string(),
        })??;

    for gateway in gateways.iter() {
        existing_machine =
            crate::machine::find_existing_machine(txn, host_mac, gateway.to_owned()).await?;
        if existing_machine.is_some() {
            break;
        }
    }

    let machine_interface = find_or_create_machine_interface(
        txn,
        existing_machine,
        host_mac,
        &gateways,
        None,
        None,
        retained_window,
    )
    .await?;
    associate_interface_with_dpu_machine(&machine_interface.id, dpu_id, txn).await?;

    Ok(machine_interface)
}

/// Reconciles host-owned admin interfaces so DPU-backed links only own DHCP addresses when active.
///
/// When the primary admin interface is DPU-backed, that interface owns the host-visible admin
/// DHCP addresses and all other DPU-backed admin links are dormant. When the primary admin
/// interface is a non-DPU host NIC, every DPU-backed admin link is dormant and this helper only
/// cleans up stale DHCP rows on those DPU-backed links.
///
/// When a DPU-backed admin link is active, its DHCP is expected to be served only by the primary
/// DPU's `forge-dhcp-server`, from the host config generated by
/// `get_managed_host_network_config`.
/// The central Kea + `carbide-dhcp` path must not answer for these links. Under that invariant it
/// is safe to move a DHCP address row between same-segment DPU-backed host interfaces when the
/// primary DPU changes: the DPU-side server reads the active config instead of consulting a
/// MAC-keyed lease database, and the move preserves the host's admin IP without needing spare pool
/// capacity.
///
/// If DPU-backed admin DHCP can ever reach Kea, do not rely on this row move alone. Kea lease/cache
/// state must be synchronized, or reconciliation should allocate a new primary address before
/// deleting the old primary's DHCP address.
///
/// Returns `true` only when the externally visible active admin config changed. Dormant-interface
/// cleanup is persisted but intentionally returns `false` by itself.
#[allow(txn_held_across_await)]
pub async fn reconcile_admin_addresses_for_host(
    txn: &mut PgConnection,
    host_machine_id: &MachineId,
) -> DatabaseResult<bool> {
    // This allow is for a limitation in the custom `txn_held_across_await` lint, not for unrelated
    // async work. The input `&mut PgConnection` is immediately wrapped in an inner transaction
    // savepoint, and every await before commit is database work performed through that savepoint
    // (`txn.as_pgconn()`, `&mut txn`, or helpers that receive it). The lint still reports the outer
    // connection parameter as held across those awaits because it does not track that
    // `Transaction::begin_inner(txn)` transfers subsequent DB work onto the wrapper.
    // Treat reconciliation as one savepoint inside the caller's transaction. All row locks,
    // advisory segment locks, address moves, and cleanup either commit together or roll back
    // together.
    let mut txn = Transaction::begin_inner(txn).await?;

    // Lock all admin segments up front instead of doing a precise pre-read of
    // this host's segment set. The precise approach would need a locked re-read
    // and retry if the host's admin interfaces moved between segments; admin
    // segment count is expected to be small, so the broader lock keeps the
    // ordering obvious and deadlock-safe.
    //
    // This matches allocator lock ordering: segment advisory lock first, then
    // machine interface/address row locks.
    let segments = load_and_lock_all_admin_segments(&mut txn).await?;
    let segments_by_id = segments
        .iter()
        .map(|segment| (segment.id, segment))
        .collect::<HashMap<_, _>>();

    // Start from all host admin interfaces so a non-DPU primary admin NIC can remain the active
    // config source while DPU-backed links are treated as dormant.
    let mut interfaces =
        find_host_admin_interfaces_for_update(txn.as_pgconn(), host_machine_id).await?;
    if !interfaces
        .iter()
        .any(|interface| interface.is_dpu_backed_host_link)
    {
        txn.commit().await?;
        return Ok(false);
    }

    // Lock existing address rows
    let interface_ids = interfaces
        .iter()
        .map(|interface| interface.id)
        .collect::<Vec<_>>();
    lock_admin_interface_addresses(txn.as_pgconn(), &interface_ids).await?;

    // The active primary admin interface to repair, paired with its segment --
    // present only when the host boots from a DPU admin link. A host that boots
    // from a non-admin primary (a HostInband integrated NIC on a managed-DPU host)
    // has no primary in the admin set, which is valid, not broken: every DPU
    // admin link is then dormant and only gets cleaned up below. A host with no
    // primary interface at all is the genuine error.
    let primary_to_repair = match interfaces
        .iter()
        .position(|interface| interface.primary_interface)
    {
        Some(index) if interfaces[index].is_dpu_backed_host_link => {
            let segment = *segments_by_id
                .get(&interfaces[index].segment_id)
                .ok_or_else(|| {
                    DatabaseError::internal(format!(
                        "Primary admin segment {} was not loaded for host {host_machine_id}",
                        interfaces[index].segment_id
                    ))
                })?;
            Some((index, segment))
        }
        Some(_) => None,
        None => {
            if !machine_has_primary_interface(host_machine_id, txn.as_pgconn()).await? {
                return Err(DatabaseError::internal(format!(
                    "Host {host_machine_id} has DPU-backed admin interfaces but no primary admin interface"
                )));
            }
            None
        }
    };

    let mut active_config_changed = false;

    if let Some((primary_index, primary_segment)) = primary_to_repair {
        // Repair the active interface first. If a dormant DPU-backed interface already owns a
        // same-segment DHCP address, move it so the host keeps its current admin IP across
        // primary-DPU changes. If there is no reusable address, allocate only the missing family.
        for family in [IpAddressFamily::Ipv4, IpAddressFamily::Ipv6]
            .into_iter()
            .filter(|family| {
                primary_segment
                    .prefixes
                    .iter()
                    .any(|prefix| prefix.prefix.is_address_family(*family))
            })
        {
            if interfaces[primary_index]
                .addresses
                .iter()
                .any(|address| address.address.is_address_family(family))
            {
                continue;
            }

            if let Some((donor_index, donor_address)) =
                find_reusable_dhcp_address(&interfaces, primary_index, family)
            {
                // Preserve the host-visible admin IP when primary-DPU ownership
                // changes. See the function-level DHCP path invariant above.
                move_dhcp_address_to_interface(
                    txn.as_pgconn(),
                    interfaces[primary_index].id,
                    interfaces[donor_index].id,
                    donor_address.address,
                )
                .await?;

                // Keep the local snapshot aligned with the database mutations:
                // The database row has moved, but `interfaces` is the source of truth for the rest of
                // this reconciliation pass. Update it immediately so dormant cleanup does not think the
                // donor still owns this DHCP address, and so primary hostname selection uses the address
                // that will actually be visible through DHCP and DNS after commit.
                interfaces[donor_index].addresses.retain(|address| {
                    !(address.address == donor_address.address
                        && address.allocation_type == AllocationType::Dhcp)
                });
                interfaces[primary_index]
                    .addresses
                    .push(MachineInterfaceAddressWithType {
                        address: donor_address.address,
                        allocation_type: AllocationType::Dhcp,
                    });
                active_config_changed = true;
            } else {
                let allocated = allocate_address_for_family(
                    txn.as_pgconn(),
                    interfaces[primary_index].id,
                    primary_segment,
                    family,
                )
                .await?;
                interfaces[primary_index]
                    .addresses
                    .extend(
                        allocated
                            .into_iter()
                            .map(|address| MachineInterfaceAddressWithType {
                                address,
                                allocation_type: AllocationType::Dhcp,
                            }),
                    );
                // The allocation also re-derives the hostname; refresh our local
                // copy so the final naming pass below sees the row's real name.
                interfaces[primary_index].hostname =
                    find_one(txn.as_pgconn(), interfaces[primary_index].id)
                        .await?
                        .hostname;
                active_config_changed = true;
            }
        }
    }

    // Remove DHCP allocations from dormant interfaces and make addressless
    // rows DNS-silent with deterministic MAC-derived hostnames. This cleanup is intentionally not
    // reported as an active config change by itself.
    for interface in interfaces
        .iter_mut()
        .filter(|interface| interface.is_dpu_backed_host_link && !interface.primary_interface)
    {
        let deleted = delete_dhcp_addresses_from_interface(txn.as_pgconn(), interface.id).await?;
        if !deleted.is_empty() {
            interface
                .addresses
                .retain(|address| address.allocation_type != AllocationType::Dhcp);
        }

        if interface.addresses.is_empty() {
            // This interface has lost all its IP addresses. The IP style parks
            // it under a placeholder name; fun keeps the name it already has;
            // serial renames it to its `serial-<mac>` form once the machine's
            // serial is known. Either way we clear its domain so it drops out
            // of DNS, since with no address there's nothing for a name to
            // point at.
            let ctx = NamingContext {
                mac_address: interface.mac_address,
                addresses: &[],
                current_hostname: Some(&interface.hostname),
                machine_id: Some(*host_machine_id),
                // Should be always false here -- the above loop filters to
                // non-primary links, but this should still read from the row
                // so the context stays accurate (e.g. if the filter changes).
                // In other words, a non-primary never takes the machine's
                // (shared) bare serial.
                is_primary: interface.primary_interface,
                // DPU-backed host links are data interfaces by definition.
                interface_type: InterfaceType::Data,
                interface_id: Some(interface.id),
                domain_id: interface.domain_id,
            };
            let hostname = host_naming::hostname_for(txn.as_pgconn(), &ctx).await?;
            if interface.domain_id.is_some() || interface.hostname != hostname {
                update_hostname_and_domain(txn.as_pgconn(), interface.id, &hostname, None).await?;
                interface.hostname = hostname;
                interface.domain_id = None;
            }
        }
    }

    if let Some((primary_index, primary_segment)) = primary_to_repair {
        // Finally, make the primary DPU-backed interface metadata match the address that
        // will be visible through DHCP, DNS, and DPU admin config.
        let primary = &interfaces[primary_index];
        if primary.addresses.is_empty() {
            return Err(DatabaseError::internal(format!(
                "Primary admin interface {} has no address after reconciliation",
                primary.id
            )));
        }
        let active_addresses: Vec<IpAddr> = primary
            .addresses
            .iter()
            .map(|address| address.address)
            .collect();
        let ctx = NamingContext {
            mac_address: primary.mac_address,
            addresses: &active_addresses,
            current_hostname: Some(&primary.hostname),
            // The primary admin interface: where serial naming takes effect, once the
            // machine's discovered serial is available.
            machine_id: Some(*host_machine_id),
            is_primary: true,
            // The primary admin interface is a data interface by definition.
            interface_type: InterfaceType::Data,
            interface_id: Some(primary.id),
            domain_id: primary.domain_id,
        };
        let active_hostname = host_naming::hostname_for(txn.as_pgconn(), &ctx).await?;
        if primary.hostname != active_hostname
            || primary.domain_id != primary_segment.config.subdomain_id
        {
            update_hostname_and_domain(
                txn.as_pgconn(),
                primary.id,
                &active_hostname,
                primary_segment.config.subdomain_id,
            )
            .await?;
            active_config_changed = true;
        }
    }

    txn.commit().await?;
    Ok(active_config_changed)
}

/// Finds host-owned admin interfaces and locks the interface rows.
async fn find_host_admin_interfaces_for_update(
    txn: &mut PgConnection,
    host_machine_id: &MachineId,
) -> DatabaseResult<Vec<AdminInterfaceForReconcile>> {
    let query = r#"
SELECT
    mi.id,
    mi.segment_id,
    mi.hostname,
    mi.domain_id,
    mi.primary_interface,
    mi.attached_dpu_machine_id IS NOT NULL
        AND mi.attached_dpu_machine_id != mi.machine_id AS is_dpu_backed_host_link,
    mi.mac_address,
    mia.address,
    mia.allocation_type
FROM machine_interfaces mi
JOIN network_segments ns ON ns.id = mi.segment_id
LEFT JOIN machine_interface_addresses mia ON mia.interface_id = mi.id
WHERE mi.machine_id = $1
  AND ns.network_segment_type = 'admin'
ORDER BY mi.id, mia.address
FOR UPDATE OF mi"#;

    let rows: Vec<AdminInterfaceForReconcileRow> = sqlx::query_as(query)
        .bind(host_machine_id)
        .fetch_all(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    let mut interfaces: Vec<AdminInterfaceForReconcile> = Vec::new();
    for row in rows {
        let need_new_interface = match interfaces.last() {
            Some(interface) => interface.id != row.id,
            None => true,
        };
        if need_new_interface {
            interfaces.push(AdminInterfaceForReconcile {
                id: row.id,
                segment_id: row.segment_id,
                hostname: row.hostname,
                domain_id: row.domain_id,
                primary_interface: row.primary_interface,
                is_dpu_backed_host_link: row.is_dpu_backed_host_link,
                mac_address: row.mac_address,
                addresses: Vec::new(),
            });
        }

        if let Some(address) = row.address {
            let allocation_type = row.allocation_type.ok_or_else(|| {
                DatabaseError::internal(format!(
                    "Interface {} has address {address} without allocation_type",
                    row.id
                ))
            })?;
            interfaces
                .last_mut()
                .expect("interface was just pushed or already exists")
                .addresses
                .push(MachineInterfaceAddressWithType {
                    address,
                    allocation_type,
                });
        }
    }

    Ok(interfaces)
}

/// Locks existing address rows for the interfaces that reconciliation may mutate.
async fn lock_admin_interface_addresses(
    txn: &mut PgConnection,
    interface_ids: &[MachineInterfaceId],
) -> DatabaseResult<()> {
    if interface_ids.is_empty() {
        return Ok(());
    }

    let ids = interface_ids
        .iter()
        .copied()
        .map(uuid::Uuid::from)
        .collect::<Vec<_>>();
    let query = r#"
SELECT id
FROM machine_interface_addresses
WHERE interface_id = ANY($1::uuid[])
ORDER BY interface_id, address
FOR UPDATE"#;

    sqlx::query(query)
        .bind(ids)
        .fetch_all(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Loads and exclusively locks all admin segments before reconciliation takes row locks.
///
/// This intentionally locks more broadly than the specific host touches so reconciliation follows
/// the same high-level lock order as address allocation: segment advisory lock first, then
/// machine interface/address row locks.
async fn load_and_lock_all_admin_segments(
    txn: &mut Transaction<'_>,
) -> DatabaseResult<Vec<NetworkSegment>> {
    let mut segment_ids =
        db_network_segment::list_segment_ids(txn.as_pgconn(), Some(NetworkSegmentType::Admin))
            .await?;
    segment_ids.sort();
    segment_ids.dedup();

    if segment_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut segments = db_network_segment::find_by(
        &mut *txn,
        ObjectColumnFilter::List(db_network_segment::IdColumn, &segment_ids),
        Default::default(),
    )
    .await?;
    segments.sort_by_key(|segment| segment.id);

    if segments.len() != segment_ids.len() {
        return Err(DatabaseError::internal(format!(
            "Loaded {} admin segments for {} admin segment IDs",
            segments.len(),
            segment_ids.len(),
        )));
    }

    lock_network_segments_exclusive(txn.as_pgconn(), &segment_ids).await?;

    Ok(segments)
}

/// Finds an existing same-segment DHCP address that can be reused by the primary interface.
fn find_reusable_dhcp_address(
    interfaces: &[AdminInterfaceForReconcile],
    primary_index: usize,
    family: IpAddressFamily,
) -> Option<(usize, MachineInterfaceAddressWithType)> {
    let primary_segment_id = interfaces[primary_index].segment_id;
    interfaces
        .iter()
        .enumerate()
        .filter(|(index, interface)| {
            *index != primary_index
                && interface.is_dpu_backed_host_link
                && interface.segment_id == primary_segment_id
        })
        .find_map(|(index, interface)| {
            interface
                .addresses
                .iter()
                .find(|address| {
                    address.allocation_type == AllocationType::Dhcp
                        && address.address.is_address_family(family)
                })
                .cloned()
                .map(|address| (index, address))
        })
}

/// Moves a DHCP address between two DPU-backed host interfaces on the same admin segment.
///
/// This intentionally changes the MAC associated with the persisted DHCP allocation. That is only
/// correct for the DPU-side `forge-dhcp-server` admin path, where the generated active host config
/// is authoritative. A Kea-backed path would also need external lease/cache synchronization.
async fn move_dhcp_address_to_interface(
    txn: &mut PgConnection,
    destination_interface_id: MachineInterfaceId,
    source_interface_id: MachineInterfaceId,
    address: IpAddr,
) -> DatabaseResult<()> {
    let query = r#"
UPDATE machine_interface_addresses AS mia
SET interface_id = $1
FROM machine_interfaces source_interface, machine_interfaces destination_interface
WHERE mia.interface_id = $2
  AND mia.address = $3::inet
  AND mia.allocation_type = $4
  AND source_interface.id = $2
  AND destination_interface.id = $1
  AND source_interface.segment_id = destination_interface.segment_id
RETURNING mia.address"#;

    let moved: Option<IpAddr> = sqlx::query_scalar(query)
        .bind(destination_interface_id)
        .bind(source_interface_id)
        .bind(address)
        .bind(AllocationType::Dhcp)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    match moved {
        Some(_) => Ok(()),
        None => Err(DatabaseError::internal(format!(
            "Could not move DHCP address {address} from interface {source_interface_id} to {destination_interface_id}",
        ))),
    }
}

/// Deletes all DHCP addresses from an interface and returns the deleted addresses.
async fn delete_dhcp_addresses_from_interface(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
) -> DatabaseResult<Vec<IpAddr>> {
    let query = "DELETE FROM machine_interface_addresses WHERE interface_id = $1 AND allocation_type = $2 RETURNING address";
    sqlx::query_scalar(query)
        .bind(interface_id)
        .bind(AllocationType::Dhcp)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Updates hostname and domain together for a machine interface.
async fn update_hostname_and_domain(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    hostname: &str,
    domain_id: Option<DomainId>,
) -> DatabaseResult<bool> {
    let query = r#"
UPDATE machine_interfaces
SET hostname = $1, domain_id = $2
WHERE id = $3
  AND (hostname IS DISTINCT FROM $1 OR domain_id IS DISTINCT FROM $2)
RETURNING id"#;
    let updated: Option<MachineInterfaceId> = sqlx::query_scalar(query)
        .bind(hostname)
        .bind(domain_id)
        .bind(interface_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(updated.is_some())
}

/// Syncs a machine interface's hostname to its current address state after an
/// address deletion, deferring to the configured naming strategy (the IP style
/// re-derives from the remaining addresses or parks the interface under the
/// dormant `noip-{mac}` placeholder; the other styles keep their names). When
/// no addresses remain the domain is cleared so the interface drops out of DNS.
pub async fn sync_hostname_after_address_change(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
) -> DatabaseResult<()> {
    let mut snapshot = find_one(&mut *txn, interface_id).await?;
    // The snapshot aggregates addresses in no particular order; sort them so
    // the derived name is stable across events.
    snapshot.addresses.sort();
    // With no addresses left, clear the domain so this interface drops out of
    // DNS (a name needs an address to point at); otherwise keep its domain.
    let domain_id = if snapshot.addresses.is_empty() {
        None
    } else {
        snapshot.domain_id
    };
    let hostname =
        host_naming::hostname_for(&mut *txn, &NamingContext::from_snapshot(&snapshot)).await?;
    update_hostname_and_domain(txn, interface_id, &hostname, domain_id).await?;
    Ok(())
}

/// Syncs hostname/domain after an address assignment.
///
/// Address-bearing interfaces rejoin the owning segment's domain so DHCP/DNS
/// projections can find them; addressless interfaces remain DNS-silent.
pub async fn sync_hostname_after_address_assignment(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    domain_id: Option<DomainId>,
) -> DatabaseResult<()> {
    // Read fresh address state before deriving the hostname and DNS domain.
    let mut snapshot = find_one(&mut *txn, interface_id).await?;
    snapshot.addresses.sort();
    let domain_id = if snapshot.addresses.is_empty() {
        None
    } else {
        domain_id
    };

    // Derive the hostname under the target domain and write both together.
    let ctx = NamingContext {
        domain_id,
        ..NamingContext::from_snapshot(&snapshot)
    };
    let hostname = host_naming::hostname_for(&mut *txn, &ctx).await?;
    update_hostname_and_domain(txn, interface_id, &hostname, domain_id).await?;
    Ok(())
}

pub async fn find_by_machine_and_segment(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    segment_id: NetworkSegmentId,
) -> Result<Vec<MachineInterfaceSnapshot>, DatabaseError> {
    static QUERY: &str = concat!(
        machine_interface_snapshot_query!(),
        " WHERE mi.machine_id = $1 AND mi.segment_id = $2::uuid",
    );
    sqlx::query_as::<_, MachineInterfaceSnapshot>(QUERY)
        .bind(machine_id)
        .bind(segment_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
        .map(|interfaces| interfaces.into_iter().collect())
}

/// Update the segment_id and domain_id for a machine interface. Used
/// when a static address assignment or DHCP re-discovery places an
/// interface on a different segment than it was previously on.
pub async fn update_segment_id(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    segment_id: NetworkSegmentId,
    domain_id: Option<DomainId>,
) -> DatabaseResult<()> {
    let query = "UPDATE machine_interfaces SET segment_id = $1, domain_id = $2 WHERE id = $3";
    sqlx::query(query)
        .bind(segment_id)
        .bind(domain_id)
        .bind(interface_id)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Reconcile an existing interface's segment with the DHCP relay address.
///
/// - If the segments match, nothing happens.
/// - If the interface is on the static-assignments anchor segment with
///   no addresses (static was removed), move it to the relay's segment.
/// - If the interface is on static-assignments with addresses, leave it
///   alone -- the operator's static assignment takes priority over DHCP.
/// - If the interface is on a different managed segment, error -- this
///   is a real network mismatch (wrong VLAN/port).
async fn reconcile_interface_segment(
    txn: &mut PgConnection,
    existing_interface: &mut MachineInterfaceSnapshot,
    relays: &[IpAddr],
) -> DatabaseResult<()> {
    let relay_segments = crate::network_segment::for_relay_all(txn, relays).await?;

    if relay_segments.is_empty() {
        return Err(DatabaseError::internal(format!(
            "No network segment defined for DHCP relay addresses: {}",
            relays.iter().join(", ")
        )));
    };
    let exact_segment_ids = exact_dhcpv6_link_address_segment_ids(&relay_segments, relays);
    let authoritative_segment_ids = if exact_segment_ids.is_empty() {
        relay_segments
            .iter()
            .map(|segment| segment.id)
            .collect::<Vec<_>>()
    } else {
        exact_segment_ids
    };

    // Prefix fallback candidates remain useful for allocation fallback, but an
    // exact DHCPv6 link-address is authoritative for existing-MAC ownership.
    if authoritative_segment_ids.contains(&existing_interface.segment_id) {
        return Ok(());
    }

    let on_static_assignments = existing_interface.segment_id
        == crate::network_segment::static_assignments(txn)
            .await
            .map(|s| s.id)
            .unwrap_or_default();

    // If the interface is on static-assignments with no addresses (as in
    // the static address was removed), move it to the relay's segment
    // so it can get a DHCP-allocated IP. The idea here being that someone
    // removed the static allocation on purpose, and now we're waiting for
    // the device to DHCP so we can see what segment it's coming in on.
    if on_static_assignments && existing_interface.addresses.is_empty() {
        let [relay_segment_id] = authoritative_segment_ids.as_slice() else {
            return Err(DatabaseError::internal(format!(
                "Cannot move interface from static-assignments with multiple candidate relays: {} ",
                relays.iter().join(", ")
            )));
        };
        let relay_segment = relay_segments
            .iter()
            .find(|segment| segment.id == *relay_segment_id)
            .ok_or_else(|| {
                DatabaseError::internal(format!(
                    "Authoritative relay segment {relay_segment_id} was not present in relay candidates"
                ))
            })?;

        tracing::info!(
            mac_address = %existing_interface.mac_address,
            previous_network_segment_id = %existing_interface.segment_id,
            next_network_segment_id = %relay_segment.id,
            "Moving interface from static-assignments into DHCP-managed segment"
        );
        update_segment_id(
            txn,
            existing_interface.id,
            relay_segment.id,
            relay_segment.config.subdomain_id,
        )
        .await?;
        existing_interface.segment_id = relay_segment.id;
    } else if on_static_assignments {
        // ...and if the interface is on static-assignments and still has
        // an addresse, the static assignment takes priority, so we leave
        // it as-is.
        tracing::debug!(
            mac_address = %existing_interface.mac_address,
            "Interface on static-assignments with addresses, leaving as-is"
        );
    } else {
        // And if it's a different managed segment, then yell. This logic
        // existing before the static-assigmnents and DHCP "reservation"
        // integration.
        return Err(DatabaseError::internal(format!(
            "Network segment mismatch for existing MAC address: {} expected: {} actual from network switch: {}",
            existing_interface.mac_address,
            existing_interface.segment_id,
            authoritative_segment_ids
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<String>>()
                .join(", "),
        )));
    }

    Ok(())
}

/// Allocate new DHCP-based IP addresses for a specific address family
/// on an existing interface that has lost its addresses (e.g. after a
/// lease expiration, because maybe it was offline for a while, etc --
/// basically anything that caused a lease expiration to be cleaned up,
/// probably from ExpireDhcpLease being called). This uses the same
/// allocation logic that we use for allocating initial addresses, and
/// only allocates from prefixes matching the requested family (IPv4
/// or IPv6).
#[allow(txn_held_across_await)]
pub async fn allocate_address_for_family(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    segment: &NetworkSegment,
    family: carbide_network::ip::IpAddressFamily,
) -> DatabaseResult<Vec<IpAddr>> {
    let mut fast_txn = Transaction::begin_inner(txn).await?;
    if family == IpAddressFamily::Ipv6 {
        lock_network_segment_exclusive(&mut fast_txn, segment).await?;
    } else {
        lock_network_segment_shared(&mut fast_txn, segment).await?;
    }

    let mut allocated_addresses = Vec::new();
    if family == IpAddressFamily::Ipv6 {
        // Use a family-only segment view so lease recovery allocates exactly one
        // address from each IPv6 prefix and does not disturb IPv4 ordering.
        let ipv6_segment = NetworkSegment {
            prefixes: segment
                .prefixes
                .iter()
                .filter(|prefix| prefix.prefix.is_ipv6())
                .cloned()
                .collect(),
            ..segment.clone()
        };
        allocated_addresses =
            allocate_v6_addresses_via_ip_allocator(&mut fast_txn, &ipv6_segment).await?;
        for address in &allocated_addresses {
            insert_machine_interface_address(
                fast_txn.as_pgconn(),
                &interface_id,
                address,
                AllocationType::Dhcp,
            )
            .await?;
        }
    } else {
        for prefix in segment
            .prefixes
            .iter()
            .filter(|p| p.prefix.is_address_family(family))
        {
            let address = allocate_next_ip_with_retry(&mut fast_txn, segment, prefix).await?;
            allocated_addresses.push(address);
            insert_machine_interface_address(
                fast_txn.as_pgconn(),
                &interface_id,
                &address,
                AllocationType::Dhcp,
            )
            .await?;
        }
    }

    fast_txn.commit().await?;

    // Nothing allocated (no prefix for the requested family): leave the
    // hostname and domain exactly as they were.
    if allocated_addresses.is_empty() {
        return Ok(allocated_addresses);
    }

    sync_hostname_after_address_assignment(txn, interface_id, segment.config.subdomain_id).await?;

    Ok(allocated_addresses)
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
    let query =
        "DELETE FROM machine_interfaces WHERE id=$1 RETURNING mac_address, boot_interface_id";
    crate::machine_interface_address::delete(txn, interface_id).await?;
    crate::dhcp_entry::delete(txn, interface_id).await?;
    let deleted: Option<(MacAddress, Option<String>)> = sqlx::query_as(query)
        .bind(*interface_id)
        .fetch_optional(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    // Every row deletion retains the boot pair: the vendor-named Redfish
    // interface id is the one piece a future row for this MAC can't always
    // rediscover (after a DPU/NIC mode flip the BMC can report the id
    // without its MAC), so it outlives the row in `retained_boot_interfaces`
    // no matter which caller deleted it.
    if let Some((mac_address, Some(boot_interface_id))) = deleted {
        crate::retained_boot_interface::upsert(&mut *txn, mac_address, &boot_interface_id).await?;
    }

    let query = "UPDATE machine_interfaces_deletion SET last_deletion=NOW() WHERE id = 1";
    sqlx::query(query)
        .bind(*interface_id)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn delete_by_ip(txn: &mut PgConnection, ip: IpAddr) -> Result<Option<()>, DatabaseError> {
    let interface = find_by_ip(&mut *txn, ip).await?;

    let Some(interface) = interface else {
        return Ok(None);
    };

    delete(&interface.id, txn).await?;

    Ok(Some(()))
}

/// Find all machine interface IDs associated with a switch.
pub async fn find_ids_by_switch_id(
    txn: &mut PgConnection,
    switch_id: &SwitchId,
) -> Result<Vec<MachineInterfaceId>, DatabaseError> {
    let query = "SELECT id FROM machine_interfaces WHERE switch_id = $1";
    sqlx::query_as::<_, MachineInterfaceId>(query)
        .bind(switch_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Find all machine interface IDs associated with a power shelf.
pub async fn find_ids_by_power_shelf_id(
    txn: &mut PgConnection,
    power_shelf_id: &PowerShelfId,
) -> Result<Vec<MachineInterfaceId>, DatabaseError> {
    let query = "SELECT id FROM machine_interfaces WHERE power_shelf_id = $1";
    sqlx::query_as::<_, MachineInterfaceId>(query)
        .bind(power_shelf_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

#[async_trait::async_trait]
impl<DB> UsedIpResolver<DB> for UsedAdminNetworkIpResolver
where
    for<'db> &'db mut DB: DbReader<'db>,
{
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
    async fn used_ips(&self, txn: &mut DB) -> Result<Vec<IpAddr>, DatabaseError> {
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
    async fn used_prefixes(&self, txn: &mut DB) -> Result<Vec<IpNetwork>, DatabaseError> {
        let used_ips = self.used_ips(txn).await?;
        let mut ip_networks: Vec<IpNetwork> = Vec::new();
        for used_ip in used_ips {
            // Use /32 for IPv4 host addresses, /128 for IPv6 host addresses.
            let prefix_len = match used_ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            let network = IpNetwork::new(used_ip, prefix_len).map_err(|e| {
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
