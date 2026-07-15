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

use carbide_network::ip::{IdentifyAddressFamily, IpAddressFamily};
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use carbide_uuid::network::NetworkSegmentId;
use mac_address::MacAddress;
use model::allocation_type::{AllocationType, AssignStaticResult};
use model::network_segment::NetworkSegmentType;
use sqlx::{FromRow, PgConnection};

use super::DatabaseError;
use crate::db_read::DbReader;

#[cfg(test)]
mod test_find_by_address;

/// Returned by allocation paths with `AddressSelectionStrategy::StaticAddress`
/// when the target IP is already held by some other interface.
#[derive(thiserror::Error, Debug)]
#[error("Address already in use: {0} by {1} in network segment {2} (Interface: {3})")]
pub struct AddressAlreadyInUseError(
    pub IpAddr,
    pub MacAddress,
    pub NetworkSegmentId,
    pub MachineInterfaceId,
);

#[derive(Debug, FromRow, Clone)]
pub struct MachineInterfaceAddress {
    pub address: IpAddr,
}

#[derive(Debug, FromRow, Clone)]
pub struct MachineInterfaceAddressWithType {
    pub address: IpAddr,
    pub allocation_type: AllocationType,
}

pub async fn find_ipv4_for_interface(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
) -> Result<MachineInterfaceAddress, DatabaseError> {
    let query =
        "SELECT * FROM machine_interface_addresses WHERE interface_id = $1 AND family(address) = 4";
    sqlx::query_as(query)
        .bind(interface_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Looks up which machine interface owns an IP, with segment metadata and **allocation type**.
///
/// `allocation_type` is used by the IP finder to classify operator static assignments
/// (`AllocationType::Static` or addresses on the `static-assignments` segment) as
/// `IpTypeStaticBmcIp` where appropriate.
pub async fn find_by_address(
    txn: impl DbReader<'_>,
    address: IpAddr,
) -> Result<Option<MachineInterfaceSearchResult>, DatabaseError> {
    let query = "SELECT mi.id, mi.machine_id, ns.name, ns.network_segment_type, mia.allocation_type
            FROM machine_interface_addresses mia
            INNER JOIN machine_interfaces mi ON mi.id = mia.interface_id
            INNER JOIN network_segments ns ON ns.id = mi.segment_id
            WHERE mia.address = $1::inet
        ";
    sqlx::query_as(query)
        .bind(address)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn delete(
    txn: &mut PgConnection,
    interface_id: &MachineInterfaceId,
) -> Result<(), DatabaseError> {
    let query = "DELETE FROM machine_interface_addresses WHERE interface_id = $1";
    sqlx::query(query)
        .bind(interface_id)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Find all addresses for an interface, including their allocation type.
pub async fn find_for_interface(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
) -> Result<Vec<MachineInterfaceAddressWithType>, DatabaseError> {
    let query =
        "SELECT address, allocation_type FROM machine_interface_addresses WHERE interface_id = $1";
    sqlx::query_as(query)
        .bind(interface_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Find the allocation type of the existing address for a given
/// interface and address family, if one exists.
pub async fn find_allocation_type_for_family(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    family: IpAddressFamily,
) -> Result<Option<AllocationType>, DatabaseError> {
    let query = "SELECT allocation_type FROM machine_interface_addresses WHERE interface_id = $1 AND family(address) = $2";
    let result: Option<(AllocationType,)> = sqlx::query_as(query)
        .bind(interface_id)
        .bind(family.pg_family())
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(result.map(|(t,)| t))
}

/// Delete the address for a given interface, address family, and
/// allocation type. Returns true if a row was deleted.
pub async fn delete_by_interface_family(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    family: IpAddressFamily,
    allocation_type: AllocationType,
) -> Result<bool, DatabaseError> {
    let query = "DELETE FROM machine_interface_addresses WHERE interface_id = $1 AND family(address) = $2 AND allocation_type = $3";
    sqlx::query(query)
        .bind(interface_id)
        .bind(family.pg_family())
        .bind(allocation_type)
        .execute(txn)
        .await
        .map(|r| r.rows_affected() > 0)
        .map_err(|e| DatabaseError::query(query, e))
}

/// Delete a specific address from a specific interface. Returns true if a
/// matching row was deleted. Scoping by `interface_id` ensures an operator
/// remove-address call only removes the caller's own address, never another
/// interface's row that happens to hold the same IP.
pub async fn delete_by_interface_and_address(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    address: IpAddr,
    allocation_type: AllocationType,
) -> Result<bool, DatabaseError> {
    let query = "DELETE FROM machine_interface_addresses WHERE interface_id = $1 AND address = $2::inet AND allocation_type = $3";
    sqlx::query(query)
        .bind(interface_id)
        .bind(address)
        .bind(allocation_type)
        .execute(txn)
        .await
        .map(|r| r.rows_affected() > 0)
        .map_err(|e| DatabaseError::query(query, e))
}

/// Insert a new address for an interface with the given allocation type.
pub async fn insert(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    address: IpAddr,
    allocation_type: AllocationType,
) -> Result<(), DatabaseError> {
    let query = "INSERT INTO machine_interface_addresses (interface_id, address, allocation_type) VALUES ($1::uuid, $2::inet, $3)";
    sqlx::query(query)
        .bind(interface_id)
        .bind(address)
        .bind(allocation_type)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Assign a static address to an interface. If the interface already
/// has an address for the same family, the behavior depends on its
/// allocation type:
///
/// - `Static`: the old static address is replaced.
/// - `Dhcp` or `Slaac`: the managed allocation is removed and
///   replaced with the static assignment.
#[allow(txn_held_across_await)]
pub async fn assign_static(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    address: IpAddr,
) -> Result<AssignStaticResult, DatabaseError> {
    let family = address.address_family();

    let existing = find_allocation_type_for_family(&mut *txn, interface_id, family).await?;

    let result = match existing {
        Some(allocation_type @ (AllocationType::Dhcp | AllocationType::Slaac)) => {
            delete_by_interface_family(&mut *txn, interface_id, family, allocation_type).await?;
            AssignStaticResult::ReplacedDhcp
        }
        Some(AllocationType::Static) => {
            delete_by_interface_family(&mut *txn, interface_id, family, AllocationType::Static)
                .await?;
            AssignStaticResult::ReplacedStatic
        }
        None => AssignStaticResult::Assigned,
    };

    insert(txn, interface_id, address, AllocationType::Static).await?;

    Ok(result)
}

/// Delete an address allocation of the given type. Returns the interfaces that
/// owned the deleted addresses (normally one, empty if nothing matched) so
/// callers can resync each one's hostname rather than guessing the owner. The
/// delete removes every matching row, so all owners are returned — not just the
/// first — since `(address, allocation_type)` is not unique on its own.
pub async fn delete_by_address(
    txn: &mut PgConnection,
    address: IpAddr,
    allocation_type: AllocationType,
) -> Result<Vec<MachineInterfaceId>, DatabaseError> {
    let query = "DELETE FROM machine_interface_addresses WHERE address = $1::inet AND allocation_type = $2 RETURNING interface_id";
    sqlx::query_scalar(query)
        .bind(address)
        .bind(allocation_type)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Delete an address allocation for a given (ip, mac) pair, which
/// of course only actually deletes when the pair matches.
///
/// Returns the interfaces that owned the deleted allocations (normally one,
/// empty if the pair matched nothing) so callers can resync each one's hostname
/// against the authoritative deleted rows rather than a separate lookup.
pub async fn delete_by_address_and_mac(
    txn: &mut PgConnection,
    address: IpAddr,
    mac_address: mac_address::MacAddress,
    allocation_type: AllocationType,
) -> Result<Vec<MachineInterfaceId>, DatabaseError> {
    let query = "DELETE FROM machine_interface_addresses mia
        USING machine_interfaces mi
        WHERE mia.interface_id = mi.id
          AND mia.address = $1::inet
          AND mia.allocation_type = $2
          AND mi.mac_address = $3::macaddr
        RETURNING mia.interface_id";
    sqlx::query_scalar(query)
        .bind(address)
        .bind(allocation_type)
        .bind(mac_address)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Check whether an interface has any address assigned for the
/// given address family.
///
/// This is used by the DHCPDISCOVER flow to decide whether to
/// re-allocate after a lease expiration. If the interface still
/// has an address for the family (static or DHCP), no re-allocation
// is needed.
pub async fn has_address_for_family(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    family: IpAddressFamily,
) -> Result<bool, DatabaseError> {
    let query = "SELECT EXISTS(SELECT 1 FROM machine_interface_addresses WHERE interface_id = $1 AND family(address) = $2)";
    sqlx::query_scalar(query)
        .bind(interface_id)
        .bind(family.pg_family())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Row shape for [`find_by_address`]: interface identity, owning segment, and how the address was
/// assigned (DHCP vs static / operator-configured).
#[derive(Debug, FromRow)]
pub struct MachineInterfaceSearchResult {
    pub id: MachineInterfaceId,
    pub machine_id: Option<MachineId>,
    pub name: String,
    pub network_segment_type: NetworkSegmentType,
    pub allocation_type: AllocationType,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies the new SLAAC allocation type survives a database round trip.
    #[crate::sqlx_test]
    async fn slaac_allocation_type_round_trips(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut txn = pool.begin().await?;

        // Create the minimal segment and interface rows needed to own an address.
        let segment_id: NetworkSegmentId = sqlx::query_scalar(
            "INSERT INTO network_segments (name, version) VALUES ($1, 'V1-T0') RETURNING id",
        )
        .bind("slaac-roundtrip")
        .fetch_one(txn.as_mut())
        .await?;
        let interface_id: MachineInterfaceId = sqlx::query_scalar(
            "INSERT INTO machine_interfaces (segment_id, mac_address, primary_interface, hostname)
             VALUES ($1, $2::macaddr, true, 'slaac-roundtrip') RETURNING id",
        )
        .bind(segment_id)
        .bind("02:00:00:00:00:01")
        .fetch_one(txn.as_mut())
        .await?;

        // Insert a SLAAC allocation through the public helper and read it back.
        insert(
            txn.as_mut(),
            interface_id,
            "2001:db8::10".parse()?,
            AllocationType::Slaac,
        )
        .await?;
        let addresses = find_for_interface(txn.as_mut(), interface_id).await?;

        // Verify the persisted row preserved the new allocation type.
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].allocation_type, AllocationType::Slaac);

        txn.rollback().await?;
        Ok(())
    }
}
