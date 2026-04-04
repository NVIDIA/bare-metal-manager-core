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

use carbide_network::ip::IpAddressFamily;
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use model::allocation_type::{AllocationType, AssignStaticResult};
use model::network_segment::NetworkSegmentType;
use sqlx::{FromRow, PgConnection};

use super::DatabaseError;
use crate::db_read::DbReader;

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

pub async fn find_by_address(
    txn: impl DbReader<'_>,
    address: IpAddr,
) -> Result<Option<MachineInterfaceSearchResult>, DatabaseError> {
    let query = "SELECT mi.id, mi.machine_id, ns.name, ns.network_segment_type
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
/// - `Dhcp`: the DHCP allocation is removed and replaced with the
///   static assignment.
#[allow(txn_held_across_await)]
pub async fn assign_static(
    txn: &mut PgConnection,
    interface_id: MachineInterfaceId,
    address: IpAddr,
) -> Result<AssignStaticResult, DatabaseError> {
    let family = if address.is_ipv4() {
        IpAddressFamily::Ipv4
    } else {
        IpAddressFamily::Ipv6
    };

    let existing = find_allocation_type_for_family(&mut *txn, interface_id, family).await?;

    let result = match existing {
        Some(AllocationType::Dhcp) => {
            delete_by_interface_family(&mut *txn, interface_id, family, AllocationType::Dhcp)
                .await?;
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

/// Delete an address allocation of the given type. Returns true if a
/// matching allocation was found and deleted, false otherwise.
pub async fn delete_by_address(
    txn: &mut PgConnection,
    address: IpAddr,
    allocation_type: model::allocation_type::AllocationType,
) -> Result<bool, DatabaseError> {
    let query =
        "DELETE FROM machine_interface_addresses WHERE address = $1::inet AND allocation_type = $2";
    sqlx::query(query)
        .bind(address)
        .bind(allocation_type)
        .execute(txn)
        .await
        .map(|r| r.rows_affected() > 0)
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

#[derive(Debug, FromRow)]
pub struct MachineInterfaceSearchResult {
    pub id: MachineInterfaceId,
    pub machine_id: Option<MachineId>,
    pub name: String,
    pub network_segment_type: NetworkSegmentType,
}
