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

use carbide_network::ip::IpAddressFamily;
use carbide_uuid::machine::MachineId;
use carbide_uuid::network::NetworkSegmentId;
use chrono::{DateTime, Utc};
use mac_address::MacAddress;
use model::dhcp_record::{DhcpRecord, IgnoredMac};
use sqlx::PgConnection;

use crate::DatabaseError;

/// Look up the DHCP record for a MAC on a segment, for one address family.
///
/// Returns `Ok(None)` when the `machine_dhcp_records` view has no row for the
/// triple -- e.g. no address of that family is allocated to the interface, or
/// the allocated address has no containing prefix on the segment.
pub async fn find_by_mac_address(
    txn: &mut PgConnection,
    mac_address: &MacAddress,
    segment_id: &NetworkSegmentId,
    address_family: IpAddressFamily,
) -> Result<Option<DhcpRecord>, DatabaseError> {
    let query = "SELECT * FROM machine_dhcp_records WHERE mac_address = $1::macaddr AND segment_id = $2::uuid AND family(address) = $3";
    sqlx::query_as(query)
        .bind(mac_address)
        .bind(segment_id)
        .bind(address_family.pg_family())
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Return the global DHCP record invalidation timestamp.
pub async fn last_invalidation_time(
    txn: &mut PgConnection,
) -> Result<DateTime<Utc>, DatabaseError> {
    let query = "SELECT last_deletion FROM machine_interfaces_deletion WHERE id = 1";
    sqlx::query_scalar(query)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Check whether a MAC address is in the ignored list.
pub async fn is_mac_ignored(
    txn: &mut PgConnection,
    mac_address: &MacAddress,
) -> Result<bool, DatabaseError> {
    let query = "SELECT EXISTS(SELECT 1 FROM ignored_macs WHERE mac_address = $1::macaddr)";
    sqlx::query_scalar(query)
        .bind(mac_address)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Insert a MAC address into the ignored list.
///
/// Silently succeeds if the MAC is already present (ON CONFLICT DO NOTHING).
pub async fn ignore_mac(
    txn: &mut PgConnection,
    mac_address: &MacAddress,
    machine_id: Option<&MachineId>,
    reason: &str,
) -> Result<(), DatabaseError> {
    let query = "INSERT INTO ignored_macs (mac_address, machine_id, reason) \
                 VALUES ($1::macaddr, $2, $3) ON CONFLICT DO NOTHING";
    sqlx::query(query)
        .bind(mac_address)
        .bind(machine_id)
        .bind(reason)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Remove a MAC address from the ignored list, returning whether it existed.
pub async fn unignore_mac(
    txn: &mut PgConnection,
    mac_address: &MacAddress,
) -> Result<bool, DatabaseError> {
    let query = "DELETE FROM ignored_macs WHERE mac_address = $1::macaddr";
    sqlx::query(query)
        .bind(mac_address)
        .execute(txn)
        .await
        .map(|r| r.rows_affected() > 0)
        .map_err(|e| DatabaseError::query(query, e))
}

/// List all ignored MACs, optionally filtering by machine ID.
pub async fn list_ignored_macs(
    txn: &mut PgConnection,
    machine_id: Option<&MachineId>,
) -> Result<Vec<IgnoredMac>, DatabaseError> {
    let (query, bind_machine_id) = match machine_id {
        Some(_) => (
            "SELECT * FROM ignored_macs WHERE machine_id = $1::uuid ORDER BY created_at",
            true,
        ),
        None => (
            "SELECT * FROM ignored_macs ORDER BY created_at",
            false,
        ),
    };
    let mut q = sqlx::query_as(query);
    if bind_machine_id {
        q = q.bind(machine_id);
    }
    q.fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}
