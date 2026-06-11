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

//! Last-known boot interface pairs that outlive their `machine_interfaces`
//! rows.
//!
//! When an interface row is deleted, its `boot_interface_id` -- the
//! vendor-named Redfish `EthernetInterface.Id` -- is the one piece of state
//! a re-ingested machine cannot always rediscover on its own: after a
//! DPU/NIC mode flip the BMC can report the interface id without its MAC,
//! so the pair can't be re-derived later. Rows here are written by
//! `machine_interface::delete` itself, keyed by MAC with no foreign keys
//! (everything they referenced is gone), and consumed once the id lands on
//! a `machine_interfaces` row again.
//!
//! Records are honored for as long as the operator-configured
//! `retained_boot_interface_window` allows. The default (`None`) is
//! forever -- if the machine eventually comes back, the pair is waiting.
//! Setting a window bounds the reach of a recycled MAC: one reappearing on
//! different hardware long after a deletion (virtual-MAC reassignment, a
//! NIC moved between slots) should not inherit an interface id that aims
//! boot-order setup at a Redfish resource that no longer exists there.
//! Migrations consume their records within minutes either way.

use mac_address::MacAddress;
use sqlx::PgConnection;

use crate::DatabaseError;

/// Record the boot interface pair for a MAC, overwriting any prior record
/// (the newest observation wins).
pub async fn upsert(
    txn: &mut PgConnection,
    mac_address: MacAddress,
    boot_interface_id: &str,
) -> Result<(), DatabaseError> {
    let query = "INSERT INTO retained_boot_interfaces (mac_address, boot_interface_id) \
                 VALUES ($1, $2) \
                 ON CONFLICT (mac_address) \
                 DO UPDATE SET boot_interface_id = EXCLUDED.boot_interface_id, recorded_at = NOW()";
    sqlx::query(query)
        .bind(mac_address)
        .bind(boot_interface_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

/// Look up the retained boot interface id for a MAC without consuming it.
/// Records older than `window` (when one is set) are not returned. The
/// consuming `take_by_mac` is the one production flows use; this read is
/// for inspection (and test assertions).
pub async fn find_by_mac(
    txn: &mut PgConnection,
    mac_address: MacAddress,
    window: Option<chrono::Duration>,
) -> Result<Option<String>, DatabaseError> {
    let query = "SELECT boot_interface_id FROM retained_boot_interfaces \
                 WHERE mac_address = $1 \
                 AND ($2::bigint IS NULL OR recorded_at > NOW() - ($2::bigint * INTERVAL '1 second'))";
    sqlx::query_scalar(query)
        .bind(mac_address)
        .bind(window.map(|w| w.num_seconds()))
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Consume the retained record for a MAC, returning its boot interface id
/// when the record is within `window` (always, when no window is set). The
/// record is removed either way -- a `machine_interfaces` row now
/// exists for the MAC, so future explorations keep it current and the
/// retention copy is done.
pub async fn take_by_mac(
    txn: &mut PgConnection,
    mac_address: MacAddress,
    window: Option<chrono::Duration>,
) -> Result<Option<String>, DatabaseError> {
    let query = "DELETE FROM retained_boot_interfaces WHERE mac_address = $1 \
                 RETURNING boot_interface_id, \
                 ($2::bigint IS NULL OR recorded_at > NOW() - ($2::bigint * INTERVAL '1 second')) AS applicable";
    let row: Option<(String, bool)> = sqlx::query_as(query)
        .bind(mac_address)
        .bind(window.map(|w| w.num_seconds()))
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(row.and_then(|(boot_interface_id, applicable)| applicable.then_some(boot_interface_id)))
}

/// Remove records that have aged out of `window`. A no-op when no window
/// is set -- without one, every record waits forever for its machine to
/// come back. Reads already ignore expired records; this sweep keeps MACs
/// that never return from occupying table rows indefinitely.
pub async fn delete_expired(
    txn: &mut PgConnection,
    window: Option<chrono::Duration>,
) -> Result<u64, DatabaseError> {
    let Some(window) = window else {
        return Ok(0);
    };
    let query = "DELETE FROM retained_boot_interfaces \
                 WHERE recorded_at <= NOW() - ($1::bigint * INTERVAL '1 second')";
    let result = sqlx::query(query)
        .bind(window.num_seconds())
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(result.rows_affected())
}
