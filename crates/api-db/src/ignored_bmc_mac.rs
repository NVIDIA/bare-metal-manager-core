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

use mac_address::MacAddress;
use model::ignored_bmc_mac::IgnoredBmcMac;
use sqlx::{PgConnection, PgPool};

use crate::DatabaseError;

/// Insert a row for `mac` with `suppress_site_explorer = true`, or update an
/// existing row to set it.  Clears `site_explorer_suppressed_at` whenever
/// `suppress_site_explorer` transitions from `false` to `true` so that the
/// decommissioning workflow can wait for a fresh acknowledgement.
pub async fn upsert_suppress_site_explorer(
    txn: &mut PgConnection,
    mac: &MacAddress,
    reason: &str,
) -> Result<(), DatabaseError> {
    let query = "\
        INSERT INTO ignored_bmc_macs \
            (bmc_mac_address, reason, suppress_site_explorer, site_explorer_suppressed_at, updated_at) \
        VALUES ($1::macaddr, $2, TRUE, NULL, now()) \
        ON CONFLICT (bmc_mac_address) DO UPDATE \
            SET suppress_site_explorer      = TRUE, \
                site_explorer_suppressed_at = CASE \
                    WHEN ignored_bmc_macs.suppress_site_explorer = FALSE THEN NULL \
                    ELSE ignored_bmc_macs.site_explorer_suppressed_at \
                END, \
                updated_at = now()";
    sqlx::query(query)
        .bind(mac)
        .bind(reason)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Record that Site Explorer has observed suppression and drained all
/// queued/in-flight work for `mac`.  This is the acknowledgement that the
/// decommissioning workflow waits on before starting hardware cleanup.
///
/// Only Site Explorer should call this function.
pub async fn record_site_explorer_suppressed(
    txn: &mut PgConnection,
    mac: &MacAddress,
) -> Result<(), DatabaseError> {
    let query = "\
        UPDATE ignored_bmc_macs \
        SET site_explorer_suppressed_at = now(), updated_at = now() \
        WHERE bmc_mac_address = $1::macaddr \
          AND suppress_site_explorer = TRUE \
          AND site_explorer_suppressed_at IS NULL";
    sqlx::query(query)
        .bind(mac)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Set `suppress_dhcp = true` for `mac` and clear `dhcp_discover_suppressed_at`
/// so the decommissioning workflow can wait for a fresh acknowledgement from
/// the DHCP server.  No-ops if the row does not exist.
pub async fn set_suppress_dhcp(
    txn: &mut PgConnection,
    mac: &MacAddress,
) -> Result<(), DatabaseError> {
    let query = "\
        UPDATE ignored_bmc_macs \
        SET suppress_dhcp               = TRUE, \
            dhcp_discover_suppressed_at = CASE \
                WHEN suppress_dhcp = FALSE THEN NULL \
                ELSE dhcp_discover_suppressed_at \
            END, \
            updated_at = now() \
        WHERE bmc_mac_address = $1::macaddr";
    sqlx::query(query)
        .bind(mac)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Record that the DHCP server observed a DHCPDISCOVER from `mac` and returned
/// no offer, proving the BMC DHCP client has returned to the INIT state.
///
/// Only the DHCP server should call this function.  The update is conditional:
/// it only writes the timestamp when suppression is enabled and no timestamp
/// has been recorded yet, so retries are safe.
pub async fn record_dhcp_discover_suppressed(
    txn: &mut PgConnection,
    mac: &MacAddress,
) -> Result<(), DatabaseError> {
    let query = "\
        UPDATE ignored_bmc_macs \
        SET dhcp_discover_suppressed_at = now(), updated_at = now() \
        WHERE bmc_mac_address = $1::macaddr \
          AND suppress_dhcp = TRUE \
          AND dhcp_discover_suppressed_at IS NULL";
    sqlx::query(query)
        .bind(mac)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Remove the ignore entry for `mac`.  Returns `true` if a row was deleted.
///
/// Callers are responsible for verifying that no managed resource still
/// references this MAC before calling this function.
pub async fn release(
    txn: &mut PgConnection,
    mac: &MacAddress,
) -> Result<bool, DatabaseError> {
    let query = "DELETE FROM ignored_bmc_macs WHERE bmc_mac_address = $1::macaddr";
    sqlx::query(query)
        .bind(mac)
        .execute(txn)
        .await
        .map(|r| r.rows_affected() > 0)
        .map_err(|e| DatabaseError::query(query, e))
}

/// Load all rows from `ignored_bmc_macs`.  Used by Site Explorer and the DHCP
/// server to build their suppression sets at the start of each pass.
pub async fn load_all(pool: &PgPool) -> Result<Vec<IgnoredBmcMac>, DatabaseError> {
    let query = "SELECT * FROM ignored_bmc_macs ORDER BY created_at";
    sqlx::query_as(query)
        .fetch_all(pool)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Look up a single entry by MAC address.
pub async fn find(
    txn: &mut PgConnection,
    mac: &MacAddress,
) -> Result<Option<IgnoredBmcMac>, DatabaseError> {
    let query = "SELECT * FROM ignored_bmc_macs WHERE bmc_mac_address = $1::macaddr";
    sqlx::query_as(query)
        .bind(mac)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}
