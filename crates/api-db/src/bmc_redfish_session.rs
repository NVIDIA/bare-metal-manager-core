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

//! Persistence layer for the `BmcSessionManager`.
//!
//! Each row records the outstanding Redfish session that the manager has
//! issued for a given `(spiffe_service_id, bmc_mac_address)` pair, so that
//! the next rotate (or a `flush_mac`) can `DELETE` the prior session on the
//! BMC. The `X-Auth-Token` itself is not persisted; it is returned to the
//! caller once and the only durable artifact is the session's `@odata.id`.

use mac_address::MacAddress;
use model::bmc_redfish_session::StoredSession;
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

/// Returns the outstanding session row for `(spiffe_service_id, bmc_mac)`
/// if any has been recorded.
pub async fn get(
    txn: impl DbReader<'_>,
    spiffe_service_id: &str,
    bmc_mac: MacAddress,
) -> DatabaseResult<Option<StoredSession>> {
    let query = "SELECT spiffe_service_id, bmc_mac_address, session_odata_id, issued_at
                 FROM bmc_redfish_sessions
                 WHERE spiffe_service_id = $1 AND bmc_mac_address = $2";

    sqlx::query_as(query)
        .bind(spiffe_service_id)
        .bind(bmc_mac)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Inserts (or overwrites) the outstanding session for
/// `(spiffe_service_id, bmc_mac)`. `issued_at` is set to `now()` server-side
/// so timestamps are consistent across replicas.
pub async fn upsert(
    txn: &mut PgConnection,
    spiffe_service_id: &str,
    bmc_mac: MacAddress,
    session_odata_id: &str,
) -> DatabaseResult<()> {
    let query = "INSERT INTO bmc_redfish_sessions
                       (spiffe_service_id, bmc_mac_address, session_odata_id, issued_at)
                       VALUES ($1, $2, $3, now())
                       ON CONFLICT (spiffe_service_id, bmc_mac_address) DO UPDATE
                       SET session_odata_id = EXCLUDED.session_odata_id,
                       issued_at        = EXCLUDED.issued_at";

    sqlx::query(query)
        .bind(spiffe_service_id)
        .bind(bmc_mac)
        .bind(session_odata_id)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Deletes the outstanding session row for `(spiffe_service_id, bmc_mac)`.
/// No-op if the row does not exist.
pub async fn delete(
    txn: &mut PgConnection,
    spiffe_service_id: &str,
    bmc_mac: MacAddress,
) -> DatabaseResult<()> {
    let query = "DELETE FROM bmc_redfish_sessions
                       WHERE spiffe_service_id = $1 AND bmc_mac_address = $2";

    sqlx::query(query)
        .bind(spiffe_service_id)
        .bind(bmc_mac)
        .execute(txn)
        .await
        .map(|_| ())
        .map_err(|e| DatabaseError::query(query, e))
}

/// Deletes every row whose `bmc_mac_address` matches `bmc_mac` and returns
/// the rows that were removed. The returned vector can be used by callers
/// that want to best-effort `DELETE` the corresponding sessions on the BMC.
pub async fn delete_by_mac(
    txn: &mut PgConnection,
    bmc_mac: MacAddress,
) -> DatabaseResult<Vec<StoredSession>> {
    let query = "DELETE FROM bmc_redfish_sessions
                 WHERE bmc_mac_address = $1
                 RETURNING spiffe_service_id, bmc_mac_address, session_odata_id, issued_at";

    sqlx::query_as(query)
        .bind(bmc_mac)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}
