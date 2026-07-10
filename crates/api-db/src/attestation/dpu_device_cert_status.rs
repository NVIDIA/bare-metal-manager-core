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

//! Per-machine record that a DPU's device-identity certificate was verified
//! against a trusted root and bound to its `machine_id`. Also the durable
//! memory that a DPU adopted a device-rooted id: [`get_by_legacy_machine_id`]
//! lets resolution recognize the DPU (by its serial-derived legacy id) even
//! when the IRoT chain cannot be fetched, so its identity never flaps.

use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use model::attestation::DpuDeviceCertStatus;
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

/// Records (or refreshes) the verified device-identity binding for a machine.
/// Keyed by `machine_id`, so re-verification of the same DPU overwrites the
/// row. A stale binding for the same `legacy_machine_id` but a different
/// device-rooted id (i.e. the physical DPU behind a serial was replaced) is
/// removed first so the legacy id maps to at most one binding.
pub async fn upsert(
    txn: &mut PgConnection,
    machine_id: MachineId,
    legacy_machine_id: Option<MachineId>,
    device_cert_sha256: &[u8],
    device_serial: &str,
    ca_id: Option<i32>,
    verified_at: &DateTime<Utc>,
) -> DatabaseResult<()> {
    if let Some(legacy_machine_id) = legacy_machine_id {
        let cleanup = "DELETE FROM dpu_device_cert_status \
             WHERE legacy_machine_id = ($1) AND machine_id != ($2)";
        sqlx::query(cleanup)
            .bind(legacy_machine_id)
            .bind(machine_id)
            .execute(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(cleanup, e))?;
    }

    let query = "INSERT INTO dpu_device_cert_status \
         (machine_id, legacy_machine_id, device_cert_sha256, device_serial, ca_id, verified_at) \
         VALUES ($1, $2, $3, $4, $5, $6) \
         ON CONFLICT (machine_id) DO UPDATE SET \
             legacy_machine_id = EXCLUDED.legacy_machine_id, \
             device_cert_sha256 = EXCLUDED.device_cert_sha256, \
             device_serial = EXCLUDED.device_serial, \
             ca_id = EXCLUDED.ca_id, \
             verified_at = EXCLUDED.verified_at";

    sqlx::query(query)
        .bind(machine_id)
        .bind(legacy_machine_id)
        .bind(device_cert_sha256)
        .bind(device_serial)
        .bind(ca_id)
        .bind(verified_at)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn get_by_machine_id(
    txn: &mut PgConnection,
    machine_id: MachineId,
) -> DatabaseResult<Option<DpuDeviceCertStatus>> {
    let query = "SELECT machine_id, legacy_machine_id, device_cert_sha256, device_serial, \
         verified_at FROM dpu_device_cert_status WHERE machine_id = ($1)";

    sqlx::query_as(query)
        .bind(machine_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Deletes any device-identity binding associated with `machine_id`, matching
/// on either the device-rooted `machine_id` or the `legacy_machine_id`. This
/// lets a force-deleted DPU re-key: without removing the binding,
/// [`get_by_legacy_machine_id`] would recognize the DPU by its serial-derived id
/// and pin it back to the same device-rooted id on the next discovery. Returns
/// the number of binding rows removed.
pub async fn delete_by_machine_id(
    txn: &mut PgConnection,
    machine_id: MachineId,
) -> DatabaseResult<u64> {
    let query = "DELETE FROM dpu_device_cert_status \
         WHERE machine_id = ($1) OR legacy_machine_id = ($1)";

    let result = sqlx::query(query)
        .bind(machine_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(result.rows_affected())
}

/// Looks up the binding by the DPU's legacy (serial-derived) id, recognizing a
/// DPU that previously adopted a device-rooted id.
pub async fn get_by_legacy_machine_id(
    db: impl DbReader<'_>,
    legacy_machine_id: MachineId,
) -> DatabaseResult<Option<DpuDeviceCertStatus>> {
    let query = "SELECT machine_id, legacy_machine_id, device_cert_sha256, device_serial, \
         verified_at FROM dpu_device_cert_status WHERE legacy_machine_id = ($1)";

    sqlx::query_as(query)
        .bind(legacy_machine_id)
        .fetch_optional(db)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}
