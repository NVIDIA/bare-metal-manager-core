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

//! Trusted NVIDIA BlueField device root CA certificates, used to verify a DPU's
//! IRoT device-identity certificate chain. Mirrors [`super::tpm_ca_certs`].

use chrono::{DateTime, Utc};
use model::attestation::DpuDeviceCaCert;
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

/// Inserts a trusted root. Returns `None` when the identical certificate is
/// already present (`UNIQUE(ca_cert_der)`), so re-running a seeding script is
/// a no-op rather than an error.
pub async fn insert(
    txn: &mut PgConnection,
    not_valid_before: &DateTime<Utc>,
    not_valid_after: &DateTime<Utc>,
    ca_cert: &[u8],
    cert_subject: &[u8],
) -> DatabaseResult<Option<DpuDeviceCaCert>> {
    let query = "INSERT INTO dpu_device_ca_certs (not_valid_before, not_valid_after, ca_cert_der, cert_subject) VALUES ($1, $2, $3, $4) ON CONFLICT (ca_cert_der) DO NOTHING RETURNING *";

    sqlx::query_as(query)
        .bind(not_valid_before)
        .bind(not_valid_after)
        .bind(ca_cert)
        .bind(cert_subject)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

/// Returns every trusted root, including its DER bytes (needed for chain
/// verification).
pub async fn get_all(db: impl DbReader<'_>) -> DatabaseResult<Vec<DpuDeviceCaCert>> {
    let query = "SELECT * FROM dpu_device_ca_certs";

    sqlx::query_as(query)
        .fetch_all(db)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn delete(
    txn: &mut PgConnection,
    ca_cert_id: i32,
) -> DatabaseResult<Option<DpuDeviceCaCert>> {
    let query = "DELETE FROM dpu_device_ca_certs WHERE id = ($1) RETURNING *";

    sqlx::query_as(query)
        .bind(ca_cert_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}
