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

//! One-time import of Vault secrets into the Postgres journal. `run()`
//! drives this at startup: with `[secrets]` configured, the import either
//! completes (recording a permanent marker) before the process serves
//! traffic, or the process does not start. Vault is never part of the
//! credential chain in this mode.

use carbide_kms_provider::KmsBackend;
use carbide_secrets::credentials::Credentials;
use sqlx::PgPool;
use zeroize::Zeroizing;

use super::routing::SecretRouting;
use super::{ImportApproach, ImportResult, PgSecretsError, VAULT_IMPORT_MARKER_PATH};

/// Import pre-read secrets into Postgres.
///
/// With `MissingOnly`, a path that already has entries is skipped before
/// any encryption happens; the per-path advisory lock inside
/// `insert_if_missing` keeps a concurrent writer from sneaking an entry in
/// between the check and the insert. With `All`, every secret appends a new
/// journal entry unconditionally.
pub async fn import_secrets(
    pool: &PgPool,
    routing: &SecretRouting,
    kms: &dyn KmsBackend,
    secrets: &[(String, Credentials)],
    approach: ImportApproach,
) -> Result<ImportResult, PgSecretsError> {
    let mut result = ImportResult::default();

    for (path, credentials) in secrets {
        // Cheap existence pre-check so MissingOnly re-imports skip the
        // DEK generation and encryption for secrets that already landed.
        // The locked check inside insert_if_missing is still the one that
        // decides.
        if matches!(approach, ImportApproach::MissingOnly)
            && db::secrets::exists(pool, path).await?
        {
            result.skipped += 1;
            continue;
        }

        let json_bytes = Zeroizing::new(serde_json::to_vec(credentials)?);
        let envelope = super::encrypt_envelope(routing, kms, path, &json_bytes).await?;

        match approach {
            ImportApproach::MissingOnly => {
                let mut txn = pool
                    .begin()
                    .await
                    .map_err(|e| PgSecretsError::Database(db::DatabaseError::acquire(e)))?;
                let inserted =
                    db::secrets::insert_if_missing(&mut txn, &envelope.as_new_entry(path)).await?;
                txn.commit().await.map_err(|e| {
                    PgSecretsError::Database(db::DatabaseError::new("commit import", e))
                })?;
                if inserted {
                    result.imported += 1;
                } else {
                    result.skipped += 1;
                }
            }
            ImportApproach::All => {
                let mut conn = pool
                    .acquire()
                    .await
                    .map_err(|e| PgSecretsError::Database(db::DatabaseError::acquire(e)))?;
                db::secrets::insert(&mut conn, &envelope.as_new_entry(path)).await?;
                result.imported += 1;
            }
        }
    }

    Ok(result)
}

/// Whether the vault import has already completed (the marker secret
/// exists).
pub async fn is_vault_import_complete(pool: &PgPool) -> Result<bool, PgSecretsError> {
    Ok(db::secrets::exists(pool, VAULT_IMPORT_MARKER_PATH).await?)
}

/// Record vault import completion by writing the marker secret. The marker
/// is an ordinary encrypted journal entry, so it needs no schema of its
/// own.
pub async fn mark_vault_import_complete(
    pool: &PgPool,
    routing: &SecretRouting,
    kms: &dyn KmsBackend,
) -> Result<(), PgSecretsError> {
    let envelope =
        super::encrypt_envelope(routing, kms, VAULT_IMPORT_MARKER_PATH, b"completed").await?;

    let mut conn = pool
        .acquire()
        .await
        .map_err(|e| PgSecretsError::Database(db::DatabaseError::acquire(e)))?;

    db::secrets::insert(&mut conn, &envelope.as_new_entry(VAULT_IMPORT_MARKER_PATH)).await?;
    Ok(())
}
