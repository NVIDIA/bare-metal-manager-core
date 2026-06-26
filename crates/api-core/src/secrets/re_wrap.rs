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

use carbide_kms_provider::{EncryptedDek, KmsBackend};
use carbide_uuid::secret::SecretId;
use sqlx::PgPool;

use super::PgSecretsError;
use super::routing::SecretRouting;

/// The internal path whose advisory lock makes re-wrap single-flight. Like
/// the import marker, it starts with a slash so it can never collide with
/// a credential path -- but unlike the marker, no row is ever written for
/// it; only its lock is used.
const RE_WRAP_LOCK_PATH: &str = "/_re_wrap";

/// What a re-wrap pass did, in journal rows.
pub struct ReWrapStaleResult {
    /// Rows whose DEK was re-wrapped to the routed KEK.
    pub re_wrapped: u64,
    /// Rows already wrapped by the routed KEK.
    pub already_current: u64,
    /// Rows still wrapped by a KEK outside the routing config after the
    /// walk. Zero means every unrouted KEK can be retired; nonzero right
    /// after a run means concurrent writers landed rows mid-walk -- run
    /// re-wrap again once the fleet's config has converged.
    pub stale_remaining: u64,
}

/// A re-wrapped DEK waiting to be written back to its row.
struct PendingReWrap {
    secret_id: SecretId,
    wrapped: EncryptedDek,
    kek_id: String,
}

/// Re-wrap every journal row whose KEK no longer matches what routing
/// assigns its path -- the operator's one verb after rotating a key in
/// config: make the table agree with the config.
///
/// Only the DEK-wrapping columns change; the encrypted values are never
/// touched. The table is walked once in journal order, each batch's KMS
/// work happens before its write transaction opens (with Transit, those
/// are network calls that must not run while a transaction is held), and
/// batches commit independently, so an interrupted run keeps its progress.
/// Historical journal entries are re-wrapped too: they must stay
/// decryptable, and re-wrapping them is what lets an old KEK be retired
/// completely.
pub async fn re_wrap_stale(
    pool: &PgPool,
    kms: &dyn KmsBackend,
    routing: &SecretRouting,
    batch_size: i64,
) -> Result<ReWrapStaleResult, PgSecretsError> {
    // One re-wrap at a time: a second concurrent run would double every
    // KMS round-trip for no benefit. The guard is a session advisory lock
    // held on a dedicated connection, not a transaction -- the walk awaits
    // Vault/KMS and opens a transaction per batch, and a lock transaction
    // held across all of that would trip `txn_held_across_await` and could
    // starve the pool. Detaching the connection guarantees the lock
    // releases when it drops, including on an early error return.
    let mut lock_conn = pool
        .acquire()
        .await
        .map_err(|e| PgSecretsError::Database(db::DatabaseError::acquire(e)))?
        .detach();
    if !db::secrets::try_lock_path_session(&mut lock_conn, RE_WRAP_LOCK_PATH).await? {
        return Err(PgSecretsError::ReWrapInProgress);
    }

    let mut result = ReWrapStaleResult {
        re_wrapped: 0,
        already_current: 0,
        stale_remaining: 0,
    };

    let mut cursor: Option<i64> = None;
    loop {
        let batch = db::secrets::find_batch_after(pool, cursor, batch_size).await?;
        let Some(last) = batch.last() else {
            break;
        };
        cursor = Some(last.seq);

        // Unwrap and re-wrap stale DEKs first, against rows as read --
        // no transaction is open yet.
        let mut pending = Vec::new();
        for row in &batch {
            let target_kek = routing.active_kek_for_path(&row.path)?;
            if row.kek_id == target_kek {
                result.already_current += 1;
                continue;
            }

            let dek = kms
                .decrypt_dek(
                    &row.kek_id,
                    &EncryptedDek {
                        ciphertext: row.encrypted_dek.clone(),
                        nonce: row.dek_nonce.clone(),
                    },
                )
                .await?;
            let wrapped = kms.encrypt_dek(target_kek, &dek).await?;
            pending.push(PendingReWrap {
                secret_id: row.secret_id,
                wrapped,
                kek_id: target_kek.to_string(),
            });
        }

        if pending.is_empty() {
            continue;
        }

        // Then one short, write-only transaction per batch.
        let mut txn = pool
            .begin()
            .await
            .map_err(|e| PgSecretsError::Database(db::DatabaseError::acquire(e)))?;
        for rewrap in &pending {
            db::secrets::update_dek_wrap(
                &mut txn,
                rewrap.secret_id,
                &rewrap.wrapped.ciphertext,
                &rewrap.wrapped.nonce,
                &rewrap.kek_id,
            )
            .await?;
        }
        txn.commit().await.map_err(|e| {
            PgSecretsError::Database(db::DatabaseError::new("commit re-wrap batch", e))
        })?;
        result.re_wrapped += pending.len() as u64;
    }

    // Report what is still wrapped by KEKs outside the routing config --
    // the operator's retire-the-old-key signal.
    let routed: Vec<String> = routing
        .routes()
        .map(|(_, kek_id)| kek_id.to_string())
        .collect();
    result.stale_remaining = db::secrets::count_wrapped_outside(pool, &routed).await? as u64;

    Ok(result)
}
