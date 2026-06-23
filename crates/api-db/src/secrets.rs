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

//! Queries for the `secrets` table -- an append-only journal of
//! envelope-encrypted credential values. Every write inserts a new row; a
//! read returns the newest row for the path. `seq DESC` is the journal
//! order everywhere: it is assigned by the database at insert, so it
//! follows true insertion order where `created_at` cannot (Postgres fixes
//! `now()` per transaction).
//!
//! Paths beginning with "/" are internal bookkeeping entries (the vault
//! import marker), not credentials. The kek-scoped queries exclude them so
//! callers that decrypt and parse whole result sets never trip over a
//! non-credential payload.

use carbide_uuid::secret::SecretId;
use model::secrets::SecretRow;
use sqlx::{PgConnection, PgTransaction};

use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

/// The envelope-encryption columns for one journal entry, exactly as the
/// manager produced them. Grouped so the insert paths cannot mix up five
/// consecutive `&[u8]`/`&str` arguments.
pub struct NewSecretEntry<'a> {
    pub path: &'a str,
    pub encrypted_value: &'a [u8],
    pub nonce: &'a [u8],
    pub kek_id: &'a str,
    pub encrypted_dek: &'a [u8],
    pub dek_nonce: &'a [u8],
}

/// Return the newest entry for a path.
pub async fn get_latest(txn: impl DbReader<'_>, path: &str) -> DatabaseResult<Option<SecretRow>> {
    let sql = "SELECT * FROM secrets WHERE path = $1
         ORDER BY seq DESC LIMIT 1";
    sqlx::query_as(sql)
        .bind(path)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))
}

/// Append a new journal entry.
pub async fn insert(txn: &mut PgConnection, entry: &NewSecretEntry<'_>) -> DatabaseResult<()> {
    let secret_id = SecretId::new();
    let sql = "INSERT INTO secrets
         (secret_id, path, encrypted_value, nonce,
          kek_id, encrypted_dek, dek_nonce)
         VALUES ($1, $2, $3, $4, $5, $6, $7)";
    sqlx::query(sql)
        .bind(secret_id)
        .bind(entry.path)
        .bind(entry.encrypted_value)
        .bind(entry.nonce)
        .bind(entry.kek_id)
        .bind(entry.encrypted_dek)
        .bind(entry.dek_nonce)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))?;
    Ok(())
}

/// Append a new journal entry only if the path has no entries yet. Returns
/// true when the row was inserted, false when entries already existed.
///
/// The check and the insert are two statements, so this takes a transaction
/// and serializes concurrent callers on a per-path advisory lock -- without
/// it, two racing creates would both pass the existence check and both
/// insert. The lock releases with the transaction.
pub async fn insert_if_missing(
    txn: &mut PgTransaction<'_>,
    entry: &NewSecretEntry<'_>,
) -> DatabaseResult<bool> {
    lock_path(txn, entry.path).await?;
    if exists(&mut **txn, entry.path).await? {
        return Ok(false);
    }
    insert(txn, entry).await?;
    Ok(true)
}

/// Take the transaction-scoped advisory lock for a path. Callers that need
/// check-then-write semantics on a path (there is no unique index -- the
/// journal allows many rows per path) take this lock first so concurrent
/// writers serialize.
///
/// The hashed string is namespaced with "secrets:" so this can never
/// collide with other subsystems that take advisory locks on their own
/// hashed strings.
pub async fn lock_path(txn: &mut PgTransaction<'_>, path: &str) -> DatabaseResult<()> {
    let sql = "SELECT pg_advisory_xact_lock(hashtextextended('secrets:' || $1, 0))";
    sqlx::query(sql)
        .bind(path)
        .execute(&mut **txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))?;
    Ok(())
}

/// Take the session-scoped advisory lock for a path on this connection,
/// without waiting. Returns false when another session already holds it.
///
/// Unlike [`lock_path`], the lock outlives any single transaction and is
/// held for as long as the connection stays open -- so a caller can guard
/// a long operation without keeping a transaction open across its awaits.
/// Release it with [`unlock_path_session`], or by dropping the connection.
pub async fn try_lock_path_session(conn: &mut PgConnection, path: &str) -> DatabaseResult<bool> {
    let sql = "SELECT pg_try_advisory_lock(hashtextextended('secrets:' || $1, 0))";
    sqlx::query_scalar(sql)
        .bind(path)
        .fetch_one(conn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))
}

/// Take the session-scoped advisory lock for a path on this connection,
/// waiting until it is free. The same release rules as
/// [`try_lock_path_session`] apply.
pub async fn lock_path_session(conn: &mut PgConnection, path: &str) -> DatabaseResult<()> {
    let sql = "SELECT pg_advisory_lock(hashtextextended('secrets:' || $1, 0))";
    sqlx::query(sql)
        .bind(path)
        .execute(conn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))?;
    Ok(())
}

/// Release a session-scoped advisory lock taken by [`lock_path_session`] or
/// [`try_lock_path_session`]. Dropping the connection releases it too, so
/// this is only needed when the connection is kept for further work.
pub async fn unlock_path_session(conn: &mut PgConnection, path: &str) -> DatabaseResult<()> {
    let sql = "SELECT pg_advisory_unlock(hashtextextended('secrets:' || $1, 0))";
    sqlx::query(sql)
        .bind(path)
        .execute(conn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))?;
    Ok(())
}

/// Whether any entries exist for the path.
pub async fn exists(txn: impl DbReader<'_>, path: &str) -> DatabaseResult<bool> {
    let sql = "SELECT EXISTS(SELECT 1 FROM secrets WHERE path = $1)";
    sqlx::query_scalar(sql)
        .bind(path)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))
}

/// Remove every journal entry for a path.
pub async fn delete_all(txn: &mut PgConnection, path: &str) -> DatabaseResult<()> {
    let sql = "DELETE FROM secrets WHERE path = $1";
    sqlx::query(sql)
        .bind(path)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))?;
    Ok(())
}

/// Remove one journal entry by id. Returns true when a row was deleted.
/// Deleting the newest entry makes the previous entry current again, which
/// is how credential rotation rolls back a failed attempt.
pub async fn delete_by_id(txn: &mut PgConnection, secret_id: SecretId) -> DatabaseResult<bool> {
    let sql = "DELETE FROM secrets WHERE secret_id = $1";
    let result = sqlx::query(sql)
        .bind(secret_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))?;
    Ok(result.rows_affected() > 0)
}

/// Return every journal entry for a path, newest first.
pub async fn get_history(txn: impl DbReader<'_>, path: &str) -> DatabaseResult<Vec<SecretRow>> {
    let sql = "SELECT * FROM secrets WHERE path = $1
         ORDER BY seq DESC";
    sqlx::query_as(sql)
        .bind(path)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))
}

/// Return one journal entry by id.
pub async fn get_by_id(
    txn: impl DbReader<'_>,
    secret_id: SecretId,
) -> DatabaseResult<Option<SecretRow>> {
    let sql = "SELECT * FROM secrets WHERE secret_id = $1";
    sqlx::query_as(sql)
        .bind(secret_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))
}

/// Return every credential journal entry whose DEK is wrapped by the given
/// KEK. Internal bookkeeping paths are excluded: callers decrypt and parse
/// these rows as credentials.
pub async fn get_all_for_kek_id(
    txn: impl DbReader<'_>,
    kek_id: &str,
) -> DatabaseResult<Vec<SecretRow>> {
    let sql = "SELECT * FROM secrets
         WHERE kek_id = $1 AND left(path, 1) <> '/'
         ORDER BY seq DESC";
    sqlx::query_as(sql)
        .bind(kek_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))
}

/// Return the credentials whose newest journal entry is wrapped by the
/// given KEK, one row per path. Internal bookkeeping paths are excluded:
/// callers decrypt and parse these rows as credentials.
pub async fn get_latest_with_kek_id(
    txn: impl DbReader<'_>,
    kek_id: &str,
) -> DatabaseResult<Vec<SecretRow>> {
    let sql = "SELECT * FROM (
             SELECT DISTINCT ON (path) *
             FROM secrets
             WHERE left(path, 1) <> '/'
             ORDER BY path, seq DESC
         ) latest
         WHERE latest.kek_id = $1";
    sqlx::query_as(sql)
        .bind(kek_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))
}

/// Return one page of the whole table in journal order. Pass the last
/// row's `seq` back as `after_seq` for the next page, or None to start
/// from the beginning. Re-wrap walks the table with this -- including the
/// internal bookkeeping rows, whose DEKs need re-wrapping like any other.
pub async fn find_batch_after(
    txn: impl DbReader<'_>,
    after_seq: Option<i64>,
    limit: i64,
) -> DatabaseResult<Vec<SecretRow>> {
    let sql = "SELECT * FROM secrets
         WHERE ($1::bigint IS NULL OR seq > $1)
         ORDER BY seq LIMIT $2";
    sqlx::query_as(sql)
        .bind(after_seq)
        .bind(limit)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))
}

/// Count the rows whose DEK is wrapped by a KEK outside the given set.
/// After a re-wrap, a zero here is the operator's signal that every KEK
/// absent from the routing config can be retired; nonzero right after a
/// re-wrap means concurrent writers landed rows mid-walk -- run it again.
pub async fn count_wrapped_outside(
    txn: impl DbReader<'_>,
    kek_ids: &[String],
) -> DatabaseResult<i64> {
    let sql = "SELECT count(*) FROM secrets WHERE kek_id <> ALL($1)";
    sqlx::query_scalar(sql)
        .bind(kek_ids)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))
}

/// Replace the DEK-wrapping columns on one row, leaving the encrypted value
/// untouched. This is the whole write side of KEK rotation: the data never
/// needs re-encrypting, only its DEK needs re-wrapping under the new KEK.
pub async fn update_dek_wrap(
    txn: &mut PgConnection,
    secret_id: SecretId,
    encrypted_dek: &[u8],
    dek_nonce: &[u8],
    kek_id: &str,
) -> DatabaseResult<()> {
    let sql = "UPDATE secrets SET encrypted_dek = $1,
         dek_nonce = $2, kek_id = $3
         WHERE secret_id = $4";
    sqlx::query(sql)
        .bind(encrypted_dek)
        .bind(dek_nonce)
        .bind(kek_id)
        .bind(secret_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(sql, e))?;
    Ok(())
}
