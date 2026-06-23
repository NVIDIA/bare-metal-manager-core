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

//! Database-backed tests for the Postgres credential manager and re-wrap.
//! These build the manager directly on the test pool with local key
//! material -- no API fixture needed.

use std::collections::HashMap;
use std::sync::Arc;

use carbide_kms_provider::{IntegratedKmsProvider, KmsBackend};
use carbide_secrets::credentials::{
    CredentialKey, CredentialReader, CredentialWriter, Credentials,
};

use super::PostgresCredentialManager;
use super::re_wrap::re_wrap_stale;
use super::routing::SecretRouting;

fn test_key(seed: u8) -> [u8; 32] {
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = seed.wrapping_add(i as u8);
    }
    key
}

/// A KMS with one key per (kek_id, seed) pair.
fn kms_with_keys(keys: &[(&str, u8)]) -> Arc<dyn KmsBackend> {
    let map: HashMap<String, [u8; 32]> = keys
        .iter()
        .map(|(kek_id, seed)| (kek_id.to_string(), test_key(*seed)))
        .collect();
    Arc::new(IntegratedKmsProvider::new(map))
}

fn catch_all_routing(kek_id: &str) -> SecretRouting {
    SecretRouting::new(vec![("/".to_string(), kek_id.to_string())])
}

fn manager(
    pool: &sqlx::PgPool,
    routing: SecretRouting,
    kms: Arc<dyn KmsBackend>,
) -> PostgresCredentialManager {
    PostgresCredentialManager::new(pool.clone(), routing, kms)
}

fn ufm_key(fabric: &str) -> CredentialKey {
    CredentialKey::UfmAuth {
        fabric: fabric.to_string(),
    }
}

fn cred(user: &str, pass: &str) -> Credentials {
    Credentials::UsernamePassword {
        username: user.to_string(),
        password: pass.to_string(),
    }
}

// Verifies the journal behavior behind set/get: every set appends, and get
// returns the newest entry.
#[crate::sqlx_test]
async fn set_get_round_trip_and_journal_latest_wins(pool: sqlx::PgPool) {
    let mgr = manager(&pool, catch_all_routing("k1"), kms_with_keys(&[("k1", 1)]));
    let key = ufm_key("fab1");

    mgr.set_credentials(&key, &cred("admin", "first"))
        .await
        .expect("first set");
    mgr.set_credentials(&key, &cred("admin", "second"))
        .await
        .expect("second set");

    let current = mgr.get_credentials(&key).await.expect("get");
    assert_eq!(current, Some(cred("admin", "second")));

    let history = mgr.get_history(&key).await.expect("history");
    assert_eq!(history.len(), 2);
    assert_eq!(history[0].credentials, cred("admin", "second"));
    assert_eq!(history[1].credentials, cred("admin", "first"));
}

// Verifies create-only semantics: the second create fails and leaves the
// first value in place.
#[crate::sqlx_test]
async fn create_fails_when_credential_exists(pool: sqlx::PgPool) {
    let mgr = manager(&pool, catch_all_routing("k1"), kms_with_keys(&[("k1", 1)]));
    let key = ufm_key("fab1");

    mgr.create_credentials(&key, &cred("admin", "original"))
        .await
        .expect("first create");

    let second = mgr
        .create_credentials(&key, &cred("admin", "usurper"))
        .await;
    let err = second.expect_err("second create must fail");
    assert!(
        err.to_string().contains("already exists"),
        "unexpected error: {err}"
    );

    let current = mgr.get_credentials(&key).await.expect("get");
    assert_eq!(current, Some(cred("admin", "original")));
}

// Verifies that delete removes the whole journal, not just the newest
// entry -- the same semantics Vault's delete gave callers.
#[crate::sqlx_test]
async fn delete_removes_all_journal_entries(pool: sqlx::PgPool) {
    let mgr = manager(&pool, catch_all_routing("k1"), kms_with_keys(&[("k1", 1)]));
    let key = ufm_key("fab1");

    mgr.set_credentials(&key, &cred("admin", "first"))
        .await
        .expect("first set");
    mgr.set_credentials(&key, &cred("admin", "second"))
        .await
        .expect("second set");
    mgr.delete_credentials(&key).await.expect("delete");

    assert_eq!(mgr.get_credentials(&key).await.expect("get"), None);
    assert!(mgr.get_history(&key).await.expect("history").is_empty());
}

// Verifies that the journal order is true write order even when two
// entries record the identical created_at (Postgres fixes now() per
// transaction): the second insert wins, by seq, not by chance.
#[crate::sqlx_test]
async fn second_write_wins_on_created_at_ties(pool: sqlx::PgPool) {
    let kms = kms_with_keys(&[("k1", 1)]);
    let routing = catch_all_routing("k1");
    let path = "tie/test/path";

    let mut txn = pool.begin().await.expect("begin");
    let first = super::encrypt_envelope(&routing, kms.as_ref(), path, b"\"first\"")
        .await
        .expect("encrypt first");
    db::secrets::insert(&mut txn, &first.as_new_entry(path))
        .await
        .expect("insert first");
    let second = super::encrypt_envelope(&routing, kms.as_ref(), path, b"\"second\"")
        .await
        .expect("encrypt second");
    db::secrets::insert(&mut txn, &second.as_new_entry(path))
        .await
        .expect("insert second");
    txn.commit().await.expect("commit");

    let newest = db::secrets::get_latest(&pool, path)
        .await
        .expect("get_latest")
        .expect("row");
    assert_eq!(
        newest.created_at,
        db::secrets::get_history(&pool, path)
            .await
            .expect("history")[1]
            .created_at,
        "both entries record the transaction's shared now()"
    );
    assert_eq!(
        newest.encrypted_value,
        second.as_new_entry(path).encrypted_value,
        "the later insert must be the newest entry"
    );
}

// Verifies the rotation rollback story: deleting the newest journal entry
// makes the previous credential current again.
#[crate::sqlx_test]
async fn delete_by_id_restores_previous_credential(pool: sqlx::PgPool) {
    let mgr = manager(&pool, catch_all_routing("k1"), kms_with_keys(&[("k1", 1)]));
    let key = ufm_key("fab1");

    mgr.set_credentials(&key, &cred("admin", "v1"))
        .await
        .expect("set v1");
    mgr.set_credentials(&key, &cred("admin", "v2"))
        .await
        .expect("set v2");

    let newest = &mgr.get_history(&key).await.expect("history")[0];
    assert_eq!(newest.credentials, cred("admin", "v2"));

    let fetched = mgr
        .get_by_id(newest.secret_id)
        .await
        .expect("get_by_id")
        .expect("entry");
    assert_eq!(fetched.credentials, cred("admin", "v2"));

    assert!(mgr.delete_by_id(newest.secret_id).await.expect("delete"));
    assert_eq!(
        mgr.get_credentials(&key).await.expect("get"),
        Some(cred("admin", "v1")),
        "the previous entry is current again"
    );
}

// Verifies the empty-password tombstone behavior the Vault reader
// established: several delete flows "delete" by writing an empty password,
// and reads must answer None for it.
#[crate::sqlx_test]
async fn empty_password_reads_as_none(pool: sqlx::PgPool) {
    let mgr = manager(&pool, catch_all_routing("k1"), kms_with_keys(&[("k1", 1)]));
    let key = ufm_key("fab1");

    mgr.set_credentials(&key, &cred("admin", "live"))
        .await
        .expect("set live");
    mgr.set_credentials(&key, &cred("admin", ""))
        .await
        .expect("set tombstone");

    assert_eq!(
        mgr.get_credentials(&key).await.expect("get"),
        None,
        "an empty-password tombstone must read as no credential"
    );
    assert_eq!(
        mgr.get_history(&key).await.expect("history").len(),
        2,
        "the journal keeps the tombstone entry itself"
    );
}

// Verifies the associated-data binding end to end: a ciphertext copied
// onto another path fails to decrypt instead of serving the wrong
// credential.
#[crate::sqlx_test]
async fn ciphertext_copied_to_another_path_does_not_decrypt(pool: sqlx::PgPool) {
    let mgr = manager(&pool, catch_all_routing("k1"), kms_with_keys(&[("k1", 1)]));
    let key_a = ufm_key("fab-a");
    let key_b = ufm_key("fab-b");

    mgr.set_credentials(&key_a, &cred("admin", "a-secret"))
        .await
        .expect("set");

    // Copy fab-a's encrypted columns onto fab-b's path, the way an
    // attacker with table access (but no keys) would.
    sqlx::query(
        "INSERT INTO secrets
             (secret_id, path, encrypted_value, nonce, kek_id, encrypted_dek, dek_nonce)
         SELECT gen_random_uuid(), $2, encrypted_value, nonce, kek_id, encrypted_dek, dek_nonce
         FROM secrets WHERE path = $1",
    )
    .bind(key_a.to_key_str().as_ref())
    .bind(key_b.to_key_str().as_ref())
    .execute(&pool)
    .await
    .expect("transplant row");

    let stolen = mgr.get_credentials(&key_b).await;
    assert!(
        stolen.is_err(),
        "a transplanted ciphertext must fail decryption, got: {stolen:?}"
    );
}

// Verifies that re-wrap moves every stale row to the KEK routing assigns,
// the rows still decrypt afterwards, and a second run finds nothing to do.
#[crate::sqlx_test]
async fn re_wrap_stale_moves_rows_and_is_idempotent(pool: sqlx::PgPool) {
    let kms = kms_with_keys(&[("old-key", 1), ("new-key", 2)]);

    // Write under old-key: two credentials, one with two journal entries.
    let mgr_old = manager(&pool, catch_all_routing("old-key"), kms.clone());
    mgr_old
        .set_credentials(&ufm_key("fab1"), &cred("admin", "one"))
        .await
        .expect("set fab1");
    mgr_old
        .set_credentials(&ufm_key("fab1"), &cred("admin", "two"))
        .await
        .expect("set fab1 again");
    mgr_old
        .set_credentials(&ufm_key("fab2"), &cred("admin", "three"))
        .await
        .expect("set fab2");

    // Rotate: routing now assigns new-key to everything.
    let routing = catch_all_routing("new-key");
    let result = re_wrap_stale(&pool, kms.as_ref(), &routing, 2)
        .await
        .expect("re-wrap");
    assert_eq!(result.re_wrapped, 3);
    assert_eq!(result.already_current, 0);
    assert_eq!(
        result.stale_remaining, 0,
        "old-key is unrouted and nothing is left on it"
    );

    // Every row decrypts, and historical entries moved too.
    let mgr_new = manager(&pool, routing.clone(), kms.clone());
    assert_eq!(
        mgr_new
            .get_credentials(&ufm_key("fab1"))
            .await
            .expect("get fab1"),
        Some(cred("admin", "two"))
    );
    assert_eq!(
        mgr_new
            .get_history(&ufm_key("fab1"))
            .await
            .expect("history")
            .len(),
        2
    );
    assert!(
        mgr_new
            .get_all_for_kek_id("old-key")
            .await
            .expect("old rows")
            .is_empty()
    );

    // A second run reports everything current and changes nothing.
    let again = re_wrap_stale(&pool, kms.as_ref(), &routing, 2)
        .await
        .expect("re-wrap again");
    assert_eq!(again.re_wrapped, 0);
    assert_eq!(again.already_current, 3);
}

// Verifies that the re-wrap counters are exact when rows move between two
// KEKs that are both still routed -- the single-pass walk classifies each
// row exactly once.
#[crate::sqlx_test]
async fn re_wrap_stale_counts_each_row_once_across_routed_keks(pool: sqlx::PgPool) {
    let kms = kms_with_keys(&[("k1", 1), ("k2", 2)]);

    // Both paths start under k1.
    let routing_old = catch_all_routing("k1");
    for path in ["alpha/one", "beta/two"] {
        let envelope = super::encrypt_envelope(&routing_old, kms.as_ref(), path, b"{}")
            .await
            .expect("encrypt");
        let mut conn = pool.acquire().await.expect("acquire");
        db::secrets::insert(&mut conn, &envelope.as_new_entry(path))
            .await
            .expect("insert");
    }

    // New routing sends beta/ to k2 while k1 stays routed for the rest.
    let routing_new = SecretRouting::new(vec![
        ("/".to_string(), "k1".to_string()),
        ("beta".to_string(), "k2".to_string()),
    ]);

    let result = re_wrap_stale(&pool, kms.as_ref(), &routing_new, 1)
        .await
        .expect("re-wrap");
    assert_eq!(result.re_wrapped, 1, "only beta/two moved");
    assert_eq!(result.already_current, 1, "alpha/one was already routed");
    assert_eq!(result.stale_remaining, 0);

    let again = re_wrap_stale(&pool, kms.as_ref(), &routing_new, 1)
        .await
        .expect("re-wrap again");
    assert_eq!(again.re_wrapped, 0);
    assert_eq!(again.already_current, 2);
}
