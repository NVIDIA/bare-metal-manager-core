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

use carbide_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialManager, CredentialReader, Credentials,
    NicLockdownIkm,
};
use carbide_uuid::dpa_interface::DpaInterfaceId;
use hkdf::Hkdf;
use sha2::Sha256;
use sqlx::PgPool;

// CURRENT_LOCKDOWN_IKM_VERSION is the site-wide lockdown IKM version the
// lock/unlock flow currently derives keys from. We will leave it hardcoded to 0 until
// we introduce rotation logic.
pub const CURRENT_LOCKDOWN_IKM_VERSION: u32 = 0;

// LOCKDOWN_KEY_LENGTH is the max length of the supported
// key by a Mellanox device. As of now it's a 64-bit key,
// which is 8 bytes, and represented as 16 hex characters.
//
// If you provide a smaller key, the underlying hw_access
// management will accept it, but prefix it with zeroes.
const LOCKDOWN_KEY_LENGTH: usize = 8;

// KdfContextVersion is used to manage versioning
// of the input KDF context provided for the key.
// As of now we're just at V1.
#[derive(Debug, Clone, Copy)]
pub enum KdfContextVersion {
    V1,
}

// KdfContext is the context provided to the underlying
// KDF function for generating stable, device-unique,
// lockdown (lock and unlock) keys.
pub struct KdfContext {
    pub mac_address: String,
    pub machine_id: String,
}

impl KdfContext {
    // to_info() provides a mechanism for, depnding on the version
    // provided, dumping out a human-readable input string. Note that
    // this does NOT include the master secret -- it is merely the
    // context data.
    fn to_info(&self, version: KdfContextVersion) -> String {
        match version {
            KdfContextVersion::V1 => {
                format!("supernic-lock:v1:{}:{}", self.mac_address, self.machine_id)
            }
        }
    }
}

// build_lockdown_key derives a single, stable lockdown key for
// the given context and version.
//
// Uses HKDF-SHA256 (RFC 5869) with the site-wide root as IKM and
// a versioned info string containing device-specific context.
// Returns a 16-character hex string representing the 64-bit key.
pub fn build_lockdown_key(
    site_wide_root: &[u8],
    ctx: &KdfContext,
    version: KdfContextVersion,
) -> Result<String, eyre::Report> {
    // TODO(chet): We could use a salt here alongside our
    // IKM, but the salt would also need to be stable. The
    // MachineId or machine serial number might actually
    // make sense as a salt, instead of being part of
    // the context, but I also don't think it matters.
    let hkdf = Hkdf::<Sha256>::new(None, site_wide_root);
    let info = ctx.to_info(version);

    let mut key = [0u8; LOCKDOWN_KEY_LENGTH];
    hkdf.expand(info.as_bytes(), &mut key)
        .map_err(|e| eyre::eyre!("HKDF expand failed: {e}"))?;

    Ok(hex::encode(key))
}

// derive_candidate_keys generates all candidate lockdown keys
// for a device, ordered from newest to oldest version. This
// allows us to handle key version rotations more gracefully
// by providing all possible candidates, with the first key
// being the most likely to unlock.
//
// Note that if we store the key version used to lock the card,
// then we only need to send down one key specific to that
// version.
//
// TODO(chet): Once I update the unlock flow to support
// multiple unlock keys, I'll remove the #[cfg(test)].
#[cfg(test)]
pub fn derive_candidate_keys(
    site_wide_root: &[u8],
    ctx: &KdfContext,
) -> Result<Vec<String>, eyre::Report> {
    Ok(vec![build_lockdown_key(
        site_wide_root,
        ctx,
        KdfContextVersion::V1,
    )?])
}

// build_kdf_context fetches the SuperNIC interface information
// from the database and builds a KdfContext from its hardware-
// derived fields (MAC address and MachineId).
async fn build_kdf_context(
    pg_pool: &PgPool,
    dpa_interface_id: DpaInterfaceId,
) -> Result<KdfContext, eyre::Report> {
    let interfaces = db::dpa_interface::find_by_ids(pg_pool, &[dpa_interface_id], false).await?;
    let dpa_interface = interfaces
        .into_iter()
        .next()
        .ok_or_else(|| eyre::eyre!("SuperNIC interface {dpa_interface_id} not found"))?;

    Ok(KdfContext {
        mac_address: dpa_interface.mac_address.to_string(),
        machine_id: dpa_interface.machine_id.to_string(),
    })
}

// lockdown_ikm_key returns the CredentialKey for the dedicated, versioned
// site-wide lockdown IKM.
fn lockdown_ikm_key(version: u32) -> CredentialKey {
    CredentialKey::NicLockdownIkm {
        credential_type: NicLockdownIkm::SiteWide { version },
    }
}

// fetch_kdf_secret fetches the IKM for the KDF from the
// dedicated site-wide lockdown credential, decoupled from the BMC root so the
// two can be rotated independently.
async fn fetch_kdf_secret(
    credential_reader: &dyn CredentialReader,
) -> Result<String, eyre::Report> {
    let ikm_key = lockdown_ikm_key(CURRENT_LOCKDOWN_IKM_VERSION);
    let credentials = credential_reader
        .get_credentials(&ikm_key)
        .await?
        .ok_or_else(|| {
            eyre::eyre!("lockdown IKM v{CURRENT_LOCKDOWN_IKM_VERSION} not found; site not seeded")
        })?;
    let Credentials::UsernamePassword { password, .. } = credentials;

    Ok(password)
}

// ensure_lockdown_ikm_seeded idempotently seeds the dedicated site-wide
// lockdown IKM (v0) by copying the current site-wide BMC root. This lets
// existing sites converge onto the decoupled lockdown key without operator
// action; going forward the two credentials start identical but rotate
// independently.
//
// Best-effort: if the BMC root is not yet configured (e.g. a brand-new site),
// this is a no-op and the IKM is seeded on a later boot once the root exists.
// Safe to run on every startup and concurrently across replicas (a lost
// create race is treated as success).
pub async fn ensure_lockdown_ikm_seeded(
    credential_manager: &dyn CredentialManager,
) -> Result<(), eyre::Report> {
    let ikm_key = lockdown_ikm_key(CURRENT_LOCKDOWN_IKM_VERSION);
    if credential_manager
        .get_credentials(&ikm_key)
        .await?
        .is_some()
    {
        tracing::debug!(
            version = CURRENT_LOCKDOWN_IKM_VERSION,
            "lockdown IKM already seeded"
        );
        return Ok(());
    }

    let bmc_root_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::SiteWideRoot,
    };
    let Some(bmc_root) = credential_manager.get_credentials(&bmc_root_key).await? else {
        tracing::warn!(
            "site-wide BMC root not set; deferring lockdown IKM seed until it is configured"
        );
        return Ok(());
    };

    match credential_manager
        .create_credentials(&ikm_key, &bmc_root)
        .await
    {
        Ok(()) => {
            tracing::info!(
                version = CURRENT_LOCKDOWN_IKM_VERSION,
                "seeded dedicated lockdown IKM from site-wide BMC root"
            );
            Ok(())
        }
        Err(e) => {
            // Another replica may have seeded concurrently between our read and
            // create; treat an already-present IKM as success.
            if credential_manager
                .get_credentials(&ikm_key)
                .await?
                .is_some()
            {
                Ok(())
            } else {
                Err(eyre::eyre!("failed to seed lockdown IKM: {e}"))
            }
        }
    }
}

// build_supernic_lockdown_key builds a single lockdown key using
// the latest KdfContextVersion. Use this for locking a card.
pub async fn build_supernic_lockdown_key(
    db_reader: &PgPool,
    dpa_interface_id: DpaInterfaceId,
    credential_reader: &dyn CredentialReader,
) -> Result<String, eyre::Report> {
    let ctx = build_kdf_context(db_reader, dpa_interface_id).await?;
    let secret = fetch_kdf_secret(credential_reader).await?;
    build_lockdown_key(secret.as_bytes(), &ctx, KdfContextVersion::V1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_is_stable() {
        let root = b"test-site-wide-root-secret";
        let ctx = KdfContext {
            mac_address: "00:11:22:33:44:55".to_string(),
            machine_id: "fm100hsdhjkfasjkdhaskjdhasd".to_string(),
        };

        let key1 = build_lockdown_key(root, &ctx, KdfContextVersion::V1).unwrap();
        let key2 = build_lockdown_key(root, &ctx, KdfContextVersion::V1).unwrap();
        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 16, "64-bit key should be 16 hex characters");
    }

    #[test]
    fn test_different_macs_produce_different_keys() {
        let root = b"test-site-wide-root-secret";
        let ctx1 = KdfContext {
            mac_address: "00:11:22:33:44:55".to_string(),
            machine_id: "fm100hsdhjkfasjkdhaskjdhasd".to_string(),
        };
        let ctx2 = KdfContext {
            mac_address: "00:11:22:33:44:56".to_string(),
            machine_id: "fm100hsdhjkfasjkdhaskjdhasd".to_string(),
        };

        let key1 = build_lockdown_key(root, &ctx1, KdfContextVersion::V1).unwrap();
        let key2 = build_lockdown_key(root, &ctx2, KdfContextVersion::V1).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_machine_ids_produce_different_keys() {
        let root = b"test-site-wide-root-secret";
        let ctx1 = KdfContext {
            mac_address: "00:11:22:33:44:55".to_string(),
            machine_id: "fm100hsdhjkfasjkdhaskjdhasd".to_string(),
        };
        let ctx2 = KdfContext {
            mac_address: "00:11:22:33:44:55".to_string(),
            machine_id: "fm100different_machine_id_here".to_string(),
        };

        let key1 = build_lockdown_key(root, &ctx1, KdfContextVersion::V1).unwrap();
        let key2 = build_lockdown_key(root, &ctx2, KdfContextVersion::V1).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_different_roots_produce_different_keys() {
        let ctx = KdfContext {
            mac_address: "00:11:22:33:44:55".to_string(),
            machine_id: "fm100hsdhjkfasjkdhaskjdhasd".to_string(),
        };

        let key1 = build_lockdown_key(b"root-secret-1", &ctx, KdfContextVersion::V1).unwrap();
        let key2 = build_lockdown_key(b"root-secret-2", &ctx, KdfContextVersion::V1).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_known_vector() {
        // This test pins a known derivation to detect accidental
        // algorithm changes.
        let root = b"test-site-wide-root-secret";
        let ctx = KdfContext {
            mac_address: "00:11:22:33:44:55".to_string(),
            machine_id: "fm100hsdhjkfasjkdhaskjdhasd".to_string(),
        };

        let key = build_lockdown_key(root, &ctx, KdfContextVersion::V1).unwrap();
        // Check against a hardcoded expected value — if this changes,
        // the KDF construction unexpectedly changed.
        assert_eq!(key, "efc63727086fa25c");
    }

    #[test]
    fn test_derive_candidate_keys() {
        let root = b"test-site-wide-root-secret";
        let ctx = KdfContext {
            mac_address: "00:11:22:33:44:55".to_string(),
            machine_id: "fm100hsdhjkfasjkdhaskjdhasd".to_string(),
        };

        let keys = derive_candidate_keys(root, &ctx).unwrap();
        assert_eq!(keys.len(), 1); // Only test against v1 for now.
        assert_eq!(keys[0].len(), 16);
    }

    use carbide_secrets::MemoryCredentialStore;
    use carbide_secrets::credentials::CredentialWriter;

    fn user_pass(password: &str) -> Credentials {
        Credentials::UsernamePassword {
            username: String::new(),
            password: password.to_string(),
        }
    }

    fn bmc_root_key() -> CredentialKey {
        CredentialKey::BmcCredentials {
            credential_type: BmcCredentialType::SiteWideRoot,
        }
    }

    #[tokio::test]
    async fn seed_copies_bmc_root_to_v0() {
        let store = MemoryCredentialStore::default();
        store
            .set_credentials(&bmc_root_key(), &user_pass("root-pass"))
            .await
            .unwrap();

        ensure_lockdown_ikm_seeded(&store).await.unwrap();

        let seeded = store
            .get_credentials(&lockdown_ikm_key(CURRENT_LOCKDOWN_IKM_VERSION))
            .await
            .unwrap();
        assert_eq!(seeded, Some(user_pass("root-pass")));
    }

    #[tokio::test]
    async fn seed_is_idempotent() {
        let store = MemoryCredentialStore::default();
        store
            .set_credentials(&bmc_root_key(), &user_pass("root-pass"))
            .await
            .unwrap();

        ensure_lockdown_ikm_seeded(&store).await.unwrap();
        // A second run must not error (the IKM already exists) and must not
        // change the value.
        ensure_lockdown_ikm_seeded(&store).await.unwrap();

        let seeded = store
            .get_credentials(&lockdown_ikm_key(CURRENT_LOCKDOWN_IKM_VERSION))
            .await
            .unwrap();
        assert_eq!(seeded, Some(user_pass("root-pass")));
    }

    #[tokio::test]
    async fn seed_preserves_existing_lockdown_ikm() {
        let store = MemoryCredentialStore::default();
        // Both the BMC root and a (diverged) lockdown IKM already exist, e.g.
        // the IKM was rotated independently after the initial seed.
        store
            .set_credentials(&bmc_root_key(), &user_pass("root-pass"))
            .await
            .unwrap();
        store
            .set_credentials(
                &lockdown_ikm_key(CURRENT_LOCKDOWN_IKM_VERSION),
                &user_pass("rotated-ikm"),
            )
            .await
            .unwrap();

        ensure_lockdown_ikm_seeded(&store).await.unwrap();

        // Seeding must not clobber the existing IKM with the BMC root.
        let seeded = store
            .get_credentials(&lockdown_ikm_key(CURRENT_LOCKDOWN_IKM_VERSION))
            .await
            .unwrap();
        assert_eq!(seeded, Some(user_pass("rotated-ikm")));
    }

    #[tokio::test]
    async fn seed_defers_when_no_bmc_root() {
        let store = MemoryCredentialStore::default();

        // No BMC root configured yet: seeding is a no-op, not an error.
        ensure_lockdown_ikm_seeded(&store).await.unwrap();

        let seeded = store
            .get_credentials(&lockdown_ikm_key(CURRENT_LOCKDOWN_IKM_VERSION))
            .await
            .unwrap();
        assert!(seeded.is_none());
    }

    #[tokio::test]
    async fn fetch_prefers_lockdown_ikm_over_bmc_root() {
        let store = MemoryCredentialStore::default();
        store
            .set_credentials(&bmc_root_key(), &user_pass("root-pass"))
            .await
            .unwrap();
        store
            .set_credentials(
                &lockdown_ikm_key(CURRENT_LOCKDOWN_IKM_VERSION),
                &user_pass("ikm-pass"),
            )
            .await
            .unwrap();

        let secret = fetch_kdf_secret(&store).await.unwrap();
        assert_eq!(secret, "ikm-pass");
    }

    #[tokio::test]
    async fn fetch_errors_when_ikm_unseeded() {
        let store = MemoryCredentialStore::default();
        // The BMC root being present is not enough: without the seeded IKM the
        // lock flow must error rather than derive from another secret.
        store
            .set_credentials(&bmc_root_key(), &user_pass("root-pass"))
            .await
            .unwrap();

        assert!(fetch_kdf_secret(&store).await.is_err());
    }
}
