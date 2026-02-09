/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use carbide_uuid::dpa_interface::DpaInterfaceId;
use forge_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialProvider, Credentials,
};
use hkdf::Hkdf;
use sha2::Sha256;
use sqlx::PgConnection;

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
// multiple unlock keys, I'll remove this.
#[allow(dead_code)]
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
    txn: &mut PgConnection,
    dpa_interface_id: DpaInterfaceId,
) -> Result<KdfContext, eyre::Report> {
    let interfaces = db::dpa_interface::find_by_ids(txn, &[dpa_interface_id], false).await?;
    let dpa_interface = interfaces
        .into_iter()
        .next()
        .ok_or_else(|| eyre::eyre!("SuperNIC interface {dpa_interface_id} not found"))?;

    Ok(KdfContext {
        mac_address: dpa_interface.mac_address.to_string(),
        machine_id: dpa_interface.machine_id.to_string(),
    })
}

// fetch_kdf_secret fetches the site-wide root secret from Vault,
// which is the IKM (Input Key Material) for the KDF.
async fn fetch_kdf_secret(
    credential_provider: &dyn CredentialProvider,
) -> Result<String, eyre::Report> {
    let credential_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::SiteWideRoot,
    };
    let credentials = credential_provider
        .get_credentials(&credential_key)
        .await?
        .ok_or_else(|| eyre::eyre!("SiteWideRoot credentials not found"))?;
    let Credentials::UsernamePassword { password, .. } = credentials;

    Ok(password)
}

// build_supernic_lockdown_key builds a single lockdown key using
// the latest KdfContextVersion. Use this for locking a card.
#[allow(txn_held_across_await)]
pub async fn build_supernic_lockdown_key(
    txn: &mut PgConnection,
    dpa_interface_id: DpaInterfaceId,
    credential_provider: &dyn CredentialProvider,
) -> Result<String, eyre::Report> {
    let ctx = build_kdf_context(txn, dpa_interface_id).await?;
    let secret = fetch_kdf_secret(credential_provider).await?;
    build_lockdown_key(secret.as_bytes(), &ctx, KdfContextVersion::V1)
}

// build_supernic_lockdown_keys builds all candidate lockdown keys
// for the given SuperNIC, covering all KdfContextVersions. Use
// this for unlocking a card, where we may need to try multiple
// key versions.
//
// TODO(chet): Once I update the unlock flow to support
// multiple unlock keys, I'll remove this.
#[allow(dead_code)]
#[allow(txn_held_across_await)]
pub async fn build_supernic_lockdown_keys(
    txn: &mut PgConnection,
    dpa_interface_id: DpaInterfaceId,
    credential_provider: &dyn CredentialProvider,
) -> Result<Vec<String>, eyre::Report> {
    let ctx = build_kdf_context(txn, dpa_interface_id).await?;
    let secret = fetch_kdf_secret(credential_provider).await?;
    derive_candidate_keys(secret.as_bytes(), &ctx)
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
}
