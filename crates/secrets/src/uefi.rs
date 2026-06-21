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

//! Seeding helpers for per-device UEFI secrets (`machines/uefi/{mac}/root`).
//!
//! Per-device UEFI secrets are the authoritative store the rotation engine
//! reads from and writes to. Until a device is rotated, the password actually
//! on the hardware is the site default that `uefi_setup` wrote, so the
//! per-device secret starts life as a copy of the site default. Two callers
//! converge devices onto a per-device secret:
//!
//! * the ingestion flow, right after it sets the UEFI password on the device
//!   (new sites, and any host that hadn't been UEFI-set yet); and
//! * a startup migration that backfills hosts whose UEFI password was already
//!   set before per-device secrets existed (existing sites).
//!
//! Both go through the create-if-missing helpers below so a per-device secret
//! is never clobbered once written.
//!
//! The per-device key (`CredentialKey::Uefi`) is MAC-keyed and identical for
//! host and DPU UEFI (the host BMC MAC vs. DPU BMC MAC disambiguates them); only
//! the *site-default* seed key differs, so the MAC-keyed helpers are generic and
//! the caller supplies the right site default.

use eyre::eyre;
use mac_address::MacAddress;

use crate::SecretsError;
use crate::credentials::{CredentialKey, CredentialManager, CredentialType, Credentials};

/// The per-device UEFI credential key for `bmc_mac` (host or DPU; the MAC
/// disambiguates).
pub fn per_device_uefi_key(bmc_mac: MacAddress) -> CredentialKey {
    CredentialKey::Uefi {
        bmc_mac_address: bmc_mac,
    }
}

/// The site-default host UEFI credential key (the value `uefi_setup` writes to
/// host hardware, and the seed for new per-device host secrets).
pub fn site_default_host_uefi_key() -> CredentialKey {
    CredentialKey::HostUefi {
        credential_type: CredentialType::SiteDefault,
    }
}

/// The site-default DPU UEFI credential key (the value `uefi_setup` writes to
/// DPU hardware, and the seed for new per-device DPU secrets).
pub fn site_default_dpu_uefi_key() -> CredentialKey {
    CredentialKey::DpuUefi {
        credential_type: CredentialType::SiteDefault,
    }
}

/// Writes `value` to the per-device UEFI secret for `bmc_mac` only if no secret
/// exists there yet. Returns `Ok(true)` when a new secret was written,
/// `Ok(false)` when one already existed.
///
/// Create-if-missing on purpose: an existing per-device secret may already
/// reflect a rotation and must not be overwritten with a (stale) site-default
/// value.
pub async fn seed_per_device_uefi_if_absent(
    manager: &dyn CredentialManager,
    bmc_mac: MacAddress,
    value: &Credentials,
) -> Result<bool, SecretsError> {
    let key = per_device_uefi_key(bmc_mac);
    if manager.get_credentials(&key).await?.is_some() {
        return Ok(false);
    }

    match manager.create_credentials(&key, value).await {
        Ok(()) => Ok(true),
        Err(e) => {
            // Another replica/iteration may have created it between our read
            // and create; treat an already-present secret as success.
            if manager.get_credentials(&key).await?.is_some() {
                Ok(false)
            } else {
                Err(e)
            }
        }
    }
}

/// Records `value` as the per-device UEFI secret for `bmc_mac`, requiring that
/// no secret already exists there.
///
/// Used by the ingestion flow immediately after `uefi_setup` applies the UEFI
/// password to the hardware for the first time. At that point a per-device
/// secret must not yet exist: its presence means a stale secret, a reused MAC,
/// or a logic bug, so we fail loudly instead of silently skipping (which would
/// leave a per-device secret that may not match the hardware) or clobbering.
/// Contrast with [`seed_per_device_uefi_if_absent`], whose create-if-missing
/// behavior is what the startup backfill of already-provisioned devices wants.
pub async fn write_per_device_uefi_expecting_absent(
    manager: &dyn CredentialManager,
    bmc_mac: MacAddress,
    value: &Credentials,
) -> Result<(), SecretsError> {
    let key = per_device_uefi_key(bmc_mac);
    if manager.get_credentials(&key).await?.is_some() {
        return Err(SecretsError::GenericError(eyre!(
            "per-device UEFI secret ({}) already exists during initial UEFI setup; \
             refusing to overwrite",
            key.to_key_str()
        )));
    }

    manager.create_credentials(&key, value).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MemoryCredentialStore;
    use crate::credentials::{CredentialReader, CredentialWriter};

    fn mac() -> MacAddress {
        MacAddress::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
    }

    fn user_pass(password: &str) -> Credentials {
        Credentials::UsernamePassword {
            username: String::new(),
            password: password.to_string(),
        }
    }

    #[tokio::test]
    async fn writes_provided_value_when_absent() {
        let store = MemoryCredentialStore::default();

        let wrote = seed_per_device_uefi_if_absent(&store, mac(), &user_pass("site-uefi"))
            .await
            .unwrap();
        assert!(wrote, "expected a new per-device secret to be written");

        let stored = store
            .get_credentials(&per_device_uefi_key(mac()))
            .await
            .unwrap();
        assert_eq!(stored, Some(user_pass("site-uefi")));
    }

    #[tokio::test]
    async fn is_idempotent_and_does_not_clobber_existing() {
        let store = MemoryCredentialStore::default();
        // A per-device secret already exists (e.g. set by a prior run or a
        // rotation) and differs from the value we'd seed.
        store
            .set_credentials(&per_device_uefi_key(mac()), &user_pass("rotated"))
            .await
            .unwrap();

        let wrote = seed_per_device_uefi_if_absent(&store, mac(), &user_pass("site-uefi"))
            .await
            .unwrap();
        assert!(!wrote, "must not overwrite an existing per-device secret");

        let preserved = store
            .get_credentials(&per_device_uefi_key(mac()))
            .await
            .unwrap();
        assert_eq!(preserved, Some(user_pass("rotated")));
    }

    #[tokio::test]
    async fn expecting_absent_writes_when_missing() {
        let store = MemoryCredentialStore::default();

        write_per_device_uefi_expecting_absent(&store, mac(), &user_pass("site-uefi"))
            .await
            .unwrap();

        let stored = store
            .get_credentials(&per_device_uefi_key(mac()))
            .await
            .unwrap();
        assert_eq!(stored, Some(user_pass("site-uefi")));
    }

    #[tokio::test]
    async fn expecting_absent_errors_and_preserves_when_present() {
        let store = MemoryCredentialStore::default();
        store
            .set_credentials(&per_device_uefi_key(mac()), &user_pass("existing"))
            .await
            .unwrap();

        let result =
            write_per_device_uefi_expecting_absent(&store, mac(), &user_pass("site-uefi")).await;
        assert!(result.is_err(), "must error when a secret already exists");

        let preserved = store
            .get_credentials(&per_device_uefi_key(mac()))
            .await
            .unwrap();
        assert_eq!(preserved, Some(user_pass("existing")));
    }
}
