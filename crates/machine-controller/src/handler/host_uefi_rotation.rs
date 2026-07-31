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

//! Machine-controller host UEFI credential rotation (REQ-2, UEFI).
//!
//! The BMC sibling ([`super::rotation`]) delegates the whole password dance to
//! the shared [`carbide_credential_rotation`] engine because a BMC password
//! change is a single synchronous Redfish call. Host UEFI is different: applying
//! a new password requires a BIOS config job plus a full host power-cycle, so
//! the convergence itself is a multi-tick FSM
//! ([`super::handle_rotating_host_uefi`]). This module is the thin
//! policy/bookkeeping adapter around that FSM:
//!
//! - *Should we enter rotation?* [`should_enter_host_uefi_rotation`] honors an
//!   operator force-converge request unconditionally, else fires the passive
//!   [`RotationGate`](carbide_credential_rotation::RotationGate) only when UEFI
//!   rotation is enabled site-wide.
//! - *What credential authenticates the change?*
//!   [`host_uefi_current_candidates`] resolves the ordered, versioned
//!   current-password candidates -- the engine-free equivalent of the BMC
//!   `change_or_recover` candidate walk.
//! - *Clear the one-shot force request* once a forced rotation has run.
//!
//! Convergence/quarantine is recorded against the same
//! `device_credential_rotation` bookkeeping the BMC engine uses, keyed by the
//! host BMC MAC (mirroring the ingestion setup path and the backfill).
//!
//! PR1 rotates the host UEFI only. DPU UEFI rotation is a follow-up in its own
//! sibling `RotatingDpuUefi` state: it too stages a BIOS settings job and reboots
//! (the DPU, not the host), is keyed by the DPU BMC MAC, and a host can carry
//! several DPUs -- distinct enough from the host flow to keep the two states
//! separate rather than overloading this one.

use carbide_secrets::credentials::{CredentialKey, CredentialReader, Credentials};
use mac_address::MacAddress;
use model::machine::ManagedHostStateSnapshot;
use state_controller::state_handler::StateHandlerError;

use crate::context::MachineStateHandlerServices;

/// The host BMC MAC keys the host-UEFI rotation bookkeeping (mirrors the
/// ingestion setup path and the backfill). A host with no BMC MAC can be neither
/// tracked nor reached, so it never enters rotation.
pub(crate) fn host_bmc_mac(mh: &ManagedHostStateSnapshot) -> Option<MacAddress> {
    mh.host_snapshot.status.bmc_info.mac
}

/// `true` when the host UEFI credential lags the staged site-wide target and is
/// not quarantined -- i.e. the host should enter its UEFI-rotation state.
pub(crate) async fn host_uefi_rotation_needed(
    services: &MachineStateHandlerServices,
    mh: &ManagedHostStateSnapshot,
) -> Result<bool, StateHandlerError> {
    let Some(mac) = host_bmc_mac(mh) else {
        return Ok(false);
    };
    services
        .uefi_rotation_gate
        .rotation_needed(&services.db_pool, mac)
        .await
        .map_err(|e| StateHandlerError::GenericError(eyre::eyre!("uefi rotation gate query: {e}")))
}

/// `true` when an operator has recorded a host UEFI force-converge request on
/// the host machine. Presence alone drives entry into `RotatingHostUefi`.
pub(crate) fn host_uefi_rotation_force_requested(mh: &ManagedHostStateSnapshot) -> bool {
    mh.host_snapshot.uefi_credential_rotation_requested
}

/// Whether a Ready host should enter `ManagedHostState::RotatingHostUefi` now.
///
/// An operator force-converge request always wins -- the ops escape hatch is
/// honored even when the site-wide flag is off. Otherwise the passive gate fires
/// only when the host's initial BIOS password was already set
/// (`bios_password_set_time.is_some()`; a never-set host is an initial-setup
/// problem, not a rotation candidate), UEFI rotation is enabled site-wide, *and*
/// the host lags the staged target; the cheap checks are ordered first so a
/// disabled site (or a never-set host) never runs the gate query.
pub(crate) async fn should_enter_host_uefi_rotation(
    services: &MachineStateHandlerServices,
    mh: &ManagedHostStateSnapshot,
) -> Result<bool, StateHandlerError> {
    if host_uefi_rotation_force_requested(mh) {
        return Ok(true);
    }
    // Passive rotation only touches a host whose initial BIOS password NICo
    // actually set: `bios_password_set_time` is stamped on that success and
    // never cleared, so `is_some()` is a durable "we have driven this host's
    // UEFI password at least once" signal. A host that never got its initial
    // password set is an initial-setup problem (owned by the ingestion
    // `UefiSetup` flow, which for the tested Dell/Lenovo vendors intercepts such
    // a Ready host before this guard is reached), not a rotation candidate --
    // attempting to rotate it would just fail and land in backoff quarantine.
    // The operator force-converge escape hatch above still overrides this.
    if mh.host_snapshot.bios_password_set_time.is_none() {
        return Ok(false);
    }
    Ok(services.site_config.uefi_rotation_enabled
        && host_uefi_rotation_needed(services, mh).await?)
}

/// Ordered current-password candidates for a host UEFI rotation, most-likely
/// first: the secret at the device's tracked current version, then the target
/// version (covers an already-applied-but-unrecorded rotation), then the empty
/// string (a never-set host, or one reset to factory). The first that
/// authenticates the change wins. This is the engine-free equivalent of the BMC
/// `change_or_recover` candidate walk; because UEFI passwords are site-wide
/// uniform per version, the current credential is fully determined by the
/// tracked version -- no per-device secret is needed.
pub(crate) async fn host_uefi_current_candidates(
    reader: &dyn CredentialReader,
    current_version: Option<u32>,
    target_version: u32,
) -> Result<Vec<String>, StateHandlerError> {
    let mut versions: Vec<u32> = Vec::new();
    if let Some(v) = current_version {
        versions.push(v);
    }
    if !versions.contains(&target_version) {
        versions.push(target_version);
    }

    let mut candidates = Vec::with_capacity(versions.len() + 1);
    for version in versions {
        if let Some(password) = read_host_uefi_password(reader, version).await? {
            candidates.push(password);
        }
    }
    // Empty last: a never-set host, or one reset to the factory default.
    candidates.push(String::new());
    Ok(candidates)
}

/// Read the site-wide host UEFI password at a specific version, or `None` if no
/// secret is staged for that version.
async fn read_host_uefi_password(
    reader: &dyn CredentialReader,
    version: u32,
) -> Result<Option<String>, StateHandlerError> {
    let key = CredentialKey::host_uefi_site_default(version);
    let credentials = reader.get_credentials(&key).await.map_err(|e| {
        StateHandlerError::GenericError(eyre::eyre!(
            "read site host UEFI credential {}: {e}",
            key.to_key_str()
        ))
    })?;
    Ok(credentials.map(|Credentials::UsernamePassword { password, .. }| password))
}

#[cfg(test)]
mod tests {
    use carbide_secrets::MemoryCredentialStore;
    use carbide_secrets::credentials::CredentialWriter;

    use super::*;

    /// Seed a versioned host UEFI secret into an in-memory reader.
    async fn seed(store: &MemoryCredentialStore, version: u32, password: &str) {
        store
            .set_credentials(
                &CredentialKey::host_uefi_site_default(version),
                &Credentials::UsernamePassword {
                    username: String::new(),
                    password: password.to_string(),
                },
            )
            .await
            .expect("seeding a host UEFI secret should succeed");
    }

    /// A tracked host lists its current-version secret first, then the target
    /// version, then the empty string, so authentication tries the most likely
    /// current password before falling back.
    #[tokio::test]
    async fn candidates_are_current_then_target_then_empty() {
        let store = MemoryCredentialStore::default();
        seed(&store, 1, "current-v1").await;
        seed(&store, 2, "target-v2").await;

        let candidates = host_uefi_current_candidates(&store, Some(1), 2)
            .await
            .expect("resolving candidates should succeed");

        assert_eq!(
            candidates,
            vec![
                "current-v1".to_string(),
                "target-v2".to_string(),
                String::new(),
            ],
        );
    }

    /// A never-rotated host (no tracked current version) tries the target then
    /// the empty string -- the first-rotation empty-vs-versioned case.
    #[tokio::test]
    async fn candidates_for_a_never_rotated_host_are_target_then_empty() {
        let store = MemoryCredentialStore::default();
        seed(&store, 0, "legacy-v0").await;

        let candidates = host_uefi_current_candidates(&store, None, 0)
            .await
            .expect("resolving candidates should succeed");

        assert_eq!(candidates, vec!["legacy-v0".to_string(), String::new()],);
    }

    /// When current and target are the same version it is listed once, so we
    /// never probe the same password twice.
    #[tokio::test]
    async fn candidates_dedupe_when_current_equals_target() {
        let store = MemoryCredentialStore::default();
        seed(&store, 3, "v3").await;

        let candidates = host_uefi_current_candidates(&store, Some(3), 3)
            .await
            .expect("resolving candidates should succeed");

        assert_eq!(candidates, vec!["v3".to_string(), String::new()]);
    }
}
