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

//! Shared per-device credential rotation engine.
//!
//! `RotateCredential` only *stages* a site-wide rotation: it writes the
//! rotate-TO secret at the next version and bumps
//! `sitewide_credential_rotation.target_version`. This crate houses the engine
//! that *converges* an individual device to that staged target, so the
//! machine-, switch-, and power-shelf-controllers share one implementation
//! instead of each re-deriving the BMC password dance.
//!
//! Today it implements BMC rotation ([`rotate_bmc`]); Host/DPU UEFI rotation
//! reuses the controllers' existing job-polling UEFI-setup state machines and
//! lives there.
//!
//! # BMC flow (single synchronous step + crash marker)
//!
//! The BMC password primitive
//! ([`carbide_redfish::libredfish::RedfishClientPool::set_bmc_root_password`])
//! is synchronous (no BIOS job to poll), so BMC rotation is one step guarded by
//! the `rotating_to_version` crash marker:
//!
//! 1. Read [`device_rotation_status`]; skip converged / quarantined / orphaned
//!    rows.
//! 2. [`mark_device_rotating_to_version`] to the live target (crash marker).
//! 3. Change the password with **change-then-verify recovery**: authenticate
//!    with the current per-device secret and change to the rotate-TO value. On
//!    failure, ask the BMC whether the rotate-TO value *already* authenticates
//!    ([`RedfishClientPool::bmc_credentials_valid`]) -- if so, a prior attempt
//!    changed the hardware before crashing and the device is already at target.
//!    This never re-issues a same-value (`new -> new`) change, which some BMCs
//!    reject under a password-reuse policy, and costs at most one extra failed
//!    login so it stays clear of BMC lockout.
//! 4. On success (or an already-at-target verify): persist the per-device secret
//!    at the new password, flush cached BMC Redfish sessions, and
//!    [`promote_rotating_to_current`].
//! 5. On failure: [`increment_rotate_attempt`] with a redacted error and an
//!    exponential [`backoff_until`] window, and report
//!    [`RotateOutcome::Quarantined`].
//!
//! Crash safety: a crash between step 2 and step 4 leaves `rotating_to_version`
//! set and `current_version` behind the target, so the next tick re-enters and
//! the change-then-verify recovery reconciles the hardware regardless of which
//! side of the change the crash landed on. A target that advanced in the
//! meantime is superseded automatically: step 2 re-marks to the *live* target
//! every tick.
//!
//! The recovery path intentionally does not re-apply the vendor password policy
//! ([`carbide_redfish::libredfish::RedfishClientPool::set_bmc_root_password`]
//! applies it on every change). That policy is a *static* per-vendor setting,
//! and every password the device has ever carried -- including its initial
//! provisioning value -- was set through `set_bmc_root_password`, so a device
//! already at the rotate-TO value already has the policy in effect; recovery has
//! nothing to restore.
//!
//! # Entry gate ([`BmcRotationGate`])
//!
//! Controllers must not pay a per-device `device_rotation_status` query on every
//! 30-second sweep. [`BmcRotationGate`] caches the cheap per-type aggregate
//! ([`rotation_status`]) with a short TTL, so a controller's per-object entry
//! guard ([`BmcRotationGate::bmc_rotation_needed`]) hits the database per-device
//! only when the site-wide aggregate says some device actually lags. In steady
//! state (nothing staged, or fully converged) the gate is one cached aggregate
//! query per TTL window, not O(devices).

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use carbide_redfish::libredfish::RedfishClientPool;
use carbide_secrets::credentials::{
    BmcCredentialType, CredentialKey, CredentialManager, Credentials,
};
use chrono::{DateTime, Utc};
use db::DatabaseError;
use db::credential_rotation::{
    CredentialRotationType, DeviceRotationStatus, backoff_until, device_rotation_status,
    increment_rotate_attempt, mark_device_rotating_to_version, promote_rotating_to_current,
    rotation_status,
};
use libredfish::model::service_root::RedfishVendor;
use mac_address::MacAddress;
use sqlx::PgPool;

/// All work in this crate is the `bmc` credential family.
const BMC: CredentialRotationType = CredentialRotationType::Bmc;

/// Default freshness window for the [`BmcRotationGate`] aggregate cache. Short
/// enough that a freshly staged rotation is picked up within roughly one sweep,
/// long enough that steady-state sweeps don't hammer the aggregate query.
const DEFAULT_AGGREGATE_TTL: Duration = Duration::from_secs(15);

/// The result of attempting to converge one device toward the staged target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotateOutcome {
    /// The device is at the target version (just rotated, or already there).
    /// The controller transitions back to its steady (`Ready`) state.
    Converged,
    /// The attempt failed; a backoff window was recorded. The controller
    /// returns to steady state and its entry guard skips this device (it reads
    /// as `quarantined`) until `until` passes.
    Quarantined { until: DateTime<Utc> },
    /// Nothing to do: no rotation row for this device (not under management, or
    /// the row was torn down). The controller transitions back without acting.
    NoWork,
}

/// Where and how to reach a single device's BMC for rotation.
///
/// `device_mac` is the BMC MAC that keys both the `device_credential_rotation`
/// row and the per-device Vault secret. `vendor` is resolved by the caller,
/// which for switch / power-shelf BMCs means probing at rotation time via
/// [`RedfishClientPool::probe_bmc_vendor`] (the precise dispatch vendor is not
/// persisted anywhere).
#[derive(Debug, Clone)]
pub struct BmcRotationTarget {
    /// BMC MAC keying the rotation row and the per-device secret.
    pub device_mac: MacAddress,
    /// BMC host (IP or hostname).
    pub host: String,
    /// BMC port, when non-default.
    pub port: Option<u16>,
    /// Precise dispatch vendor `set_bmc_root_password` branches on.
    pub vendor: RedfishVendor,
}

/// Errors that abort a rotation tick as a transient handler failure (so the
/// controller retries the whole tick), as opposed to a device-level failure
/// (which quarantines the device and is reported via
/// [`RotateOutcome::Quarantined`]).
#[derive(thiserror::Error, Debug)]
pub enum RotationEngineError {
    /// Rotation bookkeeping (the `device_credential_rotation` table) failed.
    #[error("rotation bookkeeping error: {0}")]
    Database(#[from] DatabaseError),
    /// A database connection could not be acquired from the pool.
    #[error("could not acquire a database connection: {0}")]
    Acquire(#[from] sqlx::Error),
    /// The site-wide target version is not representable as an unsigned version
    /// (a corrupted bookkeeping invariant rather than a device fault).
    #[error("rotation target version {0} is not representable")]
    BadTargetVersion(i32),
}

/// Whether `status` describes a device that still needs to converge to the
/// current site-wide target: behind the target and not currently quarantined.
///
/// A pure predicate over a status a caller already holds. A device with no
/// rotation row never reaches here (the caller resolves the row first); a
/// converged or quarantined device is left alone.
pub fn needs_rotation(status: &DeviceRotationStatus) -> bool {
    !status.converged && !status.quarantined
}

/// A short-TTL cache of the site-wide BMC rotation aggregate, shared across a
/// controller's per-object ticks (cheap to clone; `Arc`-backed).
///
/// The controller's per-tick entry guard calls
/// [`Self::bmc_rotation_needed`], which consults the cached aggregate first and
/// only issues the per-device query when the site-wide counts say some device
/// actually lags. This keeps the steady state (nothing staged / fully
/// converged) at one cheap aggregate query per TTL window rather than a
/// per-device query for every device on every sweep.
///
/// The cache is per-process: each controller replica maintains its own, which
/// is correct because it is only a gate -- the authoritative per-device check
/// and the `FOR UPDATE SKIP LOCKED` object claim still serialize the actual
/// rotation across replicas.
#[derive(Clone)]
pub struct BmcRotationGate {
    inner: Arc<Mutex<CachedAggregate>>,
    ttl: Duration,
}

#[derive(Default)]
struct CachedAggregate {
    /// When the aggregate was last refreshed; `None` before the first query.
    checked_at: Option<Instant>,
    /// Whether the last refresh saw any device lagging the site-wide target.
    work_pending: bool,
}

impl Default for BmcRotationGate {
    fn default() -> Self {
        Self::with_ttl(DEFAULT_AGGREGATE_TTL)
    }
}

impl BmcRotationGate {
    /// A gate with the default aggregate-cache TTL.
    pub fn new() -> Self {
        Self::default()
    }

    /// A gate with an explicit aggregate-cache TTL. A zero TTL disables caching
    /// (every call re-queries the aggregate) -- useful in tests.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(CachedAggregate::default())),
            ttl,
        }
    }

    /// Whether *any* BMC device currently lags the site-wide target, from the
    /// cached aggregate (refreshed at most once per TTL window).
    ///
    /// "Work pending" means the target has advanced past the v0 baseline and at
    /// least one device is pending or quarantined. The steady state -- nothing
    /// staged (`target_version == 0`) or everything converged -- returns
    /// `false` from cache without a per-device query.
    pub async fn rotation_pending(&self, pool: &PgPool) -> Result<bool, RotationEngineError> {
        // Fast path: a still-fresh cached decision, without touching the DB.
        // The guard is dropped before any await so we never hold a std mutex
        // across a suspension point.
        {
            let cache = self.inner.lock().expect("rotation gate mutex poisoned");
            if let Some(checked_at) = cache.checked_at
                && checked_at.elapsed() < self.ttl
            {
                return Ok(cache.work_pending);
            }
        }

        // Refresh with one cheap aggregate query. A concurrent refresh by
        // another tick is harmless: the query is read-only and idempotent, and
        // last-writer-wins on the cache is fine for a gate.
        let mut conn = pool.acquire().await?;
        let status = rotation_status(&mut conn, BMC).await?;
        drop(conn);
        let work_pending = status.target_version > 0 && (status.pending + status.quarantined) > 0;

        let mut cache = self.inner.lock().expect("rotation gate mutex poisoned");
        cache.checked_at = Some(Instant::now());
        cache.work_pending = work_pending;
        Ok(work_pending)
    }

    /// Controller entry guard for one device: `true` when the device's BMC
    /// credential is behind the site-wide target and not quarantined, so the
    /// controller should enter its BMC-rotation state.
    ///
    /// Gated by [`Self::rotation_pending`], so the per-device query runs only
    /// when the cached aggregate says some device lags. A device with no
    /// rotation row (not under management) returns `false`.
    pub async fn bmc_rotation_needed(
        &self,
        pool: &PgPool,
        device_mac: MacAddress,
    ) -> Result<bool, RotationEngineError> {
        if !self.rotation_pending(pool).await? {
            return Ok(false);
        }
        let mut conn = pool.acquire().await?;
        let status = device_rotation_status(&mut conn, BMC, device_mac).await?;
        Ok(status.as_ref().is_some_and(needs_rotation))
    }
}

/// Converge one device's BMC root password to the staged site-wide target.
///
/// Idempotent and crash-safe: safe to call every tick while the controller is
/// in its BMC-rotation state. Returns [`RotateOutcome::Converged`] once the
/// device is at the target (so the controller can leave the state),
/// [`RotateOutcome::Quarantined`] when an attempt failed (backoff recorded), or
/// [`RotateOutcome::NoWork`] when there is no rotation row.
///
/// `credential_manager` both *reads* the per-device and site-wide secrets and
/// *writes* the per-device secret on success -- the same store
/// `RotateCredential` staged the target into. (The Redfish pool's
/// `credential_reader` is intentionally not used here; the engine owns
/// credential resolution.)
pub async fn rotate_bmc(
    db_pool: &PgPool,
    credential_manager: &dyn CredentialManager,
    redfish_pool: &dyn RedfishClientPool,
    bmc: &BmcRotationTarget,
) -> Result<RotateOutcome, RotationEngineError> {
    let mac = bmc.device_mac;

    let mut conn = db_pool.acquire().await?;
    let status = device_rotation_status(&mut conn, BMC, mac).await?;
    drop(conn);

    let Some(status) = status else {
        return Ok(RotateOutcome::NoWork);
    };
    if status.converged {
        return Ok(RotateOutcome::Converged);
    }
    if status.quarantined {
        return Ok(RotateOutcome::Quarantined {
            until: status.quarantined_until.unwrap_or_else(Utc::now),
        });
    }
    // Convert once, up front: a target that can't be represented as an unsigned
    // version is a corrupted invariant, not a device fault, so it aborts the
    // tick rather than quarantining the device.
    let target_version = u32::try_from(status.target_version)
        .map_err(|_| RotationEngineError::BadTargetVersion(status.target_version))?;

    // Stage the crash-safety marker before touching hardware: a crash after the
    // hardware change but before the secret write leaves this set, so the next
    // tick re-enters and the two-candidate recovery reconciles. Re-marking to
    // the live target every tick is what supersedes a stale in-flight marker.
    let mut conn = db_pool.acquire().await?;
    mark_device_rotating_to_version(&mut conn, mac, BMC, status.target_version).await?;
    drop(conn);

    match converge_bmc_password(credential_manager, redfish_pool, bmc, target_version).await {
        Ok(convergence) => {
            let mut conn = db_pool.acquire().await?;
            // Flush cached BMC sessions so the next login re-authenticates with
            // the freshly-written credential rather than a now-stale token.
            db::bmc_redfish_session::delete_by_mac(&mut conn, mac).await?;
            promote_rotating_to_current(&mut conn, mac, BMC).await?;
            match convergence {
                CredentialConvergence::Changed => {
                    tracing::info!(%mac, target_version, "BMC credential rotated and converged");
                }
                // The change failed but the rotate-TO value already
                // authenticated: a prior attempt changed the hardware and
                // crashed before recording success, and this tick reconciled it.
                // WARN because reaching here means an earlier attempt was
                // interrupted mid-rotation; the redacted change error explains
                // why the direct change failed (usually a stale-credential auth
                // rejection).
                CredentialConvergence::Recovered { change_error } => {
                    tracing::warn!(
                        %mac,
                        target_version,
                        change_error = %change_error,
                        "BMC already at rotate-to credential; recovered from an interrupted prior rotation"
                    );
                }
            }
            Ok(RotateOutcome::Converged)
        }
        Err(redacted) => {
            let until = backoff_until(status.rotate_attempts, Utc::now());
            let mut conn = db_pool.acquire().await?;
            increment_rotate_attempt(&mut conn, mac, BMC, &redacted, until).await?;
            tracing::warn!(
                %mac,
                target_version,
                error = %redacted,
                "BMC credential rotation attempt failed; quarantining"
            );
            Ok(RotateOutcome::Quarantined { until })
        }
    }
}

/// How a device reached the rotate-TO credential, so the caller can tell a
/// routine rotation from a crash-recovery reconciliation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CredentialConvergence {
    /// The password change succeeded on this attempt.
    Changed,
    /// The change failed but the rotate-TO value already authenticated: a prior
    /// attempt changed the hardware and crashed before recording success, and
    /// this tick reconciled it. Carries the (redacted) change error for context.
    Recovered { change_error: String },
}

impl CredentialConvergence {
    /// Redact every secret from the recovery context error, so the swallowed
    /// change failure can be surfaced without leaking a password.
    fn redacted(self, secrets: &[&str]) -> Self {
        match self {
            Self::Changed => Self::Changed,
            Self::Recovered { change_error } => Self::Recovered {
                change_error: redact(change_error, secrets),
            },
        }
    }
}

/// Resolve the credentials, converge the device to the rotate-to password
/// (change-then-verify recovery via [`change_or_recover`]), and persist the
/// per-device secret. Returns `Err` with an already-redacted reason on any
/// device-level failure, so the caller can record it and quarantine. Never
/// returns a secret-bearing string.
async fn converge_bmc_password(
    credential_manager: &dyn CredentialManager,
    redfish_pool: &dyn RedfishClientPool,
    bmc: &BmcRotationTarget,
    rotate_to_version: u32,
) -> Result<CredentialConvergence, String> {
    let per_device_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::BmcRoot {
            bmc_mac_address: bmc.device_mac,
        },
    };
    let per_device = credential_manager
        .get_credentials(&per_device_key)
        .await
        .map_err(|e| format!("read per-device BMC secret: {e}"))?
        .ok_or_else(|| "per-device BMC secret is not set".to_string())?;

    let rotate_to_key = CredentialKey::BmcCredentials {
        credential_type: BmcCredentialType::site_wide_root(rotate_to_version),
    };
    let rotate_to = credential_manager
        .get_credentials(&rotate_to_key)
        .await
        .map_err(|e| format!("read rotate-to BMC secret: {e}"))?
        .ok_or_else(|| {
            format!("rotate-to BMC secret for version {rotate_to_version} is not staged")
        })?;

    let Credentials::UsernamePassword {
        username,
        password: current_password,
    } = per_device;
    let Credentials::UsernamePassword {
        password: new_password,
        ..
    } = rotate_to;

    let rotate_from = Credentials::UsernamePassword {
        username: username.clone(),
        password: current_password.clone(),
    };
    let rotate_to = Credentials::UsernamePassword {
        username: username.clone(),
        password: new_password.clone(),
    };

    let convergence = change_or_recover(redfish_pool, bmc, rotate_from, rotate_to)
        .await
        .map_err(|e| redact(e, &[&current_password, &new_password]))?
        .redacted(&[&current_password, &new_password]);

    // Persist the per-device secret at the new password so future logins -- and
    // the next rotation's "current" -- use it. The username is unchanged.
    let updated = Credentials::UsernamePassword {
        username,
        password: new_password.clone(),
    };
    credential_manager
        .set_credentials(&per_device_key, &updated)
        .await
        .map_err(|e| {
            redact(
                format!("persist per-device BMC secret: {e}"),
                &[&current_password, &new_password],
            )
        })?;

    Ok(convergence)
}

/// Converge the hardware to `rotate_to` with change-then-verify recovery.
///
/// The normal path authenticates with `rotate_from` (the current per-device
/// secret) and changes the password to `rotate_to`. When that fails, the
/// hardware may already be at `rotate_to` because a prior attempt changed it and
/// crashed before recording success; [`RedfishClientPool::bmc_credentials_valid`]
/// confirms that without re-issuing a same-value (`new -> new`) change some BMCs
/// reject. Only when the rotate-TO value does *not* already authenticate is the
/// change treated as a genuine failure.
///
/// Returns an already-`to_string`-ed error (still to be redacted by the caller)
/// on a genuine device-level failure. Bounded to at most one failed login on the
/// recovery path, so it cannot trip BMC lockout.
async fn change_or_recover(
    redfish_pool: &dyn RedfishClientPool,
    bmc: &BmcRotationTarget,
    rotate_from: Credentials,
    rotate_to: Credentials,
) -> Result<CredentialConvergence, String> {
    let Credentials::UsernamePassword {
        password: new_password,
        ..
    } = &rotate_to;

    let change_err = match redfish_pool
        .set_bmc_root_password(
            &bmc.host,
            bmc.port,
            bmc.vendor,
            rotate_from,
            new_password.clone(),
        )
        .await
    {
        Ok(()) => return Ok(CredentialConvergence::Changed),
        Err(e) => e.to_string(),
    };

    // The change failed. If the rotate-TO value already authenticates, a prior
    // attempt changed the hardware before crashing and the device is at target;
    // converge without a same-value change. Otherwise surface the change error.
    match redfish_pool
        .bmc_credentials_valid(&bmc.host, bmc.port, rotate_to)
        .await
    {
        Ok(true) => Ok(CredentialConvergence::Recovered {
            change_error: change_err,
        }),
        Ok(false) => Err(change_err),
        Err(verify_err) => Err(format!(
            "{change_err}; rotate-to credential probe also failed: {verify_err}"
        )),
    }
}

/// Replace every non-empty secret in `message` with `REDACTED`. Defense in
/// depth on top of the Redfish layer's own redaction, so no password reaches a
/// log line or the `rotate_last_error_redacted` column.
fn redact(message: String, secrets: &[&str]) -> String {
    let mut message = message;
    for secret in secrets {
        if !secret.is_empty() {
            message = message.replace(secret, "REDACTED");
        }
    }
    message
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use carbide_redfish::libredfish::RedfishClientPool;
    use carbide_redfish::libredfish::test_support::RedfishSim;
    use carbide_secrets::credentials::{
        BmcCredentialType, CredentialKey, CredentialReader, CredentialWriter, Credentials,
    };
    use carbide_secrets::test_support::credentials::TestCredentialManager;
    use chrono::{Duration, Utc};
    use db::credential_rotation::{
        DeviceRotationStatus, device_rotation_status, increment_rotate_attempt,
        mark_device_rotating_to_version, record_device_converged, set_next_target_version,
    };
    use libredfish::model::service_root::RedfishVendor;
    use mac_address::MacAddress;
    use sqlx::PgPool;

    use super::{
        BMC, BmcRotationGate, BmcRotationTarget, CredentialConvergence, RotateOutcome,
        change_or_recover, needs_rotation, redact, rotate_bmc,
    };

    const TEST_MAC: &str = "02:00:00:00:00:01";

    fn test_mac() -> MacAddress {
        TEST_MAC.parse().unwrap()
    }

    fn creds(username: &str, password: &str) -> Credentials {
        Credentials::UsernamePassword {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    fn target() -> BmcRotationTarget {
        BmcRotationTarget {
            device_mac: test_mac(),
            host: "127.0.0.1".to_string(),
            port: Some(443),
            vendor: RedfishVendor::NvidiaGBx00,
        }
    }

    fn per_device_key() -> CredentialKey {
        CredentialKey::BmcCredentials {
            credential_type: BmcCredentialType::BmcRoot {
                bmc_mac_address: test_mac(),
            },
        }
    }

    fn rotate_to_key(version: u32) -> CredentialKey {
        CredentialKey::BmcCredentials {
            credential_type: BmcCredentialType::site_wide_root(version),
        }
    }

    /// Record the device as converged at the current target (0), then advance
    /// the site-wide BMC target `steps` times so the device lags by `steps`.
    async fn seed_device_behind_target(pool: &PgPool, steps: i32) {
        let mut conn = pool.acquire().await.unwrap();
        record_device_converged(&mut conn, test_mac(), BMC)
            .await
            .unwrap();
        for expected in 0..steps {
            set_next_target_version(&mut conn, BMC, expected, serde_json::json!({}))
                .await
                .unwrap()
                .expect("target must advance from the expected current version");
        }
    }

    async fn status_of(pool: &PgPool) -> DeviceRotationStatus {
        let mut conn = pool.acquire().await.unwrap();
        device_rotation_status(&mut conn, BMC, test_mac())
            .await
            .unwrap()
            .expect("device row must exist")
    }

    /// A [`RedfishSim`] modeling a BMC whose `root` account currently holds
    /// `password`, with authentication enforced and same-value password changes
    /// rejected -- the vendor behavior BMC rotation's crash recovery must
    /// accommodate. Rotation scenarios then emerge from the seeded hardware
    /// password: a change authenticated with a stale credential fails, the
    /// rotate-TO value authenticates only once the hardware already carries it,
    /// and a re-issued same-value change is refused (so the engine is held to
    /// never issuing one).
    fn bmc_on_password(password: &str) -> RedfishSim {
        let sim = RedfishSim::default();
        sim.set_enforce_auth(true);
        sim.set_reject_password_reuse(true);
        sim.seed_user("root", password);
        sim
    }

    /// Whether the BMC currently authenticates with `password`.
    async fn bmc_accepts(sim: &RedfishSim, password: &str) -> bool {
        sim.bmc_credentials_valid("127.0.0.1", Some(443), creds("root", password))
            .await
            .expect("the credential probe must not raise a transport error")
    }

    #[tokio::test]
    async fn change_or_recover_changes_password_when_current_authenticates() {
        // The BMC is on "old"; the change to "new" authenticates and succeeds.
        let sim = bmc_on_password("old");

        let convergence =
            change_or_recover(&sim, &target(), creds("root", "old"), creds("root", "new"))
                .await
                .expect("the change should succeed");

        assert_eq!(
            convergence,
            CredentialConvergence::Changed,
            "a successful direct change must report Changed"
        );
        assert!(
            bmc_accepts(&sim, "new").await,
            "the change must leave the BMC on the rotate-to password"
        );
    }

    #[tokio::test]
    async fn change_or_recover_converges_when_hardware_already_on_rotate_to() {
        // The BMC is already on "new" (a prior attempt changed it before
        // crashing): the change authenticated with the stale "old" fails, but the
        // probe with "new" succeeds, so recovery converges -- and because the sim
        // rejects a same-value change, this can only pass by probing rather than
        // re-issuing the change.
        let sim = bmc_on_password("new");

        let convergence =
            change_or_recover(&sim, &target(), creds("root", "old"), creds("root", "new"))
                .await
                .expect("an already-converged BMC must be recovered");

        assert!(
            matches!(convergence, CredentialConvergence::Recovered { .. }),
            "an already-at-target BMC must report Recovered, got {convergence:?}"
        );
    }

    #[tokio::test]
    async fn change_or_recover_fails_when_neither_credential_authenticates() {
        // The BMC is on some third password, so neither the change (with "old")
        // nor the probe (with "new") authenticates: the change error is surfaced.
        let sim = bmc_on_password("mystery");

        change_or_recover(&sim, &target(), creds("root", "old"), creds("root", "new"))
            .await
            .expect_err("neither credential authenticating must surface an error");
    }

    #[tokio::test]
    async fn change_or_recover_surfaces_both_errors_when_the_probe_also_fails() {
        // The change fails and the recovery probe itself errors with a transport
        // fault (not a clean rejection): both failures are surfaced so the
        // recorded reason makes clear convergence could not even be confirmed.
        let sim = bmc_on_password("mystery");
        sim.set_change_password_error("change boom");
        sim.set_get_accounts_error(true);

        let err = change_or_recover(&sim, &target(), creds("root", "old"), creds("root", "new"))
            .await
            .expect_err("a failed change plus a failed probe must surface an error");

        assert!(
            err.contains("probe also failed"),
            "both the change and probe failures must be surfaced: {err}"
        );
    }

    #[test]
    fn needs_rotation_only_when_behind_and_not_quarantined() {
        let mut status = DeviceRotationStatus {
            target_version: 1,
            started_at: Utc::now(),
            device_mac: TEST_MAC.to_string(),
            current_version: Some(0),
            rotating_to_version: None,
            converged: false,
            quarantined: false,
            quarantined_until: None,
            rotate_attempts: 0,
            rotate_last_attempt_at: None,
            rotate_last_error_redacted: None,
        };
        assert!(needs_rotation(&status), "behind target and not quarantined");

        status.quarantined = true;
        assert!(!needs_rotation(&status), "quarantined is left alone");

        status.quarantined = false;
        status.converged = true;
        assert!(!needs_rotation(&status), "converged is left alone");
    }

    #[test]
    fn redact_replaces_every_nonempty_secret_and_skips_empty() {
        // Defense in depth: every non-empty secret is masked (an empty needle is
        // skipped, never matching the whole string) so no password fragment can
        // survive into a log line or the recorded error.
        let masked = redact(
            "login user=root current=swordfish new=hunter2".to_string(),
            &["swordfish", "hunter2", ""],
        );

        assert_eq!(masked, "login user=root current=REDACTED new=REDACTED");
        assert!(
            !masked.contains("swordfish") && !masked.contains("hunter2"),
            "no secret may survive redaction: {masked}"
        );
    }

    #[carbide_macros::sqlx_test]
    async fn rotate_bmc_converges_and_persists_new_secret(pool: PgPool) {
        seed_device_behind_target(&pool, 1).await;
        let cm = TestCredentialManager::default();
        cm.set_credentials(&per_device_key(), &creds("root", "old"))
            .await
            .unwrap();
        cm.set_credentials(&rotate_to_key(1), &creds("root", "new"))
            .await
            .unwrap();
        // The BMC is on the per-device secret ("old"), so the change succeeds.
        let redfish = bmc_on_password("old");

        let outcome = rotate_bmc(&pool, &cm, &redfish, &target())
            .await
            .expect("rotation must not raise a transient engine error");

        assert_eq!(outcome, RotateOutcome::Converged);
        let status = status_of(&pool).await;
        assert!(status.converged, "device must be recorded converged");
        assert_eq!(status.current_version, Some(1));
        assert_eq!(
            status.rotating_to_version, None,
            "the crash marker must be cleared on promotion"
        );
        // The per-device secret was rewritten to the rotate-TO password so
        // future logins (and the next rotation's "current") use it.
        let persisted = cm
            .get_credentials(&per_device_key())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(persisted, creds("root", "new"));
        // The hardware now authenticates with the rotate-TO password.
        assert!(
            bmc_accepts(&redfish, "new").await,
            "the BMC must now be on the rotate-TO password"
        );
    }

    #[carbide_macros::sqlx_test]
    async fn rotate_bmc_recovers_when_hardware_already_changed_before_crash(pool: PgPool) {
        // Models a crash after the hardware password changed but before the
        // per-device secret was persisted: the stored "current" is stale
        // ("old"), and only the rotate-TO value ("new") authenticates.
        seed_device_behind_target(&pool, 1).await;
        let cm = TestCredentialManager::default();
        cm.set_credentials(&per_device_key(), &creds("root", "old"))
            .await
            .unwrap();
        cm.set_credentials(&rotate_to_key(1), &creds("root", "new"))
            .await
            .unwrap();
        // The hardware is already on "new" while the stored secret is stale
        // ("old"): the change authenticated with "old" fails, the probe with
        // "new" succeeds, and recovery converges. The sim's same-value rejection
        // means this can only pass by probing, not by re-issuing the change.
        let redfish = bmc_on_password("new");

        let outcome = rotate_bmc(&pool, &cm, &redfish, &target()).await.unwrap();

        assert_eq!(outcome, RotateOutcome::Converged);
        assert_eq!(status_of(&pool).await.current_version, Some(1));
        assert_eq!(
            cm.get_credentials(&per_device_key())
                .await
                .unwrap()
                .unwrap(),
            creds("root", "new"),
        );
    }

    #[carbide_macros::sqlx_test]
    async fn rotate_bmc_quarantines_with_backoff_and_redacted_error(pool: PgPool) {
        seed_device_behind_target(&pool, 1).await;
        let cm = TestCredentialManager::default();
        cm.set_credentials(&per_device_key(), &creds("root", "old"))
            .await
            .unwrap();
        cm.set_credentials(&rotate_to_key(1), &creds("root", "topsecret"))
            .await
            .unwrap();
        // The BMC is on some other password and the change fails carrying the
        // rotate-TO password (so we can assert it never lands in the recorded
        // error); the rotate-TO value does not authenticate either, so the device
        // is quarantined. Redaction is exercised end to end: the redfish layer
        // and the engine both strip the password before it is recorded.
        let redfish = bmc_on_password("mystery");
        redfish.set_change_password_error("BMC rejected login with password=topsecret");

        let before = Utc::now();
        let outcome = rotate_bmc(&pool, &cm, &redfish, &target()).await.unwrap();

        let until = match outcome {
            RotateOutcome::Quarantined { until } => until,
            other => panic!("expected Quarantined, got {other:?}"),
        };
        // First failure: backoff is the base window (60s) from "now".
        assert!(until >= before + Duration::seconds(60));
        assert!(until <= Utc::now() + Duration::seconds(61));

        let status = status_of(&pool).await;
        assert!(status.quarantined, "device must be in a backoff window");
        assert!(!status.converged);
        assert_eq!(status.rotate_attempts, 1);
        let recorded = status
            .rotate_last_error_redacted
            .expect("a failure must record a redacted error");
        assert!(
            !recorded.contains("topsecret"),
            "the password must never reach the error column, got: {recorded}"
        );
        assert!(recorded.contains("REDACTED"));
        // A failed attempt must not advance the convergence marker.
        assert_eq!(status.current_version, Some(0));
    }

    #[carbide_macros::sqlx_test]
    async fn rotate_bmc_reports_converged_row_without_touching_hardware(pool: PgPool) {
        // A device already at the target (converged marker, current == target) is
        // a no-op: rotate_bmc returns Converged straight from the row without
        // resolving credentials or contacting the BMC. This is the idempotency
        // guarantee the controller relies on when it re-ticks a converged device.
        seed_device_behind_target(&pool, 0).await;
        let cm = TestCredentialManager::default();
        let redfish = bmc_on_password("old");

        let outcome = rotate_bmc(&pool, &cm, &redfish, &target()).await.unwrap();

        assert_eq!(outcome, RotateOutcome::Converged);
        assert!(
            redfish.create_client_calls().is_empty(),
            "an already-converged device must not touch hardware"
        );
    }

    #[carbide_macros::sqlx_test]
    async fn rotate_bmc_quarantines_when_rotate_to_secret_is_not_staged(pool: PgPool) {
        // The site-wide target advanced but the rotate-TO secret was never written
        // to the store (a staging bug): the device quarantines with a clear,
        // secret-free reason, and the BMC is never contacted because the missing
        // secret is caught before any change is issued.
        seed_device_behind_target(&pool, 1).await;
        let cm = TestCredentialManager::default();
        cm.set_credentials(&per_device_key(), &creds("root", "old"))
            .await
            .unwrap();
        // rotate_to_key(1) is intentionally left unstaged.
        let redfish = bmc_on_password("old");

        let outcome = rotate_bmc(&pool, &cm, &redfish, &target()).await.unwrap();

        assert!(matches!(outcome, RotateOutcome::Quarantined { .. }));
        let recorded = status_of(&pool)
            .await
            .rotate_last_error_redacted
            .expect("a failure must record a reason");
        assert!(
            recorded.contains("not staged"),
            "the reason must name the missing rotate-to secret: {recorded}"
        );
        assert!(
            redfish.create_client_calls().is_empty(),
            "a missing rotate-to secret must be caught before touching hardware"
        );
    }

    #[carbide_macros::sqlx_test]
    async fn rotate_bmc_reports_no_work_without_a_rotation_row(pool: PgPool) {
        // No `device_credential_rotation` row was seeded for this MAC.
        let cm = TestCredentialManager::default();
        let redfish = bmc_on_password("old");

        let outcome = rotate_bmc(&pool, &cm, &redfish, &target()).await.unwrap();

        assert_eq!(outcome, RotateOutcome::NoWork);
        assert!(
            redfish.create_client_calls().is_empty(),
            "an orphaned device must not touch hardware"
        );
    }

    #[carbide_macros::sqlx_test]
    async fn rotate_bmc_skips_a_quarantined_device(pool: PgPool) {
        seed_device_behind_target(&pool, 1).await;
        // Plant a future backoff window directly.
        let mut conn = pool.acquire().await.unwrap();
        increment_rotate_attempt(
            &mut conn,
            test_mac(),
            BMC,
            "earlier failure",
            Utc::now() + Duration::seconds(3600),
        )
        .await
        .unwrap();
        drop(conn);
        let cm = TestCredentialManager::default();
        let redfish = bmc_on_password("old");

        let outcome = rotate_bmc(&pool, &cm, &redfish, &target()).await.unwrap();

        assert!(matches!(outcome, RotateOutcome::Quarantined { .. }));
        assert!(
            redfish.create_client_calls().is_empty(),
            "a quarantined device must not be retried before its window passes"
        );
        // The marker is untouched (still behind target, not converged).
        assert_eq!(status_of(&pool).await.current_version, Some(0));
    }

    #[carbide_macros::sqlx_test]
    async fn rotate_bmc_converges_to_the_latest_target_when_superseded(pool: PgPool) {
        // The device lags by two versions: a rotation that began toward v1 must
        // converge to the live target (v2), not the stale intermediate.
        seed_device_behind_target(&pool, 2).await;
        // Simulate a prior crashed attempt that staged the (now stale) v1 marker.
        let mut conn = pool.acquire().await.unwrap();
        mark_device_rotating_to_version(&mut conn, test_mac(), BMC, 1)
            .await
            .unwrap();
        drop(conn);
        let cm = TestCredentialManager::default();
        cm.set_credentials(&per_device_key(), &creds("root", "old"))
            .await
            .unwrap();
        cm.set_credentials(&rotate_to_key(2), &creds("root", "newest"))
            .await
            .unwrap();
        let redfish = bmc_on_password("old");

        let outcome = rotate_bmc(&pool, &cm, &redfish, &target()).await.unwrap();

        assert_eq!(outcome, RotateOutcome::Converged);
        let status = status_of(&pool).await;
        assert_eq!(
            status.current_version,
            Some(2),
            "must converge to the live target, superseding the stale v1 marker"
        );
        assert!(status.converged);
        assert_eq!(
            cm.get_credentials(&per_device_key())
                .await
                .unwrap()
                .unwrap(),
            creds("root", "newest"),
        );
    }

    #[carbide_macros::sqlx_test]
    async fn rotation_gate_caches_aggregate_and_gates_per_device(pool: PgPool) {
        // Nothing staged yet (bmc seeded at target 0): the gate reports no work
        // without a per-device query.
        let gate = BmcRotationGate::new();
        assert!(
            !gate.rotation_pending(&pool).await.unwrap(),
            "target 0 baseline is not work"
        );
        assert!(
            !gate.bmc_rotation_needed(&pool, test_mac()).await.unwrap(),
            "no work means the per-device guard is false"
        );

        // Stage a rotation the device lags. A long-TTL gate still returns the
        // cached (stale) `false` -- proving it does not re-query every call.
        seed_device_behind_target(&pool, 1).await;
        assert!(
            !gate.rotation_pending(&pool).await.unwrap(),
            "a fresh cache must not observe the newly staged target yet"
        );

        // A zero-TTL gate always re-queries, so it observes the staged work and
        // the per-device guard now fires.
        let fresh = BmcRotationGate::with_ttl(StdDuration::ZERO);
        assert!(fresh.rotation_pending(&pool).await.unwrap());
        assert!(
            fresh.bmc_rotation_needed(&pool, test_mac()).await.unwrap(),
            "a lagging device under a live target needs rotation"
        );
        // An unknown device has no row, so the guard is false even when work is
        // pending site-wide.
        let unknown: MacAddress = "02:00:00:00:00:ff".parse().unwrap();
        assert!(!fresh.bmc_rotation_needed(&pool, unknown).await.unwrap());
    }
}
