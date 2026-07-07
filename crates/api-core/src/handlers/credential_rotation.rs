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

//! `RotateCredential` / `GetCredentialRotationStatus` handlers.
//!
//! `RotateCredential` *stages* a site-wide rotation: it writes the rotate-TO
//! secret at the next version and then publishes the new `target_version` with a
//! compare-and-set. The current site-wide credential is defined by
//! `sitewide_credential_rotation.target_version` -- consumers resolve the live
//! version from that table rather than from a fixed unversioned path -- so the
//! CAS bump is what makes the new version current (table-driven contract). This
//! holds for every family (BMC, Host/DPU UEFI, lockdown IKM); a rotation never
//! writes an unversioned alias. It does **not** converge existing devices --
//! that is the rotation engine's job (a later change) -- so immediately after a
//! rotate every device reads as "pending" until the engine lands.
//! `GetCredentialRotationStatus` reports that convergence.
//!
//! NVOS is rejected for now: NICo does not own the NVOS password until REQ-6
//! (set-NVOS-from-factory), so there is no baseline to rotate from and the
//! backfill deliberately seeds no `nvos` target row.

use ::rpc::forge as rpc;
use carbide_authn::middleware::Principal;
use carbide_secrets::credentials::{BmcCredentialType, CredentialKey, Credentials, NicLockdownIkm};
use mac_address::MacAddress;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::Api;

type RotationType = db::credential_rotation::CredentialRotationType;

/// Narrows a non-negative DB `integer` to the proto `uint32`, surfacing the
/// (impossible, given the column CHECKs) negative/overflow case as an internal
/// error rather than silently wrapping.
fn to_u32(value: i32, what: &str) -> Result<u32, CarbideError> {
    u32::try_from(value)
        .map_err(|e| CarbideError::internal(format!("{what} {value} is not representable: {e}")))
}

/// [`to_u32`] lifted over an optional column.
fn opt_to_u32(value: Option<i32>, what: &str) -> Result<Option<u32>, CarbideError> {
    value.map(|v| to_u32(v, what)).transpose()
}

/// Non-secret identifiers of the authenticated caller, for the rotation audit
/// record. Returns the empty list when no `AuthContext` is attached (e.g. a test
/// harness that bypasses the auth middleware); the rotation still proceeds since
/// authorization is enforced upstream -- this only enriches `request_meta`.
fn initiator_identifiers<T>(request: &Request<T>) -> Vec<String> {
    request
        .extensions()
        .get::<crate::auth::AuthContext>()
        .map(|ctx| {
            ctx.principals
                .iter()
                .map(Principal::as_identifier)
                .collect()
        })
        .unwrap_or_default()
}

/// Maps the proto rotation family onto the DB enum, rejecting `nvos` (not yet
/// managed; see the module docs) and an unknown wire value.
fn to_rotation_type(credential_type: i32) -> Result<RotationType, CarbideError> {
    let parsed = rpc::RotationCredentialType::try_from(credential_type).map_err(|_| {
        CarbideError::NotFoundError {
            kind: "rotation_credential_type",
            id: credential_type.to_string(),
        }
    })?;
    match parsed {
        rpc::RotationCredentialType::RotationBmc => Ok(RotationType::Bmc),
        rpc::RotationCredentialType::RotationHostUefi => Ok(RotationType::HostUefi),
        rpc::RotationCredentialType::RotationDpuUefi => Ok(RotationType::DpuUefi),
        rpc::RotationCredentialType::RotationLockdownIkm => Ok(RotationType::LockdownIkm),
        rpc::RotationCredentialType::RotationNvos => Err(CarbideError::FailedPrecondition(
            "NVOS rotation is not supported yet: NICo does not own the NVOS password until \
             set-NVOS-from-factory (REQ-6) ships"
                .to_string(),
        )),
        // The proto3 zero value. Rejected rather than defaulted so a caller that
        // omits the family never silently rotates BMC (the most sensitive one).
        rpc::RotationCredentialType::Unspecified => Err(CarbideError::InvalidArgument(
            "credential_type must be set to a specific rotation family".to_string(),
        )),
    }
}

/// The immutable, version-addressed key a rotation writes for a family
/// (`.../v{N}`): the rotation stages version N's secret here and consumers read
/// it back by version. Which version is "current" is resolved from
/// `sitewide_credential_rotation.target_version`, not from any fixed path -- the
/// table-driven contract. Every family is fully table-driven (BMC, Host/DPU
/// UEFI, lockdown IKM): a rotation only writes the versioned secret and bumps
/// the target, never an unversioned alias. Consumers resolve the live key via
/// the per-family helpers ([`BmcCredentialType::site_wide_root`],
/// [`CredentialKey::host_uefi_site_default`], [`CredentialKey::dpu_uefi_site_default`]).
fn versioned_rotation_key(rotation_type: RotationType, version: u32) -> CredentialKey {
    match rotation_type {
        RotationType::Bmc => CredentialKey::BmcCredentials {
            credential_type: BmcCredentialType::SiteWideRootVersioned { version },
        },
        RotationType::HostUefi => CredentialKey::HostUefiSiteVersioned { version },
        RotationType::DpuUefi => CredentialKey::DpuUefiSiteVersioned { version },
        RotationType::LockdownIkm => CredentialKey::NicLockdownIkm {
            credential_type: NicLockdownIkm::SiteWide { version },
        },
        // nvos is rejected in `to_rotation_type` before we ever build keys.
        RotationType::Nvos => unreachable!("nvos is rejected before key construction"),
    }
}

pub(crate) async fn rotate_credential(
    api: &Api,
    request: Request<rpc::RotateCredentialRequest>,
) -> Result<Response<rpc::RotateCredentialResult>, Status> {
    // Do not log_request_data: the request may carry an operator-supplied password.
    // Capture the caller identity for the audit record before consuming the
    // request (the extensions, including the AuthContext, live on the envelope).
    let initiator = initiator_identifiers(&request);
    let req = request.into_inner();
    let rotation_type = to_rotation_type(req.credential_type)?;

    // Resolve the rotate-TO password: an operator-supplied password is validated
    // against the same policy the generator guarantees; otherwise we
    // auto-generate one.
    let operator_supplied_password = req.password.is_some();
    let password = match req.password {
        Some(password) => {
            Credentials::validate_password_strength(&password)
                .map_err(|e| CarbideError::InvalidArgument(e.to_string()))?;
            password
        }
        None => Credentials::generate_password(),
    };
    let new_credentials = Credentials::UsernamePassword {
        // Site-wide credentials carry no username (matches the set-from-factory
        // handlers in `credential.rs`).
        username: String::new(),
        password,
    };

    // Read the current target so we know the version to stage at (current + 1).
    // Every supported type has a backfilled target row.
    let mut txn = api.txn_begin().await?;
    let current = db::credential_rotation::current_target_version(&mut txn, rotation_type).await?;
    txn.commit().await?;
    let current = current.ok_or_else(|| {
        CarbideError::FailedPrecondition(format!(
            "no site-wide rotation target exists for {rotation_type:?}"
        ))
    })?;
    let next_version = u32::try_from(current + 1).map_err(|e| {
        CarbideError::internal(format!(
            "rotation target version {current} + 1 overflows: {e}"
        ))
    })?;

    let versioned_credential = versioned_rotation_key(rotation_type, next_version);

    // Crash-safe ordering: write the immutable versioned rotate-TO secret
    // (`.../v{N}`) first, then publish the new target via CAS. Publishing the
    // target last means a device ingested mid-rotation is never recorded as
    // converged to a version whose versioned secret is not already in place. The
    // model is fully table-driven: consumers resolve the live version from
    // `target_version`, so the CAS bump alone makes the new version current --
    // there is no unversioned alias to republish.
    stage_versioned_secret(
        api,
        &versioned_credential,
        &new_credentials,
        operator_supplied_password,
        next_version,
    )
    .await?;

    // Publish the new target with a compare-and-set against the version we read.
    // `None` means another rotation advanced the target first; surface that as a
    // precondition failure so the operator re-checks status and retries rather
    // than assume this rotation took effect.
    let request_meta = serde_json::json!({ "reason": req.reason, "initiator": initiator });
    let mut txn = api.txn_begin().await?;
    let staged = db::credential_rotation::set_next_target_version(
        &mut txn,
        rotation_type,
        current,
        request_meta,
    )
    .await?;
    let staged = staged.ok_or_else(|| {
        CarbideError::ConcurrentModificationError(
            "credential rotation",
            format!(
                "the site-wide target for {rotation_type:?} advanced past version {current} \
                 during this rotation"
            ),
        )
    })?;
    txn.commit().await?;

    Ok(Response::new(rpc::RotateCredentialResult {
        credential_type: req.credential_type,
        target_version: u32::try_from(staged.target_version).map_err(|e| {
            CarbideError::internal(format!(
                "staged target version {} is not representable: {e}",
                staged.target_version
            ))
        })?,
        started_at: Some(staged.started_at.into()),
    }))
}

/// Writes the rotate-TO secret at its versioned path, returning the value now
/// stored there.
///
/// `create_credentials` is create-only (write-once per version). A failure means
/// either the slot is already populated -- a concurrent rotation, or a prior
/// attempt that crashed after writing the secret but before publishing the
/// target -- or a genuine store error. We read the slot back to tell them apart
/// without relying on a typed error:
///
/// * slot populated, operator-supplied password matches (or auto-generated):
///   adopt the stored value so a retry idempotently completes the in-flight
///   rotation;
/// * slot populated, operator-supplied password differs: a different rotation
///   already claimed this version, so report a conflict;
/// * slot empty: the create failed for real.
async fn stage_versioned_secret(
    api: &Api,
    versioned_key: &CredentialKey,
    new_credentials: &Credentials,
    operator_supplied_password: bool,
    next_version: u32,
) -> Result<Credentials, CarbideError> {
    match api
        .credential_manager
        .create_credentials(versioned_key, new_credentials)
        .await
    {
        Ok(()) => Ok(new_credentials.clone()),
        Err(create_err) => match api.credential_manager.get_credentials(versioned_key).await {
            Ok(Some(existing)) => {
                if operator_supplied_password && existing != *new_credentials {
                    Err(CarbideError::ConcurrentModificationError(
                        "credential rotation",
                        format!(
                            "rotate-to version {next_version} is already staged with a \
                             different password"
                        ),
                    ))
                } else {
                    Ok(existing)
                }
            }
            _ => Err(CarbideError::internal(format!(
                "failed to stage the rotate-to secret at version {next_version}: {create_err:?}"
            ))),
        },
    }
}

pub(crate) async fn get_credential_rotation_status(
    api: &Api,
    request: Request<rpc::CredentialRotationStatusRequest>,
) -> Result<Response<rpc::CredentialRotationStatusResult>, Status> {
    crate::api::log_request_data(&request);
    let req = request.into_inner();
    let rotation_type = to_rotation_type(req.credential_type)?;

    // A device_mac scopes the report to a single device; otherwise report the
    // site-wide aggregate.
    if let Some(device_mac) = req.device_mac.as_deref() {
        return device_rotation_status_response(api, rotation_type, device_mac).await;
    }

    let mut txn = api.txn_begin().await?;
    let status = db::credential_rotation::rotation_status(&mut txn, rotation_type).await?;
    txn.commit().await?;

    Ok(Response::new(rpc::CredentialRotationStatusResult {
        target_version: to_u32(status.target_version, "target version")?,
        converged: status.converged.max(0) as u64,
        pending: status.pending.max(0) as u64,
        quarantined: status.quarantined.max(0) as u64,
        quarantined_device_macs: status.quarantined_device_macs,
        started_at: Some(status.started_at.into()),
        // Complete only when every device has reached the target. Quarantined
        // devices are behind the target (in backoff), so they must keep the
        // rotation from reading as complete -- otherwise an operator sees
        // "complete" while devices are still stuck on the old credential.
        complete: status.pending == 0 && status.quarantined == 0,
        device: None,
    }))
}

/// Reports convergence for a single device (matched by `device_mac`) instead of
/// the site-wide aggregate. The count fields describe just this one device (each
/// 0 or 1), and `device` carries the per-device detail. A MAC with no rotation
/// record is a `NotFound` rather than a fabricated "not established" status, so a
/// mistyped MAC is reported instead of silently looking pending.
async fn device_rotation_status_response(
    api: &Api,
    rotation_type: RotationType,
    device_mac: &str,
) -> Result<Response<rpc::CredentialRotationStatusResult>, Status> {
    // Map a malformed MAC to InvalidArgument (a client error); the blanket
    // `CarbideError::from` for a parse error would otherwise surface as Internal.
    let mac: MacAddress = device_mac.parse::<MacAddress>().map_err(|e| {
        CarbideError::InvalidArgument(format!(
            "device_mac '{device_mac}' is not a valid MAC address: {e}"
        ))
    })?;

    let mut txn = api.txn_begin().await?;
    let status =
        db::credential_rotation::device_rotation_status(&mut txn, rotation_type, mac).await?;
    txn.commit().await?;

    let status = status.ok_or(CarbideError::NotFoundError {
        kind: "device_credential_rotation",
        id: device_mac.to_string(),
    })?;

    // The queried set is exactly one device, so the aggregate counts collapse to
    // 0/1 and stay consistent with the site-wide definitions (a device is pending
    // only when it is neither converged nor quarantined).
    let pending = !status.converged && !status.quarantined;
    let quarantined_device_macs = if status.quarantined {
        vec![status.device_mac.clone()]
    } else {
        Vec::new()
    };

    let device = rpc::DeviceCredentialRotationStatus {
        device_mac: status.device_mac,
        current_version: opt_to_u32(status.current_version, "current version")?,
        rotating_to_version: opt_to_u32(status.rotating_to_version, "rotating-to version")?,
        converged: status.converged,
        quarantined: status.quarantined,
        quarantined_until: status.quarantined_until.map(Into::into),
        rotate_attempts: to_u32(status.rotate_attempts, "rotate attempts")?,
        last_attempt_at: status.rotate_last_attempt_at.map(Into::into),
        last_error: status.rotate_last_error_redacted,
    };

    Ok(Response::new(rpc::CredentialRotationStatusResult {
        target_version: to_u32(status.target_version, "target version")?,
        converged: u64::from(status.converged),
        pending: u64::from(pending),
        quarantined: u64::from(status.quarantined),
        quarantined_device_macs,
        started_at: Some(status.started_at.into()),
        complete: status.converged && !status.quarantined,
        device: Some(device),
    }))
}
