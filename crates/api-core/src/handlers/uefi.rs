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
use ::rpc::forge as rpc;
use carbide_secrets::credentials::{CredentialKey, CredentialReader, Credentials};
use db::WithTransaction;
use futures_util::FutureExt;
use model::machine::LoadSnapshotOptions;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

/// The current site-wide host UEFI target version a device should be driven to,
/// from `sitewide_credential_rotation.target_version`. A stored `target_version`
/// of 0 is the legacy unversioned site-default baseline; a *missing* row is an
/// error, since the backfill migration seeds a `host_uefi` row on every site.
/// This is the table-driven "current site-wide host UEFI credential" resolution
/// used when *setting* the password.
async fn host_uefi_target_version(conn: &mut sqlx::PgConnection) -> Result<u32, db::DatabaseError> {
    let version = db::credential_rotation::current_target_version(
        conn,
        db::credential_rotation::CredentialRotationType::HostUefi,
    )
    .await?
    .ok_or_else(|| db::DatabaseError::Internal {
        message: "no site-wide host_uefi rotation target row exists; the backfill migration \
                  seeds one for every active credential type, so a missing row indicates a \
                  broken or unmigrated database"
            .to_string(),
    })?;
    // The column is constrained non-negative, so a failed conversion means a
    // corrupt value, not "no rotation" -- surface it rather than masking it.
    u32::try_from(version).map_err(|e| db::DatabaseError::Internal {
        message: format!("host UEFI target_version {version} is out of range for u32: {e}"),
    })
}

/// The host UEFI version a device currently carries, for authenticating against
/// its existing password when clearing it. Returns the device's converged
/// `current_version` (which can lag the site target mid-rotation, once the UEFI
/// rotation engine exists), or the site target it was recorded against when
/// `current_version` is NULL.
///
/// The caller must have already confirmed the host's UEFI password is set: a
/// password-bearing host always has a `host_uefi` convergence row keyed by its
/// BMC MAC, because NICo writes that row in the same transaction that stamps
/// `bios_password_set_time` (see `set_host_uefi_password`), and the backfill
/// seeded one for every pre-existing host with a password. A missing row is
/// therefore a broken invariant -- error rather than guessing the site target
/// and authenticating with the wrong password.
async fn host_uefi_device_version(
    conn: &mut sqlx::PgConnection,
    bmc_mac: mac_address::MacAddress,
) -> Result<u32, db::DatabaseError> {
    let status = db::credential_rotation::device_rotation_status(
        &mut *conn,
        db::credential_rotation::CredentialRotationType::HostUefi,
        bmc_mac,
    )
    .await?
    .ok_or_else(|| db::DatabaseError::Internal {
        message: format!(
            "no host_uefi device_credential_rotation row for BMC MAC {bmc_mac}, but the host's \
             UEFI password is set; convergence is recorded alongside bios_password_set_time, so a \
             missing row indicates broken rotation bookkeeping or an unmigrated database"
        ),
    })?;
    let version = status.current_version.unwrap_or(status.target_version);
    u32::try_from(version).map_err(|e| db::DatabaseError::Internal {
        message: format!("host UEFI device version {version} is out of range for u32: {e}"),
    })
}

/// Read the host UEFI credential at `key`, mapping a store error or a missing
/// secret to a `CarbideError`. Used to resolve the password the low-level
/// `redfish` UEFI calls apply (they no longer read the store themselves).
async fn read_uefi_credentials(
    reader: &dyn CredentialReader,
    key: &CredentialKey,
) -> Result<Credentials, CarbideError> {
    reader
        .get_credentials(key)
        .await
        .map_err(|e| {
            CarbideError::internal(format!(
                "failed to read UEFI credential {}: {e}",
                key.to_key_str()
            ))
        })?
        .ok_or_else(|| {
            CarbideError::internal(format!("UEFI credential {} is not set", key.to_key_str()))
        })
}

/// Resolve the site-wide host UEFI credential to *set* on a device: the secret
/// at the current `host_uefi` target version (table-driven; v0 = the legacy
/// unversioned site-default).
pub(crate) async fn host_uefi_set_credentials(
    conn: &mut sqlx::PgConnection,
    reader: &dyn CredentialReader,
) -> Result<Credentials, CarbideError> {
    let version = host_uefi_target_version(conn).await.map_err(|e| {
        CarbideError::internal(format!("failed to read host UEFI target version: {e}"))
    })?;
    read_uefi_credentials(reader, &CredentialKey::host_uefi_site_default(version)).await
}

/// Resolve the host UEFI credential a device currently carries, to authenticate
/// a *clear* against its existing password (the device's converged version; see
/// [`host_uefi_device_version`]).
pub(crate) async fn host_uefi_clear_credentials(
    conn: &mut sqlx::PgConnection,
    reader: &dyn CredentialReader,
    bmc_mac: mac_address::MacAddress,
) -> Result<Credentials, CarbideError> {
    let version = host_uefi_device_version(conn, bmc_mac).await.map_err(|e| {
        CarbideError::internal(format!("failed to read host UEFI device version: {e}"))
    })?;
    read_uefi_credentials(reader, &CredentialKey::host_uefi_site_default(version)).await
}

pub(crate) async fn clear_host_uefi_password(
    api: &Api,
    request: Request<rpc::ClearHostUefiPasswordRequest>,
) -> Result<Response<rpc::ClearHostUefiPasswordResponse>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let request = request.into_inner();

    // https://github.com/NVIDIA/carbide-core/issues/116
    // Resolve machine_id from machine_query first (preferred),
    // otherwise fall back to the host_id (now deprecated).
    let machine_id = if let Some(query) = request.machine_query {
        match db::machine::find_by_query(&mut txn, &query).await? {
            Some(machine) => {
                log_machine_id(&machine.id);
                machine.id
            }
            None => {
                return Err(CarbideError::NotFoundError {
                    kind: "machine",
                    id: query,
                }
                .into());
            }
        }
    } else {
        // Old logic that used to assume machine ID only. If you
        // use anything other than a machine ID here it's going
        // to yell (e.g. old carbide-admin-cli).
        convert_and_log_machine_id(request.host_id.as_ref())?
    };

    if !machine_id.machine_type().is_host() {
        return Err(CarbideError::InvalidArgument(
            "carbide only supports clearing the UEFI password on discovered hosts".into(),
        )
        .into());
    }

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &machine_id,
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: api.runtime_config.host_health,
        },
    )
    .await?
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    // If we have no record of a UEFI password ever being set on this host,
    // there is nothing to clear. Issuing the redfish ChangePassword call in
    // that case fails on the BMC with a confusing 400 (the OldPassword we
    // send doesn't match the empty value the BMC expects), so short-circuit
    // with a warning and a successful no-op response instead of surfacing an
    // internal error to the operator.
    if snapshot.host_snapshot.bios_password_set_time.is_none() {
        txn.commit().await?;
        tracing::warn!(
            %machine_id,
            "No UEFI password is recorded as set on this host; nothing to clear"
        );
        return Ok(Response::new(rpc::ClearHostUefiPasswordResponse {
            job_id: None,
        }));
    }

    let addr = snapshot.host_snapshot.bmc_addr().ok_or_else(|| {
        CarbideError::InvalidArgument("specified machine does not have BMC address".into())
    })?;

    // Clearing must authenticate with the password the device currently carries,
    // which is resolved per-device by BMC MAC. Without the MAC we cannot pick the
    // right credential, so fail rather than guess the site default and present a
    // wrong password to the BMC.
    let bmc_mac = snapshot.host_snapshot.bmc_info.mac.ok_or_else(|| {
        CarbideError::InvalidArgument(
            "specified machine does not have a known BMC MAC address".into(),
        )
    })?;

    let bmc_access_info =
        db::machine_interface::lookup_bmc_access_info(&mut txn, addr.ip(), Some(addr.port()))
            .await?;

    // Resolve the credential the device currently carries so the clear
    // authenticates with the right password (table-driven; see
    // `host_uefi_clear_credentials`). Done before the commit while the txn is
    // open.
    let clear_credentials =
        host_uefi_clear_credentials(&mut txn, api.redfish_pool.credential_reader(), bmc_mac)
            .await?;

    // Don't hold the transaction across an await point
    txn.commit().await?;

    let redfish_client = api
        .redfish_pool
        .client_by_info(&bmc_access_info)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "unable to create redfish client",
            );
            CarbideError::Internal {
                message: format!(
                    "Could not create connection to Redfish API to {machine_id}, check logs"
                ),
            }
        })?;

    let job_id: Option<String> = api
        .redfish_pool
        .clear_host_uefi_password(redfish_client.as_ref(), clear_credentials)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to run clear_host_uefi_password call");
            CarbideError::internal(format!(
                "failed redfish clear_host_uefi_password subtask: {e}"
            ))
        })?;

    Ok(Response::new(rpc::ClearHostUefiPasswordResponse { job_id }))
}

pub(crate) async fn set_host_uefi_password(
    api: &Api,
    request: Request<rpc::SetHostUefiPasswordRequest>,
) -> Result<Response<rpc::SetHostUefiPasswordResponse>, Status> {
    log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let request = request.into_inner();

    // https://github.com/NVIDIA/carbide-core/issues/116
    // Resolve machine_id from machine_query first (preferred),
    // otherwise fall back to the host_id (now deprecated).
    let machine_id = if let Some(query) = request.machine_query {
        match db::machine::find_by_query(&mut txn, &query).await? {
            Some(machine) => {
                log_machine_id(&machine.id);
                machine.id
            }
            None => {
                return Err(CarbideError::NotFoundError {
                    kind: "machine",
                    id: query,
                }
                .into());
            }
        }
    } else {
        // Old logic that used to assume machine ID only. If you
        // use anything other than a machine ID here it's going
        // to yell (e.g. old carbide-admin-cli).
        convert_and_log_machine_id(request.host_id.as_ref())?
    };

    if !machine_id.machine_type().is_host() {
        return Err(CarbideError::InvalidArgument(
            "carbide only supports setting the UEFI password on discovered hosts".into(),
        )
        .into());
    }

    let snapshot = db::managed_host::load_snapshot(
        &mut txn,
        &machine_id,
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: api.runtime_config.host_health,
        },
    )
    .await?
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    let addr = snapshot.host_snapshot.bmc_addr().ok_or_else(|| {
        CarbideError::InvalidArgument("specified machine does not have BMC address".into())
    })?;

    // A known BMC MAC is a hard precondition for setting the UEFI password: it
    // keys the host_uefi rotation bookkeeping recorded below, so reject the
    // request up front rather than driving the device and only then discovering
    // we cannot track its convergence.
    let host_bmc_mac = snapshot.host_snapshot.bmc_info.mac.ok_or_else(|| {
        CarbideError::InvalidArgument(
            "specified machine does not have a known BMC MAC address".into(),
        )
    })?;

    let bmc_access_info =
        db::machine_interface::lookup_bmc_access_info(&mut txn, addr.ip(), Some(addr.port()))
            .await?;

    // Resolve the site-wide host UEFI credential to set (table-driven; v0 = the
    // legacy unversioned site-default). Resolved before the commit.
    let host_uefi_credentials =
        host_uefi_set_credentials(&mut txn, api.redfish_pool.credential_reader()).await?;

    // Let txn drop so we don't hold it across a redfish request
    txn.commit().await?;

    let redfish_client = api
        .redfish_pool
        .client_by_info(&bmc_access_info)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "unable to create redfish client",
            );
            CarbideError::RedfishClientCreation {
                inner: e.into(),
                machine_id,
            }
        })?;

    let job_id = api
        .redfish_pool
        .uefi_setup(redfish_client.as_ref(), false, host_uefi_credentials)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to run uefi_setup call");
            CarbideError::internal(format!("failed redfish uefi_setup subtask: {e}"))
        })?;
    // uefi_setup returns a BMC job_id; the password change completes
    // asynchronously on the device and we do not poll it here. We optimistically
    // stamp bios_password_set_time and, in the same transaction, record host_uefi
    // convergence (keyed by the host BMC MAC, mirroring the backfill) so the two
    // always agree -- convergence rides along with the pre-existing marker. If
    // the dispatched job ultimately fails on the BMC, both are inaccurate.
    //
    // TODO(credential-rotation): gate both the bios_password_set_time stamp and
    // the host_uefi convergence record on confirmed job_id completion (poll the
    // BMC job rather than trusting dispatch). Whatever confirms completion should
    // perform both updates together -- convergence does not need its own separate
    // write path or operator-facing API; it follows bios_password_set_time.
    api.with_txn(|txn| {
        async move {
            db::machine::update_bios_password_set_time(&machine_id, txn).await?;
            db::credential_rotation::record_device_converged(
                txn,
                host_bmc_mac,
                db::credential_rotation::CredentialRotationType::HostUefi,
            )
            .await?;
            Ok::<(), db::DatabaseError>(())
        }
        .boxed()
    })
    .await?
    .map_err(|e| {
        tracing::error!(
            error = %e,
            "Failed to update bios_password_set_time",
        );
        CarbideError::Internal {
            message: format!("Failed to update BIOS password timestamp: {e}"),
        }
    })?;

    Ok(Response::new(rpc::SetHostUefiPasswordResponse { job_id }))
}
