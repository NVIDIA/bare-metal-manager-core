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
use carbide_secrets::credentials::{CredentialKey, CredentialManager};
use carbide_uuid::machine::MachineId;
use db::WithTransaction;
use futures_util::FutureExt;
use mac_address::MacAddress;
use model::machine::LoadSnapshotOptions;
use sqlx::PgPool;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

/// Backfills per-device host UEFI secrets (`machines/uefi/{mac}/root`) for
/// existing sites. For every host whose UEFI password was already set before
/// per-device secrets existed, copies the current site-default host UEFI value
/// into the per-device key. New hosts are handled inline by the ingestion state
/// machine right after the password is set; this migration covers hosts that
/// are already past UEFI setup.
///
/// Idempotent and best-effort: runs on every startup, fetches the site default
/// once, skips hosts already seeded, and never overwrites an existing
/// per-device secret (so a rotated value is preserved). No-op when the
/// site-default host UEFI credential is not configured yet.
///
/// DPUs are handled separately by [`seed_existing_dpu_uefi_secrets`].
pub async fn seed_existing_host_uefi_secrets(
    db_pool: &PgPool,
    credential_manager: &dyn CredentialManager,
) -> Result<(), eyre::Report> {
    let devices = db::machine::list_hosts_with_uefi_password_set(db_pool).await?;
    backfill_per_device_uefi(
        credential_manager,
        &carbide_secrets::uefi::site_default_host_uefi_key(),
        devices,
        "host",
    )
    .await
}

/// Backfills per-device DPU UEFI secrets (`machines/uefi/{mac}/root`) for
/// existing sites.
///
/// DPUs have no per-device "UEFI password set" marker (unlike a host's
/// `bios_password_set_time`), so this uses a coarser assumption: if the
/// site-wide DPU UEFI password is configured, the UEFI setup flow is presumed
/// to have applied it to every DPU, and so every DPU's per-device secret is
/// seeded from it. No-op when the site-default DPU UEFI credential is not
/// configured. Idempotent and create-if-missing, so it never clobbers an
/// already-seeded or rotated per-device secret.
pub async fn seed_existing_dpu_uefi_secrets(
    db_pool: &PgPool,
    credential_manager: &dyn CredentialManager,
) -> Result<(), eyre::Report> {
    let devices = db::machine::list_dpus_with_bmc_mac(db_pool).await?;
    backfill_per_device_uefi(
        credential_manager,
        &carbide_secrets::uefi::site_default_dpu_uefi_key(),
        devices,
        "DPU",
    )
    .await
}

/// Shared per-device UEFI backfill: resolves `site_default_key` once and seeds
/// each device's per-device secret from it (create-if-missing). A no-op when
/// the site default is unset. `kind` is purely for log context.
async fn backfill_per_device_uefi(
    credential_manager: &dyn CredentialManager,
    site_default_key: &CredentialKey,
    devices: Vec<(MachineId, MacAddress)>,
    kind: &str,
) -> Result<(), eyre::Report> {
    let Some(site_default) = credential_manager.get_credentials(site_default_key).await? else {
        tracing::info!(
            kind,
            "site-default UEFI credential not set; skipping per-device UEFI backfill"
        );
        return Ok(());
    };

    let mut seeded = 0usize;
    for (machine_id, bmc_mac) in devices {
        match carbide_secrets::uefi::seed_per_device_uefi_if_absent(
            credential_manager,
            bmc_mac,
            &site_default,
        )
        .await
        {
            Ok(true) => seeded += 1,
            Ok(false) => {}
            Err(e) => {
                tracing::warn!(
                    machine_id = %machine_id,
                    kind,
                    error = %e,
                    "failed to backfill per-device UEFI secret; will retry next startup"
                );
            }
        }
    }

    if seeded > 0 {
        tracing::info!(count = seeded, kind, "backfilled per-device UEFI secrets");
    }
    Ok(())
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
            "Carbide only supports clearing the UEFI password on discovered hosts".into(),
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
        CarbideError::InvalidArgument("Specified machine does not have BMC address".into())
    })?;

    let bmc_access_info =
        db::machine_interface::lookup_bmc_access_info(&mut txn, addr.ip(), Some(addr.port()))
            .await?;

    // Don't hold the transaction across an await point
    txn.commit().await?;

    let redfish_client = api
        .redfish_pool
        .client_by_info(&bmc_access_info)
        .await
        .map_err(|e| {
            tracing::error!("unable to create redfish client: {}", e);
            CarbideError::Internal {
                message: format!(
                    "Could not create connection to Redfish API to {machine_id}, check logs"
                ),
            }
        })?;

    let job_id: Option<String> = api
        .redfish_pool
        .clear_host_uefi_password(redfish_client.as_ref())
        .await
        .map_err(|e| {
            tracing::error!(%e, "Failed to run clear_host_uefi_password call");
            CarbideError::internal(format!(
                "Failed redfish clear_host_uefi_password subtask: {e}"
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
            "Carbide only supports setting the UEFI password on discovered hosts".into(),
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
        CarbideError::InvalidArgument("Specified machine does not have BMC address".into())
    })?;

    let bmc_access_info =
        db::machine_interface::lookup_bmc_access_info(&mut txn, addr.ip(), Some(addr.port()))
            .await?;

    // Let txn drop so we don't hold it across a redfish request
    txn.commit().await?;

    let redfish_client = api
        .redfish_pool
        .client_by_info(&bmc_access_info)
        .await
        .map_err(|e| {
            tracing::error!("unable to create redfish client: {}", e);
            CarbideError::RedfishClientCreation {
                inner: e.into(),
                machine_id,
            }
        })?;

    let job_id = api
        .redfish_pool
        .uefi_setup(redfish_client.as_ref(), false)
        .await
        .map_err(|e| {
            tracing::error!(%e, "Failed to run uefi_setup call");
            CarbideError::internal(format!("Failed redfish uefi_setup subtask: {e}"))
        })?;
    api.with_txn(|txn| db::machine::update_bios_password_set_time(&machine_id, txn).boxed())
        .await?
        .map_err(|e| {
            tracing::error!("Failed to update bios_password_set_time: {}", e);
            CarbideError::Internal {
                message: format!("Failed to update BIOS password timestamp: {e}"),
            }
        })?;

    Ok(Response::new(rpc::SetHostUefiPasswordResponse { job_id }))
}
