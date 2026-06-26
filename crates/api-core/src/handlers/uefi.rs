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
use db::WithTransaction;
use futures_util::FutureExt;
use model::machine::LoadSnapshotOptions;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

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

    // A known BMC MAC is a hard precondition for setting the UEFI password: it
    // keys the host_uefi rotation bookkeeping recorded below, so reject the
    // request up front rather than driving the device and only then discovering
    // we cannot track its convergence.
    let host_bmc_mac = snapshot.host_snapshot.bmc_info.mac.ok_or_else(|| {
        CarbideError::InvalidArgument(
            "Specified machine does not have a known BMC MAC address".into(),
        )
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
        tracing::error!("Failed to update bios_password_set_time: {}", e);
        CarbideError::Internal {
            message: format!("Failed to update BIOS password timestamp: {e}"),
        }
    })?;

    Ok(Response::new(rpc::SetHostUefiPasswordResponse { job_id }))
}
