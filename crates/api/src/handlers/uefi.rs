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
use model::machine::LoadSnapshotOptions;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

#[allow(txn_held_across_await)]
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
        return Err(Status::invalid_argument(
            "Carbide only supports clearing the UEFI password on discovered hosts",
        ));
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

    let redfish_client = api
        .redfish_pool
        .create_client_from_machine(&snapshot.host_snapshot, &mut txn)
        .await
        .map_err(|e| {
            tracing::error!("unable to create redfish client: {}", e);
            Status::internal(format!(
                "Could not create connection to Redfish API to {machine_id}, check logs"
            ))
        })?;

    let job_id: Option<String> =
        crate::redfish::clear_host_uefi_password(redfish_client.as_ref(), api.redfish_pool.clone())
            .await?;

    txn.commit().await?;

    Ok(Response::new(rpc::ClearHostUefiPasswordResponse { job_id }))
}

#[allow(txn_held_across_await)]
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
        return Err(Status::invalid_argument(
            "Carbide only supports setting the UEFI password on discovered hosts",
        ));
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

    let redfish_client = api
        .redfish_pool
        .create_client_from_machine(&snapshot.host_snapshot, &mut txn)
        .await
        .map_err(|e| {
            tracing::error!("unable to create redfish client: {}", e);
            Status::internal(format!(
                "Could not create connection to Redfish API to {machine_id}, check logs"
            ))
        })?;

    let job_id =
        crate::redfish::set_host_uefi_password(redfish_client.as_ref(), api.redfish_pool.clone())
            .await?;

    db::machine::update_bios_password_set_time(&machine_id, &mut txn)
        .await
        .map_err(|e| {
            tracing::error!("Failed to update bios_password_set_time: {}", e);
            Status::internal(format!("Failed to update BIOS password timestamp: {e}"))
        })?;

    txn.commit().await?;

    Ok(Response::new(rpc::SetHostUefiPasswordResponse { job_id }))
}
