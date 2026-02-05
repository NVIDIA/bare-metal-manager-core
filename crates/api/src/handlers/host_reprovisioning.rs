/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use ::rpc::forge as rpc;
use carbide_uuid::machine::MachineId;
use db::WithTransaction;
use futures_util::FutureExt;
use itertools::Itertools;
use model::machine::LoadSnapshotOptions;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

pub(crate) async fn reset_host_reprovisioning(
    api: &Api,
    request: Request<MachineId>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let machine_id = convert_and_log_machine_id(Some(&request.into_inner()))?;

    let mut txn = api.txn_begin().await?;

    db::host_machine_update::reset_host_reprovisioning_request(&mut txn, &machine_id, false)
        .await?;
    txn.commit().await?;

    Ok(Response::new(()))
}

pub(crate) async fn trigger_host_reprovisioning(
    api: &Api,
    request: Request<rpc::HostReprovisioningRequest>,
) -> Result<Response<()>, Status> {
    use ::rpc::forge::host_reprovisioning_request::Mode;

    log_request_data(&request);
    let req = request.into_inner();
    let machine_id = convert_and_log_machine_id(req.machine_id.as_ref())?;

    let mut txn = api.txn_begin().await?;

    let snapshot =
        db::managed_host::load_snapshot(&mut txn, &machine_id, LoadSnapshotOptions::default())
            .await?
            .ok_or(CarbideError::NotFoundError {
                kind: "machine",
                id: machine_id.to_string(),
            })?;

    if let Some(request) = snapshot.host_snapshot.reprovision_requested
        && request.started_at.is_some()
    {
        return Err(
            CarbideError::internal("Reprovisioning is already started.".to_string()).into(),
        );
    }

    match req.mode() {
        Mode::Set => {
            let initiator = req.initiator().as_str_name();
            db::host_machine_update::trigger_host_reprovisioning_request(
                &mut txn,
                initiator,
                &machine_id,
            )
            .await?;
        }
        Mode::Clear => {
            db::host_machine_update::clear_host_reprovisioning_request(&mut txn, &machine_id)
                .await?;
        }
    }

    txn.commit().await?;

    Ok(Response::new(()))
}

pub(crate) async fn list_hosts_waiting_for_reprovisioning(
    api: &Api,
    request: Request<rpc::HostReprovisioningListRequest>,
) -> Result<Response<rpc::HostReprovisioningListResponse>, Status> {
    log_request_data(&request);

    let hosts = api
        .with_txn(|txn| db::machine::list_machines_requested_for_host_reprovisioning(txn).boxed())
        .await??
        .into_iter()
        .map(
            |x| rpc::host_reprovisioning_list_response::HostReprovisioningListItem {
                id: Some(x.id),
                state: x.current_state().to_string(),
                requested_at: x
                    .reprovision_requested
                    .as_ref()
                    .map(|a| a.requested_at.into()),
                initiator: x
                    .reprovision_requested
                    .as_ref()
                    .map(|a| a.initiator.clone())
                    .unwrap_or_default(),
                initiated_at: x
                    .reprovision_requested
                    .as_ref()
                    .map(|a| a.started_at.map(|x| x.into()))
                    .unwrap_or_default(),
                user_approval_received: x
                    .reprovision_requested
                    .as_ref()
                    .map(|x| x.user_approval_received)
                    .unwrap_or_default(),
            },
        )
        .collect_vec();

    Ok(Response::new(rpc::HostReprovisioningListResponse { hosts }))
}

pub async fn mark_manual_firmware_upgrade_complete(
    api: &Api,
    request: Request<MachineId>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let machine_id = convert_and_log_machine_id(Some(&request.into_inner()))?;

    let mut txn = api.txn_begin().await?;

    db::host_machine_update::set_manual_firmware_upgrade_completed(&mut txn, &machine_id).await?;

    txn.commit().await?;

    Ok(Response::new(()))
}
