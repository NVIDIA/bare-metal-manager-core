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
use model::machine::network::ManagedHostQuarantineState;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

pub(crate) async fn set_managed_host_quarantine_state(
    api: &Api,
    request: Request<rpc::SetManagedHostQuarantineStateRequest>,
) -> Result<Response<rpc::SetManagedHostQuarantineStateResponse>, Status> {
    log_request_data(&request);
    let rpc::SetManagedHostQuarantineStateRequest {
        quarantine_state,
        machine_id,
    } = request.into_inner();
    let machine_id = convert_and_log_machine_id(machine_id.as_ref())?;
    let Some(quarantine_state) = quarantine_state else {
        return Err(CarbideError::MissingArgument("quarantine_state").into());
    };
    let quarantine_state: ManagedHostQuarantineState =
        quarantine_state.try_into().map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    let prior_quarantine_state =
        db::machine::set_quarantine_state(&mut txn, &machine_id, quarantine_state)
            .await?
            .map(Into::into);

    txn.commit().await?;

    Ok(Response::new(rpc::SetManagedHostQuarantineStateResponse {
        prior_quarantine_state,
    }))
}

pub(crate) async fn get_managed_host_quarantine_state(
    api: &Api,
    request: Request<rpc::GetManagedHostQuarantineStateRequest>,
) -> Result<Response<rpc::GetManagedHostQuarantineStateResponse>, Status> {
    log_request_data(&request);
    let rpc::GetManagedHostQuarantineStateRequest { machine_id } = request.into_inner();
    let machine_id = convert_and_log_machine_id(machine_id.as_ref())?;

    let mut txn = api.txn_begin().await?;

    let quarantine_state = db::machine::get_quarantine_state(&mut txn, &machine_id)
        .await?
        .map(Into::into);

    txn.commit().await?;

    Ok(Response::new(rpc::GetManagedHostQuarantineStateResponse {
        quarantine_state,
    }))
}

pub(crate) async fn clear_managed_host_quarantine_state(
    api: &Api,
    request: Request<rpc::ClearManagedHostQuarantineStateRequest>,
) -> Result<Response<rpc::ClearManagedHostQuarantineStateResponse>, Status> {
    log_request_data(&request);

    let rpc::ClearManagedHostQuarantineStateRequest { machine_id } = request.into_inner();
    let machine_id = convert_and_log_machine_id(machine_id.as_ref())?;

    let mut txn = api.txn_begin().await?;

    let prior_quarantine_state = db::machine::clear_quarantine_state(&mut txn, &machine_id)
        .await?
        .map(Into::into);

    txn.commit().await?;

    Ok(tonic::Response::new(
        rpc::ClearManagedHostQuarantineStateResponse {
            prior_quarantine_state,
        },
    ))
}
