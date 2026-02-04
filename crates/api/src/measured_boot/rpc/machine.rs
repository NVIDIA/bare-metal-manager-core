/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

/*!
 * gRPC handlers for measured boot mock-machine related API calls.
 */

use std::str::FromStr;

use ::rpc::errors::RpcDataConversionError;
use carbide_uuid::machine::MachineId;
use db::WithTransaction;
use db::measured_boot::interface::machine::get_candidate_machine_records;
use futures_util::FutureExt;
use measured_boot::pcr::PcrRegisterValue;
use rpc::protos::measured_boot::{
    AttestCandidateMachineRequest, AttestCandidateMachineResponse, ListCandidateMachinesRequest,
    ListCandidateMachinesResponse, ShowCandidateMachineRequest, ShowCandidateMachineResponse,
    ShowCandidateMachinesRequest, ShowCandidateMachinesResponse, show_candidate_machine_request,
};
use tonic::Status;

use crate::CarbideError;
use crate::api::Api;

/// handle_attest_candidate_machine handles the AttestCandidateMachine API endpoint.
pub async fn handle_attest_candidate_machine(
    api: &Api,
    req: AttestCandidateMachineRequest,
) -> Result<AttestCandidateMachineResponse, Status> {
    let mut txn = api.txn_begin().await?;
    let report = db::measured_boot::report::new(
        &mut txn,
        MachineId::from_str(&req.machine_id).map_err(|_| {
            CarbideError::from(RpcDataConversionError::InvalidMachineId(req.machine_id))
        })?,
        &PcrRegisterValue::from_pb_vec(req.pcr_values),
    )
    .await
    .map_err(|e| Status::internal(format!("failed saving measurements: {e}")))?;

    txn.commit().await?;
    Ok(AttestCandidateMachineResponse {
        report: Some(report.into()),
    })
}

/// handle_show_candidate_machine handles the ShowCandidateMachine API endpoint.
pub async fn handle_show_candidate_machine(
    api: &Api,
    req: ShowCandidateMachineRequest,
) -> Result<ShowCandidateMachineResponse, Status> {
    let mut txn = api.txn_begin().await?;
    let machine = match req.selector {
        // Show a machine with the given ID.
        Some(show_candidate_machine_request::Selector::MachineId(machine_uuid)) => {
            db::measured_boot::machine::from_id(
                &mut txn,
                MachineId::from_str(&machine_uuid).map_err(|_| {
                    CarbideError::from(RpcDataConversionError::InvalidMachineId(machine_uuid))
                })?,
            )
            .await
            .map_err(|e| Status::internal(format!("{e}")))?
        }
        // Show all system profiles.
        None => return Err(Status::invalid_argument("selector required")),
    };

    txn.commit().await?;

    Ok(ShowCandidateMachineResponse {
        machine: Some(machine.into()),
    })
}

/// handle_show_candidate_machines handles the ShowCandidateMachines API endpoint.
pub async fn handle_show_candidate_machines(
    api: &Api,
    _req: ShowCandidateMachinesRequest,
) -> Result<ShowCandidateMachinesResponse, Status> {
    Ok(ShowCandidateMachinesResponse {
        machines: api
            .with_txn(|txn| db::measured_boot::machine::get_all(txn).boxed())
            .await?
            .map_err(|e| Status::internal(format!("{e}")))?
            .into_iter()
            .map(|machine| machine.into())
            .collect(),
    })
}

/// handle_list_candidate_machines handles the ListCandidateMachine API endpoint.
pub async fn handle_list_candidate_machines(
    api: &Api,
    _req: ListCandidateMachinesRequest,
) -> Result<ListCandidateMachinesResponse, Status> {
    Ok(ListCandidateMachinesResponse {
        machines: api
            .with_txn(|txn| get_candidate_machine_records(txn).boxed())
            .await?
            .map_err(|e| Status::internal(format!("failed to read records: {e}")))?
            .into_iter()
            .map(|record| record.into())
            .collect(),
    })
}
