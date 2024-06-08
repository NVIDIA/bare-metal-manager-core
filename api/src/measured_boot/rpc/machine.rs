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

use crate::measured_boot::interface::machine::get_candidate_machine_records;
use crate::measured_boot::{
    interface::common::PcrRegisterValue, model::machine::CandidateMachine,
    model::report::MeasurementReport,
};
use crate::model::machine::machine_id::MachineId;
use crate::model::RpcDataConversionError;
use crate::CarbideError;
use rpc::protos::measured_boot::show_candidate_machine_request;
use rpc::protos::measured_boot::{
    AttestCandidateMachineRequest, AttestCandidateMachineResponse, ListCandidateMachinesRequest,
    ListCandidateMachinesResponse, ShowCandidateMachineRequest, ShowCandidateMachineResponse,
    ShowCandidateMachinesRequest, ShowCandidateMachinesResponse,
};
use sqlx::{Pool, Postgres};
use std::str::FromStr;
use tonic::Status;

/// handle_attest_candidate_machine handles the AttestCandidateMachine API endpoint.
pub async fn handle_attest_candidate_machine(
    db_conn: &Pool<Postgres>,
    req: &AttestCandidateMachineRequest,
) -> Result<AttestCandidateMachineResponse, Status> {
    let report = MeasurementReport::new(
        db_conn,
        MachineId::from_str(&req.machine_id).map_err(|_| {
            CarbideError::from(RpcDataConversionError::InvalidMachineId(
                req.machine_id.clone(),
            ))
        })?,
        &PcrRegisterValue::from_pb_vec(&req.pcr_values),
    )
    .await
    .map_err(|e| Status::internal(format!("failed saving measurements: {}", e)))?;

    Ok(AttestCandidateMachineResponse {
        report: Some(report.into()),
    })
}

/// handle_show_candidate_machine handles the ShowCandidateMachine API endpoint.
pub async fn handle_show_candidate_machine(
    db_conn: &Pool<Postgres>,
    req: &ShowCandidateMachineRequest,
) -> Result<ShowCandidateMachineResponse, Status> {
    let machine = match &req.selector {
        // Show a machine with the given ID.
        Some(show_candidate_machine_request::Selector::MachineId(machine_uuid)) => {
            CandidateMachine::from_id(
                db_conn,
                MachineId::from_str(machine_uuid).map_err(|_| {
                    CarbideError::from(RpcDataConversionError::InvalidMachineId(
                        machine_uuid.clone(),
                    ))
                })?,
            )
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
        }
        // Show all system profiles.
        None => return Err(Status::invalid_argument("selector required")),
    };

    Ok(ShowCandidateMachineResponse {
        machine: Some(machine.into()),
    })
}

/// handle_show_candidate_machines handles the ShowCandidateMachines API endpoint.
pub async fn handle_show_candidate_machines(
    db_conn: &Pool<Postgres>,
    _req: &ShowCandidateMachinesRequest,
) -> Result<ShowCandidateMachinesResponse, Status> {
    Ok(ShowCandidateMachinesResponse {
        machines: CandidateMachine::get_all(db_conn)
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
            .drain(..)
            .map(|machine| machine.into())
            .collect(),
    })
}

/// handle_list_candidate_machines handles the ListCandidateMachine API endpoint.
pub async fn handle_list_candidate_machines(
    db_conn: &Pool<Postgres>,
    _req: &ListCandidateMachinesRequest,
) -> Result<ListCandidateMachinesResponse, Status> {
    Ok(ListCandidateMachinesResponse {
        machines: get_candidate_machine_records(db_conn)
            .await
            .map_err(|e| Status::internal(format!("failed to read records: {}", e)))?
            .iter()
            .map(|record| record.clone().into())
            .collect(),
    })
}
