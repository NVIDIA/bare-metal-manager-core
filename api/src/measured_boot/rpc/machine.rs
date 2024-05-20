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

use tonic::Status;

use crate::measured_boot::interface::machine::get_mock_machines_records;
use crate::measured_boot::{
    dto::keys::MockMachineId, interface::common::PcrRegisterValue, model::machine::MockMachine,
    model::report::MeasurementReport,
};
use rpc::protos::measured_boot::show_mock_machine_request;
use rpc::protos::measured_boot::{
    AttestMockMachineRequest, AttestMockMachineResponse, CreateMockMachineRequest,
    CreateMockMachineResponse, DeleteMockMachineRequest, DeleteMockMachineResponse,
    ListMockMachineRequest, ListMockMachineResponse, ShowMockMachineRequest,
    ShowMockMachineResponse, ShowMockMachinesRequest, ShowMockMachinesResponse,
};
use sqlx::{Pool, Postgres};

pub async fn handle_create_mock_machine(
    db_conn: &Pool<Postgres>,
    req: &CreateMockMachineRequest,
) -> Result<CreateMockMachineResponse, Status> {
    let mock_machine = MockMachine::new(db_conn, MockMachineId(req.machine_id.clone()), &req.attrs)
        .await
        .map_err(|e| Status::internal(format!("failed to create machine: {}", e)))?;

    Ok(CreateMockMachineResponse {
        machine: Some(mock_machine.into()),
    })
}

pub async fn handle_delete_mock_machine(
    db_conn: &Pool<Postgres>,
    req: &DeleteMockMachineRequest,
) -> Result<DeleteMockMachineResponse, Status> {
    Ok(DeleteMockMachineResponse {
        machine: MockMachine::delete_where_id(db_conn, MockMachineId(req.machine_id.clone()))
            .await
            .map_err(|e| Status::internal(format!("failed to delete machine: {}", e)))?
            .or(None)
            .map(|machine| machine.into()),
    })
}

pub async fn handle_attest_mock_machine(
    db_conn: &Pool<Postgres>,
    req: &AttestMockMachineRequest,
) -> Result<AttestMockMachineResponse, Status> {
    let report = MeasurementReport::new(
        db_conn,
        MockMachineId(req.machine_id.clone()),
        &PcrRegisterValue::from_pb_vec(&req.pcr_values),
    )
    .await
    .map_err(|e| Status::internal(format!("failed saving measurements: {}", e)))?;

    Ok(AttestMockMachineResponse {
        report: Some(report.into()),
    })
}

pub async fn handle_show_mock_machine(
    db_conn: &Pool<Postgres>,
    req: &ShowMockMachineRequest,
) -> Result<ShowMockMachineResponse, Status> {
    let machine = match &req.selector {
        // Show a machine with the given ID.
        Some(show_mock_machine_request::Selector::MachineId(machine_uuid)) => {
            MockMachine::from_id(db_conn, MockMachineId(machine_uuid.clone()))
                .await
                .map_err(|e| Status::internal(format!("{}", e)))?
        }
        // Show all system profiles.
        None => return Err(Status::invalid_argument("selector required")),
    };

    Ok(ShowMockMachineResponse {
        machine: Some(machine.into()),
    })
}

pub async fn handle_show_mock_machines(
    db_conn: &Pool<Postgres>,
    _req: &ShowMockMachinesRequest,
) -> Result<ShowMockMachinesResponse, Status> {
    Ok(ShowMockMachinesResponse {
        machines: MockMachine::get_all(db_conn)
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
            .drain(..)
            .map(|machine| machine.into())
            .collect(),
    })
}

pub async fn handle_list_mock_machine(
    db_conn: &Pool<Postgres>,
    _req: &ListMockMachineRequest,
) -> Result<ListMockMachineResponse, Status> {
    Ok(ListMockMachineResponse {
        machines: get_mock_machines_records(db_conn)
            .await
            .map_err(|e| Status::internal(format!("failed to read records: {}", e)))?
            .iter()
            .map(|record| record.clone().into())
            .collect(),
    })
}
