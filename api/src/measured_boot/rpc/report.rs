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
 * gRPC handlers for measurement report related API calls.
 */

use tonic::Status;

use crate::measured_boot::dto::keys::MeasurementReportId;
use crate::measured_boot::interface::report::{
    get_all_measurement_report_records, get_measurement_report_records_for_machine_id, match_report,
};
use crate::measured_boot::rpc::common::{begin_txn, commit_txn};
use crate::measured_boot::{
    interface::common::{parse_pcr_index_input, PcrRegisterValue, PcrSet},
    model::report::MeasurementReport,
};
use crate::model::machine::machine_id::MachineId;
use crate::model::RpcDataConversionError;
use crate::CarbideError;
use rpc::protos::measured_boot::list_measurement_report_request;
use rpc::protos::measured_boot::{
    CreateMeasurementReportRequest, CreateMeasurementReportResponse,
    DeleteMeasurementReportRequest, DeleteMeasurementReportResponse, ListMeasurementReportRequest,
    ListMeasurementReportResponse, MatchMeasurementReportRequest, MatchMeasurementReportResponse,
    MeasurementReportRecordPb, PromoteMeasurementReportRequest, PromoteMeasurementReportResponse,
    RevokeMeasurementReportRequest, RevokeMeasurementReportResponse,
    ShowMeasurementReportForIdRequest, ShowMeasurementReportForIdResponse,
    ShowMeasurementReportsForMachineRequest, ShowMeasurementReportsForMachineResponse,
    ShowMeasurementReportsRequest, ShowMeasurementReportsResponse,
};
use sqlx::{Pool, Postgres};
use std::str::FromStr;

/// handle_create_measurement_report handles the CreateMeasurementReport
/// API endpoint.
pub async fn handle_create_measurement_report(
    db_conn: &Pool<Postgres>,
    req: &CreateMeasurementReportRequest,
) -> Result<CreateMeasurementReportResponse, Status> {
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
    .map_err(|e| Status::internal(format!("report creation failed: {}", e)))?;

    Ok(CreateMeasurementReportResponse {
        report: Some(report.into()),
    })
}

/// handle_delete_measurement_report handles the DeleteMeasurementReport
/// API endpoint.
pub async fn handle_delete_measurement_report(
    db_conn: &Pool<Postgres>,
    req: &DeleteMeasurementReportRequest,
) -> Result<DeleteMeasurementReportResponse, Status> {
    let report = MeasurementReport::delete_for_id(
        db_conn,
        MeasurementReportId::from_grpc(req.report_id.clone())?,
    )
    .await
    .map_err(|e| Status::internal(format!("delete failed: {}", e)))?;

    Ok(DeleteMeasurementReportResponse {
        report: Some(report.into()),
    })
}

/// handle_promote_measurement_report handles the PromoteMeasurementReport
/// API endpoint.
pub async fn handle_promote_measurement_report(
    db_conn: &Pool<Postgres>,
    req: &PromoteMeasurementReportRequest,
) -> Result<PromoteMeasurementReportResponse, Status> {
    let pcr_set: Option<PcrSet> = match !req.pcr_registers.is_empty() {
        true => Some(parse_pcr_index_input(&req.pcr_registers).map_err(|e| {
            Status::invalid_argument(format!("pcr_register parsing failed: {}", e))
        })?),
        false => None,
    };

    let mut txn = begin_txn(db_conn).await?;
    let report = MeasurementReport::from_id_with_txn(
        &mut txn,
        MeasurementReportId::from_grpc(req.report_id.clone())?,
    )
    .await
    .map_err(|e| Status::internal(format!("promotion failed fetching report: {}", e)))?;

    let bundle = report
        .create_active_bundle_with_txn(&mut txn, &pcr_set)
        .await
        .map_err(|e| {
            Status::internal(format!(
                "promotion failed promoting into active bundle: {}",
                e
            ))
        })?;

    commit_txn(txn).await?;

    Ok(PromoteMeasurementReportResponse {
        bundle: Some(bundle.into()),
    })
}

/// handle_revoke_measurement_report handles the RevokeMeasurementReport
/// API endpoint.
pub async fn handle_revoke_measurement_report(
    db_conn: &Pool<Postgres>,
    req: &RevokeMeasurementReportRequest,
) -> Result<RevokeMeasurementReportResponse, Status> {
    let pcr_set: Option<PcrSet> = match &req.pcr_registers.len() {
        n if n < &1 => None,
        _ => Some(parse_pcr_index_input(&req.pcr_registers).map_err(|e| {
            Status::invalid_argument(format!("pcr_register parsing failed: {}", e))
        })?),
    };

    let mut txn = begin_txn(db_conn).await?;
    let report = MeasurementReport::from_id_with_txn(
        &mut txn,
        MeasurementReportId::from_grpc(req.report_id.clone())?,
    )
    .await
    .map_err(|e| Status::internal(format!("promotion failed fetching report: {}", e)))?;

    let bundle = report
        .create_revoked_bundle_with_txn(&mut txn, &pcr_set)
        .await
        .map_err(|e| {
            Status::internal(format!(
                "promotion failed promoting into revoked bundle: {}",
                e
            ))
        })?;

    commit_txn(txn).await?;

    Ok(RevokeMeasurementReportResponse {
        bundle: Some(bundle.into()),
    })
}

/// handle_show_measurement_report_for_id handles the
/// ShowMeasurementReportForId API endpoint.
pub async fn handle_show_measurement_report_for_id(
    db_conn: &Pool<Postgres>,
    req: &ShowMeasurementReportForIdRequest,
) -> Result<ShowMeasurementReportForIdResponse, Status> {
    Ok(ShowMeasurementReportForIdResponse {
        report: Some(
            MeasurementReport::from_id(
                db_conn,
                MeasurementReportId::from_grpc(req.report_id.clone())?,
            )
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
            .into(),
        ),
    })
}

/// handle_show_measurement_reports_for_machine handles the
/// ShowMeasurementReportsForMachine API endpoint.
pub async fn handle_show_measurement_reports_for_machine(
    db_conn: &Pool<Postgres>,
    req: &ShowMeasurementReportsForMachineRequest,
) -> Result<ShowMeasurementReportsForMachineResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;

    Ok(ShowMeasurementReportsForMachineResponse {
        reports: MeasurementReport::get_all_for_machine_id(
            &mut txn,
            MachineId::from_str(&req.machine_id).map_err(|_| {
                CarbideError::from(RpcDataConversionError::InvalidMachineId(
                    req.machine_id.clone(),
                ))
            })?,
        )
        .await
        .map_err(|e| Status::internal(format!("{}", e)))?
        .drain(..)
        .map(|report| report.into())
        .collect(),
    })
}

/// handle_show_measurement_reports handles the ShowMeasurementReports
/// API endpoint.
pub async fn handle_show_measurement_reports(
    db_conn: &Pool<Postgres>,
    _req: &ShowMeasurementReportsRequest,
) -> Result<ShowMeasurementReportsResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;

    Ok(ShowMeasurementReportsResponse {
        reports: MeasurementReport::get_all(&mut txn)
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
            .drain(..)
            .map(|report| report.into())
            .collect(),
    })
}

/// handle_list_measurement_report handles the ListMeasurementReport
/// API endpoint.
pub async fn handle_list_measurement_report(
    db_conn: &Pool<Postgres>,
    req: &ListMeasurementReportRequest,
) -> Result<ListMeasurementReportResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let reports: Vec<MeasurementReportRecordPb> = match &req.selector {
        Some(list_measurement_report_request::Selector::MachineId(machine_id)) => {
            get_measurement_report_records_for_machine_id(
                &mut txn,
                MachineId::from_str(machine_id).map_err(|_| {
                    CarbideError::from(RpcDataConversionError::InvalidMachineId(machine_id.clone()))
                })?,
            )
            .await
            .map_err(|e| Status::internal(format!("failed loading report records: {}", e)))?
            .iter()
            .map(|report| report.clone().into())
            .collect()
        }
        None => get_all_measurement_report_records(&mut txn)
            .await
            .map_err(|e| Status::internal(format!("failed loading report records: {}", e)))?
            .iter()
            .map(|report| report.clone().into())
            .collect(),
    };
    Ok(ListMeasurementReportResponse { reports })
}

/// handle_match_measurement_report handles the MatchMeasurementReport
/// API endpoint.
pub async fn handle_match_measurement_report(
    db_conn: &Pool<Postgres>,
    req: &MatchMeasurementReportRequest,
) -> Result<MatchMeasurementReportResponse, Status> {
    let mut reports = match_report(db_conn, &PcrRegisterValue::from_pb_vec(&req.pcr_values))
        .await
        .map_err(|e| Status::internal(format!("failure during report matching: {}", e)))?;

    reports.sort_by(|a, b| a.ts.cmp(&b.ts));

    let report_pbs: Vec<MeasurementReportRecordPb> =
        reports.iter().map(|report| report.clone().into()).collect();

    Ok(MatchMeasurementReportResponse {
        reports: report_pbs,
    })
}
