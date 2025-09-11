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

use crate::CarbideError;
use crate::measured_boot::db;
use crate::measured_boot::interface::report::{
    get_all_measurement_report_records, get_measurement_report_records_for_machine_id,
    match_latest_reports,
};
use crate::measured_boot::rpc::common::{begin_txn, commit_txn};
use ::rpc::errors::RpcDataConversionError;
use ::rpc::measured_boot::pcr::{PcrRegisterValue, PcrSet, parse_pcr_index_input};
use ::rpc::uuid::machine::MachineId;
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
    req: CreateMeasurementReportRequest,
) -> Result<CreateMeasurementReportResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let report = db::report::new_with_txn(
        &mut txn,
        MachineId::from_str(&req.machine_id).map_err(|_| {
            CarbideError::from(RpcDataConversionError::InvalidMachineId(req.machine_id))
        })?,
        &PcrRegisterValue::from_pb_vec(req.pcr_values),
    )
    .await
    .map_err(|e| Status::internal(format!("report creation failed: {e}")))?;

    commit_txn(txn).await?;
    Ok(CreateMeasurementReportResponse {
        report: Some(report.into()),
    })
}

/// handle_delete_measurement_report handles the DeleteMeasurementReport
/// API endpoint.
pub async fn handle_delete_measurement_report(
    db_conn: &Pool<Postgres>,
    req: DeleteMeasurementReportRequest,
) -> Result<DeleteMeasurementReportResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let report = db::report::delete_for_id(
        &mut txn,
        req.report_id
            .ok_or(CarbideError::MissingArgument("report_id"))?,
    )
    .await
    .map_err(|e| Status::internal(format!("delete failed: {e}")))?;

    commit_txn(txn).await?;
    Ok(DeleteMeasurementReportResponse {
        report: Some(report.into()),
    })
}

/// handle_promote_measurement_report handles the PromoteMeasurementReport
/// API endpoint.
pub async fn handle_promote_measurement_report(
    db_conn: &Pool<Postgres>,
    req: PromoteMeasurementReportRequest,
) -> Result<PromoteMeasurementReportResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let pcr_set: Option<PcrSet> =
        match !req.pcr_registers.is_empty() {
            true => Some(parse_pcr_index_input(&req.pcr_registers).map_err(|e| {
                Status::invalid_argument(format!("pcr_register parsing failed: {e}"))
            })?),
            false => None,
        };

    let report = db::report::from_id_with_txn(
        &mut txn,
        req.report_id
            .ok_or(CarbideError::MissingArgument("report_id"))?,
    )
    .await
    .map_err(|e| Status::internal(format!("promotion failed fetching report: {e}")))?;

    let bundle = db::report::create_active_bundle_with_txn(&mut txn, &report, &pcr_set)
        .await
        .map_err(|e| {
            Status::internal(format!(
                "promotion failed promoting into active bundle: {e}"
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
    req: RevokeMeasurementReportRequest,
) -> Result<RevokeMeasurementReportResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let pcr_set: Option<PcrSet> =
        match &req.pcr_registers.len() {
            n if n < &1 => None,
            _ => Some(parse_pcr_index_input(&req.pcr_registers).map_err(|e| {
                Status::invalid_argument(format!("pcr_register parsing failed: {e}"))
            })?),
        };

    let report = db::report::from_id_with_txn(
        &mut txn,
        req.report_id
            .ok_or(CarbideError::MissingArgument("report_id"))?,
    )
    .await
    .map_err(|e| Status::internal(format!("promotion failed fetching report: {e}")))?;

    let bundle = db::report::create_revoked_bundle_with_txn(&mut txn, &report, &pcr_set)
        .await
        .map_err(|e| {
            Status::internal(format!(
                "promotion failed promoting into revoked bundle: {e}"
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
    req: ShowMeasurementReportForIdRequest,
) -> Result<ShowMeasurementReportForIdResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    Ok(ShowMeasurementReportForIdResponse {
        report: Some(
            db::report::from_id_with_txn(
                &mut txn,
                req.report_id
                    .ok_or(CarbideError::MissingArgument("report_id"))?,
            )
            .await
            .map_err(|e| Status::internal(format!("{e}")))?
            .into(),
        ),
    })
}

/// handle_show_measurement_reports_for_machine handles the
/// ShowMeasurementReportsForMachine API endpoint.
pub async fn handle_show_measurement_reports_for_machine(
    db_conn: &Pool<Postgres>,
    req: ShowMeasurementReportsForMachineRequest,
) -> Result<ShowMeasurementReportsForMachineResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    Ok(ShowMeasurementReportsForMachineResponse {
        reports: db::report::get_all_for_machine_id(
            &mut txn,
            MachineId::from_str(&req.machine_id).map_err(|_| {
                CarbideError::from(RpcDataConversionError::InvalidMachineId(req.machine_id))
            })?,
        )
        .await
        .map_err(|e| Status::internal(format!("{e}")))?
        .drain(..)
        .map(|report| report.into())
        .collect(),
    })
}

/// handle_show_measurement_reports handles the ShowMeasurementReports
/// API endpoint.
pub async fn handle_show_measurement_reports(
    db_conn: &Pool<Postgres>,
    _req: ShowMeasurementReportsRequest,
) -> Result<ShowMeasurementReportsResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    Ok(ShowMeasurementReportsResponse {
        reports: db::report::get_all(&mut txn)
            .await
            .map_err(|e| Status::internal(format!("{e}")))?
            .drain(..)
            .map(|report| report.into())
            .collect(),
    })
}

/// handle_list_measurement_report handles the ListMeasurementReport
/// API endpoint.
pub async fn handle_list_measurement_report(
    db_conn: &Pool<Postgres>,
    req: ListMeasurementReportRequest,
) -> Result<ListMeasurementReportResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let reports: Vec<MeasurementReportRecordPb> = match req.selector {
        Some(list_measurement_report_request::Selector::MachineId(machine_id)) => {
            get_measurement_report_records_for_machine_id(
                &mut txn,
                MachineId::from_str(&machine_id).map_err(|_| {
                    CarbideError::from(RpcDataConversionError::InvalidMachineId(machine_id))
                })?,
            )
            .await
            .map_err(|e| Status::internal(format!("failed loading report records: {e}")))?
            .into_iter()
            .map(|report| report.into())
            .collect()
        }
        None => get_all_measurement_report_records(&mut txn)
            .await
            .map_err(|e| Status::internal(format!("failed loading report records: {e}")))?
            .into_iter()
            .map(|report| report.into())
            .collect(),
    };
    Ok(ListMeasurementReportResponse { reports })
}

/// handle_match_measurement_report handles the MatchMeasurementReport
/// API endpoint.
pub async fn handle_match_measurement_report(
    db_conn: &Pool<Postgres>,
    req: MatchMeasurementReportRequest,
) -> Result<MatchMeasurementReportResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let mut reports =
        match_latest_reports(&mut txn, &PcrRegisterValue::from_pb_vec(req.pcr_values))
            .await
            .map_err(|e| Status::internal(format!("failure during report matching: {e}")))?;

    reports.sort_by(|a, b| a.ts.cmp(&b.ts));

    let report_pbs: Vec<MeasurementReportRecordPb> =
        reports.iter().map(|report| report.clone().into()).collect();

    Ok(MatchMeasurementReportResponse {
        reports: report_pbs,
    })
}
