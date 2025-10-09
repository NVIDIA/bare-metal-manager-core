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
 * gRPC handlers for measured boot site management API calls.
 */

use std::str::FromStr;

use ::rpc::errors::RpcDataConversionError;
use forge_uuid::machine::MachineId;
use forge_uuid::measured_boot::TrustedMachineId;
use measured_boot::records::{
    MeasurementApprovedMachineRecord, MeasurementApprovedProfileRecord, MeasurementApprovedType,
};
use measured_boot::site::{MachineAttestationSummaryList, SiteModel};
use rpc::protos::measured_boot::{
    AddMeasurementTrustedMachineRequest, AddMeasurementTrustedMachineResponse,
    AddMeasurementTrustedProfileRequest, AddMeasurementTrustedProfileResponse,
    ExportSiteMeasurementsRequest, ExportSiteMeasurementsResponse, ImportSiteMeasurementsRequest,
    ImportSiteMeasurementsResponse, ImportSiteResult, ListAttestationSummaryRequest,
    ListAttestationSummaryResponse, ListMeasurementTrustedMachinesRequest,
    ListMeasurementTrustedMachinesResponse, ListMeasurementTrustedProfilesRequest,
    ListMeasurementTrustedProfilesResponse, MeasurementApprovedMachineRecordPb,
    MeasurementApprovedProfileRecordPb, RemoveMeasurementTrustedMachineRequest,
    RemoveMeasurementTrustedMachineResponse, RemoveMeasurementTrustedProfileRequest,
    RemoveMeasurementTrustedProfileResponse, remove_measurement_trusted_machine_request,
    remove_measurement_trusted_profile_request,
};
use sqlx::{Pool, Postgres};
use tonic::Status;

use crate::CarbideError;
use crate::measured_boot::db;
use crate::measured_boot::interface::site::{
    get_approved_machines, get_approved_profiles, insert_into_approved_machines,
    insert_into_approved_profiles, list_attestation_summary,
    remove_from_approved_machines_by_approval_id, remove_from_approved_machines_by_machine_id,
    remove_from_approved_profiles_by_approval_id, remove_from_approved_profiles_by_profile_id,
};
use crate::measured_boot::rpc::common::{begin_txn, commit_txn};

/// handle_import_site_measurements handles the ImportSiteMeasurements
/// API endpoint.
pub async fn handle_import_site_measurements(
    db_conn: &Pool<Postgres>,
    req: ImportSiteMeasurementsRequest,
) -> Result<ImportSiteMeasurementsResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;

    // Convert the site model from the SiteModelPb (and
    // make sure its good).
    let site_model = match &req.model {
        Some(site_model_pb) => SiteModel::from_pb(site_model_pb).map_err(|e| {
            Status::invalid_argument(format!("input site model failed translation: {e}"))
        })?,
        None => return Err(Status::invalid_argument("site model cannot be empty")),
    };

    // And now import it!
    let result = db::site::import(&mut txn, &site_model)
        .await
        .map_err(|e| Status::internal(format!("site import failed: {e}")))
        .map(|_| ImportSiteMeasurementsResponse {
            result: ImportSiteResult::Success.into(),
        });

    commit_txn(txn).await?;
    result
}

/// handle_export_site_measurements handles the ExportSiteMeasurements
/// API endpoint.
pub async fn handle_export_site_measurements(
    db_conn: &Pool<Postgres>,
    _req: ExportSiteMeasurementsRequest,
) -> Result<ExportSiteMeasurementsResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let site_model = db::site::export(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("export failed: {e}")))?;

    Ok(ExportSiteMeasurementsResponse {
        model: Some(
            SiteModel::to_pb(&site_model)
                .map_err(|e| Status::internal(format!("model to pb failed: {e}")))?,
        ),
    })
}

/// handle_add_measurement_trusted_machine handles the
/// AddMeasurementTrustedMachine API endpoint.
pub async fn handle_add_measurement_trusted_machine(
    db_conn: &Pool<Postgres>,
    req: AddMeasurementTrustedMachineRequest,
) -> Result<AddMeasurementTrustedMachineResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let approval_type = req.approval_type();
    let approval_record = insert_into_approved_machines(
        &mut txn,
        TrustedMachineId::from_str(&req.machine_id).map_err(|_| {
            CarbideError::from(RpcDataConversionError::InvalidMachineId(req.machine_id))
        })?,
        MeasurementApprovedType::from(approval_type),
        Some(req.pcr_registers),
        Some(req.comments),
    )
    .await
    .map_err(|e| Status::internal(format!("failed to insert trusted machine approval: {e}")))?;

    commit_txn(txn).await?;
    Ok(AddMeasurementTrustedMachineResponse {
        approval_record: Some(approval_record.into()),
    })
}

/// handle_remove_measurement_trusted_machine handles the
/// RemoveMeasurementTrustedMachine API endpoint.
pub async fn handle_remove_measurement_trusted_machine(
    db_conn: &Pool<Postgres>,
    req: RemoveMeasurementTrustedMachineRequest,
) -> Result<RemoveMeasurementTrustedMachineResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;

    let approval_record: MeasurementApprovedMachineRecord = match req.selector {
        // Remove by approval ID.
        Some(remove_measurement_trusted_machine_request::Selector::ApprovalId(approval_uuid)) => {
            remove_from_approved_machines_by_approval_id(&mut txn, approval_uuid)
                .await
                .map_err(|e| Status::internal(format!("removal failed: {e}")))?
        }
        // Remove by machine ID.
        Some(remove_measurement_trusted_machine_request::Selector::MachineId(machine_id)) => {
            remove_from_approved_machines_by_machine_id(
                &mut txn,
                MachineId::from_str(&machine_id).map_err(|_| {
                    CarbideError::from(RpcDataConversionError::InvalidMachineId(machine_id))
                })?,
            )
            .await
            .map_err(|e| Status::internal(format!("removal failed: {e}")))?
        }
        // Oops, forgot to set a selector.
        None => {
            return Err(Status::invalid_argument(
                "approval or machine ID selector missing",
            ));
        }
    };

    commit_txn(txn).await?;
    Ok(RemoveMeasurementTrustedMachineResponse {
        approval_record: Some(approval_record.into()),
    })
}

/// handle_list_measurement_trusted_machines handles the
/// ListMeasurementTrustedMachines API endpoint.
pub async fn handle_list_measurement_trusted_machines(
    db_conn: &Pool<Postgres>,
    _req: ListMeasurementTrustedMachinesRequest,
) -> Result<ListMeasurementTrustedMachinesResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let approval_records: Vec<MeasurementApprovedMachineRecordPb> = get_approved_machines(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("failed to fetch machine approvals: {e}")))?
        .into_iter()
        .map(|record| record.into())
        .collect();

    Ok(ListMeasurementTrustedMachinesResponse { approval_records })
}

/// handle_add_measurement_trusted_profile handles the
/// AddMeasurementTrustedProfile API endpoint.
pub async fn handle_add_measurement_trusted_profile(
    db_conn: &Pool<Postgres>,
    req: AddMeasurementTrustedProfileRequest,
) -> Result<AddMeasurementTrustedProfileResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let approval_type = req.approval_type();
    let approval_record = insert_into_approved_profiles(
        &mut txn,
        req.profile_id
            .ok_or(CarbideError::MissingArgument("profile_id"))?,
        MeasurementApprovedType::from(approval_type),
        req.pcr_registers,
        req.comments,
    )
    .await
    .map_err(|e| Status::internal(format!("failed to insert trusted profile approval: {e}")))?;

    commit_txn(txn).await?;
    Ok(AddMeasurementTrustedProfileResponse {
        approval_record: Some(approval_record.into()),
    })
}

/// handle_remove_measurement_trusted_profile handles the
/// RemoveMeasurementTrustedProfile API endpoint.
pub async fn handle_remove_measurement_trusted_profile(
    db_conn: &Pool<Postgres>,
    req: RemoveMeasurementTrustedProfileRequest,
) -> Result<RemoveMeasurementTrustedProfileResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let approval_record: MeasurementApprovedProfileRecord = match req.selector {
        // Remove by approval ID.
        Some(remove_measurement_trusted_profile_request::Selector::ApprovalId(approval_uuid)) => {
            remove_from_approved_profiles_by_approval_id(&mut txn, approval_uuid)
                .await
                .map_err(|e| Status::internal(format!("removal failed: {e}")))?
        }
        // Remove by profile ID.
        Some(remove_measurement_trusted_profile_request::Selector::ProfileId(profile_id)) => {
            remove_from_approved_profiles_by_profile_id(&mut txn, profile_id)
                .await
                .map_err(|e| Status::internal(format!("removal failed: {e}")))?
        }
        // Oops, forgot to set a selector.
        None => {
            return Err(Status::invalid_argument(
                "approval or profile ID selector missing",
            ));
        }
    };

    commit_txn(txn).await?;
    Ok(RemoveMeasurementTrustedProfileResponse {
        approval_record: Some(approval_record.into()),
    })
}

/// handle_list_measurement_trusted_profiles handles the
/// ListMeasurementTrustedProfiles API endpoint.
pub async fn handle_list_measurement_trusted_profiles(
    db_conn: &Pool<Postgres>,
    _req: ListMeasurementTrustedProfilesRequest,
) -> Result<ListMeasurementTrustedProfilesResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let approval_records: Vec<MeasurementApprovedProfileRecordPb> = get_approved_profiles(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("failed to fetch profile approvals: {e}")))?
        .into_iter()
        .map(|record| record.into())
        .collect();

    Ok(ListMeasurementTrustedProfilesResponse { approval_records })
}

pub async fn handle_list_attestation_summary(
    db_conn: &Pool<Postgres>,
    _req: ListAttestationSummaryRequest,
) -> Result<ListAttestationSummaryResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let attestation_summary = list_attestation_summary(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("failed to fetch attestation summary: {e}")))?;

    Ok(MachineAttestationSummaryList::to_grpc(&attestation_summary))
}
