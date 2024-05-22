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

use tonic::Status;

use crate::measured_boot::dto::keys::{
    MeasurementApprovedMachineId, MeasurementApprovedProfileId, MeasurementSystemProfileId,
    MockMachineId,
};
use crate::measured_boot::dto::records::{
    MeasurementApprovedMachineRecord, MeasurementApprovedProfileRecord, MeasurementApprovedType,
};
use crate::measured_boot::interface::site::{
    get_approved_machines, get_approved_profiles, insert_into_approved_machines,
    insert_into_approved_profiles, remove_from_approved_machines_by_approval_id,
    remove_from_approved_machines_by_machine_id, remove_from_approved_profiles_by_approval_id,
    remove_from_approved_profiles_by_profile_id,
};
use crate::measured_boot::model::site::SiteModel;
use crate::measured_boot::rpc::common::{begin_txn, commit_txn};

use rpc::protos::measured_boot::remove_measurement_trusted_machine_request;
use rpc::protos::measured_boot::remove_measurement_trusted_profile_request;
use rpc::protos::measured_boot::{
    AddMeasurementTrustedMachineRequest, AddMeasurementTrustedMachineResponse,
    AddMeasurementTrustedProfileRequest, AddMeasurementTrustedProfileResponse,
    ExportSiteMeasurementsRequest, ExportSiteMeasurementsResponse, ImportSiteMeasurementsRequest,
    ImportSiteMeasurementsResponse, ImportSiteResult, ListMeasurementTrustedMachinesRequest,
    ListMeasurementTrustedMachinesResponse, ListMeasurementTrustedProfilesRequest,
    ListMeasurementTrustedProfilesResponse, MeasurementApprovedMachineRecordPb,
    MeasurementApprovedProfileRecordPb, RemoveMeasurementTrustedMachineRequest,
    RemoveMeasurementTrustedMachineResponse, RemoveMeasurementTrustedProfileRequest,
    RemoveMeasurementTrustedProfileResponse,
};

use sqlx::{Pool, Postgres};

///////////////////////////////////////////////////////////////////////////////
/// handle_import_site_measurements handles the ImportSiteMeasurements
/// API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_import_site_measurements(
    db_conn: &Pool<Postgres>,
    req: &ImportSiteMeasurementsRequest,
) -> Result<ImportSiteMeasurementsResponse, Status> {
    // Convert the site model from the SiteModelPb (and
    // make sure its good).
    let site_model = match &req.model {
        Some(site_model_pb) => SiteModel::from_pb(site_model_pb).map_err(|e| {
            Status::invalid_argument(format!("input site model failed translation: {}", e))
        })?,
        None => return Err(Status::invalid_argument("site model cannot be empty")),
    };

    // And now import it!
    SiteModel::import(db_conn, &site_model)
        .await
        .map_err(|e| Status::internal(format!("site import failed: {}", e)))
        .map(|_| ImportSiteMeasurementsResponse {
            result: ImportSiteResult::Success.into(),
        })
}

///////////////////////////////////////////////////////////////////////////////
/// handle_export_site_measurements handles the ExportSiteMeasurements
/// API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_export_site_measurements(
    db_conn: &Pool<Postgres>,
    _req: &ExportSiteMeasurementsRequest,
) -> Result<ExportSiteMeasurementsResponse, Status> {
    let site_model = SiteModel::export(db_conn)
        .await
        .map_err(|e| Status::internal(format!("export failed: {}", e)))?;

    Ok(ExportSiteMeasurementsResponse {
        model: Some(
            SiteModel::to_pb(&site_model)
                .map_err(|e| Status::internal(format!("model to pb failed: {}", e)))?,
        ),
    })
}

///////////////////////////////////////////////////////////////////////////////
/// handle_add_measurement_trusted_machine handles the
/// AddMeasurementTrustedMachine API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_add_measurement_trusted_machine(
    db_conn: &Pool<Postgres>,
    req: &AddMeasurementTrustedMachineRequest,
) -> Result<AddMeasurementTrustedMachineResponse, Status> {
    let approval_record = insert_into_approved_machines(
        db_conn,
        MockMachineId(req.machine_id.clone()),
        MeasurementApprovedType::from(req.approval_type()),
        Some(req.pcr_registers.clone()),
        Some(req.comments.clone()),
    )
    .await
    .map_err(|e| Status::internal(format!("failed to insert trusted machine approval: {}", e)))?;

    Ok(AddMeasurementTrustedMachineResponse {
        approval_record: Some(approval_record.into()),
    })
}

///////////////////////////////////////////////////////////////////////////////
/// handle_remove_measurement_trusted_machine handles the
/// RemoveMeasurementTrustedMachine API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_remove_measurement_trusted_machine(
    db_conn: &Pool<Postgres>,
    req: &RemoveMeasurementTrustedMachineRequest,
) -> Result<RemoveMeasurementTrustedMachineResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;

    let approval_record: MeasurementApprovedMachineRecord = match &req.selector {
        // Remove by approval ID.
        Some(remove_measurement_trusted_machine_request::Selector::ApprovalId(approval_uuid)) => {
            remove_from_approved_machines_by_approval_id(
                &mut txn,
                MeasurementApprovedMachineId::from_grpc(Some(approval_uuid.clone()))?,
            )
            .await
            .map_err(|e| Status::internal(format!("removal failed: {}", e)))?
        }
        // Remove by machine ID.
        Some(remove_measurement_trusted_machine_request::Selector::MachineId(machine_id)) => {
            remove_from_approved_machines_by_machine_id(&mut txn, MockMachineId(machine_id.clone()))
                .await
                .map_err(|e| Status::internal(format!("removal failed: {}", e)))?
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

///////////////////////////////////////////////////////////////////////////////
/// handle_list_measurement_trusted_machines handles the
/// ListMeasurementTrustedMachines API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_list_measurement_trusted_machines(
    db_conn: &Pool<Postgres>,
    _req: &ListMeasurementTrustedMachinesRequest,
) -> Result<ListMeasurementTrustedMachinesResponse, Status> {
    let approval_records: Vec<MeasurementApprovedMachineRecordPb> = get_approved_machines(db_conn)
        .await
        .map_err(|e| Status::internal(format!("failed to fetch machine approvals: {}", e)))?
        .into_iter()
        .map(|record| record.into())
        .collect();

    Ok(ListMeasurementTrustedMachinesResponse { approval_records })
}

///////////////////////////////////////////////////////////////////////////////
/// handle_add_measurement_trusted_profile handles the
/// AddMeasurementTrustedProfile API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_add_measurement_trusted_profile(
    db_conn: &Pool<Postgres>,
    req: &AddMeasurementTrustedProfileRequest,
) -> Result<AddMeasurementTrustedProfileResponse, Status> {
    let approval_record = insert_into_approved_profiles(
        db_conn,
        MeasurementSystemProfileId::from_grpc(req.profile_id.clone())?,
        MeasurementApprovedType::from(req.approval_type()),
        req.pcr_registers.as_ref().cloned(),
        req.comments.as_ref().cloned(),
    )
    .await
    .map_err(|e| Status::internal(format!("failed to insert trusted profile approval: {}", e)))?;

    Ok(AddMeasurementTrustedProfileResponse {
        approval_record: Some(approval_record.into()),
    })
}

///////////////////////////////////////////////////////////////////////////////
/// handle_remove_measurement_trusted_profile handles the
/// RemoveMeasurementTrustedProfile API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_remove_measurement_trusted_profile(
    db_conn: &Pool<Postgres>,
    req: &RemoveMeasurementTrustedProfileRequest,
) -> Result<RemoveMeasurementTrustedProfileResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;

    let approval_record: MeasurementApprovedProfileRecord = match &req.selector {
        // Remove by approval ID.
        Some(remove_measurement_trusted_profile_request::Selector::ApprovalId(approval_uuid)) => {
            remove_from_approved_profiles_by_approval_id(
                &mut txn,
                MeasurementApprovedProfileId::from_grpc(Some(approval_uuid.clone()))?,
            )
            .await
            .map_err(|e| Status::internal(format!("removal failed: {}", e)))?
        }
        // Remove by profile ID.
        Some(remove_measurement_trusted_profile_request::Selector::ProfileId(profile_id)) => {
            remove_from_approved_profiles_by_profile_id(
                &mut txn,
                MeasurementSystemProfileId::from_grpc(Some(profile_id.clone()))?,
            )
            .await
            .map_err(|e| Status::internal(format!("removal failed: {}", e)))?
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

///////////////////////////////////////////////////////////////////////////////
/// handle_list_measurement_trusted_profiles handles the
/// ListMeasurementTrustedProfiles API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_list_measurement_trusted_profiles(
    db_conn: &Pool<Postgres>,
    _req: &ListMeasurementTrustedProfilesRequest,
) -> Result<ListMeasurementTrustedProfilesResponse, Status> {
    let approval_records: Vec<MeasurementApprovedProfileRecordPb> = get_approved_profiles(db_conn)
        .await
        .map_err(|e| Status::internal(format!("failed to fetch profile approvals: {}", e)))?
        .into_iter()
        .map(|record| record.into())
        .collect();

    Ok(ListMeasurementTrustedProfilesResponse { approval_records })
}
