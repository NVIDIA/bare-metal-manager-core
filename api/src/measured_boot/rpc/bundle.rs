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
 * gRPC handlers for measurement bundle related API calls.
 */

use tonic::Status;

use crate::measured_boot::interface::bundle::get_measurement_bundle_records_with_txn;
use crate::measured_boot::interface::common::PcrRegisterValue;
use crate::measured_boot::rpc::common::{begin_txn, commit_txn};
use crate::measured_boot::{
    dto::keys::MeasurementBundleId,
    interface::bundle::{get_machines_for_bundle_id, get_machines_for_bundle_name},
};
use rpc::protos::measured_boot::{
    CreateMeasurementBundleRequest, CreateMeasurementBundleResponse,
    DeleteMeasurementBundleRequest, DeleteMeasurementBundleResponse,
    ListMeasurementBundleMachinesRequest, ListMeasurementBundleMachinesResponse,
    ListMeasurementBundlesRequest, ListMeasurementBundlesResponse, MeasurementBundleRecordPb,
    RenameMeasurementBundleRequest, RenameMeasurementBundleResponse, ShowMeasurementBundleRequest,
    ShowMeasurementBundleResponse, ShowMeasurementBundlesRequest, ShowMeasurementBundlesResponse,
    UpdateMeasurementBundleRequest, UpdateMeasurementBundleResponse,
};
use sqlx::{Pool, Postgres};

use crate::measured_boot::dto::keys::MeasurementSystemProfileId;
use crate::measured_boot::dto::records::MeasurementBundleState;
use crate::measured_boot::model::bundle::MeasurementBundle;
use rpc::protos::measured_boot::delete_measurement_bundle_request;
use rpc::protos::measured_boot::list_measurement_bundle_machines_request;
use rpc::protos::measured_boot::rename_measurement_bundle_request;
use rpc::protos::measured_boot::show_measurement_bundle_request;
use rpc::protos::measured_boot::update_measurement_bundle_request;

///////////////////////////////////////////////////////////////////////////////
/// handle_create_measurement_bundle handles the CreateMeasurementBundle
/// API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_create_measurement_bundle(
    db_conn: &Pool<Postgres>,
    req: &CreateMeasurementBundleRequest,
) -> Result<CreateMeasurementBundleResponse, Status> {
    let state = MeasurementBundleState::from(req.state());
    let bundle = MeasurementBundle::new(
        db_conn,
        MeasurementSystemProfileId::from_grpc(req.profile_id.clone())?,
        req.name.as_ref().cloned(),
        &PcrRegisterValue::from_pb_vec(&req.pcr_values),
        Some(state),
    )
    .await
    .map_err(|e| Status::internal(format!("failed to create new bundle: {}", e)))?;

    Ok(CreateMeasurementBundleResponse {
        bundle: Some(bundle.into()),
    })
}

///////////////////////////////////////////////////////////////////////////////
/// handle_delete_measurement_bundle handles the DeleteMeasurementBundle
/// API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_delete_measurement_bundle(
    db_conn: &Pool<Postgres>,
    req: &DeleteMeasurementBundleRequest,
) -> Result<DeleteMeasurementBundleResponse, Status> {
    let bundle = match &req.selector {
        // Delete for the given bundle ID.
        Some(delete_measurement_bundle_request::Selector::BundleId(bundle_uuid)) => {
            MeasurementBundle::delete_for_id(
                db_conn,
                MeasurementBundleId::from_grpc(Some(bundle_uuid.clone()))?,
                false,
            )
            .await
            .map_err(|e| Status::internal(format!("deletion failed: {}", e)))?
        }

        // Delete for the given bundle name.
        Some(delete_measurement_bundle_request::Selector::BundleName(bundle_name)) => {
            MeasurementBundle::delete_for_name(db_conn, bundle_name.clone(), false)
                .await
                .map_err(|e| Status::internal(format!("deletion failed: {}", e)))?
        }

        // ID or name is needed.
        None => {
            return Err(Status::invalid_argument("deletion selector is required"));
        }
    };

    Ok(DeleteMeasurementBundleResponse {
        bundle: Some(bundle.into()),
    })
}

///////////////////////////////////////////////////////////////////////////////
/// handle_rename_measurement_bundle handles the RenameMeasurementBundle
/// API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_rename_measurement_bundle(
    db_conn: &Pool<Postgres>,
    req: &RenameMeasurementBundleRequest,
) -> Result<RenameMeasurementBundleResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let bundle = match &req.selector {
        // Rename for the given bundle ID.
        Some(rename_measurement_bundle_request::Selector::BundleId(bundle_uuid)) => {
            MeasurementBundle::rename_for_id(
                &mut txn,
                MeasurementBundleId::from_grpc(Some(bundle_uuid.clone()))?,
                req.new_bundle_name.clone(),
            )
            .await
            .map_err(|e| Status::internal(format!("rename failed: {}", e)))?
        }

        // Rename for the given bundle name.
        Some(rename_measurement_bundle_request::Selector::BundleName(bundle_name)) => {
            MeasurementBundle::rename_for_name(
                &mut txn,
                bundle_name.clone(),
                req.new_bundle_name.clone(),
            )
            .await
            .map_err(|e| Status::internal(format!("rename failed: {}", e)))?
        }

        // ID or name is needed.
        None => {
            return Err(Status::invalid_argument("rename selector is required"));
        }
    };

    commit_txn(txn).await?;

    Ok(RenameMeasurementBundleResponse {
        bundle: Some(bundle.into()),
    })
}

///////////////////////////////////////////////////////////////////////////////
/// handle_update_measurement_bundle handles the UpdateMeasurementBundle
/// API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_update_measurement_bundle(
    db_conn: &Pool<Postgres>,
    req: &UpdateMeasurementBundleRequest,
) -> Result<UpdateMeasurementBundleResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;

    let bundle_id = match &req.selector {
        // Update for the given bundle ID.
        Some(update_measurement_bundle_request::Selector::BundleId(bundle_uuid)) => {
            MeasurementBundleId::from_grpc(Some(bundle_uuid.clone()))?
        }
        // Update for the given bundle name.
        Some(update_measurement_bundle_request::Selector::BundleName(bundle_name)) => {
            MeasurementBundle::from_name_with_txn(&mut txn, bundle_name.clone())
                .await
                .map_err(|e| Status::internal(format!("deletion failed: {}", e)))?
                .bundle_id
        }
        // ID or name is needed.
        None => {
            return Err(Status::invalid_argument("deletion selector is required"));
        }
    };

    // And then set it in the database.
    let bundle = MeasurementBundle::set_state_for_id(&mut txn, bundle_id, req.state().into())
        .await
        .map_err(|e| Status::internal(format!("failed to update bundle: {}", e)))?;

    commit_txn(txn).await?;

    Ok(UpdateMeasurementBundleResponse {
        bundle: Some(bundle.into()),
    })
}

///////////////////////////////////////////////////////////////////////////////
/// handle_show_measurement_bundle handles the ShowMeasurementBundle
/// API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_show_measurement_bundle(
    db_conn: &Pool<Postgres>,
    req: &ShowMeasurementBundleRequest,
) -> Result<ShowMeasurementBundleResponse, Status> {
    let bundle = match &req.selector {
        Some(show_measurement_bundle_request::Selector::BundleId(bundle_uuid)) => {
            MeasurementBundle::from_id(
                db_conn,
                MeasurementBundleId::from_grpc(Some(bundle_uuid.clone()))?,
            )
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
        }
        Some(show_measurement_bundle_request::Selector::BundleName(bundle_name)) => {
            MeasurementBundle::from_name(db_conn, bundle_name.clone())
                .await
                .map_err(|e| Status::internal(format!("{}", e)))?
        }
        None => return Err(Status::invalid_argument("selector must be provided")),
    };

    Ok(ShowMeasurementBundleResponse {
        bundle: Some(bundle.into()),
    })
}

///////////////////////////////////////////////////////////////////////////////
/// handle_show_measurement_bundles handles the ShowMeasurementBundles
/// API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_show_measurement_bundles(
    db_conn: &Pool<Postgres>,
    _req: &ShowMeasurementBundlesRequest,
) -> Result<ShowMeasurementBundlesResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    Ok(ShowMeasurementBundlesResponse {
        bundles: MeasurementBundle::get_all(&mut txn)
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
            .drain(..)
            .map(|bundle| bundle.into())
            .collect(),
    })
}

///////////////////////////////////////////////////////////////////////////////
/// handle_list_measurement_bundles handles the ListMeasurementBundles
/// API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_list_measurement_bundles(
    db_conn: &Pool<Postgres>,
    _req: &ListMeasurementBundlesRequest,
) -> Result<ListMeasurementBundlesResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let bundles: Vec<MeasurementBundleRecordPb> = get_measurement_bundle_records_with_txn(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("{}", e)))?
        .drain(..)
        .map(|record| record.into())
        .collect();

    Ok(ListMeasurementBundlesResponse { bundles })
}

///////////////////////////////////////////////////////////////////////////////
/// handle_list_measurement_bundle_machines handles the
/// ListMeasurementBundleMachines API endpoint.
///////////////////////////////////////////////////////////////////////////////

pub async fn handle_list_measurement_bundle_machines(
    db_conn: &Pool<Postgres>,
    req: &ListMeasurementBundleMachinesRequest,
) -> Result<ListMeasurementBundleMachinesResponse, Status> {
    let machine_ids: Vec<String> = match &req.selector {
        // Select by bundle ID.
        Some(list_measurement_bundle_machines_request::Selector::BundleId(bundle_uuid)) => {
            get_machines_for_bundle_id(
                db_conn,
                MeasurementBundleId::from_grpc(Some(bundle_uuid.clone()))?,
            )
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
            .drain(..)
            .map(|machine_id| machine_id.to_string())
            .collect()
        }
        // ...or by profile name.
        Some(list_measurement_bundle_machines_request::Selector::BundleName(bundle_name)) => {
            get_machines_for_bundle_name(db_conn, bundle_name.clone())
                .await
                .map_err(|e| Status::internal(format!("{}", e)))?
                .drain(..)
                .map(|machine_id| machine_id.to_string())
                .collect()
        }
        // ...and it has to be either by ID or name.
        None => return Err(Status::invalid_argument("selector required")),
    };

    Ok(ListMeasurementBundleMachinesResponse { machine_ids })
}
