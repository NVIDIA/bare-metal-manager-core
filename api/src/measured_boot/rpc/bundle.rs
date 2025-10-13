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

use measured_boot::pcr::PcrRegisterValue;
use measured_boot::records::MeasurementBundleState;
use rpc::protos::measured_boot::{
    CreateMeasurementBundleRequest, CreateMeasurementBundleResponse,
    DeleteMeasurementBundleRequest, DeleteMeasurementBundleResponse, FindClosestBundleMatchRequest,
    ListMeasurementBundleMachinesRequest, ListMeasurementBundleMachinesResponse,
    ListMeasurementBundlesRequest, ListMeasurementBundlesResponse, MeasurementBundleRecordPb,
    RenameMeasurementBundleRequest, RenameMeasurementBundleResponse, ShowMeasurementBundleRequest,
    ShowMeasurementBundleResponse, ShowMeasurementBundlesRequest, ShowMeasurementBundlesResponse,
    UpdateMeasurementBundleRequest, UpdateMeasurementBundleResponse,
    delete_measurement_bundle_request, list_measurement_bundle_machines_request,
    rename_measurement_bundle_request, show_measurement_bundle_request,
    update_measurement_bundle_request,
};
use sqlx::{Pool, Postgres};
use tonic::Status;

use crate::db::measured_boot::bundle;
use crate::db::measured_boot::interface::bundle::{
    get_machines_for_bundle_id, get_machines_for_bundle_name,
    get_measurement_bundle_records_with_txn,
};
use crate::errors::CarbideError;
use crate::measured_boot::rpc::common::{begin_txn, commit_txn};

/// handle_create_measurement_bundle handles the CreateMeasurementBundle
/// API endpoint.
pub async fn handle_create_measurement_bundle(
    db_conn: &Pool<Postgres>,
    req: CreateMeasurementBundleRequest,
) -> Result<CreateMeasurementBundleResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let state = req.state();
    let bundle = crate::db::measured_boot::bundle::new_with_txn(
        &mut txn,
        req.profile_id
            .ok_or(CarbideError::MissingArgument("profile_id"))?,
        req.name,
        &PcrRegisterValue::from_pb_vec(req.pcr_values),
        Some(MeasurementBundleState::from(state)),
    )
    .await
    .map_err(|e| Status::internal(format!("failed to create new bundle: {e}")))?;

    commit_txn(txn).await?;
    Ok(CreateMeasurementBundleResponse {
        bundle: Some(bundle.into()),
    })
}

/// handle_delete_measurement_bundle handles the DeleteMeasurementBundle
/// API endpoint.
pub async fn handle_delete_measurement_bundle(
    db_conn: &Pool<Postgres>,
    req: DeleteMeasurementBundleRequest,
) -> Result<DeleteMeasurementBundleResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let bundle = match req.selector {
        // Delete for the given bundle ID.
        Some(delete_measurement_bundle_request::Selector::BundleId(bundle_uuid)) => {
            crate::db::measured_boot::bundle::delete_for_id_with_txn(&mut txn, bundle_uuid, false)
                .await
                .map_err(|e| Status::internal(format!("deletion failed: {e}")))?
        }

        // Delete for the given bundle name.
        Some(delete_measurement_bundle_request::Selector::BundleName(bundle_name)) => {
            crate::db::measured_boot::bundle::delete_for_name(&mut txn, bundle_name, false)
                .await
                .map_err(|e| Status::internal(format!("deletion failed: {e}")))?
        }

        // ID or name is needed.
        None => {
            return Err(Status::invalid_argument("deletion selector is required"));
        }
    };

    commit_txn(txn).await?;
    Ok(DeleteMeasurementBundleResponse {
        bundle: Some(bundle.into()),
    })
}

/// handle_rename_measurement_bundle handles the RenameMeasurementBundle
/// API endpoint.
pub async fn handle_rename_measurement_bundle(
    db_conn: &Pool<Postgres>,
    req: RenameMeasurementBundleRequest,
) -> Result<RenameMeasurementBundleResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let bundle = match req.selector {
        // Rename for the given bundle ID.
        Some(rename_measurement_bundle_request::Selector::BundleId(bundle_uuid)) => {
            crate::db::measured_boot::bundle::rename_for_id(
                &mut txn,
                bundle_uuid,
                req.new_bundle_name,
            )
            .await
            .map_err(|e| Status::internal(format!("rename failed: {e}")))?
        }

        // Rename for the given bundle name.
        Some(rename_measurement_bundle_request::Selector::BundleName(bundle_name)) => {
            crate::db::measured_boot::bundle::rename_for_name(
                &mut txn,
                bundle_name,
                req.new_bundle_name,
            )
            .await
            .map_err(|e| Status::internal(format!("rename failed: {e}")))?
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

/// handle_update_measurement_bundle handles the UpdateMeasurementBundle
/// API endpoint.
pub async fn handle_update_measurement_bundle(
    db_conn: &Pool<Postgres>,
    req: UpdateMeasurementBundleRequest,
) -> Result<UpdateMeasurementBundleResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let state = req.state();
    let bundle_id = match req.selector {
        // Update for the given bundle ID.
        Some(update_measurement_bundle_request::Selector::BundleId(bundle_uuid)) => bundle_uuid,
        // Update for the given bundle name.
        Some(update_measurement_bundle_request::Selector::BundleName(bundle_name)) => {
            crate::db::measured_boot::bundle::from_name_with_txn(&mut txn, bundle_name)
                .await
                .map_err(|e| Status::internal(format!("deletion failed: {e}")))?
                .bundle_id
        }
        // ID or name is needed.
        None => {
            return Err(Status::invalid_argument("deletion selector is required"));
        }
    };

    // And then set it in the database.
    let bundle =
        crate::db::measured_boot::bundle::set_state_for_id(&mut txn, bundle_id, state.into())
            .await
            .map_err(|e| Status::internal(format!("failed to update bundle: {e}")))?;

    commit_txn(txn).await?;
    Ok(UpdateMeasurementBundleResponse {
        bundle: Some(bundle.into()),
    })
}

/// handle_show_measurement_bundle handles the ShowMeasurementBundle
/// API endpoint.
pub async fn handle_show_measurement_bundle(
    db_conn: &Pool<Postgres>,
    req: ShowMeasurementBundleRequest,
) -> Result<ShowMeasurementBundleResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let bundle = match req.selector {
        Some(show_measurement_bundle_request::Selector::BundleId(bundle_uuid)) => {
            crate::db::measured_boot::bundle::from_id_with_txn(&mut txn, bundle_uuid)
                .await
                .map_err(|e| Status::internal(format!("{e}")))?
        }
        Some(show_measurement_bundle_request::Selector::BundleName(bundle_name)) => {
            crate::db::measured_boot::bundle::from_name_with_txn(&mut txn, bundle_name)
                .await
                .map_err(|e| Status::internal(format!("{e}")))?
        }
        None => return Err(Status::invalid_argument("selector must be provided")),
    };

    Ok(ShowMeasurementBundleResponse {
        bundle: Some(bundle.into()),
    })
}

/// handle_show_measurement_bundles handles the ShowMeasurementBundles
/// API endpoint.
pub async fn handle_show_measurement_bundles(
    db_conn: &Pool<Postgres>,
    _req: ShowMeasurementBundlesRequest,
) -> Result<ShowMeasurementBundlesResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    Ok(ShowMeasurementBundlesResponse {
        bundles: crate::db::measured_boot::bundle::get_all(&mut txn)
            .await
            .map_err(|e| Status::internal(format!("{e}")))?
            .drain(..)
            .map(|bundle| bundle.into())
            .collect(),
    })
}

/// handle_list_measurement_bundles handles the ListMeasurementBundles
/// API endpoint.
pub async fn handle_list_measurement_bundles(
    db_conn: &Pool<Postgres>,
    _req: ListMeasurementBundlesRequest,
) -> Result<ListMeasurementBundlesResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let bundles: Vec<MeasurementBundleRecordPb> = get_measurement_bundle_records_with_txn(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("{e}")))?
        .drain(..)
        .map(|record| record.into())
        .collect();

    Ok(ListMeasurementBundlesResponse { bundles })
}

/// handle_list_measurement_bundle_machines handles the
/// ListMeasurementBundleMachines API endpoint.
pub async fn handle_list_measurement_bundle_machines(
    db_conn: &Pool<Postgres>,
    req: ListMeasurementBundleMachinesRequest,
) -> Result<ListMeasurementBundleMachinesResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let machine_ids: Vec<String> = match req.selector {
        // Select by bundle ID.
        Some(list_measurement_bundle_machines_request::Selector::BundleId(bundle_uuid)) => {
            get_machines_for_bundle_id(&mut txn, bundle_uuid)
                .await
                .map_err(|e| Status::internal(format!("{e}")))?
                .drain(..)
                .map(|machine_id| machine_id.to_string())
                .collect()
        }
        // ...or by profile name.
        Some(list_measurement_bundle_machines_request::Selector::BundleName(bundle_name)) => {
            get_machines_for_bundle_name(&mut txn, bundle_name)
                .await
                .map_err(|e| Status::internal(format!("{e}")))?
                .drain(..)
                .map(|machine_id| machine_id.to_string())
                .collect()
        }
        // ...and it has to be either by ID or name.
        None => return Err(Status::invalid_argument("selector required")),
    };

    Ok(ListMeasurementBundleMachinesResponse { machine_ids })
}

pub async fn handle_find_closest_match(
    db_conn: &Pool<Postgres>,
    req: FindClosestBundleMatchRequest,
) -> Result<ShowMeasurementBundleResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;

    let report_id = req
        .report_id
        .ok_or(CarbideError::MissingArgument("report_id"))?;

    let report = crate::db::measured_boot::report::from_id_with_txn(&mut txn, report_id)
        .await
        .map_err(|e| Status::internal(format!("{e}")))?;

    // get profile
    let journal =
        crate::db::measured_boot::journal::get_journal_for_report_id(&mut txn, report_id).await?;

    let bundle = match bundle::find_closest_match_with_txn(
        &mut txn,
        journal.profile_id.ok_or(Status::invalid_argument(
            "A journal without profile detected",
        ))?,
        &report.pcr_values(),
    )
    .await?
    {
        Some(matched_bundle) => matched_bundle,
        None => {
            return Ok(ShowMeasurementBundleResponse { bundle: None });
        }
    };

    Ok(ShowMeasurementBundleResponse {
        bundle: Some(bundle.into()),
    })
}
