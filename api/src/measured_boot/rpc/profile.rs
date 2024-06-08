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
 * gRPC handlers for measurement profile related API calls.
 */

use tonic::Status;

use crate::measured_boot::dto::keys::MeasurementSystemProfileId;
use crate::measured_boot::interface::profile::{
    export_measurement_profile_records, get_bundles_for_profile_id, get_bundles_for_profile_name,
    get_machines_for_profile_id, get_machines_for_profile_name,
};
use crate::measured_boot::model::profile::MeasurementSystemProfile;
use crate::measured_boot::rpc::common::{begin_txn, commit_txn};
use rpc::protos::measured_boot::delete_measurement_system_profile_request;
use rpc::protos::measured_boot::list_measurement_system_profile_bundles_request;
use rpc::protos::measured_boot::list_measurement_system_profile_machines_request;
use rpc::protos::measured_boot::rename_measurement_system_profile_request;
use rpc::protos::measured_boot::show_measurement_system_profile_request;
use rpc::protos::measured_boot::{
    CreateMeasurementSystemProfileRequest, CreateMeasurementSystemProfileResponse,
    DeleteMeasurementSystemProfileRequest, DeleteMeasurementSystemProfileResponse,
    ListMeasurementSystemProfileBundlesRequest, ListMeasurementSystemProfileBundlesResponse,
    ListMeasurementSystemProfileMachinesRequest, ListMeasurementSystemProfileMachinesResponse,
    ListMeasurementSystemProfilesRequest, ListMeasurementSystemProfilesResponse,
    MeasurementSystemProfileRecordPb, RenameMeasurementSystemProfileRequest,
    RenameMeasurementSystemProfileResponse, ShowMeasurementSystemProfileRequest,
    ShowMeasurementSystemProfileResponse, ShowMeasurementSystemProfilesRequest,
    ShowMeasurementSystemProfilesResponse, Uuid,
};
use sqlx::{Pool, Postgres};
use std::collections::HashMap;

/// handle_create_system_measurement_profile handles the
/// CreateMeasurementSystemProfile API endpoint.
pub async fn handle_create_system_measurement_profile(
    db_conn: &Pool<Postgres>,
    req: &CreateMeasurementSystemProfileRequest,
) -> Result<CreateMeasurementSystemProfileResponse, Status> {
    // Vendor and product are the two baseline attrs, so
    // just treat them as requirements, and then smash the
    // remaining ones on as "extra-attrs".
    let mut vals = HashMap::from([
        (String::from("vendor"), req.vendor.clone()),
        (String::from("product"), req.product.clone()),
    ]);
    for kv_pair in req.extra_attrs.iter() {
        vals.insert(kv_pair.key.clone(), kv_pair.value.clone());
    }

    Ok(CreateMeasurementSystemProfileResponse {
        system_profile: Some(
            MeasurementSystemProfile::new(db_conn, req.name.clone(), &vals)
                .await
                .map_err(|e| Status::invalid_argument(e.to_string()))?
                .into(),
        ),
    })
}

/// handle_rename_measurement_system_profile handles the
/// RenameMeasurementSystemProfile API endpoint.
pub async fn handle_rename_measurement_system_profile(
    db_conn: &Pool<Postgres>,
    req: &RenameMeasurementSystemProfileRequest,
) -> Result<RenameMeasurementSystemProfileResponse, Status> {
    let mut txn = begin_txn(db_conn).await?;
    let profile = match &req.selector {
        // Rename for the given system_profile ID.
        Some(rename_measurement_system_profile_request::Selector::ProfileId(
            system_profile_uuid,
        )) => MeasurementSystemProfile::rename_for_id(
            &mut txn,
            MeasurementSystemProfileId::from_grpc(Some(system_profile_uuid.clone()))?,
            req.new_profile_name.clone(),
        )
        .await
        .map_err(|e| Status::internal(format!("rename failed: {}", e)))?,

        // Rename for the given system_profile name.
        Some(rename_measurement_system_profile_request::Selector::ProfileName(
            system_profile_name,
        )) => MeasurementSystemProfile::rename_for_name(
            &mut txn,
            system_profile_name.clone(),
            req.new_profile_name.clone(),
        )
        .await
        .map_err(|e| Status::internal(format!("rename failed: {}", e)))?,

        // ID or name is needed.
        None => {
            return Err(Status::invalid_argument("rename selector is required"));
        }
    };

    commit_txn(txn).await?;

    Ok(RenameMeasurementSystemProfileResponse {
        profile: Some(profile.into()),
    })
}

/// handle_delete_measurement_system_profile handles the
/// DeleteMeasurementSystemProfile API endpoint.
pub async fn handle_delete_measurement_system_profile(
    db_conn: &Pool<Postgres>,
    req: &DeleteMeasurementSystemProfileRequest,
) -> Result<DeleteMeasurementSystemProfileResponse, Status> {
    let profile: Option<MeasurementSystemProfile> = match &req.selector {
        // Deleting a profile based on profile ID.
        Some(delete_measurement_system_profile_request::Selector::ProfileId(profile_uuid)) => {
            delete_for_uuid(db_conn, profile_uuid.clone()).await?
        }
        // Deleting a profile based on profile name.
        Some(delete_measurement_system_profile_request::Selector::ProfileName(profile_name)) => {
            delete_for_name(db_conn, profile_name.clone()).await?
        }
        // Trying to delete a profile without a selector.
        None => return Err(Status::invalid_argument("profile selector is required")),
    };

    if let Some(system_profile) = profile {
        Ok(DeleteMeasurementSystemProfileResponse {
            system_profile: Some(system_profile.into()),
        })
    } else {
        Err(Status::not_found(
            "profile not found with provided selector",
        ))
    }
}

/// handle_show_measurement_system_profile handles the
/// ShowMeasurementSystemProfile API endpoint.
pub async fn handle_show_measurement_system_profile(
    db_conn: &Pool<Postgres>,
    req: &ShowMeasurementSystemProfileRequest,
) -> Result<ShowMeasurementSystemProfileResponse, Status> {
    let system_profile = match &req.selector {
        // Show a system profile with the given profile ID.
        Some(show_measurement_system_profile_request::Selector::ProfileId(profile_uuid)) => {
            MeasurementSystemProfile::load_from_id(
                db_conn,
                MeasurementSystemProfileId::from_grpc(Some(profile_uuid.clone()))?,
            )
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
        }
        // Show a system profile with the given profile name.
        Some(show_measurement_system_profile_request::Selector::ProfileName(profile_name)) => {
            MeasurementSystemProfile::load_from_name(db_conn, profile_name.clone())
                .await
                .map_err(|e| Status::internal(format!("{}", e)))?
        }
        // Show all system profiles.
        None => return Err(Status::invalid_argument("selector required")),
    };

    Ok(ShowMeasurementSystemProfileResponse {
        system_profile: Some(system_profile.into()),
    })
}

/// handle_show_measurement_system_profiles handles the
/// ShowMeasurementSystemProfiles API endpoint.
pub async fn handle_show_measurement_system_profiles(
    db_conn: &Pool<Postgres>,
    _req: &ShowMeasurementSystemProfilesRequest,
) -> Result<ShowMeasurementSystemProfilesResponse, Status> {
    Ok(ShowMeasurementSystemProfilesResponse {
        system_profiles: MeasurementSystemProfile::get_all(db_conn)
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
            .drain(..)
            .map(|profile| profile.into())
            .collect(),
    })
}

/// handle_list_measurement_system_profiles handles the
/// ListMeasurementSystemProfiles API endpoint.
pub async fn handle_list_measurement_system_profiles(
    db_conn: &Pool<Postgres>,
    _req: &ListMeasurementSystemProfilesRequest,
) -> Result<ListMeasurementSystemProfilesResponse, Status> {
    let system_profiles: Vec<MeasurementSystemProfileRecordPb> =
        export_measurement_profile_records(db_conn)
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
            .drain(..)
            .map(|record| record.into())
            .collect();

    Ok(ListMeasurementSystemProfilesResponse { system_profiles })
}

/// handle_list_measurement_system_profile_bundles handles the
/// ListMeasurementSystemProfileBundles API endpoint.
pub async fn handle_list_measurement_system_profile_bundles(
    db_conn: &Pool<Postgres>,
    req: &ListMeasurementSystemProfileBundlesRequest,
) -> Result<ListMeasurementSystemProfileBundlesResponse, Status> {
    let bundle_ids: Vec<Uuid> = match &req.selector {
        // ...and do it by profile ID.
        Some(list_measurement_system_profile_bundles_request::Selector::ProfileId(
            profile_uuid,
        )) => get_bundles_for_profile_id(
            db_conn,
            MeasurementSystemProfileId::from_grpc(Some(profile_uuid.clone()))?,
        )
        .await
        .map_err(|e| Status::internal(format!("{}", e)))?
        .drain(..)
        .map(|bundle_id| bundle_id.into())
        .collect(),

        // ...or do it by profile name.
        Some(list_measurement_system_profile_bundles_request::Selector::ProfileName(
            profile_name,
        )) => get_bundles_for_profile_name(db_conn, profile_name.clone())
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
            .drain(..)
            .map(|bundle_id| bundle_id.into())
            .collect(),

        // ... either a UUID or name is required.
        None => return Err(Status::invalid_argument("selector required")),
    };

    Ok(ListMeasurementSystemProfileBundlesResponse { bundle_ids })
}

/// handle_list_measurement_system_profile_machines handles the
/// ListMeasurementSystemProfileMachines API endpoint.
pub async fn handle_list_measurement_system_profile_machines(
    db_conn: &Pool<Postgres>,
    req: &ListMeasurementSystemProfileMachinesRequest,
) -> Result<ListMeasurementSystemProfileMachinesResponse, Status> {
    let machine_ids: Vec<String> = match &req.selector {
        // ...and do it by profile ID.
        Some(list_measurement_system_profile_machines_request::Selector::ProfileId(profile_id)) => {
            get_machines_for_profile_id(
                db_conn,
                MeasurementSystemProfileId::from_grpc(Some(profile_id.clone()))?,
            )
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
            .drain(..)
            .map(|machine_id| machine_id.to_string())
            .collect()
        }
        // ...or do it by profile name.
        Some(list_measurement_system_profile_machines_request::Selector::ProfileName(
            profile_name,
        )) => get_machines_for_profile_name(db_conn, profile_name.clone())
            .await
            .map_err(|e| Status::internal(format!("{}", e)))?
            .drain(..)
            .map(|machine_id| machine_id.to_string())
            .collect(),
        // ...and it has to be either by ID or name.
        None => return Err(Status::invalid_argument("selector required")),
    };

    Ok(ListMeasurementSystemProfileMachinesResponse { machine_ids })
}

/// delete_for_uuid specifically handles deleting
/// a system profile by ID.
async fn delete_for_uuid(
    db_conn: &Pool<Postgres>,
    profile_uuid: Uuid,
) -> Result<Option<MeasurementSystemProfile>, Status> {
    match MeasurementSystemProfileId::try_from(profile_uuid) {
        Ok(profile_id) => {
            match MeasurementSystemProfile::delete_for_id(db_conn, profile_id).await {
                Ok(optional_profile) => Ok(optional_profile),
                Err(e) => Err(Status::internal(format!("error deleting profile: {}", e))),
            }
        }
        Err(e) => Err(Status::invalid_argument(format!(
            "input profile UUID failed translation: {}",
            e
        ))),
    }
}

/// delete_for_name specifically handles deleting
/// a system profile by name.
async fn delete_for_name(
    db_conn: &Pool<Postgres>,
    profile_name: String,
) -> Result<Option<MeasurementSystemProfile>, Status> {
    match MeasurementSystemProfile::delete_for_name(db_conn, profile_name).await {
        Ok(optional_profile) => Ok(optional_profile),
        Err(e) => Err(Status::internal(format!("error deleting profile: {}", e))),
    }
}
