/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::str::FromStr;

use ::rpc::forge as rpc;
use carbide_uuid::rack::RackId;
use db::{expected_rack as db_expected_rack, rack as db_rack};
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::Api;

/// add_expected_rack creates an expected rack record and ensures a corresponding rack
/// entry exists in the racks table with the given rack_type. Returns AlreadyExists if
/// the expected rack record already exists.
pub async fn add_expected_rack(
    api: &Api,
    request: Request<rpc::ExpectedRack>,
) -> Result<Response<()>, Status> {
    let expected_rack = request.into_inner();
    let rack_id = expected_rack
        .rack_id
        .ok_or_else(|| Status::invalid_argument("rack_id is required"))?;
    let rack_type = expected_rack.rack_type.clone();
    if rack_type.is_empty() {
        return Err(Status::invalid_argument("rack_type is required"));
    }

    // Look up the rack type definition from configuration.
    let rack_type_def = api
        .runtime_config
        .rack_types
        .get(&rack_type)
        .ok_or_else(|| {
            Status::invalid_argument(format!(
                "Unknown rack_type: {}. Must be one of: {:?}",
                rack_type,
                api.runtime_config
                    .rack_types
                    .rack_types
                    .keys()
                    .collect::<Vec<_>>()
            ))
        })?
        .clone();

    let metadata = expected_rack.metadata.unwrap_or_default();
    let metadata = model::metadata::Metadata::try_from(metadata)
        .map_err(|e| Status::invalid_argument(format!("Invalid metadata: {}", e)))?;

    let mut txn = api.txn_begin().await?;

    // Check if the expected rack already exists.
    if db_expected_rack::find_by_rack_id(&mut txn, rack_id)
        .await
        .map_err(CarbideError::from)?
        .is_some()
    {
        return Err(Status::already_exists(format!(
            "Expected rack with ID {} already exists",
            rack_id
        )));
    }

    // Create the expected rack record.
    db_expected_rack::create(&mut txn, rack_id, rack_type, metadata)
        .await
        .map_err(CarbideError::from)?;

    // Ensure a rack entry exists and embed the full rack type definition.
    // The rack may have been created earlier by a device arriving first
    // with this rack_id, in which case it won't have a definition yet.
    match db_rack::get(&mut txn, rack_id).await {
        Ok(rack) => {
            if rack.config.rack_type_definition.is_some() {
                // Rack already has a definition set — don't silently overwrite it.
                return Err(Status::already_exists(format!(
                    "Rack {} already has a rack_type_definition. Use update to change it.",
                    rack_id
                )));
            }
            // Rack exists but has no definition (created by a device arriving first).
            let mut config = rack.config.clone();
            config.rack_type_definition = Some(rack_type_def);
            db_rack::update(&mut txn, rack_id, &config)
                .await
                .map_err(CarbideError::from)?;
        }
        Err(_) => {
            // No rack entry yet — create one with the definition.
            let rack = db_rack::create(&mut txn, rack_id, vec![], vec![], vec![])
                .await
                .map_err(CarbideError::from)?;
            let mut config = rack.config.clone();
            config.rack_type_definition = Some(rack_type_def);
            db_rack::update(&mut txn, rack_id, &config)
                .await
                .map_err(CarbideError::from)?;
        }
    }

    txn.commit().await?;
    Ok(Response::new(()))
}

/// delete_expected_rack deletes an expected rack by its rack_id.
pub async fn delete_expected_rack(
    api: &Api,
    request: Request<rpc::ExpectedRackRequest>,
) -> Result<Response<()>, Status> {
    let req = request.into_inner();
    let rack_id = RackId::from_str(&req.rack_id)
        .map_err(|e| Status::invalid_argument(format!("Invalid rack ID: {}", e)))?;
    let mut txn = api.txn_begin().await?;
    db_expected_rack::delete(rack_id, &mut txn)
        .await
        .map_err(CarbideError::from)?;
    txn.commit().await?;
    Ok(Response::new(()))
}

/// update_expected_rack updates an existing expected rack's rack_type and metadata.
pub async fn update_expected_rack(
    api: &Api,
    request: Request<rpc::ExpectedRack>,
) -> Result<Response<()>, Status> {
    let expected_rack = request.into_inner();
    let rack_id = expected_rack
        .rack_id
        .ok_or_else(|| Status::invalid_argument("rack_id is required"))?;
    let rack_type = expected_rack.rack_type.clone();
    if rack_type.is_empty() {
        return Err(Status::invalid_argument("rack_type is required"));
    }

    // Look up the rack type definition from configuration.
    let rack_type_def = api
        .runtime_config
        .rack_types
        .get(&rack_type)
        .ok_or_else(|| {
            Status::invalid_argument(format!(
                "Unknown rack_type: {}. Must be one of: {:?}",
                rack_type,
                api.runtime_config
                    .rack_types
                    .rack_types
                    .keys()
                    .collect::<Vec<_>>()
            ))
        })?
        .clone();

    let metadata = expected_rack.metadata.unwrap_or_default();
    let metadata = model::metadata::Metadata::try_from(metadata)
        .map_err(|e| Status::invalid_argument(format!("Invalid metadata: {}", e)))?;

    let mut txn = api.txn_begin().await?;
    let mut existing = db_expected_rack::find_by_rack_id(&mut txn, rack_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| Status::not_found(format!("Expected rack with ID {} not found", rack_id)))?;

    db_expected_rack::update(&mut existing, &mut txn, rack_type, metadata)
        .await
        .map_err(CarbideError::from)?;

    // Update the embedded rack type definition in the rack config.
    if let Ok(rack) = db_rack::get(&mut txn, rack_id).await {
        let mut config = rack.config.clone();
        config.rack_type_definition = Some(rack_type_def);
        db_rack::update(&mut txn, rack_id, &config)
            .await
            .map_err(CarbideError::from)?;
    }

    txn.commit().await?;
    Ok(Response::new(()))
}

/// get_expected_rack returns a specific expected rack by its rack_id.
pub async fn get_expected_rack(
    api: &Api,
    request: Request<rpc::ExpectedRackRequest>,
) -> Result<Response<rpc::ExpectedRack>, Status> {
    let req = request.into_inner();
    let rack_id = RackId::from_str(&req.rack_id)
        .map_err(|e| Status::invalid_argument(format!("Invalid rack ID: {}", e)))?;
    let mut txn = api.txn_begin().await?;
    let expected_rack = db_expected_rack::find_by_rack_id(&mut txn, rack_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| Status::not_found(format!("Expected rack with ID {} not found", rack_id)))?;
    txn.commit().await?;
    Ok(Response::new(rpc::ExpectedRack::from(expected_rack)))
}

/// get_all_expected_racks returns all expected racks.
pub async fn get_all_expected_racks(
    api: &Api,
    _request: Request<()>,
) -> Result<Response<rpc::ExpectedRackList>, Status> {
    let mut txn = api.txn_begin().await?;
    let expected_racks = db_expected_rack::find_all(&mut txn)
        .await
        .map_err(CarbideError::from)?;
    txn.commit().await?;
    let expected_racks: Vec<rpc::ExpectedRack> = expected_racks
        .into_iter()
        .map(rpc::ExpectedRack::from)
        .collect();
    Ok(Response::new(rpc::ExpectedRackList { expected_racks }))
}

/// replace_all_expected_racks clears all expected racks and creates new ones from the request.
pub async fn replace_all_expected_racks(
    api: &Api,
    request: Request<rpc::ExpectedRackList>,
) -> Result<Response<()>, Status> {
    let req = request.into_inner();
    let mut txn = api.txn_begin().await?;

    db_expected_rack::clear(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    for expected_rack in req.expected_racks {
        let rack_id = expected_rack
            .rack_id
            .ok_or_else(|| Status::invalid_argument("rack_id is required"))?;
        let rack_type = expected_rack.rack_type.clone();
        if rack_type.is_empty() {
            return Err(Status::invalid_argument("rack_type is required"));
        }
        if api.runtime_config.rack_types.get(&rack_type).is_none() {
            return Err(Status::invalid_argument(format!(
                "Unknown rack_type: {}",
                rack_type
            )));
        }
        let metadata = expected_rack.metadata.unwrap_or_default();
        let metadata = model::metadata::Metadata::try_from(metadata)
            .map_err(|e| Status::invalid_argument(format!("Invalid metadata: {}", e)))?;
        db_expected_rack::create(&mut txn, rack_id, rack_type, metadata)
            .await
            .map_err(CarbideError::from)?;
    }

    txn.commit().await?;
    Ok(Response::new(()))
}

/// delete_all_expected_racks deletes all expected racks.
pub async fn delete_all_expected_racks(
    api: &Api,
    _request: Request<()>,
) -> Result<Response<()>, Status> {
    let mut txn = api.txn_begin().await?;
    db_expected_rack::clear(&mut txn)
        .await
        .map_err(CarbideError::from)?;
    txn.commit().await?;
    Ok(Response::new(()))
}
