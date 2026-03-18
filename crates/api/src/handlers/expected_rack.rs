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
use model::expected_rack::ExpectedRack;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::Api;

/// add_expected_rack creates an expected rack record and a corresponding rack
/// entry in the racks table with the embedded capabilities. Returns
/// AlreadyExists if the expected rack record already exists.
pub async fn add_expected_rack(
    api: &Api,
    request: Request<rpc::ExpectedRack>,
) -> Result<Response<()>, Status> {
    let rack: ExpectedRack = request
        .into_inner()
        .try_into()
        .map_err(CarbideError::from)?;

    // Validate the rack_type exists in configuration.
    if api.runtime_config.rack_types.get(&rack.rack_type).is_none() {
        return Err(CarbideError::InvalidArgument(format!(
            "Unknown rack_type: {}. Must be one of: {:?}",
            rack.rack_type,
            api.runtime_config
                .rack_types
                .rack_types
                .keys()
                .collect::<Vec<_>>()
        ))
        .into());
    }

    let rack_id = rack.rack_id;
    let rack_type = rack.rack_type.clone();

    let mut txn = api.txn_begin().await?;

    // Check if the expected rack already exists.
    if db_expected_rack::find_by_rack_id(&mut txn, rack_id)
        .await
        .map_err(CarbideError::from)?
        .is_some()
    {
        return Err(CarbideError::AlreadyFoundError {
            kind: "expected_rack",
            id: rack_id.to_string(),
        }
        .into());
    }

    // Create the expected rack record.
    db_expected_rack::create(&mut txn, rack)
        .await
        .map_err(CarbideError::from)?;

    // Create the rack entry with the rack_type name. Expected racks are the
    // only way rack entries get created.
    let db_rack = db_rack::create(&mut txn, rack_id, vec![], vec![], vec![])
        .await
        .map_err(CarbideError::from)?;
    let mut config = db_rack.config.clone();
    config.rack_type = Some(rack_type);
    db_rack::update(&mut txn, rack_id, &config)
        .await
        .map_err(CarbideError::from)?;

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
        .map_err(|e| CarbideError::InvalidArgument(format!("Invalid rack ID: {}", e)))?;
    let mut txn = api.txn_begin().await?;
    db_expected_rack::delete(&mut txn, rack_id)
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
    let rack: ExpectedRack = request
        .into_inner()
        .try_into()
        .map_err(CarbideError::from)?;

    // Validate the rack_type exists in configuration.
    if api.runtime_config.rack_types.get(&rack.rack_type).is_none() {
        return Err(CarbideError::InvalidArgument(format!(
            "Unknown rack_type: {}. Must be one of: {:?}",
            rack.rack_type,
            api.runtime_config
                .rack_types
                .rack_types
                .keys()
                .collect::<Vec<_>>()
        ))
        .into());
    }

    let rack_id = rack.rack_id;
    let rack_type = rack.rack_type.clone();

    let mut txn = api.txn_begin().await?;
    db_expected_rack::find_by_rack_id(&mut txn, rack_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "expected_rack",
            id: rack_id.to_string(),
        })?;

    db_expected_rack::update(&mut txn, &rack)
        .await
        .map_err(CarbideError::from)?;

    // Update the rack_type name in the rack config.
    if let Ok(db_rack) = db_rack::get(&mut txn, rack_id).await {
        let mut config = db_rack.config.clone();
        config.rack_type = Some(rack_type);
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
        .map_err(|e| CarbideError::InvalidArgument(format!("Invalid rack ID: {}", e)))?;
    let mut txn = api.txn_begin().await?;
    let expected_rack = db_expected_rack::find_by_rack_id(&mut txn, rack_id)
        .await
        .map_err(CarbideError::from)?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "expected_rack",
            id: rack_id.to_string(),
        })?;
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
        let rack: ExpectedRack = expected_rack.try_into().map_err(CarbideError::from)?;

        if api.runtime_config.rack_types.get(&rack.rack_type).is_none() {
            return Err(CarbideError::InvalidArgument(format!(
                "Unknown rack_type: {}",
                rack.rack_type
            ))
            .into());
        }

        db_expected_rack::create(&mut txn, rack)
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
