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

use ::rpc::forge as rpc;
use db::switch as db_switch;
use tonic::{Request, Response, Status};

use crate::api::Api;

pub async fn find_switch(
    api: &Api,
    request: Request<rpc::SwitchQuery>,
) -> Result<Response<rpc::SwitchList>, Status> {
    let query = request.into_inner();
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    // Handle ID search (takes precedence)
    let switch_list = if let Some(id) = query.switch_id {
        db_switch::find_by(
            &mut txn,
            db::ObjectColumnFilter::One(db_switch::IdColumn, &id),
            db_switch::SwitchSearchConfig::default(),
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to find switch: {}", e)))?
    } else if let Some(name) = query.name {
        // Handle name search
        db_switch::find_by(
            &mut txn,
            db::ObjectColumnFilter::One(db_switch::NameColumn, &name),
            db_switch::SwitchSearchConfig::default(),
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to find switch: {}", e)))?
    } else {
        // No filter - return all
        db_switch::find_by(
            &mut txn,
            db::ObjectColumnFilter::<db_switch::IdColumn>::All,
            db_switch::SwitchSearchConfig::default(),
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to find switch: {}", e)))?
    };

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    let switches: Vec<rpc::Switch> = switch_list
        .into_iter()
        .map(rpc::Switch::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| Status::internal(format!("Failed to convert switch: {}", e)))?;

    Ok(Response::new(rpc::SwitchList { switches }))
}

// TODO: block if switch is in use (firmware update, etc.)
pub async fn delete_switch(
    api: &Api,
    request: Request<rpc::SwitchDeletionRequest>,
) -> Result<Response<rpc::SwitchDeletionResult>, Status> {
    let req = request.into_inner();

    let switch_id = match req.id {
        Some(id) => id,
        None => return Err(Status::invalid_argument("Switch ID is required")),
    };

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    let mut switch_list = db_switch::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db_switch::IdColumn, &switch_id),
        db_switch::SwitchSearchConfig::default(),
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to find switch: {}", e)))?;

    if switch_list.is_empty() {
        return Err(Status::not_found(format!("Switch {} not found", switch_id)));
    }

    let switch = switch_list.first_mut().unwrap();
    db_switch::mark_as_deleted(switch, &mut txn)
        .await
        .map_err(|e| Status::internal(format!("Failed to delete switch: {}", e)))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    Ok(Response::new(rpc::SwitchDeletionResult {}))
}
