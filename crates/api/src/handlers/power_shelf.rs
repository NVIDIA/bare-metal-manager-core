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

use ::rpc::forge as rpc;
use db::power_shelf as db_power_shelf;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::Api;

pub async fn find_power_shelf(
    api: &Api,
    request: Request<rpc::PowerShelfQuery>,
) -> Result<Response<rpc::PowerShelfList>, Status> {
    let query = request.into_inner();
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| CarbideError::Internal {
            message: format!("Database error: {}", e),
        })?;

    // Handle ID search (takes precedence)
    let power_shelf_list = if let Some(id) = query.power_shelf_id {
        db_power_shelf::find_by(
            &mut txn,
            db::ObjectColumnFilter::One(db_power_shelf::IdColumn, &id),
            db_power_shelf::PowerShelfSearchConfig::default(),
        )
        .await
        .map_err(|e| CarbideError::Internal {
            message: format!("Failed to find power shelf: {}", e),
        })?
    } else if let Some(name) = query.name {
        // Handle name search
        db_power_shelf::find_by(
            &mut txn,
            db::ObjectColumnFilter::One(db_power_shelf::NameColumn, &name),
            db_power_shelf::PowerShelfSearchConfig::default(),
        )
        .await
        .map_err(|e| CarbideError::Internal {
            message: format!("Failed to find power shelf: {}", e),
        })?
    } else {
        // No filter - return all
        db_power_shelf::find_by(
            &mut txn,
            db::ObjectColumnFilter::<db_power_shelf::IdColumn>::All,
            db_power_shelf::PowerShelfSearchConfig::default(),
        )
        .await
        .map_err(|e| CarbideError::Internal {
            message: format!("Failed to find power shelf: {}", e),
        })?
    };

    txn.commit().await.map_err(|e| CarbideError::Internal {
        message: format!("Failed to commit transaction: {}", e),
    })?;

    let power_shelves: Vec<rpc::PowerShelf> = power_shelf_list
        .into_iter()
        .map(rpc::PowerShelf::try_from)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| CarbideError::Internal {
            message: format!("Failed to convert power shelf: {}", e),
        })?;

    Ok(Response::new(rpc::PowerShelfList { power_shelves }))
}

pub async fn delete_power_shelf(
    api: &Api,
    request: Request<rpc::PowerShelfDeletionRequest>,
) -> Result<Response<rpc::PowerShelfDeletionResult>, Status> {
    let req = request.into_inner();

    let power_shelf_id = match req.id {
        Some(id) => id,
        None => {
            return Err(
                CarbideError::InvalidArgument("Power shelf ID is required".to_string()).into(),
            );
        }
    };

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| CarbideError::Internal {
            message: format!("Database error: {}", e),
        })?;

    let mut power_shelf_list = db_power_shelf::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db_power_shelf::IdColumn, &power_shelf_id),
        db_power_shelf::PowerShelfSearchConfig::default(),
    )
    .await
    .map_err(|e| CarbideError::Internal {
        message: format!("Failed to find power shelf: {}", e),
    })?;

    if power_shelf_list.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "power_shelf",
            id: power_shelf_id.to_string(),
        }
        .into());
    }

    let power_shelf = power_shelf_list.first_mut().unwrap();
    db_power_shelf::mark_as_deleted(power_shelf, &mut txn)
        .await
        .map_err(|e| CarbideError::Internal {
            message: format!("Failed to delete power shelf: {}", e),
        })?;

    txn.commit().await.map_err(|e| CarbideError::Internal {
        message: format!("Failed to commit transaction: {}", e),
    })?;

    Ok(Response::new(rpc::PowerShelfDeletionResult {}))
}
