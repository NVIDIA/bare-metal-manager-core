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

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use db::{ObjectColumnFilter, power_shelf as db_power_shelf};
use model::metadata::Metadata;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_request_data};

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

pub async fn find_ids(
    api: &Api,
    request: Request<rpc::PowerShelfSearchFilter>,
) -> Result<Response<rpc::PowerShelfIdList>, Status> {
    log_request_data(&request);

    let filter: model::power_shelf::PowerShelfSearchFilter = request.into_inner().into();

    let power_shelf_ids = db_power_shelf::find_ids(&api.database_connection, filter).await?;

    Ok(Response::new(rpc::PowerShelfIdList {
        ids: power_shelf_ids,
    }))
}

pub async fn find_by_ids(
    api: &Api,
    request: Request<rpc::PowerShelvesByIdsRequest>,
) -> Result<Response<rpc::PowerShelfList>, Status> {
    log_request_data(&request);

    let power_shelf_ids = request.into_inner().power_shelf_ids;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if power_shelf_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if power_shelf_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let mut txn = api.txn_begin().await?;

    let power_shelf_list = db_power_shelf::find_by(
        &mut txn,
        ObjectColumnFilter::List(db_power_shelf::IdColumn, &power_shelf_ids),
    )
    .await?;

    let bmc_info_map: std::collections::HashMap<_, _> = {
        let rows = db_power_shelf::find_bmc_info_by_power_shelf_ids(&mut txn, &power_shelf_ids)
            .await
            .map_err(|e| CarbideError::Internal {
                message: format!("Failed to get power shelf BMC info: {}", e),
            })?;

        rows.into_iter()
            .map(|row| {
                (
                    row.power_shelf_id,
                    rpc::BmcInfo {
                        ip: Some(row.pmc_ip.to_string()),
                        mac: Some(row.pmc_mac.to_string()),
                        version: None,
                        firmware_version: None,
                        port: None,
                    },
                )
            })
            .collect()
    };

    let _ = txn.rollback().await;

    let power_shelves: Vec<rpc::PowerShelf> = power_shelf_list
        .into_iter()
        .map(|ps| {
            let id = ps.id;
            let bmc_info = bmc_info_map.get(&id).cloned();

            rpc::PowerShelf::try_from(ps).map(|mut rpc_ps| {
                rpc_ps.bmc_info = bmc_info;
                rpc_ps
            })
        })
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

/// Force deletes a power shelf and optionally its associated interfaces from the database.
/// Unlike `delete_power_shelf` (soft delete), this immediately hard-deletes the power shelf,
/// its state history, and optionally its machine interfaces.
pub async fn admin_force_delete_power_shelf(
    api: &Api,
    request: Request<rpc::AdminForceDeletePowerShelfRequest>,
) -> Result<Response<rpc::AdminForceDeletePowerShelfResponse>, Status> {
    log_request_data(&request);
    let request = request.into_inner();

    let power_shelf_id = request
        .power_shelf_id
        .ok_or_else(|| CarbideError::InvalidArgument("power_shelf_id is required".to_string()))?;

    let mut txn = api.txn_begin().await?;

    // Verify the power shelf exists.
    let power_shelf_list = db_power_shelf::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db_power_shelf::IdColumn, &power_shelf_id),
    )
    .await
    .map_err(CarbideError::from)?;

    if power_shelf_list.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "power_shelf",
            id: power_shelf_id.to_string(),
        }
        .into());
    }

    // Optionally delete associated machine interfaces.
    let mut interfaces_deleted: u32 = 0;
    if request.delete_interfaces {
        let interface_ids =
            db::machine_interface::find_ids_by_power_shelf_id(&mut txn, &power_shelf_id)
                .await
                .map_err(CarbideError::from)?;
        for interface_id in &interface_ids {
            db::machine_interface::delete(interface_id, &mut txn)
                .await
                .map_err(CarbideError::from)?;
        }
        interfaces_deleted = interface_ids.len() as u32;
    }

    // Delete state history.
    db::power_shelf_state_history::delete_by_power_shelf_id(&mut txn, &power_shelf_id)
        .await
        .map_err(CarbideError::from)?;

    // Hard-delete the power shelf.
    db_power_shelf::final_delete(power_shelf_id, &mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await?;

    Ok(Response::new(rpc::AdminForceDeletePowerShelfResponse {
        power_shelf_id: power_shelf_id.to_string(),
        interfaces_deleted,
    }))
}

pub async fn find_power_shelf_state_histories(
    api: &Api,
    request: Request<rpc::PowerShelfStateHistoriesRequest>,
) -> Result<Response<rpc::StateHistories>, Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let power_shelf_ids = request.power_shelf_ids;

    let max_find_by_ids = api.runtime_config.max_find_by_ids as usize;
    if power_shelf_ids.len() > max_find_by_ids {
        return Err(CarbideError::InvalidArgument(format!(
            "no more than {max_find_by_ids} IDs can be accepted"
        ))
        .into());
    } else if power_shelf_ids.is_empty() {
        return Err(
            CarbideError::InvalidArgument("at least one ID must be provided".to_string()).into(),
        );
    }

    let mut txn = api.txn_begin().await?;

    let results =
        db::power_shelf_state_history::find_by_power_shelf_ids(&mut txn, &power_shelf_ids)
            .await
            .map_err(CarbideError::from)?;

    let mut response = rpc::StateHistories::default();
    for (power_shelf_id, records) in results {
        response.histories.insert(
            power_shelf_id.to_string(),
            ::rpc::forge::StateHistoryRecords {
                records: records.into_iter().map(Into::into).collect(),
            },
        );
    }

    txn.commit().await?;

    Ok(tonic::Response::new(response))
}

pub(crate) async fn update_power_shelf_metadata(
    api: &Api,
    request: Request<rpc::PowerShelfMetadataUpdateRequest>,
) -> std::result::Result<tonic::Response<()>, tonic::Status> {
    log_request_data(&request);
    let request = request.into_inner();
    let power_shelf_id = request.power_shelf_id.ok_or_else(|| {
        CarbideError::from(RpcDataConversionError::MissingArgument("power_shelf_id"))
    })?;

    let metadata = match request.metadata {
        Some(m) => Metadata::try_from(m).map_err(CarbideError::from)?,
        _ => {
            return Err(
                CarbideError::from(RpcDataConversionError::MissingArgument("metadata")).into(),
            );
        }
    };
    metadata.validate(true).map_err(CarbideError::from)?;

    let mut txn = api.txn_begin().await?;

    let power_shelves = db_power_shelf::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db_power_shelf::IdColumn, &power_shelf_id),
    )
    .await
    .map_err(CarbideError::from)?;

    let power_shelf =
        power_shelves
            .into_iter()
            .next()
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "power_shelf",
                id: power_shelf_id.to_string(),
            })?;

    let expected_version: config_version::ConfigVersion = match request.if_version_match {
        Some(version) => version.parse().map_err(CarbideError::from)?,
        None => power_shelf.version,
    };

    db_power_shelf::update_metadata(&mut txn, &power_shelf_id, expected_version, metadata).await?;

    txn.commit().await?;

    Ok(tonic::Response::new(()))
}
