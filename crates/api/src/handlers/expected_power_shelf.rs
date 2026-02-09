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
use db::{DatabaseError, expected_power_shelf as db_expected_power_shelf};
use mac_address::MacAddress;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::Api;

pub async fn add_expected_power_shelf(
    api: &Api,
    request: Request<rpc::ExpectedPowerShelf>,
) -> Result<Response<()>, Status> {
    let expected_power_shelf = request.into_inner();

    let bmc_mac_address = MacAddress::try_from(expected_power_shelf.bmc_mac_address.as_str())
        .map_err(|e| Status::invalid_argument(format!("Invalid MAC address: {}", e)))?;

    let metadata = expected_power_shelf.metadata.unwrap_or_default();
    let metadata = model::metadata::Metadata::try_from(metadata)
        .map_err(|e| Status::invalid_argument(format!("Invalid metadata: {}", e)))?;

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    let request_rack_id = expected_power_shelf.rack_id;
    db_expected_power_shelf::create(
        &mut txn,
        bmc_mac_address,
        expected_power_shelf.bmc_username,
        expected_power_shelf.bmc_password,
        expected_power_shelf.shelf_serial_number,
        if expected_power_shelf.ip_address.is_empty() {
            None
        } else {
            expected_power_shelf.ip_address.parse().ok()
        },
        metadata,
        request_rack_id,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to create expected power shelf: {}", e)))?;

    if let Some(rack_id) = request_rack_id {
        match db::rack::get(&mut txn, rack_id).await {
            Ok(rack) => {
                let mut config = rack.config.clone();
                if !config.expected_power_shelves.contains(&bmc_mac_address) {
                    config.expected_power_shelves.push(bmc_mac_address);
                    db::rack::update(&mut txn, rack_id, &config)
                        .await
                        .map_err(CarbideError::from)?;
                }
            }
            Err(_) => {
                let expected_power_shelves = vec![bmc_mac_address];
                let _rack =
                    db::rack::create(&mut txn, rack_id, vec![], vec![], expected_power_shelves)
                        .await
                        .map_err(CarbideError::from)?;
            }
        }
    }

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    Ok(Response::new(()))
}

pub async fn delete_expected_power_shelf(
    api: &Api,
    request: Request<rpc::ExpectedPowerShelfRequest>,
) -> Result<Response<()>, Status> {
    let req = request.into_inner();

    let bmc_mac_address = MacAddress::try_from(req.bmc_mac_address.as_str())
        .map_err(|e| Status::invalid_argument(format!("Invalid MAC address: {}", e)))?;

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    db_expected_power_shelf::delete(bmc_mac_address, &mut txn)
        .await
        .map_err(|e| Status::internal(format!("Failed to delete expected power shelf: {}", e)))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    // TODO Add cleanup for rack

    Ok(Response::new(()))
}

pub async fn update_expected_power_shelf(
    api: &Api,
    request: Request<rpc::ExpectedPowerShelf>,
) -> Result<Response<()>, Status> {
    let expected_power_shelf = request.into_inner();

    let bmc_mac_address = MacAddress::try_from(expected_power_shelf.bmc_mac_address.as_str())
        .map_err(|e| Status::invalid_argument(format!("Invalid MAC address: {}", e)))?;

    let metadata = expected_power_shelf.metadata.unwrap_or_default();
    let metadata = model::metadata::Metadata::try_from(metadata)
        .map_err(|e| Status::invalid_argument(format!("Invalid metadata: {}", e)))?;

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    let mut existing = db_expected_power_shelf::find_by_bmc_mac_address(&mut txn, bmc_mac_address)
        .await
        .map_err(|e| Status::internal(format!("Failed to find expected power shelf: {}", e)))?
        .ok_or_else(|| {
            Status::not_found(format!(
                "Expected power shelf with MAC address {} not found",
                bmc_mac_address
            ))
        })?;

    db_expected_power_shelf::update(
        &mut existing,
        &mut txn,
        expected_power_shelf.bmc_username,
        expected_power_shelf.bmc_password,
        expected_power_shelf.shelf_serial_number,
        if expected_power_shelf.ip_address.is_empty() {
            None
        } else {
            expected_power_shelf.ip_address.parse().ok()
        },
        metadata,
        expected_power_shelf.rack_id,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to update expected power shelf: {}", e)))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    Ok(Response::new(()))
}

pub async fn get_expected_power_shelf(
    api: &Api,
    request: Request<rpc::ExpectedPowerShelfRequest>,
) -> Result<Response<rpc::ExpectedPowerShelf>, Status> {
    let req = request.into_inner();

    let bmc_mac_address = MacAddress::try_from(req.bmc_mac_address.as_str())
        .map_err(|e| Status::invalid_argument(format!("Invalid MAC address: {}", e)))?;

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    let expected_power_shelf =
        db_expected_power_shelf::find_by_bmc_mac_address(&mut txn, bmc_mac_address)
            .await
            .map_err(|e| Status::internal(format!("Failed to find expected power shelf: {}", e)))?
            .ok_or_else(|| {
                Status::not_found(format!(
                    "Expected power shelf with MAC address {} not found",
                    bmc_mac_address
                ))
            })?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    let response = rpc::ExpectedPowerShelf::from(expected_power_shelf);
    Ok(Response::new(response))
}

pub async fn get_all_expected_power_shelves(
    api: &Api,
    _request: Request<()>,
) -> Result<Response<rpc::ExpectedPowerShelfList>, Status> {
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    let expected_power_shelves = db_expected_power_shelf::find_all(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("Failed to find expected power shelves: {}", e)))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    let expected_power_shelves: Vec<rpc::ExpectedPowerShelf> = expected_power_shelves
        .into_iter()
        .map(rpc::ExpectedPowerShelf::from)
        .collect();

    Ok(Response::new(rpc::ExpectedPowerShelfList {
        expected_power_shelves,
    }))
}

pub async fn replace_all_expected_power_shelves(
    api: &Api,
    request: Request<rpc::ExpectedPowerShelfList>,
) -> Result<Response<()>, Status> {
    let req = request.into_inner();

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    // Clear all existing expected power shelves
    db_expected_power_shelf::clear(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("Failed to clear expected power shelves: {}", e)))?;

    // Add all new expected power shelves
    for expected_power_shelf in req.expected_power_shelves {
        let bmc_mac_address =
            MacAddress::try_from(expected_power_shelf.bmc_mac_address.as_str())
                .map_err(|e| Status::invalid_argument(format!("Invalid MAC address: {}", e)))?;

        let metadata = expected_power_shelf.metadata.unwrap_or_default();
        let metadata = model::metadata::Metadata::try_from(metadata)
            .map_err(|e| Status::invalid_argument(format!("Invalid metadata: {}", e)))?;

        db_expected_power_shelf::create(
            &mut txn,
            bmc_mac_address,
            expected_power_shelf.bmc_username,
            expected_power_shelf.bmc_password,
            expected_power_shelf.shelf_serial_number,
            if expected_power_shelf.ip_address.is_empty() {
                None
            } else {
                expected_power_shelf.ip_address.parse().ok()
            },
            metadata,
            expected_power_shelf.rack_id,
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to create expected power shelf: {}", e)))?;
    }

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    Ok(Response::new(()))
}

pub async fn delete_all_expected_power_shelves(
    api: &Api,
    _request: Request<()>,
) -> Result<Response<()>, Status> {
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    db_expected_power_shelf::clear(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("Failed to clear expected power shelves: {}", e)))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    Ok(Response::new(()))
}

pub async fn get_all_expected_power_shelves_linked(
    api: &Api,
    _request: Request<()>,
) -> Result<Response<rpc::LinkedExpectedPowerShelfList>, Status> {
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    let linked_expected_power_shelves = db_expected_power_shelf::find_all_linked(&mut txn)
        .await
        .map_err(|e| {
            Status::internal(format!(
                "Failed to find linked expected power shelves: {}",
                e
            ))
        })?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    let linked_expected_power_shelves: Vec<rpc::LinkedExpectedPowerShelf> =
        linked_expected_power_shelves
            .into_iter()
            .map(rpc::LinkedExpectedPowerShelf::from)
            .collect();

    Ok(Response::new(rpc::LinkedExpectedPowerShelfList {
        expected_power_shelves: linked_expected_power_shelves,
    }))
}

// Utility method called by `explore`. Not a grpc handler.
// TODO(chet): Remove dead_code once the exploration is wired up.
#[allow(dead_code)]
pub(crate) async fn query(
    api: &Api,
    mac: MacAddress,
) -> Result<Option<model::expected_power_shelf::ExpectedPowerShelf>, CarbideError> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new("begin find_many_by_bmc_mac_address", e))
    })?;

    let mut expected =
        db_expected_power_shelf::find_many_by_bmc_mac_address(&mut txn, &[mac]).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new("commit find_many_by_bmc_mac_address", e))
    })?;

    Ok(expected.remove(&mac))
}
