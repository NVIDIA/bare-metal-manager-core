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
use db::{DatabaseError, expected_switch as db_expected_switch};
use mac_address::MacAddress;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::Api;

pub async fn add_expected_switch(
    api: &Api,
    request: Request<rpc::ExpectedSwitch>,
) -> Result<Response<()>, Status> {
    let expected_switch = request.into_inner();

    let bmc_mac_address = MacAddress::try_from(expected_switch.bmc_mac_address.as_str())
        .map_err(|e| Status::invalid_argument(format!("Invalid MAC address: {}", e)))?;

    let metadata = expected_switch.metadata.unwrap_or_default();
    let metadata = model::metadata::Metadata::try_from(metadata)
        .map_err(|e| Status::invalid_argument(format!("Invalid metadata: {}", e)))?;

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    db_expected_switch::create(
        &mut txn,
        bmc_mac_address,
        expected_switch.bmc_username,
        expected_switch.bmc_password,
        expected_switch.switch_serial_number,
        metadata,
        expected_switch.rack_id,
        expected_switch.nvos_username,
        expected_switch.nvos_password,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to create expected switch: {}", e)))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    Ok(Response::new(()))
}

pub async fn delete_expected_switch(
    api: &Api,
    request: Request<rpc::ExpectedSwitchRequest>,
) -> Result<Response<()>, Status> {
    let req = request.into_inner();

    let bmc_mac_address = MacAddress::try_from(req.bmc_mac_address.as_str())
        .map_err(|e| Status::invalid_argument(format!("Invalid MAC address: {}", e)))?;

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    db_expected_switch::delete(bmc_mac_address, &mut txn)
        .await
        .map_err(|e| Status::internal(format!("Failed to delete expected switch: {}", e)))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    Ok(Response::new(()))
}

pub async fn update_expected_switch(
    api: &Api,
    request: Request<rpc::ExpectedSwitch>,
) -> Result<Response<()>, Status> {
    let expected_switch = request.into_inner();

    let bmc_mac_address = MacAddress::try_from(expected_switch.bmc_mac_address.as_str())
        .map_err(|e| Status::invalid_argument(format!("Invalid MAC address: {}", e)))?;

    let metadata = expected_switch.metadata.unwrap_or_default();
    let metadata = model::metadata::Metadata::try_from(metadata)
        .map_err(|e| Status::invalid_argument(format!("Invalid metadata: {}", e)))?;

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    let mut existing = db_expected_switch::find_by_bmc_mac_address(&mut txn, bmc_mac_address)
        .await
        .map_err(|e| Status::internal(format!("Failed to find expected switch: {}", e)))?
        .ok_or_else(|| {
            Status::not_found(format!(
                "Expected switch with MAC address {} not found",
                bmc_mac_address
            ))
        })?;

    db_expected_switch::update(
        &mut existing,
        &mut txn,
        expected_switch.bmc_username,
        expected_switch.bmc_password,
        expected_switch.switch_serial_number,
        metadata,
        expected_switch.rack_id,
        expected_switch.nvos_username,
        expected_switch.nvos_password,
    )
    .await
    .map_err(|e| Status::internal(format!("Failed to update expected switch: {}", e)))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    Ok(Response::new(()))
}

pub async fn get_expected_switch(
    api: &Api,
    request: Request<rpc::ExpectedSwitchRequest>,
) -> Result<Response<rpc::ExpectedSwitch>, Status> {
    let req = request.into_inner();

    let bmc_mac_address = MacAddress::try_from(req.bmc_mac_address.as_str())
        .map_err(|e| Status::invalid_argument(format!("Invalid MAC address: {}", e)))?;

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    let expected_switch = db_expected_switch::find_by_bmc_mac_address(&mut txn, bmc_mac_address)
        .await
        .map_err(|e| Status::internal(format!("Failed to find expected switch: {}", e)))?
        .ok_or_else(|| {
            Status::not_found(format!(
                "Expected switch with MAC address {} not found",
                bmc_mac_address
            ))
        })?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    let response = rpc::ExpectedSwitch::from(expected_switch);
    Ok(Response::new(response))
}

pub async fn get_all_expected_switches(
    api: &Api,
    _request: Request<()>,
) -> Result<Response<rpc::ExpectedSwitchList>, Status> {
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    let expected_switches = db_expected_switch::find_all(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("Failed to find expected switches: {}", e)))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    let expected_switches: Vec<rpc::ExpectedSwitch> = expected_switches
        .into_iter()
        .map(rpc::ExpectedSwitch::from)
        .collect();

    Ok(Response::new(rpc::ExpectedSwitchList { expected_switches }))
}

pub async fn replace_all_expected_switches(
    api: &Api,
    request: Request<rpc::ExpectedSwitchList>,
) -> Result<Response<()>, Status> {
    let req = request.into_inner();

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    // Clear all existing expected switches
    db_expected_switch::clear(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("Failed to clear expected switches: {}", e)))?;

    // Add all new expected switches
    for expected_switch in req.expected_switches {
        let bmc_mac_address = MacAddress::try_from(expected_switch.bmc_mac_address.as_str())
            .map_err(|e| Status::invalid_argument(format!("Invalid MAC address: {}", e)))?;

        let metadata = expected_switch.metadata.unwrap_or_default();
        let metadata = model::metadata::Metadata::try_from(metadata)
            .map_err(|e| Status::invalid_argument(format!("Invalid metadata: {}", e)))?;

        db_expected_switch::create(
            &mut txn,
            bmc_mac_address,
            expected_switch.bmc_username,
            expected_switch.bmc_password,
            expected_switch.switch_serial_number,
            metadata,
            expected_switch.rack_id,
            expected_switch.nvos_username,
            expected_switch.nvos_password,
        )
        .await
        .map_err(|e| Status::internal(format!("Failed to create expected switch: {}", e)))?;
    }

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    Ok(Response::new(()))
}

pub async fn delete_all_expected_switches(
    api: &Api,
    _request: Request<()>,
) -> Result<Response<()>, Status> {
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    db_expected_switch::clear(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("Failed to clear expected switches: {}", e)))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    Ok(Response::new(()))
}

pub async fn get_all_expected_switches_linked(
    api: &Api,
    _request: Request<()>,
) -> Result<Response<rpc::LinkedExpectedSwitchList>, Status> {
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| Status::internal(format!("Database error: {}", e)))?;

    let linked_expected_switches = db_expected_switch::find_all_linked(&mut txn)
        .await
        .map_err(|e| Status::internal(format!("Failed to find linked expected switches: {}", e)))?;

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    let linked_expected_switches: Vec<rpc::LinkedExpectedSwitch> = linked_expected_switches
        .into_iter()
        .map(rpc::LinkedExpectedSwitch::from)
        .collect();

    Ok(Response::new(rpc::LinkedExpectedSwitchList {
        expected_switches: linked_expected_switches,
    }))
}

// Utility method called by `explore`. Not a grpc handler.
// TODO(chet): Remove dead_code once wired up with the explorer.
#[allow(dead_code)]
pub(crate) async fn query(
    api: &Api,
    mac: MacAddress,
) -> Result<Option<model::expected_switch::ExpectedSwitch>, CarbideError> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new("begin find_many_by_bmc_mac_address", e))
    })?;

    let mut expected = db_expected_switch::find_many_by_bmc_mac_address(&mut txn, &[mac]).await?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new("commit find_many_by_bmc_mac_address", e))
    })?;

    Ok(expected.remove(&mac))
}
