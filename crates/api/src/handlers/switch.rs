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

    // if include_addresses, attempt to get IP address and BMC MAC address for each switch
    let address_map: std::collections::HashMap<String, (String, String)> =
        if query.include_addresses.unwrap_or(false) {
            let endpoints = db_switch::get_switch_endpoints_from_dhcp(&mut txn)
                .await
                .map_err(|e| Status::internal(format!("Failed to get switch addresses: {}", e)))?;

            endpoints
                .into_iter()
                .map(|ep| {
                    (
                        ep.serial_number,
                        (ep.ip_address.to_string(), ep.bmc_mac_address.to_string()),
                    )
                })
                .collect()
        } else {
            std::collections::HashMap::new()
        };

    txn.commit()
        .await
        .map_err(|e| Status::internal(format!("Failed to commit transaction: {}", e)))?;

    let switches: Vec<rpc::Switch> = switch_list
        .into_iter()
        .map(|s| {
            let serial = s.config.name.clone();
            let (ip_address, bmc_mac_address) = address_map
                .get(&serial)
                .map(|(ip, mac)| (Some(ip.clone()), Some(mac.clone())))
                .unwrap_or((None, None));

            rpc::Switch::try_from(s).map(|mut rpc_switch| {
                rpc_switch.ip_address = ip_address;
                rpc_switch.bmc_mac_address = bmc_mac_address;
                rpc_switch
            })
        })
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
