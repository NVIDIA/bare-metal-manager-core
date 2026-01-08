/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use db::{WithTransaction, rack as db_rack};
use futures_util::FutureExt;
use tonic::{Request, Response, Status};

use crate::api::Api;

pub async fn get_rack(
    api: &Api,
    request: Request<rpc::GetRackRequest>,
) -> Result<Response<rpc::GetRackResponse>, Status> {
    let req = request.into_inner();
    let rack = api
        .with_txn(|txn| {
            async move {
                if let Some(id) = req.id {
                    let r = db_rack::get(txn, id.as_str())
                        .await
                        .map_err(|e| Status::internal(format!("Getting rack {}", e)))?;
                    Ok::<_, Status>(vec![r.into()])
                } else {
                    let racks = db_rack::list(txn)
                        .await
                        .map_err(|e| Status::internal(format!("Listing racks {}", e)))?
                        .into_iter()
                        .map(|x| x.into())
                        .collect();
                    Ok(racks)
                }
            }
            .boxed()
        })
        .await??;
    Ok(Response::new(rpc::GetRackResponse { rack }))
}

pub async fn delete_rack(
    api: &Api,
    request: Request<rpc::DeleteRackRequest>,
) -> Result<Response<()>, Status> {
    let req = request.into_inner();
    api.with_txn(|txn| {
        async move {
            let rack = db_rack::get(txn, req.id.as_str())
                .await
                .map_err(|e| Status::internal(format!("Getting rack {}", e)))?;
            db_rack::mark_as_deleted(&rack, txn)
                .await
                .map_err(|e| Status::internal(format!("Marking rack deleted {}", e)))?;
            Ok::<_, Status>(())
        }
        .boxed()
    })
    .await??;
    Ok(Response::new(()))
}

pub async fn rack_manager_call(
    api: &Api,
    request: Request<rpc::RackManagerForgeRequest>,
) -> Result<Response<rpc::RackManagerForgeResponse>, Status> {
    let req = request.into_inner();
    let cmd = rpc::RackManagerForgeCmd::try_from(req.cmd)
        .map_err(|e| tonic::Status::internal(e.to_string()))?;
    let json = match cmd {
        rpc::RackManagerForgeCmd::InventoryGet => {
            let response = api
                .rms_client
                .inventory_get()
                .await
                .map_err(|e| tonic::Status::internal(e.to_string()))?;
            serde_json::to_string(&response).unwrap_or("{}".to_string())
        }
        rpc::RackManagerForgeCmd::RemoveNode => {
            if let Some(node_id) = req.node_id {
                let response = api
                    .rms_client
                    .remove_node(node_id)
                    .await
                    .map_err(|e| tonic::Status::internal(e.to_string()))?;
                serde_json::to_string(&response).unwrap_or("{}".to_string())
            } else {
                return Err(tonic::Status::not_found("Node id not specified"));
            }
        }
        rpc::RackManagerForgeCmd::GetPoweronOrder => {
            let response = api
                .rms_client
                .get_poweron_order()
                .await
                .map_err(|e| tonic::Status::internal(e.to_string()))?;
            serde_json::to_string(&response).unwrap_or("{}".to_string())
        }
        rpc::RackManagerForgeCmd::GetPowerState => {
            if let Some(node_id) = req.node_id {
                let response = api
                    .rms_client
                    .get_power_state(node_id)
                    .await
                    .map_err(|e| tonic::Status::internal(e.to_string()))?;
                serde_json::to_string(&response).unwrap_or("{}".to_string())
            } else {
                return Err(tonic::Status::not_found("Node id not specified"));
            }
        }
        rpc::RackManagerForgeCmd::GetFirmwareInventory => {
            if let Some(node_id) = req.node_id {
                let response = api
                    .rms_client
                    .get_firmware_inventory(node_id)
                    .await
                    .map_err(|e| tonic::Status::internal(e.to_string()))?;
                serde_json::to_string(&response).unwrap_or("{}".to_string())
            } else {
                return Err(tonic::Status::not_found("Node id not specified"));
            }
        }
        rpc::RackManagerForgeCmd::GetAvailableFwImages => {
            if let Some(node_id) = req.node_id {
                let response = api
                    .rms_client
                    .get_available_fw_images(node_id)
                    .await
                    .map_err(|e| tonic::Status::internal(e.to_string()))?;
                serde_json::to_string(&response).unwrap_or("{}".to_string())
            } else {
                return Err(tonic::Status::not_found("Node id not specified"));
            }
        }
        rpc::RackManagerForgeCmd::GetBkcFiles => {
            let response = api
                .rms_client
                .get_bkc_files()
                .await
                .map_err(|e| tonic::Status::internal(e.to_string()))?;
            serde_json::to_string(&response).unwrap_or("{}".to_string())
        }
        rpc::RackManagerForgeCmd::CheckBkcCompliance => {
            let response = api
                .rms_client
                .check_bkc_compliance()
                .await
                .map_err(|e| tonic::Status::internal(e.to_string()))?;
            serde_json::to_string(&response).unwrap_or("{}".to_string())
        }
    };
    Ok(Response::new(rpc::RackManagerForgeResponse {
        json_result: Some(json),
    }))
}
