/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::str::FromStr;

use ::rpc::forge as rpc;
use carbide_uuid::rack::RackId;
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
                    let rack_id = RackId::from_str(&id)
                        .map_err(|e| Status::invalid_argument(format!("Invalid rack ID: {}", e)))?;
                    let r = db_rack::get(txn, rack_id)
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
            let rack_id = RackId::from_str(&req.id)
                .map_err(|e| Status::invalid_argument(format!("Invalid rack ID: {}", e)))?;
            let rack = db_rack::get(txn, rack_id)
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
