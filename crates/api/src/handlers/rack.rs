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
