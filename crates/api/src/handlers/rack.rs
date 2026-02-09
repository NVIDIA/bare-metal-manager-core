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

/// List health report overrides for a rack.
///
/// This is a stub - actual implementation TBD.
/// Similar to list_health_report_overrides but for racks table.
#[allow(clippy::unused_async)] // Will need async when implemented
pub async fn list_rack_health_report_overrides(
    _api: &Api,
    request: Request<rpc::ListRackHealthReportOverridesRequest>,
) -> Result<Response<rpc::ListHealthReportOverrideResponse>, Status> {
    let req = request.into_inner();
    tracing::info!(
        rack_id = ?req.rack_id,
        "list_rack_health_report_overrides called (stub)"
    );

    // TODO: Implement rack health override listing
    Err(Status::unimplemented(
        "ListRackHealthReportOverrides is not yet implemented",
    ))
}

/// Insert a health report override for a rack.
///
/// This is a stub - actual implementation TBD.
/// Similar to insert_health_report_override but for racks table.
#[allow(clippy::unused_async)] // Will need async when implemented
pub async fn insert_rack_health_report_override(
    _api: &Api,
    request: Request<rpc::InsertRackHealthReportOverrideRequest>,
) -> Result<Response<()>, Status> {
    let req = request.into_inner();
    tracing::info!(
        rack_id = ?req.rack_id,
        "insert_rack_health_report_override called (stub)"
    );

    // TODO: Implement rack health override insertion
    Err(Status::unimplemented(
        "InsertRackHealthReportOverride is not yet implemented",
    ))
}

/// Remove a health report override for a rack.
///
/// This is a stub - actual implementation TBD.
/// Similar to remove_health_report_override but for racks table.
#[allow(clippy::unused_async)] // Will need async when implemented
pub async fn remove_rack_health_report_override(
    _api: &Api,
    request: Request<rpc::RemoveRackHealthReportOverrideRequest>,
) -> Result<Response<()>, Status> {
    let req = request.into_inner();
    tracing::info!(
        rack_id = ?req.rack_id,
        source = %req.source,
        "remove_rack_health_report_override called (stub)"
    );

    // TODO: Implement rack health override removal
    Err(Status::unimplemented(
        "RemoveRackHealthReportOverride is not yet implemented",
    ))
}
