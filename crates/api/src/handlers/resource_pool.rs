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

use std::collections::HashMap;

use ::rpc::forge as rpc;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::Api;

pub(crate) async fn grow(
    api: &Api,
    request: Request<rpc::GrowResourcePoolRequest>,
) -> Result<Response<rpc::GrowResourcePoolResponse>, Status> {
    crate::api::log_request_data(&request);

    let toml_text = request.into_inner().text;

    let mut txn = api.txn_begin().await?;

    let mut pools = HashMap::new();
    let table: toml::Table = toml_text
        .parse()
        .map_err(|e: toml::de::Error| tonic::Status::invalid_argument(e.to_string()))?;
    for (name, def) in table {
        let d: model::resource_pool::ResourcePoolDef = def
            .try_into()
            .map_err(|e: toml::de::Error| tonic::Status::invalid_argument(e.to_string()))?;
        pools.insert(name, d);
    }
    use db::resource_pool::DefineResourcePoolError as DE;
    match db::resource_pool::define_all_from(&mut txn, &pools).await {
        Ok(()) => {
            txn.commit().await?;
            Ok(Response::new(rpc::GrowResourcePoolResponse {}))
        }
        Err(DE::InvalidArgument(msg)) => Err(tonic::Status::invalid_argument(msg)),
        Err(DE::InvalidToml(err)) => Err(tonic::Status::invalid_argument(err.to_string())),
        Err(DE::ResourcePoolError(msg)) => Err(tonic::Status::internal(msg.to_string())),
        Err(DE::DatabaseError(err)) => Err(tonic::Status::internal(err.to_string())),
        Err(err @ DE::TooBig(_, _)) => Err(tonic::Status::out_of_range(err.to_string())),
    }
}

pub(crate) async fn list(
    api: &Api,
    request: Request<rpc::ListResourcePoolsRequest>,
) -> Result<tonic::Response<rpc::ResourcePools>, tonic::Status> {
    crate::api::log_request_data(&request);

    let mut txn = api.txn_begin().await?;

    let snapshot = db::resource_pool::all(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await?;

    Ok(Response::new(rpc::ResourcePools {
        pools: snapshot.into_iter().map(|s| s.into()).collect(),
    }))
}
