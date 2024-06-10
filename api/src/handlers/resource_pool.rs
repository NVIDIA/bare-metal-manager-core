/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;

use ::rpc::forge as rpc;
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;
use tonic::{Request, Response, Status};

use crate::api::Api;
use crate::db::DatabaseError;
use crate::CarbideError;

pub(crate) async fn grow<C1, C2>(
    api: &Api<C1, C2>,
    request: Request<rpc::GrowResourcePoolRequest>,
) -> Result<Response<rpc::GrowResourcePoolResponse>, Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

    let toml_text = request.into_inner().text;

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin admin_grow_resource_pool",
            e,
        ))
    })?;

    let mut pools = HashMap::new();
    let table: toml::Table = toml_text
        .parse()
        .map_err(|e: toml::de::Error| tonic::Status::invalid_argument(e.to_string()))?;
    for (name, def) in table {
        let d: crate::resource_pool::ResourcePoolDef = def
            .try_into()
            .map_err(|e: toml::de::Error| tonic::Status::invalid_argument(e.to_string()))?;
        pools.insert(name, d);
    }
    use crate::resource_pool::DefineResourcePoolError as DE;
    match crate::resource_pool::define_all_from(&mut txn, &pools).await {
        Ok(()) => {
            txn.commit().await.map_err(|e| {
                CarbideError::from(DatabaseError::new(
                    file!(),
                    line!(),
                    "end admin_grow_resource_pool",
                    e,
                ))
            })?;
            Ok(Response::new(rpc::GrowResourcePoolResponse {}))
        }
        Err(DE::InvalidArgument(msg)) => Err(tonic::Status::invalid_argument(msg)),
        Err(DE::InvalidToml(err)) => Err(tonic::Status::invalid_argument(err.to_string())),
        Err(DE::ResourcePoolError(msg)) => Err(tonic::Status::internal(msg.to_string())),
        Err(err @ DE::TooBig(_, _)) => Err(tonic::Status::out_of_range(err.to_string())),
    }
}

pub(crate) async fn list<C1, C2>(
    api: &Api<C1, C2>,
    request: Request<rpc::ListResourcePoolsRequest>,
) -> Result<tonic::Response<rpc::ResourcePools>, tonic::Status>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    crate::api::log_request_data(&request);

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin admin_list_resource_pools ",
            e,
        ))
    })?;

    let snapshot = crate::resource_pool::all(&mut txn)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "end admin_list_resource_pools",
            e,
        ))
    })?;

    Ok(Response::new(rpc::ResourcePools {
        pools: snapshot.into_iter().map(|s| s.into()).collect(),
    }))
}
