/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::sync::Arc;

use askama::Template;
use axum::extract::State as AxumState;
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;
use http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;

use crate::api::Api;

#[derive(Template)]
#[template(path = "resource_pool_show.html")]
struct ResourcePoolShow {
    pools: Vec<ResourcePoolDisplay>,
}

struct ResourcePoolDisplay {
    name: String,
    min: String,
    max: String,
    size: u64,
    allocated: String,
}

impl From<forgerpc::ResourcePool> for ResourcePoolDisplay {
    fn from(pool: forgerpc::ResourcePool) -> Self {
        Self {
            name: pool.name,
            min: pool.min,
            max: pool.max,
            size: pool.total,
            allocated: format!(
                "{} ({:.0}%)",
                pool.allocated,
                pool.allocated as f64 / pool.total as f64 * 100.0
            ),
        }
    }
}

/// List resource pools
pub async fn show_html<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let out = match fetch_resource_pools(state).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "admin_list_resource_pools");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed loading resource pools",
            )
                .into_response();
        }
    };
    let mut pools: Vec<ResourcePoolDisplay> = Vec::new();
    for rp in out.into_iter() {
        pools.push(rp.into());
    }
    let tmpl = ResourcePoolShow { pools };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_json<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let out = match fetch_resource_pools(state).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "admin_list_resource_pools");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed loading resource pools",
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(out)).into_response()
}

async fn fetch_resource_pools<
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
>(
    api: Arc<Api<C1, C2>>,
) -> Result<Vec<forgerpc::ResourcePool>, tonic::Status> {
    let request = tonic::Request::new(forgerpc::ListResourcePoolsRequest {});
    let mut out = api
        .admin_list_resource_pools(request)
        .await
        .map(|response| response.into_inner())?;
    out.pools.sort_unstable_by(|p1, p2| p1.name.cmp(&p2.name));
    Ok(out.pools)
}
