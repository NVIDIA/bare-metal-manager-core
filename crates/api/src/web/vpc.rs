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

use std::sync::Arc;

use askama::Template;
use axum::Json;
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use hyper::http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "vpc_show.html")]
struct VpcShow {
    vpcs: Vec<VpcRowDisplay>,
}

struct VpcRowDisplay {
    id: String,
    metadata: rpc::forge::Metadata,
    tenant_organization_id: String,
    tenant_keyset_id: String,
    network_virtualization_type: String,
    vni: String,
}

impl From<forgerpc::Vpc> for VpcRowDisplay {
    fn from(vpc: forgerpc::Vpc) -> Self {
        Self {
            network_virtualization_type: format!("{:?}", vpc.network_virtualization_type()),
            id: vpc.id.unwrap_or_default().to_string(),
            metadata: vpc.metadata.unwrap_or_default(),
            tenant_organization_id: vpc.tenant_organization_id,
            tenant_keyset_id: vpc.tenant_keyset_id.unwrap_or_default(),
            vni: vpc.vni.map(|vni| vni.to_string()).unwrap_or_default(),
        }
    }
}

/// List VPCs
pub async fn show_html(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let vpcs = match fetch_vpcs(state.clone()).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_vpcs");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading VPCs").into_response();
        }
    };

    let tmpl = VpcShow {
        vpcs: vpcs.into_iter().map(Into::into).collect(),
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_all_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let vpcs = match fetch_vpcs(state).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_vpcs");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading VPCs").into_response();
        }
    };
    let list = forgerpc::VpcList { vpcs };
    serde_json::to_string(&list).unwrap();
    (StatusCode::OK, Json(list)).into_response()
}

async fn fetch_vpcs(api: Arc<Api>) -> Result<Vec<forgerpc::Vpc>, tonic::Status> {
    let request = tonic::Request::new(forgerpc::VpcSearchFilter::default());

    let vpc_ids = api.find_vpc_ids(request).await?.into_inner().vpc_ids;

    let mut vpcs = Vec::new();
    let mut offset = 0;
    while offset != vpc_ids.len() {
        const PAGE_SIZE: usize = 100;
        let page_size = PAGE_SIZE.min(vpc_ids.len() - offset);
        let next_ids = &vpc_ids[offset..offset + page_size];
        let next_vpcs = api
            .find_vpcs_by_ids(tonic::Request::new(forgerpc::VpcsByIdsRequest {
                vpc_ids: next_ids.to_vec(),
            }))
            .await?
            .into_inner();

        vpcs.extend(next_vpcs.vpcs.into_iter());
        offset += page_size;
    }

    vpcs.sort_unstable_by(|vpc1, vpc2| {
        // Order by name first, and ID second
        let ord = vpc1.name.cmp(&vpc2.name);
        if !ord.is_eq() {
            return ord;
        }

        vpc1.id
            .as_ref()
            .map(|id| id.to_string())
            .cmp(&vpc2.id.as_ref().map(|id| id.to_string()))
    });
    Ok(vpcs)
}

#[derive(Template)]
#[template(path = "vpc_detail.html")]
struct VpcDetail {
    id: String,
    tenant_organization_id: String,
    tenant_keyset_id: String,
    network_virtualization_type: String,
    vni: String,
    version: String,
    metadata: rpc::forge::Metadata,
}

impl From<forgerpc::Vpc> for VpcDetail {
    fn from(vpc: forgerpc::Vpc) -> Self {
        Self {
            network_virtualization_type: format!("{:?}", vpc.network_virtualization_type()),
            id: vpc.id.unwrap_or_default().to_string(),
            metadata: vpc.metadata.unwrap_or_default(),
            tenant_organization_id: vpc.tenant_organization_id,
            tenant_keyset_id: vpc.tenant_keyset_id.unwrap_or_default(),
            vni: vpc.vni.map(|vni| vni.to_string()).unwrap_or_default(),
            version: vpc.version,
        }
    }
}

/// View VPC details
pub async fn detail(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(vpc_id): AxumPath<String>,
) -> Response {
    let (show_json, vpc_id_string) = match vpc_id.strip_suffix(".json") {
        Some(vpc_id) => (true, vpc_id.to_string()),
        None => (false, vpc_id),
    };

    let vpc_id = match vpc_id_string.parse() {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid VPC ID {vpc_id_string}: {e}"),
            )
                .into_response();
        }
    };

    let request = tonic::Request::new(forgerpc::VpcsByIdsRequest {
        vpc_ids: vec![vpc_id],
    });
    let vpc = match state
        .find_vpcs_by_ids(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(x) if x.vpcs.is_empty() => {
            return super::not_found_response(vpc_id_string);
        }
        Ok(x) if x.vpcs.len() != 1 => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("VPC list for {vpc_id} returned {} VPCs", x.vpcs.len()),
            )
                .into_response();
        }
        Ok(mut x) => x.vpcs.remove(0),
        Err(err) => {
            tracing::error!(%err, "find_vpcs");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading VPCs").into_response();
        }
    };

    if show_json {
        return (StatusCode::OK, Json(vpc)).into_response();
    }

    let tmpl: VpcDetail = vpc.into();
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}
