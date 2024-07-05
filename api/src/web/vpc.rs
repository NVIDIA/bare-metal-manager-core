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
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;

use crate::api::Api;

#[derive(Template)]
#[template(path = "vpc_show.html")]
struct VpcShow {
    vpcs: Vec<VpcRowDisplay>,
}

struct VpcRowDisplay {
    id: String,
    name: String,
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
            name: vpc.name,
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

pub async fn show_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
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
    let request = tonic::Request::new(forgerpc::VpcSearchQuery {
        id: None,
        name: None,
    });
    let mut vpcs = api
        .find_vpcs(request)
        .await
        .map(|response| response.into_inner())?;
    vpcs.vpcs.sort_unstable_by(|vpc1, vpc2| {
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
    Ok(vpcs.vpcs)
}

#[derive(Template)]
#[template(path = "vpc_detail.html")]
struct VpcDetail {
    id: String,
    name: String,
    tenant_organization_id: String,
    tenant_keyset_id: String,
    network_virtualization_type: String,
    vni: String,
    version: String,
}

impl From<forgerpc::Vpc> for VpcDetail {
    fn from(vpc: forgerpc::Vpc) -> Self {
        Self {
            network_virtualization_type: format!("{:?}", vpc.network_virtualization_type()),
            id: vpc.id.unwrap_or_default().to_string(),
            name: vpc.name,
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
    let request = tonic::Request::new(forgerpc::VpcSearchQuery {
        id: Some(::rpc::common::Uuid {
            value: vpc_id.clone(),
        }),
        name: None,
    });
    let mut vpcs: forgerpc::VpcList = match state
        .find_vpcs(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "find_vpcs");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading VPCs").into_response();
        }
    };
    if vpcs.vpcs.is_empty() {
        return super::not_found_response(vpc_id);
    }
    if vpcs.vpcs.len() != 1 {
        tracing::error!(%vpc_id, "Expected exactly 1 match, found {}", vpcs.vpcs.len());
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Expected exactly one VPC to match",
        )
            .into_response();
    }
    let vpc = vpcs.vpcs.pop().unwrap(); // safe, we check above

    let tmpl: VpcDetail = vpc.into();
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}
