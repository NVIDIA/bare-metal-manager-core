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
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;
use http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;

use crate::api::Api;

#[derive(Template)]
#[template(path = "ib_partition_show.html")]
struct IbPartitionShow {
    partitions: Vec<IbPartitionRowDisplay>,
}

struct IbPartitionRowDisplay {
    id: String,
    tenant_organization_id: String,
    name: String,
    state: String,
    pkey: String,
}

impl From<forgerpc::IbPartition> for IbPartitionRowDisplay {
    fn from(partition: forgerpc::IbPartition) -> Self {
        Self {
            id: partition.id.map(|id| id.value).unwrap_or_default(),
            tenant_organization_id: partition
                .config
                .as_ref()
                .map(|config| config.tenant_organization_id.clone())
                .unwrap_or_default(),
            name: partition
                .config
                .as_ref()
                .map(|config| config.name.clone())
                .unwrap_or_default(),
            state: partition
                .status
                .as_ref()
                .and_then(|status| forgerpc::TenantState::try_from(status.state).ok())
                .map(|state| format!("{:?}", state))
                .unwrap_or_default(),
            pkey: partition
                .status
                .as_ref()
                .and_then(|status| status.pkey.clone())
                .unwrap_or_default(),
        }
    }
}

/// List partitions
pub async fn show_html<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let partitions = match fetch_ib_partitions(state.clone()).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_ib_partitions");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading IB partitions",
            )
                .into_response();
        }
    };

    let tmpl = IbPartitionShow {
        partitions: partitions.into_iter().map(Into::into).collect(),
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_json<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let partitions = match fetch_ib_partitions(state).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_ib_partitions");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading IB partitions",
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(partitions)).into_response()
}

async fn fetch_ib_partitions<
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
>(
    api: Arc<Api<C1, C2>>,
) -> Result<Vec<forgerpc::IbPartition>, tonic::Status> {
    let request = tonic::Request::new(forgerpc::IbPartitionQuery {
        id: None,
        search_config: Some(forgerpc::IbPartitionSearchConfig {
            include_history: false,
        }),
    });
    let mut partitions = api
        .find_ib_partitions(request)
        .await
        .map(|response| response.into_inner())?;
    partitions
        .ib_partitions
        .sort_unstable_by(|p1, p2: &rpc::IbPartition| {
            // Sort by tenant_org and name
            // Otherwise fall back to ID
            if let (Some(p1), Some(p2)) = (p1.config.as_ref(), p2.config.as_ref()) {
                let ord = p1.tenant_organization_id.cmp(&p2.tenant_organization_id);
                if ord.is_ne() {
                    return ord;
                }
                let ord = p1.name.cmp(&p2.name);
                if ord.is_ne() {
                    return ord;
                }
            }
            if let (Some(id1), Some(id2)) = (p1.id.as_ref(), p2.id.as_ref()) {
                return id1.value.cmp(&id2.value);
            }
            // This path should never be taken, since ID is always set
            (p1 as *const rpc::IbPartition).cmp(&(p2 as *const rpc::IbPartition))
        });
    Ok(partitions.ib_partitions)
}

#[derive(Template)]
#[template(path = "ib_partition_detail.html")]
struct IbPartitionDetail {
    id: String,
    config_version: String,
    tenant_organization_id: String,
    name: String,
    state: String,
    pkey: String,
    service_level: String,
    rate_limit: String,
    mtu: String,
    enable_sharp: String,
}

impl From<forgerpc::IbPartition> for IbPartitionDetail {
    fn from(partition: forgerpc::IbPartition) -> Self {
        Self {
            id: partition.id.map(|id| id.value).unwrap_or_default(),
            config_version: partition.config_version,
            tenant_organization_id: partition
                .config
                .as_ref()
                .map(|config| config.tenant_organization_id.clone())
                .unwrap_or_default(),
            name: partition
                .config
                .as_ref()
                .map(|config| config.name.clone())
                .unwrap_or_default(),
            state: partition
                .status
                .as_ref()
                .and_then(|status| forgerpc::TenantState::try_from(status.state).ok())
                .map(|state| format!("{:?}", state))
                .unwrap_or_default(),
            pkey: partition
                .status
                .as_ref()
                .and_then(|status| status.pkey.clone())
                .unwrap_or_default(),
            service_level: partition
                .status
                .as_ref()
                .and_then(|status| status.service_level)
                .map(|service_level| service_level.to_string())
                .unwrap_or_default(),
            rate_limit: partition
                .status
                .as_ref()
                .and_then(|status| status.rate_limit)
                .map(|rate_limit| rate_limit.to_string())
                .unwrap_or_default(),
            mtu: partition
                .status
                .as_ref()
                .and_then(|status| status.mtu)
                .map(|mtu| mtu.to_string())
                .unwrap_or_default(),
            enable_sharp: partition
                .status
                .as_ref()
                .and_then(|status| status.enable_sharp)
                .map(|enable_sharp| enable_sharp.to_string())
                .unwrap_or_default(),
        }
    }
}

/// View partition details
pub async fn detail<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
    AxumPath(partition_id): AxumPath<String>,
) -> Response {
    let request = tonic::Request::new(forgerpc::IbPartitionQuery {
        id: Some(forgerpc::Uuid {
            value: partition_id.clone(),
        }),
        search_config: Some(forgerpc::IbPartitionSearchConfig {
            include_history: true,
        }),
    });
    let mut partitions = match state
        .find_ib_partitions(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(n) => n,
        Err(err) if err.code() == tonic::Code::NotFound => {
            return super::not_found_response(partition_id);
        }
        Err(err) => {
            tracing::error!(%err, "find_ib_partitions");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading IB partitions",
            )
                .into_response();
        }
    };
    if partitions.ib_partitions.len() != 1 {
        tracing::error!(%partition_id, "Expected exactly 1 match, found {}", partitions.ib_partitions.len());
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Expected exactly one IB partition to match",
        )
            .into_response();
    }
    let partition = partitions.ib_partitions.pop().unwrap(); // safe, we check above

    let tmpl: IbPartitionDetail = partition.into();
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}
