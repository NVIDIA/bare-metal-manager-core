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

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::extract::{Query, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "network_status.html")]
struct NetworkStatus {
    dpus: Vec<NetworkStatusDisplay>,
    active_filter: String,
    all_count: usize,
    healthy_count: usize,
    unhealthy_count: usize,
    outdated_count: usize,
}

#[derive(Clone)]
struct NetworkStatusDisplay {
    observed_at: String,
    dpu_machine_id: String,
    network_config_version: String,
    is_healthy: bool,
    check_failed: String,
    agent_version: String,
    is_agent_updated: bool,
}

impl From<forgerpc::DpuNetworkStatus> for NetworkStatusDisplay {
    fn from(mut st: forgerpc::DpuNetworkStatus) -> Self {
        let h = st.health.take().unwrap(); // safe, caller filtered
        let failed_health_check = if !h.failed.is_empty() {
            format!(
                "{} ({})",
                h.failed.first().map(String::as_str).unwrap_or_default(),
                h.message.unwrap_or_default(),
            )
        } else {
            "".to_string()
        };
        let agent_version = st.dpu_agent_version.unwrap_or_default();
        Self {
            observed_at: st
                .observed_at
                .map(|o| {
                    let dt: chrono::DateTime<chrono::Utc> = o.try_into().unwrap_or_default();
                    dt.format("%Y-%m-%d %H:%M:%S.%3f").to_string()
                })
                .unwrap_or_default(),
            dpu_machine_id: st
                .dpu_machine_id
                .unwrap_or_else(super::invalid_machine_id)
                .to_string(),
            network_config_version: st.network_config_version.unwrap_or_default(),
            is_healthy: h.is_healthy,
            check_failed: failed_health_check,
            is_agent_updated: agent_version == forge_version::v!(build_version),
            agent_version,
        }
    }
}

pub async fn show_html(
    AxumState(state): AxumState<Arc<Api>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let filter = params.get("filter").cloned().unwrap_or("all".to_string());

    let all_status = match fetch_network_status(state).await {
        Ok(all) => all,
        Err(err) => {
            tracing::error!(%err, "fetch_network_status");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading network status",
            )
                .into_response();
        }
    };
    let all_count = all_status.len();
    let mut dpus = Vec::with_capacity(all_status.len());
    let (mut healthy_count, mut unhealthy_count, mut outdated_count) = (0, 0, 0);
    for st in all_status.into_iter() {
        let display: NetworkStatusDisplay = st.into();
        if display.is_healthy {
            healthy_count += 1;
        } else {
            unhealthy_count += 1;
        }
        if !display.is_agent_updated {
            outdated_count += 1;
        }
        match filter.as_str() {
            "all" => dpus.push(display),
            "healthy" => {
                if display.is_healthy {
                    dpus.push(display);
                }
            }
            "unhealthy" => {
                if !display.is_healthy {
                    dpus.push(display);
                }
            }
            "outdated" => {
                if !display.is_agent_updated {
                    dpus.push(display);
                }
            }
            _ => {
                return (StatusCode::BAD_REQUEST, "Unknown filter").into_response();
            }
        }
    }
    let tmpl = NetworkStatus {
        dpus,
        active_filter: filter,
        all_count,
        healthy_count,
        unhealthy_count,
        outdated_count,
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let all_status = match fetch_network_status(state).await {
        Ok(all) => all,
        Err(err) => {
            tracing::error!(%err, "fetch_network_status");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading network status",
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(all_status)).into_response()
}

async fn fetch_network_status(
    api: Arc<Api>,
) -> Result<Vec<forgerpc::DpuNetworkStatus>, tonic::Status> {
    let request = tonic::Request::new(forgerpc::ManagedHostNetworkStatusRequest {});
    let mut all_status = api
        .get_all_managed_host_network_status(request)
        .await
        .map(|response| response.into_inner())?;
    all_status.all.retain(|ns| ns.health.is_some());
    Ok(all_status.all)
}
