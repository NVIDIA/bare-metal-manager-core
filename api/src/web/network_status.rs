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

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "network_status.html")]
struct NetworkStatus {
    healthy: Vec<NetworkStatusDisplay>,
    unhealthy: Vec<NetworkStatusDisplay>,
}

struct NetworkStatusDisplay {
    observed_at: String,
    dpu_machine_id: String,
    network_config_version: String,
    is_healthy: bool,
    check_failed: String,
    agent_version: String,
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
            agent_version: st.dpu_agent_version.unwrap_or_default(),
        }
    }
}

pub async fn show_html<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
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
    let mut healthy = Vec::new();
    let mut unhealthy = Vec::new();
    //for st in all_status.into_iter().filter(|st| st.health.is_some()) {
    for st in all_status.into_iter() {
        let display: NetworkStatusDisplay = st.into();
        if display.is_healthy {
            healthy.push(display);
        } else {
            unhealthy.push(display);
        }
    }
    let tmpl = NetworkStatus { healthy, unhealthy };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_json<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
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

async fn fetch_network_status<
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
>(
    api: Arc<Api<C1, C2>>,
) -> Result<Vec<forgerpc::DpuNetworkStatus>, tonic::Status> {
    let request = tonic::Request::new(forgerpc::ManagedHostNetworkStatusRequest {});
    let mut all_status = api
        .get_all_managed_host_network_status(request)
        .await
        .map(|response| response.into_inner())?;
    all_status.all.retain(|ns| ns.health.is_some());
    Ok(all_status.all)
}
