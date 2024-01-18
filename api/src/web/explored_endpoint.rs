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
use rpc::site_explorer::{ExploredEndpoint, ExploredManagedHost, SiteExplorationReport};

use crate::api::Api;

#[derive(Template)]
#[template(path = "explored_endpoints_show.html")]
struct ExploredEndpointsShow {
    endpoints: Vec<ExploredEndpointDisplay>,
    managed_hosts: Vec<ExploredManagedHost>,
}

impl From<SiteExplorationReport> for ExploredEndpointsShow {
    fn from(report: SiteExplorationReport) -> Self {
        Self {
            endpoints: report.endpoints.into_iter().map(Into::into).collect(),
            managed_hosts: report.managed_hosts,
        }
    }
}

struct ExploredEndpointDisplay {
    address: String,
    endpoint_type: String,
    last_exploration_error: String,
    machine_id: String,
    serial_numbers: Vec<String>,
}

impl From<ExploredEndpoint> for ExploredEndpointDisplay {
    fn from(ep: ExploredEndpoint) -> Self {
        let report_ref = ep.report.as_ref();
        Self {
            address: ep.address,
            endpoint_type: report_ref
                .map(|report| report.endpoint_type.clone())
                .unwrap_or_default(),
            last_exploration_error: report_ref
                .and_then(|report| report.last_exploration_error.clone())
                .unwrap_or_default(),
            machine_id: report_ref
                .and_then(|report| report.machine_id.clone())
                .unwrap_or_default(),
            serial_numbers: report_ref
                .map(|report| {
                    report
                        .systems
                        .iter()
                        .map(|s| s.serial_number().to_string())
                        .collect()
                })
                .unwrap_or_default(),
        }
    }
}

/// List explored endpoints
pub async fn show_html<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let report = match fetch_explored_endpoints(state).await {
        Ok(report) => report,
        Err(err) => {
            tracing::error!(%err, "fetch_explored_endpoints");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading site exploration report",
            )
                .into_response();
        }
    };

    let tmpl = ExploredEndpointsShow::from(report);
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_json<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let report = match fetch_explored_endpoints(state).await {
        Ok(report) => report,
        Err(err) => {
            tracing::error!(%err, "fetch_explored_endpoints");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading site exploration report",
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(report)).into_response()
}

async fn fetch_explored_endpoints<
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
>(
    api: Arc<Api<C1, C2>>,
) -> Result<SiteExplorationReport, tonic::Status> {
    let request = tonic::Request::new(forgerpc::GetSiteExplorationRequest {});
    api.get_site_exploration_report(request)
        .await
        .map(|response| response.into_inner())
}

#[derive(Template)]
#[template(path = "explored_endpoint_detail.html")]
struct ExploredEndpointDetail {
    endpoint: ExploredEndpoint,
}

impl From<ExploredEndpoint> for ExploredEndpointDetail {
    fn from(endpoint: ExploredEndpoint) -> Self {
        Self { endpoint }
    }
}

/// View details of an explored endpoint
pub async fn detail<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
    AxumPath(endpoint_ip): AxumPath<String>,
) -> Response {
    let report = match fetch_explored_endpoints(state).await {
        Ok(report) => report,
        Err(err) => {
            tracing::error!(%err, "fetch_explored_endpoints");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading site exploration report",
            )
                .into_response();
        }
    };

    let endpoint = match report
        .endpoints
        .into_iter()
        .find(|ep| ep.address.trim() == endpoint_ip.trim())
    {
        Some(ep) => ep,
        None => {
            tracing::error!(%endpoint_ip, "Could not find matching endpoint exploration report");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not find matching endpoint exploration report",
            )
                .into_response();
        }
    };

    let display = ExploredEndpointDetail::from(endpoint);
    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}
