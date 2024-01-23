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
use rpc::site_explorer::{ExploredEndpoint, SiteExplorationReport};

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "explored_endpoints_show.html")]
struct ExploredEndpointsShow {
    endpoints: Vec<ExploredEndpointDisplay>,
    managed_hosts: Vec<ExploredManagedHostDisplay>,
}

impl From<SiteExplorationReport> for ExploredEndpointsShow {
    fn from(report: SiteExplorationReport) -> Self {
        let endpoints: Vec<ExploredEndpointDisplay> =
            report.endpoints.iter().map(Into::into).collect();

        let mut managed_hosts = Vec::new();
        for mh in report.managed_hosts {
            let host = match report
                .endpoints
                .binary_search_by(|ep| ep.address.cmp(&mh.host_bmc_ip))
            {
                Ok(idx) => Some(&report.endpoints[idx]),
                Err(_) => None,
            };
            let host = host.and_then(|h| h.report.as_ref());
            // We can only binary search by host because the endpoints list is
            // sorted by that
            let dpu = report
                .endpoints
                .iter()
                .find(|ep| ep.address == mh.dpu_bmc_ip);
            let dpu = dpu.and_then(|dpu| dpu.report.as_ref());

            managed_hosts.push(ExploredManagedHostDisplay {
                host_bmc_ip: mh.host_bmc_ip,
                dpu_bmc_ip: mh.dpu_bmc_ip,
                dpu_machine_id: dpu
                    .map(|report| report.machine_id().to_string())
                    .unwrap_or_default(),
                host_vendor: host
                    .map(|report| report.vendor().to_string())
                    .unwrap_or_default(),
                host_serial_numbers: host
                    .map(|report| {
                        report
                            .systems
                            .iter()
                            .filter_map(|sys| sys.serial_number.clone())
                            .collect()
                    })
                    .unwrap_or_default(),
                dpu_serial_numbers: dpu
                    .map(|report| {
                        report
                            .systems
                            .iter()
                            .filter_map(|sys| sys.serial_number.clone())
                            .collect()
                    })
                    .unwrap_or_default(),
                dpu_oob_mac: dpu
                    .and_then(|report| report.systems.get(0))
                    .and_then(|sys| sys.ethernet_interfaces.get(0))
                    .and_then(|iface| iface.mac_address.clone())
                    .unwrap_or_default(),
            });
        }

        Self {
            endpoints,
            managed_hosts,
        }
    }
}

struct ExploredManagedHostDisplay {
    host_bmc_ip: String,
    dpu_bmc_ip: String,
    dpu_machine_id: String,
    host_vendor: String,
    dpu_serial_numbers: Vec<String>,
    host_serial_numbers: Vec<String>,
    dpu_oob_mac: String,
}
struct ExploredEndpointDisplay {
    address: String,
    endpoint_type: String,
    last_exploration_error: String,
    vendor: String,
    bmc_mac_addrs: Vec<String>,
    machine_id: String,
    serial_numbers: Vec<String>,
}

impl From<&ExploredEndpoint> for ExploredEndpointDisplay {
    fn from(ep: &ExploredEndpoint) -> Self {
        let report_ref = ep.report.as_ref();
        Self {
            address: ep.address.clone(),
            endpoint_type: report_ref
                .map(|report| report.endpoint_type.clone())
                .unwrap_or_default(),
            last_exploration_error: report_ref
                .and_then(|report| report.last_exploration_error.clone())
                .unwrap_or_default(),
            bmc_mac_addrs: report_ref
                .map(|report| {
                    report
                        .managers
                        .iter()
                        .flat_map(|m| {
                            m.ethernet_interfaces
                                .iter()
                                .filter_map(|iface| iface.mac_address.clone())
                        })
                        .collect::<Vec<String>>()
                })
                .unwrap_or_default(),
            vendor: report_ref
                .and_then(|report| report.vendor.clone())
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
        .map(|mut report| {
            // Sort everything for a a pretter display
            report.endpoints.sort_by(|a, b| a.address.cmp(&b.address));
            report
                .managed_hosts
                .sort_by(|a, b| a.host_bmc_ip.cmp(&b.host_bmc_ip));
            report
        })
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
