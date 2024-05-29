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

            managed_hosts.push(ExploredManagedHostDisplay {
                host_bmc_ip: mh.host_bmc_ip,
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
                dpus: mh
                    .dpus
                    .iter()
                    .map(|d| {
                        let report = report
                            .endpoints
                            .iter()
                            .find(|ep| ep.address == d.bmc_ip)
                            .and_then(|dpu| dpu.report.as_ref());
                        ExploredDpuDisplay {
                            dpu_bmc_ip: d.bmc_ip.clone(),
                            dpu_machine_id: report
                                .map(|r| r.machine_id().to_string())
                                .unwrap_or_default(),
                            dpu_serial_numbers: report
                                .map(|r| {
                                    r.systems
                                        .iter()
                                        .filter_map(|sys| sys.serial_number.clone())
                                        .collect()
                                })
                                .unwrap_or_default(),
                            host_pf_mac: d.host_pf_mac_address.clone().unwrap_or_default(),
                            dpu_oob_mac: report
                                .and_then(|r| r.systems.first())
                                .and_then(|sys| sys.ethernet_interfaces.first())
                                .and_then(|iface| iface.mac_address.clone())
                                .unwrap_or_default(),
                        }
                    })
                    .collect(),
            });
        }

        Self {
            endpoints,
            managed_hosts,
        }
    }
}

struct ExploredDpuDisplay {
    dpu_bmc_ip: String,
    dpu_machine_id: String,
    dpu_serial_numbers: Vec<String>,
    host_pf_mac: String,
    dpu_oob_mac: String,
}

struct ExploredManagedHostDisplay {
    host_bmc_ip: String,
    host_serial_numbers: Vec<String>,
    host_vendor: String,
    dpus: Vec<ExploredDpuDisplay>,
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
pub async fn show_html(AxumState(state): AxumState<Arc<Api>>) -> Response {
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

pub async fn show_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
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

async fn fetch_explored_endpoints(api: Arc<Api>) -> Result<SiteExplorationReport, tonic::Status> {
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
pub async fn detail(
    AxumState(state): AxumState<Arc<Api>>,
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
