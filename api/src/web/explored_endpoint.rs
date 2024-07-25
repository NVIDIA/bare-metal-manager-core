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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use askama::Template;
use axum::extract::{Path as AxumPath, Query, State as AxumState};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;
use rpc::site_explorer::{ExploredEndpoint, SiteExplorationReport};
use serde::Deserialize;

use super::filters;
use crate::api::Api;
use crate::model::machine::machine_id;

#[derive(Template)]
#[template(path = "explored_endpoints_show.html")]
struct ExploredEndpointsShow {
    vendors: Vec<String>,
    endpoints: Vec<ExploredEndpointDisplay>,
    filter_name: &'static str,
    active_vendor_filter: String,
    is_errors_only: bool,
}

#[derive(Template)]
#[template(path = "explored_endpoints_show_paired.html")]
struct ExploredEndpointsShowPaired {
    managed_hosts: Vec<ExploredManagedHostDisplay>,
}

/// Create the managed host display
impl From<SiteExplorationReport> for ExploredEndpointsShowPaired {
    fn from(report: SiteExplorationReport) -> Self {
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

        Self { managed_hosts }
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
pub async fn show_html_all(
    AxumState(state): AxumState<Arc<Api>>,
    Query(params): Query<HashMap<String, String>>,
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

    let endpoints: Vec<ExploredEndpointDisplay> = report.endpoints.iter().map(Into::into).collect();
    let vendors = vendors(&endpoints); // need vendors pre-filtering
    let vendor_filter = params
        .get("vendor-filter")
        .cloned()
        .unwrap_or("ALL".to_string());
    let is_errors_only = params.get("errors-only").is_some();
    let query_filter = query_filter_for(params);
    let tmpl = ExploredEndpointsShow {
        filter_name: "All",
        vendors,
        endpoints: endpoints.into_iter().filter(|x| query_filter(x)).collect(),
        active_vendor_filter: vendor_filter,
        is_errors_only,
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_html_paired(AxumState(state): AxumState<Arc<Api>>) -> Response {
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

    let tmpl = ExploredEndpointsShowPaired::from(report);
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_html_unpaired(
    AxumState(state): AxumState<Arc<Api>>,
    Query(params): Query<HashMap<String, String>>,
) -> Response {
    let report = match fetch_explored_endpoints(state.clone()).await {
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

    let paired_bmcs: HashSet<&str> = report
        .managed_hosts
        .iter()
        .flat_map(|mh| [mh.host_bmc_ip.as_str(), mh.dpu_bmc_ip.as_str()])
        .collect();
    let endpoints: Vec<ExploredEndpointDisplay> = report
        .endpoints
        .iter()
        .filter(|ep| !paired_bmcs.contains(ep.address.as_str()))
        .map(Into::into)
        .collect();

    // We have filtered out the ones Site Explorer paired. Now filter the pre-site-explorer ones.
    // Once we are 100% site explorer everywhere we can remove this part
    let bmc_ips: Vec<String> = endpoints.iter().map(|ep| ep.address.clone()).collect();
    let req = tonic::Request::new(forgerpc::BmcIpList { bmc_ips });
    let legacy_paired_bmcs: HashSet<String> = match state.find_machine_ids_by_bmc_ips(req).await {
        Ok(res) => res
            .into_inner()
            .pairs
            .into_iter()
            .map(|pair| pair.bmc_ip)
            .collect(),
        Err(err) => {
            tracing::error!(%err, "find_machine_ids_by_bmc_ips");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error find_machine_ids_by_bmc_ips",
            )
                .into_response();
        }
    };
    let endpoints: Vec<_> = endpoints
        .into_iter()
        .filter(|ep| !legacy_paired_bmcs.contains(ep.address.as_str()))
        .collect();

    let vendors = vendors(&endpoints); // need vendors pre-filtering

    let vendor_filter = params
        .get("vendor-filter")
        .cloned()
        .unwrap_or("ALL".to_string());
    let is_errors_only = params.get("errors-only").is_some();
    let query_filter = query_filter_for(params);
    let tmpl = ExploredEndpointsShow {
        filter_name: "Unpaired",
        vendors,
        endpoints: endpoints.into_iter().filter(|x| query_filter(x)).collect(),
        active_vendor_filter: vendor_filter,
        is_errors_only,
    };
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
    let report = match fetch_explored_endpoints(state.clone()).await {
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

    let mut endpoint = match report
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
    // Site Explorer doesn't link Host Explored Endpoints with their machine, only DPUs.
    // So do it here.
    if let Some(ref mut report) = endpoint.report {
        if report.machine_id.is_none() {
            let req = tonic::Request::new(forgerpc::BmcIpList {
                bmc_ips: vec![endpoint.address.clone()],
            });
            match state.find_machine_ids_by_bmc_ips(req).await {
                Ok(res) => {
                    if let Some(pair) = res.into_inner().pairs.first() {
                        // we found a matching machine
                        report.machine_id = pair
                            .machine_id
                            .as_ref()
                            .and_then(|rpc_machine_id| {
                                machine_id::try_parse_machine_id(rpc_machine_id).ok()
                            })
                            .map(|machine_id| machine_id.to_string());
                    }
                }
                Err(err) => {
                    tracing::error!(%err, "find_machine_ids_by_bmc_ips");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Error find_machine_ids_by_bmc_ips",
                    )
                        .into_response();
                }
            }
        }
    }

    let display = ExploredEndpointDetail::from(endpoint);
    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

pub async fn re_explore(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(endpoint_ip): AxumPath<String>,
    Form(form): Form<ReExploreEndpointAction>,
) -> impl IntoResponse {
    let view_url = format!("/admin/explored_endpoint/{endpoint_ip}");

    if let Err(err) = state
        .re_explore_endpoint(tonic::Request::new(rpc::forge::ReExploreEndpointRequest {
            ip_address: endpoint_ip.clone(),
            if_version_match: form.if_version_match,
        }))
        .await
        .map(|response| response.into_inner())
    {
        tracing::error!(%err, endpoint_ip, "re_explore_endpoint");
        return Redirect::to(&view_url);
    }

    Redirect::to(&view_url)
}

#[derive(Deserialize, Debug)]
pub struct ReExploreEndpointAction {
    if_version_match: Option<String>,
}

fn vendors(endpoints: &[ExploredEndpointDisplay]) -> Vec<String> {
    let vendors: HashSet<String> = endpoints
        .iter()
        .map(|ep| ep.vendor.clone())
        .filter(|v| !v.is_empty())
        .collect();
    let mut vendors: Vec<String> = vendors.into_iter().collect();
    vendors.sort();
    vendors
}

fn query_filter_for(
    mut params: HashMap<String, String>,
) -> Box<dyn Fn(&ExploredEndpointDisplay) -> bool> {
    let vf: Box<dyn Fn(&ExploredEndpointDisplay) -> bool> =
        match params.remove("vendor-filter").map(|v| v.trim().to_string()) {
            Some(v) if v != "ALL" => Box::new(move |ep: &ExploredEndpointDisplay| {
                ep.vendor.to_uppercase() == v || v == "NONE" && ep.vendor.is_empty()
            }),
            _ => Box::new(|_| true),
        };
    let ef: Box<dyn Fn(&ExploredEndpointDisplay) -> bool> = if params.contains_key("errors-only") {
        Box::new(|ep: &ExploredEndpointDisplay| !ep.last_exploration_error.is_empty())
    } else {
        Box::new(|_| true)
    };
    Box::new(move |x| vf(x) && ef(x))
}
