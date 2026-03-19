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
use axum::extract::State as AxumState;
use axum::response::{Html, IntoResponse, Response};
use chrono::{DateTime, Utc};
use hyper::http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;
use utils::models::dhcp::DhcpConfig;

use crate::api::Api;

#[derive(Template)]
#[template(path = "ipam_dhcp.html")]
struct IpamDhcp {
    entries: Vec<DhcpEntryDisplay>,
    lease_duration_secs: i64,
}

struct DhcpEntryDisplay {
    ip_address: String,
    mac_address: String,
    machine_id: String,
    hostname: String,
    created: String,
    last_dhcp: String,
    last_dhcp_rfc3339: String,
}

impl DhcpEntryDisplay {
    fn from_interface(mi: forgerpc::MachineInterface) -> Vec<Self> {
        let created: DateTime<Utc> = mi
            .created
            .and_then(|t| t.try_into().ok())
            .unwrap_or_default();
        let last_dhcp: Option<DateTime<Utc>> = mi.last_dhcp.and_then(|t| t.try_into().ok());

        let machine_id = mi
            .machine_id
            .as_ref()
            .map(|id| id.to_string())
            .unwrap_or_default();

        if mi.address.is_empty() {
            return Vec::new();
        }

        mi.address
            .into_iter()
            .map(|addr| DhcpEntryDisplay {
                ip_address: addr,
                mac_address: mi.mac_address.clone(),
                machine_id: machine_id.clone(),
                hostname: mi.hostname.clone(),
                created: created.format("%F %T %Z").to_string(),
                last_dhcp: last_dhcp
                    .map(|d| d.format("%F %T %Z").to_string())
                    .unwrap_or_default(),
                last_dhcp_rfc3339: last_dhcp.map(|d| d.to_rfc3339()).unwrap_or_default(),
            })
            .collect()
    }
}

/// DHCP allocations page
pub async fn dhcp_html(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let interfaces = match fetch_interfaces(state).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "find_interfaces for DHCP");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading DHCP allocations",
            )
                .into_response();
        }
    };

    let mut entries: Vec<DhcpEntryDisplay> = interfaces
        .into_iter()
        .flat_map(DhcpEntryDisplay::from_interface)
        .collect();
    entries.sort_by(|a, b| a.ip_address.cmp(&b.ip_address));

    let tmpl = IpamDhcp {
        entries,
        lease_duration_secs: DhcpConfig::default().lease_time_secs as i64,
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn dhcp_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let interfaces = match fetch_interfaces(state).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "find_interfaces for DHCP JSON");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading DHCP allocations",
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(interfaces)).into_response()
}

async fn fetch_interfaces(api: Arc<Api>) -> Result<Vec<forgerpc::MachineInterface>, tonic::Status> {
    let request = tonic::Request::new(forgerpc::InterfaceSearchQuery { id: None, ip: None });
    let mut out = api
        .find_interfaces(request)
        .await
        .map(|response| response.into_inner())?;
    out.interfaces
        .sort_unstable_by(|a, b| a.hostname.cmp(&b.hostname));
    Ok(out.interfaces)
}

#[derive(Template)]
#[template(path = "ipam_placeholder.html")]
struct IpamPlaceholder {
    section: &'static str,
}

/// DNS placeholder page
pub async fn dns_html() -> Response {
    let tmpl = IpamPlaceholder { section: "DNS" };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

/// Underlay Networks placeholder page
pub async fn underlay_html() -> Response {
    let tmpl = IpamPlaceholder {
        section: "Underlay Networks",
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

/// Overlay Networks placeholder page
pub async fn overlay_html() -> Response {
    let tmpl = IpamPlaceholder {
        section: "Overlay Networks",
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}
