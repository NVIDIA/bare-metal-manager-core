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

use std::collections::BTreeMap;
use std::sync::Arc;

use askama::Template;
use axum::Json;
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use chrono::{DateTime, Utc};
use hyper::http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "interface_show.html")]
struct InterfaceShow {
    interfaces: Vec<InterfaceRowDisplay>,
}

struct InterfaceRowDisplay {
    id: String,
    mac_address: String,
    ip_address: String,
    machine_id: String,
    hostname: String,
    vendor: String,
    domain_name: String,
}

impl From<forgerpc::MachineInterface> for InterfaceRowDisplay {
    fn from(mi: forgerpc::MachineInterface) -> Self {
        Self {
            id: mi.id.unwrap_or_default().to_string(),
            mac_address: mi.mac_address,
            ip_address: mi.address.join(","),
            machine_id: mi
                .machine_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_default(),
            hostname: mi.hostname,
            vendor: mi.vendor.unwrap_or_default(),
            domain_name: String::new(), // filled in later
        }
    }
}

/// List machine interfaces
pub async fn show_html(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let machine_interfaces = match fetch_machine_interfaces(state.clone()).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "find_interfaces");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading machine interfaces",
            )
                .into_response();
        }
    };

    let request = tonic::Request::new(::rpc::protos::dns::DomainSearchQuery {
        id: None,
        name: None,
    });
    let domain_list = match state
        .find_domain(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "find_domain");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading domains").into_response();
        }
    };
    let domainlist_map = domain_list
        .domains
        .into_iter()
        .map(|x| (x.id.unwrap_or_default(), x.name))
        .collect::<BTreeMap<_, _>>();

    let mut interfaces = Vec::new();
    for iface in machine_interfaces {
        let domain_name = domainlist_map
            .get(&iface.domain_id.unwrap_or_default())
            .cloned()
            .unwrap_or_default();
        let mut display: InterfaceRowDisplay = iface.into();
        display.domain_name = domain_name;
        interfaces.push(display);
    }
    let tmpl = InterfaceShow { interfaces };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_all_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let machine_interfaces = match fetch_machine_interfaces(state).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_machine_interfaces");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading machine interfaces",
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(machine_interfaces)).into_response()
}

async fn fetch_machine_interfaces(
    api: Arc<Api>,
) -> Result<Vec<forgerpc::MachineInterface>, tonic::Status> {
    let request = tonic::Request::new(forgerpc::InterfaceSearchQuery { id: None, ip: None });
    let mut out = api
        .find_interfaces(request)
        .await
        .map(|response| response.into_inner())?;
    out.interfaces
        .sort_unstable_by(|iface1, iface2| iface1.hostname.cmp(&iface2.hostname));
    Ok(out.interfaces)
}

#[derive(Template)]
#[template(path = "interface_detail.html")]
struct InterfaceDetail {
    id: String,
    dpu_machine_id: String,
    machine_id: String,
    segment_id: String,
    mac_address: String,
    ip_address: String,
    hostname: String,
    vendor: String,
    domain_id: String,
    domain_name: String,
    is_primary: bool,
    created: String,
    last_dhcp: String,
    is_bmc: bool,
}

impl From<forgerpc::MachineInterface> for InterfaceDetail {
    fn from(mi: forgerpc::MachineInterface) -> Self {
        let created: DateTime<Utc> = mi
            .created
            .expect("machine_interfaces.created is NOT NULL in DB, should exist")
            .try_into()
            .unwrap_or_default();
        let last_dhcp: Option<DateTime<Utc>> = match mi.last_dhcp {
            None => None,
            Some(d) => d.try_into().ok(),
        };
        Self {
            id: mi.id.unwrap_or_default().to_string(),
            dpu_machine_id: mi
                .attached_dpu_machine_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_default(),
            machine_id: mi
                .machine_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_default(),
            segment_id: mi.segment_id.unwrap_or_default().to_string(),
            mac_address: mi.mac_address,
            ip_address: mi.address.join(","),
            hostname: mi.hostname,
            vendor: mi.vendor.unwrap_or_default(),
            is_primary: mi.primary_interface,
            domain_id: mi.domain_id.unwrap_or_default().to_string(),
            // filled in later
            domain_name: String::new(),
            // e.g "2001-07-08 00:34:60	UTC"
            created: created.format("%F %T %Z").to_string(),
            last_dhcp: last_dhcp
                .map(|d| d.format("%F %T %Z").to_string())
                .unwrap_or_default(),
            is_bmc: mi.is_bmc.unwrap_or(false),
        }
    }
}

/// View machine interface details
pub async fn detail(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(interface_id): AxumPath<String>,
) -> Response {
    let (show_json, interface_id_string) = match interface_id.strip_suffix(".json") {
        Some(interface_id) => (true, interface_id.to_string()),
        None => (false, interface_id),
    };

    let interface_id = match interface_id_string.parse() {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid interface ID: {e}"),
            )
                .into_response();
        }
    };

    let request = tonic::Request::new(forgerpc::InterfaceSearchQuery {
        id: Some(interface_id),
        ip: None,
    });
    let mut machine_interfaces = match state
        .find_interfaces(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(n) => n,
        Err(err) if err.code() == tonic::Code::NotFound => {
            return super::not_found_response(interface_id_string);
        }
        Err(err) => {
            tracing::error!(%err, "find_interfaces");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading machine interface",
            )
                .into_response();
        }
    };

    if machine_interfaces.interfaces.len() != 1 {
        tracing::error!(%interface_id, "Expected exactly 1 match, found {}", machine_interfaces.interfaces.len());
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Expected exactly one interface to match",
        )
            .into_response();
    }
    let interface = machine_interfaces.interfaces.pop().unwrap(); // safe, we check above

    if show_json {
        return (StatusCode::OK, Json(interface)).into_response();
    }

    let tmpl: InterfaceDetail = interface.into();
    // TODO tmpl.domain_name = domain_name;
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}
