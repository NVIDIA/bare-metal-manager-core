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
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use carbide_uuid::domain::DomainId;
use carbide_uuid::network::NetworkSegmentId;
use hyper::http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "network_segment_show.html")]
struct NetworkSegmentShow {
    admin: Vec<NetworkSegmentRowDisplay>,
    tenant: Vec<NetworkSegmentRowDisplay>,
    underlay: Vec<NetworkSegmentRowDisplay>,
}

struct NetworkSegmentRowDisplay {
    name: String,
    id: String,
    vpc_id: String,
    created: String,
    state: String,
    time_in_state_above_sla: bool,
    sub_domain: String,
    mtu: i32,
    prefixes: String,
    version: String,
}

impl From<forgerpc::NetworkSegment> for NetworkSegmentRowDisplay {
    fn from(segment: forgerpc::NetworkSegment) -> Self {
        Self {
            id: segment.id.unwrap_or_default().to_string(),
            name: segment.name,
            vpc_id: segment.vpc_id.map(|id| id.to_string()).unwrap_or_default(),
            created: segment.created.unwrap_or_default().to_string(),
            state: format!(
                "{:?}",
                forgerpc::TenantState::try_from(segment.state).unwrap_or_default()
            ),
            time_in_state_above_sla: segment
                .state_sla
                .as_ref()
                .map(|sla| sla.time_in_state_above_sla)
                .unwrap_or_default(),
            sub_domain: String::new(), // filled in later
            mtu: segment.mtu.unwrap_or(-1),
            prefixes: segment
                .prefixes
                .iter()
                .map(|x| x.prefix.to_string())
                .collect::<Vec<String>>()
                .join(", "),
            version: segment.version,
        }
    }
}

/// List network segments
pub async fn show_html(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let networks = match fetch_network_segments(state.clone()).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_network_segments");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading network segments",
            )
                .into_response();
        }
    };

    let mut admin = Vec::new();
    let mut underlay = Vec::new();
    let mut tenant = Vec::new();
    for n in networks.into_iter() {
        let mut domain_name = String::new();
        if let Some(domain_id) = n.subdomain_id.as_ref()
            && let Ok(name) = get_domain_name(state.clone(), domain_id).await
        {
            domain_name = name;
        };
        let segment_type = n.segment_type;
        let mut display: NetworkSegmentRowDisplay = n.into();
        display.sub_domain = domain_name;
        match forgerpc::NetworkSegmentType::try_from(segment_type) {
            Ok(forgerpc::NetworkSegmentType::Admin) => admin.push(display),
            Ok(forgerpc::NetworkSegmentType::Underlay) => underlay.push(display),
            Ok(forgerpc::NetworkSegmentType::Tenant) => tenant.push(display),
            _ => {
                tracing::error!(segment_type, "Invalid NetworkSegmentType, skipping");
            }
        }
    }

    let tmpl = NetworkSegmentShow {
        admin,
        underlay,
        tenant,
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_all_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let networks = match fetch_network_segments(state).await {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "fetch_network_segments");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading network segments",
            )
                .into_response();
        }
    };
    (StatusCode::OK, Json(networks)).into_response()
}

async fn fetch_network_segments(
    api: Arc<Api>,
) -> Result<Vec<forgerpc::NetworkSegment>, tonic::Status> {
    let request = tonic::Request::new(forgerpc::NetworkSegmentSearchFilter::default());

    let network_segments_ids = api
        .find_network_segment_ids(request)
        .await?
        .into_inner()
        .network_segments_ids;

    let mut segments = Vec::new();
    let mut offset = 0;
    while offset != network_segments_ids.len() {
        const PAGE_SIZE: usize = 100;
        let page_size = PAGE_SIZE.min(network_segments_ids.len() - offset);
        let next_ids = &network_segments_ids[offset..offset + page_size];
        let next_vpcs = api
            .find_network_segments_by_ids(tonic::Request::new(
                forgerpc::NetworkSegmentsByIdsRequest {
                    network_segments_ids: next_ids.to_vec(),
                    include_history: false,
                    include_num_free_ips: false,
                },
            ))
            .await?
            .into_inner();

        segments.extend(next_vpcs.network_segments.into_iter());
        offset += page_size;
    }

    segments.sort_unstable_by(|ns1, ns2| ns1.name.cmp(&ns2.name));
    Ok(segments)
}

async fn get_domain_name(state: Arc<Api>, domain_id: &DomainId) -> eyre::Result<String> {
    let request = tonic::Request::new(rpc::protos::dns::DomainSearchQuery {
        id: Some(*domain_id),
        name: None,
    });
    let domain_list = state
        .find_domain(request)
        .await
        .map(|response| response.into_inner())?;

    if domain_list.domains.len() != 1 {
        eyre::bail!(
            "Expected one domain matching {domain_id}, found {}",
            domain_list.domains.len()
        );
    }
    Ok(domain_list.domains[0].name.clone())
}

#[derive(Template)]
#[template(path = "network_segment_detail.html")]
struct NetworkSegmentDetail {
    id: String,
    name: String,
    vpc_id: String,
    version: String,
    created: String,
    updated: String,
    deleted: String,
    state: String,
    state_sla: String,
    time_in_state_above_sla: bool,
    state_reason: Option<rpc::forge::ControllerStateReason>,
    domain_id: String,
    domain_name: String,
    segment_type: String,
    prefixes: Vec<NetworkSegmentPrefix>,
    history: Vec<NetworkSegmentHistory>,
}

struct NetworkSegmentPrefix {
    index: usize,
    id: String,
    prefix: String,
    gateway: String,
    reserve_first: i32,
}

struct NetworkSegmentHistory {
    state: String,
    version: String,
}

impl From<forgerpc::NetworkSegment> for NetworkSegmentDetail {
    fn from(segment: forgerpc::NetworkSegment) -> Self {
        let mut prefixes = Vec::new();
        for (i, p) in segment.prefixes.into_iter().enumerate() {
            prefixes.push(NetworkSegmentPrefix {
                index: i,
                id: p.id.unwrap_or_default().to_string(),
                prefix: p.prefix,
                gateway: p
                    .gateway
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string())
                    .to_string(),
                reserve_first: p.reserve_first,
            });
        }
        let mut history = Vec::new();
        for h in segment.history.into_iter() {
            history.push(NetworkSegmentHistory {
                state: h.state,
                version: h.version,
            });
        }
        Self {
            id: segment.id.unwrap_or_default().to_string(),
            name: segment.name,
            version: segment.version,
            vpc_id: segment.vpc_id.map(|id| id.to_string()).unwrap_or_default(),
            created: segment.created.unwrap_or_default().to_string(),
            updated: segment.updated.unwrap_or_default().to_string(),
            deleted: segment
                .deleted
                .map(|x| x.to_string())
                .unwrap_or("Not Deleted".to_string()),
            state: format!(
                "{:?}",
                forgerpc::TenantState::try_from(segment.state).unwrap_or_default()
            ),
            state_sla: segment
                .state_sla
                .as_ref()
                .and_then(|sla| sla.sla)
                .map(|sla| {
                    config_version::format_duration(
                        chrono::TimeDelta::try_from(sla).unwrap_or(chrono::TimeDelta::MAX),
                    )
                })
                .unwrap_or_default(),
            time_in_state_above_sla: segment
                .state_sla
                .as_ref()
                .map(|sla| sla.time_in_state_above_sla)
                .unwrap_or_default(),
            state_reason: segment.state_reason,
            domain_id: segment.subdomain_id.unwrap_or_default().to_string(),
            domain_name: String::new(), // filled in later
            segment_type: format!(
                "{:?}",
                forgerpc::NetworkSegmentType::try_from(segment.segment_type).unwrap_or_default()
            ),
            prefixes,
            history,
        }
    }
}

/// View networks segment details
pub async fn detail(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(segment_id): AxumPath<String>,
) -> Response {
    let (show_json, segment_id_string) = match segment_id.strip_suffix(".json") {
        Some(segment_id) => (true, segment_id.to_string()),
        None => (false, segment_id),
    };

    let segment_id = match segment_id_string.parse::<NetworkSegmentId>() {
        Ok(id) => id,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("Invalid network segment ID {segment_id_string}: {e}"),
            )
                .into_response();
        }
    };

    let request = tonic::Request::new(forgerpc::NetworkSegmentsByIdsRequest {
        network_segments_ids: vec![segment_id],
        include_history: true,
        include_num_free_ips: true,
    });
    let segment = match state
        .find_network_segments_by_ids(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(n) if n.network_segments.is_empty() => {
            return super::not_found_response(segment_id_string);
        }
        Ok(n) if n.network_segments.len() != 1 => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Network Segment list for {segment_id} returned {} segments",
                    n.network_segments.len()
                ),
            )
                .into_response();
        }
        Ok(mut n) => n.network_segments.remove(0),
        Err(err) => {
            tracing::error!(%err, "find_network_segments");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading network segments",
            )
                .into_response();
        }
    };

    if show_json {
        return (StatusCode::OK, Json(segment)).into_response();
    }

    let mut domain_name = String::new();
    if let Some(domain_id) = segment.subdomain_id.as_ref()
        && let Ok(name) = get_domain_name(state.clone(), domain_id).await
    {
        domain_name = name;
    };
    let mut tmpl: NetworkSegmentDetail = segment.into();
    tmpl.domain_name = domain_name;
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}
