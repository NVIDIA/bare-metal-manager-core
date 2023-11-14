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
#[template(path = "network_segment_show.html")]
struct NetworkSegmentShow {
    admin: Vec<NetworkSegmentRowDisplay>,
    tenant: Vec<NetworkSegmentRowDisplay>,
    underlay: Vec<NetworkSegmentRowDisplay>,
}

struct NetworkSegmentRowDisplay {
    name: String,
    id: String,
    created: String,
    state: String,
    sub_domain: String,
    mtu: i32,
    prefixes: String,
    circuit_ids: String,
    version: String,
}

impl From<forgerpc::NetworkSegment> for NetworkSegmentRowDisplay {
    fn from(segment: forgerpc::NetworkSegment) -> Self {
        Self {
            id: segment.id.unwrap_or_default().to_string(),
            name: segment.name,
            created: segment.created.unwrap_or_default().to_string(),
            state: format!(
                "{:?}",
                forgerpc::TenantState::from_i32(segment.state).unwrap_or_default()
            ),
            sub_domain: String::new(), // filled in later
            mtu: segment.mtu.unwrap_or(-1),
            prefixes: segment
                .prefixes
                .iter()
                .map(|x| x.prefix.to_string())
                .collect::<Vec<String>>()
                .join(", "),
            circuit_ids: segment
                .prefixes
                .iter()
                .map(|x| x.circuit_id.clone().unwrap_or_else(|| "NA".to_owned()))
                .collect::<Vec<String>>()
                .join(", "),
            version: segment.version,
        }
    }
}

/// List network segments
pub async fn show_html<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
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
        if let Some(domain_id) = n.subdomain_id.as_ref() {
            if let Ok(name) = get_domain_name(state.clone(), domain_id).await {
                domain_name = name;
            };
        }
        let segment_type = n.segment_type;
        let mut display: NetworkSegmentRowDisplay = n.into();
        display.sub_domain = domain_name;
        match forgerpc::NetworkSegmentType::from_i32(segment_type) {
            Some(forgerpc::NetworkSegmentType::Admin) => admin.push(display),
            Some(forgerpc::NetworkSegmentType::Underlay) => underlay.push(display),
            Some(forgerpc::NetworkSegmentType::Tenant) => tenant.push(display),
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

pub async fn show_json<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
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

async fn fetch_network_segments<
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
>(
    api: Arc<Api<C1, C2>>,
) -> Result<Vec<forgerpc::NetworkSegment>, tonic::Status> {
    let request = tonic::Request::new(forgerpc::NetworkSegmentQuery {
        id: None,
        search_config: Some(forgerpc::NetworkSegmentSearchConfig {
            include_history: false,
        }),
    });
    let mut networks = api
        .find_network_segments(request)
        .await
        .map(|response| response.into_inner())?;
    networks
        .network_segments
        .sort_unstable_by(|ns1, ns2| ns1.name.cmp(&ns2.name));
    Ok(networks.network_segments)
}

async fn get_domain_name<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    state: Arc<Api<C1, C2>>,
    domain_id: &forgerpc::Uuid,
) -> eyre::Result<String> {
    let request = tonic::Request::new(forgerpc::DomainSearchQuery {
        id: Some(domain_id.clone()),
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
    created: String,
    updated: String,
    deleted: String,
    state: String,
    domain_id: String,
    domain_name: String,
    segment_type: String,
    prefixes: Vec<NetworkSegmentPrefix>,
    history: Vec<NetworkSegmentHistory>,
}

struct NetworkSegmentPrefix {
    sn: usize,
    id: String,
    prefix: String,
    gateway: String,
    reserve_first: i32,
    circuit_id: String,
}

struct NetworkSegmentHistory {
    state: String,
    version: String,
    time: String,
}

impl From<forgerpc::NetworkSegment> for NetworkSegmentDetail {
    fn from(segment: forgerpc::NetworkSegment) -> Self {
        let mut prefixes = Vec::new();
        for (i, p) in segment.prefixes.into_iter().enumerate() {
            prefixes.push(NetworkSegmentPrefix {
                sn: i,
                id: p.id.clone().unwrap_or_default().to_string(),
                prefix: p.prefix,
                gateway: p
                    .gateway
                    .clone()
                    .unwrap_or_else(|| "Unknown".to_string())
                    .to_string(),
                reserve_first: p.reserve_first,
                circuit_id: p.circuit_id.unwrap_or_default(),
            });
        }
        let mut history = Vec::new();
        for h in segment.history.into_iter() {
            history.push(NetworkSegmentHistory {
                state: h.state,
                version: h.version,
                time: h.time.unwrap_or_default().to_string(),
            });
        }
        Self {
            id: segment.id.unwrap_or_default().to_string(),
            name: segment.name,
            created: segment.created.unwrap_or_default().to_string(),
            updated: segment.updated.unwrap_or_default().to_string(),
            deleted: segment
                .deleted
                .map(|x| x.to_string())
                .unwrap_or("Not Deleted".to_string()),
            state: format!(
                "{:?}",
                forgerpc::TenantState::from_i32(segment.state).unwrap_or_default()
            ),
            domain_id: segment
                .subdomain_id
                .unwrap_or_else(super::default_uuid)
                .to_string(),
            domain_name: String::new(), // filled in later
            segment_type: format!(
                "{:?}",
                forgerpc::NetworkSegmentType::from_i32(segment.segment_type).unwrap_or_default()
            ),
            prefixes,
            history,
        }
    }
}

/// View networks segment details
pub async fn detail<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
    AxumPath(segment_id): AxumPath<String>,
) -> Response {
    let request = tonic::Request::new(forgerpc::NetworkSegmentQuery {
        id: Some(forgerpc::Uuid {
            value: segment_id.clone(),
        }),
        search_config: Some(forgerpc::NetworkSegmentSearchConfig {
            include_history: true,
        }),
    });
    let mut networks = match state
        .find_network_segments(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(n) => n,
        Err(err) => {
            tracing::error!(%err, "find_network_segments");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading network segments",
            )
                .into_response();
        }
    };
    if networks.network_segments.len() != 1 {
        tracing::error!(%segment_id, "Expected exactly 1 match, found {}", networks.network_segments.len());
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Expected exactly one network segment to match",
        )
            .into_response();
    }
    let segment = networks.network_segments.pop().unwrap(); // safe, we check above

    let mut domain_name = String::new();
    if let Some(domain_id) = segment.subdomain_id.as_ref() {
        if let Ok(name) = get_domain_name(state.clone(), domain_id).await {
            domain_name = name;
        };
    }
    let mut tmpl: NetworkSegmentDetail = segment.into();
    tmpl.domain_name = domain_name;
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}
