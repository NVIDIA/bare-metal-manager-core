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

use std::collections::BTreeMap;
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
            id: mi.id.unwrap_or_default().value,
            mac_address: mi.mac_address,
            ip_address: mi.address.join(","),
            machine_id: mi
                .machine_id
                .as_ref()
                .map(::rpc::MachineId::to_string)
                .unwrap_or_default(),
            hostname: mi.hostname,
            vendor: mi.vendor.unwrap_or_default(),
            domain_name: String::new(), // filled in later
        }
    }
}

/// List machine interfaces
pub async fn show_html<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
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

    let request = tonic::Request::new(forgerpc::DomainSearchQuery {
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
        .map(|x| (x.id.unwrap_or_default().value, x.name))
        .collect::<BTreeMap<_, _>>();

    let mut interfaces = Vec::new();
    for iface in machine_interfaces {
        let domain_name = domainlist_map
            .get(&iface.domain_id.clone().unwrap_or_default().value)
            .cloned()
            .unwrap_or_default();
        let mut display: InterfaceRowDisplay = iface.into();
        display.domain_name = domain_name;
        interfaces.push(display);
    }
    let tmpl = InterfaceShow { interfaces };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_json<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
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

async fn fetch_machine_interfaces<
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
>(
    api: Arc<Api<C1, C2>>,
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
}

impl From<forgerpc::MachineInterface> for InterfaceDetail {
    fn from(mi: forgerpc::MachineInterface) -> Self {
        Self {
            id: mi.id.unwrap_or_default().value,
            dpu_machine_id: mi
                .attached_dpu_machine_id
                .as_ref()
                .map(::rpc::MachineId::to_string)
                .unwrap_or_default(),
            machine_id: mi
                .machine_id
                .as_ref()
                .map(::rpc::MachineId::to_string)
                .unwrap_or_default(),
            segment_id: mi
                .segment_id
                .clone()
                .unwrap_or_else(super::default_uuid)
                .to_string(),
            mac_address: mi.mac_address,
            ip_address: mi.address.join(","),
            hostname: mi.hostname,
            vendor: mi.vendor.unwrap_or_default(),
            is_primary: mi.primary_interface,
            domain_id: mi.domain_id.unwrap_or_default().to_string(),
            domain_name: String::new(), // filled in later
        }
    }
}

/// View machine interface details
pub async fn detail<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
    AxumPath(interface_id): AxumPath<String>,
) -> Response {
    let request = tonic::Request::new(forgerpc::InterfaceSearchQuery {
        id: Some(forgerpc::Uuid {
            value: interface_id.clone(),
        }),
        ip: None,
    });
    let mut machine_interfaces = match state
        .find_interfaces(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(n) => n,
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

    let tmpl: InterfaceDetail = interface.into();
    // TODO tmpl.domain_name = domain_name;
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}
