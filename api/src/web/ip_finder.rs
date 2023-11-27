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

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
//use axum::extract::{Path as AxumPath, State as AxumState};
use axum::extract::{Query, State as AxumState};
use axum::response::{Html, IntoResponse};
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;
use http::StatusCode;
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;

use crate::api::Api;

#[derive(Template)]
#[template(path = "ip_finder.html")]
struct IpFinder {
    ip: String,
    found: Vec<IpMatch>,
}

struct IpMatch {
    name: &'static str,
    url: String,
    message: String,
}

pub async fn find<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
    Query(mut params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let ip_to_find = params.remove("ip");
    let mut found = Vec::new();
    if let Some(ip) = ip_to_find.as_ref() {
        let req = forgerpc::FindIpAddressRequest { ip: ip.to_string() };
        let request = tonic::Request::new(req);
        let out = match state
            .find_ip_address(request)
            .await
            .map(|response| response.into_inner())
        {
            Ok(m) => m,
            Err(_) => {
                let tmpl = IpFinder {
                    ip: ip_to_find.unwrap_or_default(),
                    found: Vec::new(),
                };
                return (StatusCode::OK, Html(tmpl.render().unwrap()));
            }
        };
        for m in out.matches {
            let ip_type = match forgerpc::IpType::from_i32(m.ip_type) {
                Some(t) => t,
                None => {
                    tracing::error!(ip_type = m.ip_type, "Invalid IpType");
                    continue;
                }
            };
            use forgerpc::IpType::*;
            let (name, url) = match ip_type {
                StaticDataDhcpServer => ("DHCP Server", "".to_string()),
                StaticDataRouteServer => ("Route Server", "".to_string()),
                ResourcePool => ("Resource Pool", "/admin/resource-pool".to_string()),
                InstanceAddress => (
                    "Instance",
                    format!("/admin/instance/{}", m.owner_id.unwrap_or_default()),
                ),
                MachineAddress => (
                    "Machine",
                    format!("/admin/machine/{}", m.owner_id.unwrap_or_default()),
                ),
                BmcIp => (
                    "BMC IP",
                    format!("/admin/machine/{}", m.owner_id.unwrap_or_default()),
                ),
                LoopbackIp => (
                    "Loopback IP",
                    format!("/admin/machine/{}", m.owner_id.unwrap_or_default()),
                ),
                NetworkSegment => (
                    "Network Segment",
                    format!("/admin/network-segment/{}", m.owner_id.unwrap_or_default()),
                ),
            };
            found.push(IpMatch {
                name,
                url,
                message: m.message,
            });
        }
    }

    let tmpl = IpFinder {
        ip: ip_to_find.unwrap_or_default(),
        found,
    };
    (StatusCode::OK, Html(tmpl.render().unwrap()))
}
