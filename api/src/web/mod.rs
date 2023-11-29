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
use axum::extract::State as AxumState;
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post, Router};
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;
use http::{Request, StatusCode};
use rpc::forge as forgerpc;
use rpc::forge::forge_server::Forge;
use tower_http::normalize_path::NormalizePath;

use crate::api::Api;
use crate::ethernet_virtualization::EthVirtData;

mod domain;
mod filters;
mod instance;
mod interface;
mod ip_finder;
mod machine;
mod managed_host;
mod network_device;
mod network_segment;
mod network_status;
mod resource_pool;

const WEB_AUTH: &str = "admin:Welcome123";

/// All the URLs in the admin interface. Nested under /admin in api.rs.
pub fn routes<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    api: Arc<Api<C1, C2>>,
) -> NormalizePath<Router> {
    NormalizePath::trim_trailing_slash(
        Router::new()
            .route("/", get(root))
            .route("/domain", get(domain::show_html))
            .route("/domain.json", get(domain::show_json))
            .route("/dpu", get(machine::show_dpus_html))
            .route("/dpu.json", get(machine::show_dpus_json))
            .route("/host", get(machine::show_hosts_html))
            .route("/host.json", get(machine::show_hosts_json))
            .route("/instance", get(instance::show_html))
            .route("/instance.json", get(instance::show_json))
            .route("/instance/:instance_id", get(instance::detail))
            .route("/interface", get(interface::show_html))
            .route("/interface.json", get(interface::show_json))
            .route("/interface/:interface_id", get(interface::detail))
            .route("/ip-finder", get(ip_finder::find))
            .route("/machine", get(machine::show_all_html))
            .route("/machine.json", get(machine::show_all_json))
            .route("/machine/:machine_id", get(machine::detail))
            .route("/managed-host", get(managed_host::show_html))
            .route("/managed-host.json", get(managed_host::show_json))
            .route("/managed-host/:machine_id", get(managed_host::detail))
            .route(
                "/managed-host/:machine_id/maintenance",
                post(managed_host::maintenance),
            )
            .route("/network-device", get(network_device::show_html))
            .route("/network-device.json", get(network_device::show_json))
            .route("/network-segment", get(network_segment::show_html))
            .route("/network-segment.json", get(network_segment::show_json))
            .route("/network-segment/:segment_id", get(network_segment::detail))
            .route("/network-status", get(network_status::show_html))
            .route("/network-status.json", get(network_status::show_json))
            .route("/resource-pool", get(resource_pool::show_html))
            .route("/resource-pool.json", get(resource_pool::show_json))
            .layer(axum::middleware::from_fn(auth_basic))
            .with_state(api),
    )
}

pub async fn auth_basic<T>(req: Request<T>, next: Next<T>) -> Result<Response, StatusCode> {
    let must_auth = (
        StatusCode::UNAUTHORIZED,
        [(http::header::WWW_AUTHENTICATE, "Basic realm=Carbide")],
    );
    match req.headers().get("Authorization") {
        None => {
            return Ok(must_auth.into_response());
        }
        Some(auth_val) => {
            let Ok(auth_val) = auth_val.to_str() else {
                tracing::debug!("Invalid auth header");
                return Err(StatusCode::BAD_REQUEST);
            };
            if !is_valid_auth(auth_val) {
                return Ok(must_auth.into_response());
            }
        }
    };
    Ok(next.run(req).await)
}

fn is_valid_auth(auth_str: &str) -> bool {
    let parts: Vec<&str> = auth_str.split(' ').collect();
    if parts.len() != 2 || parts[0] != "Basic" {
        tracing::trace!(auth_str, "Auth must match 'Basic <str>'");
        return false;
    }
    let Ok(plain) = base64::decode(parts[1]) else {
        tracing::trace!(auth_str, "Auth should be base64");
        return false;
    };
    let plain = String::from_utf8_lossy(&plain);
    if plain != WEB_AUTH {
        tracing::trace!(auth_str, "Wrong username or password");
        return false;
    }
    true
}

#[derive(Template)]
#[template(path = "index.html")]
struct Index {
    version: &'static str,
    agent_upgrade_policy: &'static str,
    eth_data: EthVirtData,
    dpu_nic_firmware_initial_update_enabled: bool,
    dpu_nic_firmware_reprovision_update_enabled: bool,
}

pub async fn root<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    state: AxumState<Arc<Api<C1, C2>>>,
) -> impl IntoResponse {
    let request = tonic::Request::new(forgerpc::DpuAgentUpgradePolicyRequest { new_policy: None });
    use forgerpc::AgentUpgradePolicy::*;
    let agent_upgrade_policy = match state
        .dpu_agent_upgrade_policy_action(request)
        .await
        .map(|response| response.into_inner())
        .map(|p| p.active_policy)
    {
        Ok(x) if x == Off as i32 => "Off",
        Ok(x) if x == UpOnly as i32 => "Upgrade only",
        Ok(x) if x == UpDown as i32 => "Upgade and Downgrade",
        Ok(_) => "Unknown",
        Err(err) => {
            tracing::error!(%err, "dpu_agent_upgrade_policy_action");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new()));
        }
    };

    let index = Index {
        version: forge_version::v!(build_version),
        eth_data: state.eth_data.clone(),
        dpu_nic_firmware_initial_update_enabled: state
            .machine_update_config
            .dpu_nic_firmware_initial_update_enabled,
        dpu_nic_firmware_reprovision_update_enabled: state
            .machine_update_config
            .dpu_nic_firmware_reprovision_update_enabled,

        agent_upgrade_policy,
    };
    (StatusCode::OK, Html(index.render().unwrap()))
}

pub(crate) fn invalid_machine_id() -> rpc::forge::MachineId {
    rpc::forge::MachineId {
        id: "INVALID_MACHINE".to_string(),
    }
}

pub(crate) fn default_uuid() -> rpc::forge::Uuid {
    rpc::forge::Uuid {
        value: "00000000-0000-0000-0000-000000000000".to_string(),
    }
}
