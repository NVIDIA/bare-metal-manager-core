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

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "machine_show.html")]
struct MachineShow {
    title: &'static str,
    machines: Vec<MachineRowDisplay>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct MachineRowDisplay {
    hostname: String,
    id: String,
    state: String,
    state_version: String,
    attached_dpu_id: String,
    primary_interface_id: String,
    ip_address: String,
    mac_address: String,
    is_host: bool,
}

impl From<forgerpc::Machine> for MachineRowDisplay {
    fn from(m: forgerpc::Machine) -> Self {
        let mut machine_interfaces = m
            .interfaces
            .into_iter()
            .filter(|x| x.primary_interface)
            .collect::<Vec<forgerpc::MachineInterface>>();
        let (hostname, primary_interface_id, ip_address, mac_address, attached_dpu_id) =
            if machine_interfaces.is_empty() {
                (
                    "None".to_string(),
                    "None".to_string(),
                    "None".to_string(),
                    "None".to_string(),
                    "None".to_string(),
                )
            } else {
                let mi = machine_interfaces.remove(0);
                (
                    mi.hostname,
                    mi.id.unwrap_or_default().to_string(),
                    mi.address.join(","),
                    mi.mac_address,
                    mi.attached_dpu_machine_id
                        .map(|x| x.to_string())
                        .unwrap_or_else(|| "NA".to_string()),
                )
            };

        MachineRowDisplay {
            hostname,
            id: m.id.unwrap_or_default().id,
            state: m.state,
            state_version: m.state_version,
            attached_dpu_id,
            primary_interface_id,
            ip_address,
            mac_address,
            is_host: m.machine_type == forgerpc::MachineType::Host as i32,
        }
    }
}

pub async fn show_hosts_html<
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
>(
    state: AxumState<Arc<Api<C1, C2>>>,
) -> impl IntoResponse {
    show(state, true, false).await
}

pub async fn show_hosts_json<
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let machines = match fetch_machines(state, false).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "fetch_machines");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading machines").into_response();
        }
    };
    (StatusCode::OK, Json(machines)).into_response()
}

pub async fn show_dpus_html<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    state: AxumState<Arc<Api<C1, C2>>>,
) -> impl IntoResponse {
    show(state, false, true).await
}

pub async fn show_dpus_json<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let mut machines = match fetch_machines(state, true).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "fetch_machines");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading machines").into_response();
        }
    };
    machines
        .machines
        .retain(|m| m.machine_type == forgerpc::MachineType::Dpu as i32);
    (StatusCode::OK, Json(machines)).into_response()
}

/// List machines
pub async fn show_all_html<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    state: AxumState<Arc<Api<C1, C2>>>,
) -> impl IntoResponse {
    show(state, true, true).await
}

pub async fn show_all_json<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let machines = match fetch_machines(state, true).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "fetch_machines");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading machines").into_response();
        }
    };
    (StatusCode::OK, Json(machines)).into_response()
}

async fn show<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
    include_hosts: bool,
    include_dpus: bool,
) -> impl IntoResponse {
    let mut all_machines = match fetch_machines(state, include_dpus).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "find_machines");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new()));
        }
    };

    let mut machines: Vec<MachineRowDisplay> = Vec::new();
    use forgerpc::MachineType;
    for m in all_machines.machines.drain(..) {
        match MachineType::from_i32(m.machine_type) {
            Some(MachineType::Host) => {
                if include_hosts {
                    machines.push(m.into());
                }
            }
            Some(MachineType::Dpu) => {
                if include_dpus {
                    machines.push(m.into());
                }
            }
            _ => {}
        }
    }
    machines.sort_unstable();

    let tmpl = MachineShow {
        machines,
        title: if include_hosts && include_dpus {
            "Machines"
        } else if include_hosts {
            "Hosts"
        } else {
            "DPUs"
        },
    };
    (StatusCode::OK, Html(tmpl.render().unwrap()))
}

async fn fetch_machines<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    api: Arc<Api<C1, C2>>,
    include_dpus: bool,
) -> Result<forgerpc::MachineList, tonic::Status> {
    let request = tonic::Request::new(forgerpc::MachineSearchQuery {
        id: None,
        fqdn: None,
        search_config: Some(forgerpc::MachineSearchConfig {
            include_dpus,
            include_history: true,
            include_predicted_host: true,
            only_maintenance: false,
            include_associated_machine_id: false,
            include_hosts: true,
        }),
    });
    api.find_machines(request)
        .await
        .map(|response| response.into_inner())
}

#[derive(Template)]
#[template(path = "machine_detail.html")]
struct MachineDetail {
    id: String,
    host_id: String,
    state: String,
    state_version: String,
    machine_type: String,
    hostname: String,
    is_host: bool,
    network_config: String,
    history: Vec<MachineHistoryDisplay>,
    interfaces: Vec<MachineInterfaceDisplay>,
}

struct MachineHistoryDisplay {
    event: String,
    version: String,
    time: String,
}

struct MachineInterfaceDisplay {
    sn: usize,
    id: String,
    dpu_id: String,
    segment_id: String,
    domain_id: String,
    hostname: String,
    primary: String,
    mac_address: String,
    addresses: String,
}

impl From<forgerpc::Machine> for MachineDetail {
    fn from(m: forgerpc::Machine) -> Self {
        let mut history = Vec::new();
        for e in m.events.into_iter().rev() {
            history.push(MachineHistoryDisplay {
                event: e.event,
                version: e.version,
                time: e.time.unwrap_or_default().to_string(),
            });
        }

        let mut hostname = String::new();
        let mut interfaces = Vec::new();
        for (i, interface) in m.interfaces.into_iter().enumerate() {
            if interface.primary_interface {
                hostname = interface.hostname.clone();
            }
            interfaces.push(MachineInterfaceDisplay {
                sn: i,
                id: interface.id.clone().unwrap_or_default().to_string(),
                dpu_id: interface
                    .attached_dpu_machine_id
                    .clone()
                    .unwrap_or_else(super::invalid_machine_id)
                    .to_string(),
                segment_id: interface
                    .segment_id
                    .clone()
                    .unwrap_or_else(super::default_uuid)
                    .to_string(),
                domain_id: interface
                    .domain_id
                    .clone()
                    .unwrap_or_else(super::default_uuid)
                    .to_string(),
                hostname: interface.hostname.clone(),
                primary: interface.primary_interface.to_string(),
                mac_address: interface.mac_address.clone(),
                addresses: interface.address.join(","),
            });
        }

        let machine_id = m.id.unwrap_or_default().id;
        MachineDetail {
            id: machine_id.clone(),
            state: m.state,
            state_version: m.state_version,
            machine_type: get_machine_type(&machine_id),
            is_host: m.machine_type == forgerpc::MachineType::Host as i32,
            network_config: String::new(), // filled in later
            hostname,
            history,
            interfaces,
            host_id: m
                .associated_host_machine_id
                .map_or_else(String::default, |id| id.to_string()),
        }
    }
}

/// View machine
pub async fn detail<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
    AxumPath(machine_id): AxumPath<String>,
) -> impl IntoResponse {
    let rpc_machine_id = forgerpc::MachineId {
        id: machine_id.clone(),
    };
    let request = tonic::Request::new(rpc_machine_id.clone());

    let machine = match state
        .get_machine(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, %machine_id, "get_machine");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new()));
        }
    };

    let mut display: MachineDetail = machine.into();
    if !display.is_host {
        let request = tonic::Request::new(forgerpc::ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(forgerpc::MachineId {
                id: display.id.clone(),
            }),
        });
        if let Ok(netconf) = state
            .get_managed_host_network_config(request)
            .await
            .map(|response| response.into_inner())
        {
            display.network_config = format!("{netconf:?}").replace(", ", "<br/>");
        }
    }
    (StatusCode::OK, Html(display.render().unwrap()))
}

fn get_machine_type(machine_id: &str) -> String {
    if machine_id.starts_with("fm100p") {
        "Host (Predicted)"
    } else if machine_id.starts_with("fm100h") {
        "Host"
    } else {
        "DPU"
    }
    .to_string()
}
