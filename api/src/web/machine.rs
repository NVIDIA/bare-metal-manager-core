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
use chrono::{TimeDelta, Utc};
use config_version::ConfigVersion;
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;
use http::StatusCode;
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as forgerpc, MachineInventorySoftwareComponent};

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
    time_in_state: String,
    associated_dpu_id: String,
    associated_host_id: String,
    sys_vendor: String,
    product_serial: String,
    ip_address: String,
    mac_address: String,
    is_host: bool,
    num_gpus: usize,
    num_ib_ifs: usize,
}

impl From<forgerpc::Machine> for MachineRowDisplay {
    fn from(m: forgerpc::Machine) -> Self {
        let mut machine_interfaces = m
            .interfaces
            .into_iter()
            .filter(|x| x.primary_interface)
            .collect::<Vec<forgerpc::MachineInterface>>();
        let (hostname, ip_address, mac_address) = if machine_interfaces.is_empty() {
            ("None".to_string(), "None".to_string(), "None".to_string())
        } else {
            let mi = machine_interfaces.remove(0);
            (mi.hostname, mi.address.join(","), mi.mac_address)
        };

        let mut sys_vendor = String::new();
        let mut product_serial = String::new();
        let mut num_gpus = 0;
        let mut num_ib_ifs = 0;
        if let Some(di) = m.discovery_info.as_ref() {
            if let Some(dmi) = di.dmi_data.as_ref() {
                sys_vendor = dmi.sys_vendor.clone();
                product_serial = dmi.product_serial.clone();
            }
            num_gpus = di.gpus.len();
            num_ib_ifs = di.infiniband_interfaces.len();
        }

        MachineRowDisplay {
            hostname,
            id: m.id.unwrap_or_default().id,
            state: m.state,
            time_in_state: since_state_change(&m.state_version),
            ip_address,
            mac_address,
            is_host: m.machine_type == forgerpc::MachineType::Host as i32,
            associated_dpu_id: m
                .associated_dpu_machine_id
                .map(|id| id.id)
                .unwrap_or_default(),
            associated_host_id: m
                .associated_host_machine_id
                .map(|id| id.id)
                .unwrap_or_default(),
            sys_vendor,
            product_serial,
            num_gpus,
            num_ib_ifs,
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
        match MachineType::try_from(m.machine_type) {
            Ok(MachineType::Host) => {
                if include_hosts {
                    machines.push(m.into());
                }
            }
            Ok(MachineType::Dpu) => {
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

pub async fn fetch_machines<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
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
            include_associated_machine_id: true,
            exclude_hosts: false,
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
    time_in_state: String,
    machine_type: String,
    hostname: String,
    is_host: bool,
    network_config: String,
    history: Vec<MachineHistoryDisplay>,
    bios_version: String,
    board_version: String,
    product_name: String,
    product_serial: String,
    board_serial: String,
    chassis_serial: String,
    sys_vendor: String,
    interfaces: Vec<MachineInterfaceDisplay>,
    ib_interfaces: Vec<MachineIbInterfaceDisplay>,
    inventory: Vec<MachineInventorySoftwareComponent>,
}

struct MachineHistoryDisplay {
    event: String,
    version: String,
    time: String,
}

struct MachineInterfaceDisplay {
    index: usize,
    id: String,
    dpu_id: String,
    segment_id: String,
    domain_id: String,
    hostname: String,
    primary: String,
    mac_address: String,
    addresses: String,
}

#[derive(Debug, Default)]
struct MachineIbInterfaceDisplay {
    guid: String,
    device: String,
    vendor: String,
    slot: String,
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
                index: i,
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

        let mut bios_version = String::new();
        let mut board_version = String::new();
        let mut product_name = String::new();
        let mut product_serial = String::new();
        let mut board_serial = String::new();
        let mut chassis_serial = String::new();
        let mut sys_vendor = String::new();
        let mut ib_interfaces = Vec::new();
        let mut inventory = Vec::new();
        if let Some(di) = m.discovery_info.as_ref() {
            if let Some(dmi) = di.dmi_data.as_ref() {
                product_name = dmi.product_name.clone();
                product_serial = dmi.product_serial.clone();
                board_serial = dmi.board_serial.clone();
                chassis_serial = dmi.chassis_serial.clone();
                sys_vendor = dmi.sys_vendor.clone();
                bios_version = dmi.bios_version.clone();
                board_version = dmi.board_version.clone();
            }

            for iface in di.infiniband_interfaces.iter() {
                let mut iface_display = MachineIbInterfaceDisplay {
                    guid: iface.guid.clone(),
                    ..Default::default()
                };
                if let Some(props) = iface.pci_properties.as_ref() {
                    iface_display.device = props.device.clone();
                    iface_display.vendor = props.vendor.clone();
                    iface_display.slot = props.slot.clone().unwrap_or_default();
                }
                ib_interfaces.push(iface_display);
            }
        }
        if let Some(inv) = m.inventory.as_ref() {
            inventory.extend(inv.components.iter().cloned());
        }

        let machine_id = m.id.unwrap_or_default().id;
        MachineDetail {
            id: machine_id.clone(),
            time_in_state: since_state_change(&m.state_version),
            state: m.state,
            state_version: m.state_version,
            machine_type: get_machine_type(&machine_id),
            is_host: m.machine_type == forgerpc::MachineType::Host as i32,
            network_config: String::new(), // filled in later
            hostname,
            history,
            bios_version,
            board_version,
            product_serial,
            chassis_serial,
            board_serial,
            sys_vendor,
            product_name,
            ib_interfaces,
            interfaces,
            inventory,
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
        Err(err) if err.code() == tonic::Code::NotFound => {
            return (StatusCode::NOT_FOUND, Html(machine_id.to_string()));
        }
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
            display.network_config = serde_json::to_string_pretty(&netconf)
                .unwrap_or_else(|_| "\"Invalid\"".to_string());
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

/// Human readable amount of time since we entered the given state version
fn since_state_change(ver: &str) -> String {
    let Ok(state_version_t) = ver.parse::<ConfigVersion>() else {
        return "state version parse error".to_string();
    };
    let now = Utc::now();
    let state_ts = state_version_t.timestamp();
    if state_ts < now {
        format_duration(now - state_ts)
    } else {
        String::new()
    }
}

fn format_duration(d: TimeDelta) -> String {
    let seconds = d.num_seconds();
    const SECONDS_IN_MINUTE: i64 = 60;
    const SECONDS_IN_HOUR: i64 = SECONDS_IN_MINUTE * 60;
    const SECONDS_IN_DAY: i64 = 24 * SECONDS_IN_HOUR;

    let days = seconds / SECONDS_IN_DAY;
    let hours = (seconds % SECONDS_IN_DAY) / SECONDS_IN_HOUR;
    let minutes = (seconds % SECONDS_IN_HOUR) / SECONDS_IN_MINUTE;
    let seconds = seconds % SECONDS_IN_MINUTE;

    let mut parts = vec![];
    if days > 0 {
        parts.push(plural(days, "day"));
    }
    if hours > 0 {
        parts.push(plural(hours, "hour"));
    }
    if minutes > 0 {
        parts.push(plural(minutes, "minute"));
    }
    if parts.is_empty() {
        // Only include seconds if less than 1 minute
        parts.push(plural(seconds, "second"));
    }
    match parts.len() {
        0 => String::from("0 seconds"),
        1 => parts.remove(0),
        _ => {
            let last = parts.pop().unwrap();
            format!("{} and {}", parts.join(", "), last)
        }
    }
}

fn plural(val: i64, period: &str) -> String {
    if val == 1 {
        format!("{val} {period}")
    } else {
        format!("{val} {period}s")
    }
}
