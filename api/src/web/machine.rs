/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as forgerpc, MachineInventorySoftwareComponent, OverrideMode};
use utils::managed_host_display::to_time;

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "machine_show.html")]
struct MachineShow {
    title: &'static str,
    machines: Vec<MachineRowDisplay>,
}

#[derive(PartialEq, Eq)]
struct MachineRowDisplay {
    id: String,
    hostname: String,
    state: String,
    time_in_state: String,
    time_in_state_above_sla: bool,
    associated_dpu_ids: Vec<String>,
    associated_host_id: String,
    sys_vendor: String,
    product_serial: String,
    ip_address: String,
    mac_address: String,
    is_host: bool,
    num_gpus: usize,
    num_ib_ifs: usize,
    health_probe_alerts: Vec<health_report::HealthProbeAlert>,
    override_mode_counts: String,
}

impl PartialOrd for MachineRowDisplay {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for MachineRowDisplay {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Since Machine IDs are unique, we don't have to compare by anything else
        self.id.cmp(&other.id)
    }
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
        let override_count = m
            .health_overrides
            .iter()
            .filter(|o| o.mode() == OverrideMode::Override)
            .count();
        let merge_count = m
            .health_overrides
            .iter()
            .filter(|o| o.mode() == OverrideMode::Merge)
            .count();

        let health = m
            .health
            .as_ref()
            .map(|h| {
                health_report::HealthReport::try_from(h.clone())
                    .unwrap_or_else(health_report::HealthReport::malformed_report)
            })
            .unwrap_or_else(health_report::HealthReport::missing_report);

        MachineRowDisplay {
            hostname,
            id: m.id.unwrap_or_default().id,
            state: m.state,
            time_in_state: config_version::since_state_change_humanized(&m.state_version),
            time_in_state_above_sla: m
                .state_sla
                .as_ref()
                .map(|sla| sla.time_in_state_above_sla)
                .unwrap_or_default(),
            ip_address,
            mac_address,
            is_host: m.machine_type == forgerpc::MachineType::Host as i32,
            associated_dpu_ids: m
                .associated_dpu_machine_ids
                .into_iter()
                .map(|i| i.id)
                .collect(),
            associated_host_id: m
                .associated_host_machine_id
                .map(|id| id.id)
                .unwrap_or_default(),
            sys_vendor,
            product_serial,
            num_gpus,
            num_ib_ifs,
            health_probe_alerts: health.alerts.clone(),
            override_mode_counts: format!(
                "{}",
                if override_count > 0 {
                    override_count
                } else {
                    merge_count
                }
            ),
        }
    }
}

pub async fn show_hosts_html(state: AxumState<Arc<Api>>) -> impl IntoResponse {
    show(state, true, false).await
}

pub async fn show_hosts_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let machines = match fetch_machines(state, false).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "fetch_machines");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading machines").into_response();
        }
    };
    (StatusCode::OK, Json(machines)).into_response()
}

pub async fn show_dpus_html(state: AxumState<Arc<Api>>) -> impl IntoResponse {
    show(state, false, true).await
}

pub async fn show_dpus_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
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
pub async fn show_all_html(state: AxumState<Arc<Api>>) -> impl IntoResponse {
    show(state, true, true).await
}

pub async fn show_all_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let machines = match fetch_machines(state, true).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "fetch_machines");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading machines").into_response();
        }
    };
    (StatusCode::OK, Json(machines)).into_response()
}

async fn show(
    AxumState(state): AxumState<Arc<Api>>,
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

pub async fn fetch_machines(
    api: Arc<Api>,
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
    state_sla: String,
    time_in_state_above_sla: bool,
    last_reboot: String,
    state_reason: String,
    machine_type: String,
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
    health: health_report::HealthReport,
    health_overrides: Vec<String>,
    bmc_info: Option<rpc::forge::BmcInfo>,
    discovery_info_json: String,
}

struct MachineHistoryDisplay {
    event: String,
    version: String,
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
            });
        }

        let mut interfaces = Vec::new();
        for (i, interface) in m.interfaces.into_iter().enumerate() {
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
            time_in_state: config_version::since_state_change_humanized(&m.state_version),
            state: m.state,
            state_version: m.state_version,
            state_sla: m
                .state_sla
                .as_ref()
                .and_then(|sla| sla.sla.clone())
                .map(|sla| {
                    config_version::format_duration(
                        chrono::TimeDelta::try_from(sla).unwrap_or(chrono::TimeDelta::max_value()),
                    )
                })
                .unwrap_or_default(),
            time_in_state_above_sla: m
                .state_sla
                .as_ref()
                .map(|sla| sla.time_in_state_above_sla)
                .unwrap_or_default(),
            last_reboot: to_time(
                m.last_reboot_time.clone(),
                &rpc::MachineId {
                    id: machine_id.clone(),
                },
            )
            .unwrap_or("N/A".to_string()),
            state_reason: m
                .state_reason
                .as_ref()
                .and_then(utils::reason_to_user_string)
                .unwrap_or_default(),
            machine_type: get_machine_type(&machine_id),
            is_host: m.machine_type == forgerpc::MachineType::Host as i32,
            network_config: String::new(), // filled in later
            bmc_info: m.bmc_info.clone(),
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
            health: m
                .health
                .as_ref()
                .map(|h| {
                    health_report::HealthReport::try_from(h.clone())
                        .unwrap_or_else(health_report::HealthReport::malformed_report)
                })
                .unwrap_or_else(health_report::HealthReport::missing_report),
            health_overrides: m
                .health_overrides
                .iter()
                .map(|o| o.source.clone())
                .collect(),
            discovery_info_json: m
                .discovery_info
                .as_ref()
                .map(|info| {
                    serde_json::to_string_pretty(info)
                        .unwrap_or_else(|e| format!("Formatting error: {e}"))
                })
                .unwrap_or_else(|| "null".to_string()),
        }
    }
}

/// View machine
pub async fn detail(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
) -> Response {
    let rpc_machine_id = ::rpc::common::MachineId {
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
            return super::not_found_response(machine_id);
        }
        Err(err) => {
            tracing::error!(%err, %machine_id, "get_machine");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response();
        }
    };

    let mut display: MachineDetail = machine.into();
    if !display.is_host {
        let request = tonic::Request::new(forgerpc::ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(::rpc::common::MachineId {
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
    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

pub fn get_machine_type(machine_id: &str) -> String {
    if machine_id.starts_with("fm100p") {
        "Host (Predicted)"
    } else if machine_id.starts_with("fm100h") {
        "Host"
    } else {
        "DPU"
    }
    .to_string()
}
