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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use askama::Template;
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use carbide_uuid::machine::{MachineId, MachineType};
use hyper::http::StatusCode;
use model::machine::network::ManagedHostQuarantineState;
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as forgerpc, MachineInventorySoftwareComponent, OverrideMode};
use serde::Deserialize;
use utils::managed_host_display::to_time;

use super::filters;
use super::machine_state_history::{MachineStateHistoryRecord, MachineStateHistoryTable};
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
    metadata: rpc::forge::Metadata,
    instance_type_id: String,
    instance_type: String,
    num_nvlink_gpus: usize,
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
        let mut num_nvlink_gpus = 0;
        if let Some(di) = m.discovery_info.as_ref() {
            if let Some(dmi) = di.dmi_data.as_ref() {
                sys_vendor = dmi.sys_vendor.clone();
                product_serial = dmi.product_serial.clone();
            }
            num_gpus = di.gpus.len();
            num_ib_ifs = di.infiniband_interfaces.len();
        }
        if let Some(nvlink_info) = m.nvlink_info.as_ref() {
            num_nvlink_gpus = nvlink_info.gpus.len();
        }
        let replace_count = m
            .health_overrides
            .iter()
            .filter(|o| o.mode() == OverrideMode::Replace)
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
            id: m.id.map(|id| id.to_string()).unwrap_or_default(),
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
                .map(|i| i.to_string())
                .collect(),
            associated_host_id: m
                .associated_host_machine_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
            sys_vendor,
            product_serial,
            num_gpus,
            num_ib_ifs,
            health_probe_alerts: health.alerts,
            override_mode_counts: format!(
                "{}",
                if replace_count > 0 {
                    replace_count
                } else {
                    merge_count
                }
            ),
            metadata: m.metadata.unwrap_or_default(),
            instance_type_id: m.instance_type_id.unwrap_or_default(),
            instance_type: String::new(),
            num_nvlink_gpus,
        }
    }
}

pub async fn show_hosts_html(state: AxumState<Arc<Api>>) -> impl IntoResponse {
    show(state, true, false).await
}

pub async fn show_hosts_json(AxumState(state): AxumState<Arc<Api>>) -> Response {
    let machines = match fetch_machines(state, false, true).await {
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
    let mut machines = match fetch_machines(state, true, true).await {
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
    let machines = match fetch_machines(state, true, true).await {
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
) -> Response {
    let mut all_machines = match fetch_machines(state.clone(), include_dpus, false).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "find_machines");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(err.to_string())).into_response();
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

    let instance_type_ids: HashSet<String> = machines
        .iter()
        .filter_map(|m| match m.instance_type_id.is_empty() {
            false => Some(m.instance_type_id.clone()),
            true => None,
        })
        .collect();

    let instance_types =
        match fetch_instance_type_names(&state, instance_type_ids.into_iter().collect()).await {
            Ok(instance_types) => instance_types,
            Err(e) => return e,
        };

    for m in machines.iter_mut() {
        if let Some(instance_type) = instance_types.get(&m.instance_type_id) {
            m.instance_type = instance_type.clone();
        }
    }

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
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn fetch_machine(
    api: &Api,
    machine_id: MachineId,
) -> Result<::rpc::forge::Machine, Response> {
    let request = tonic::Request::new(rpc::forge::MachinesByIdsRequest {
        machine_ids: vec![machine_id],
        include_history: true,
    });

    let machine = match api
        .find_machines_by_ids(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(m) if m.machines.is_empty() => {
            return Err(super::not_found_response(format!(
                "{machine_id}\n<a href=\"/admin/machine/{machine_id}/state-history\">View State history for Machine</a>"
            )));
        }
        Ok(m) if m.machines.len() != 1 => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Machine list for {machine_id} returned {} machines",
                    m.machines.len()
                ),
            )
                .into_response());
        }
        Ok(mut m) => m.machines.remove(0),
        Err(err) if err.code() == tonic::Code::NotFound => {
            return Err(super::not_found_response(machine_id.to_string()));
        }
        Err(err) => {
            tracing::error!(%err, %machine_id, "find_machines_by_ids");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(err.to_string())).into_response());
        }
    };

    Ok(machine)
}

/// Fetches Instance Type Names for the given Instance Type IDs
pub async fn fetch_instance_type_names(
    api: &Api,
    instance_type_ids: Vec<String>,
) -> Result<HashMap<String, String>, Response> {
    if instance_type_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let request =
        tonic::Request::new(rpc::forge::FindInstanceTypesByIdsRequest { instance_type_ids });

    let instance_types = api
        .find_instance_types_by_ids(request)
        .await
        .map_err(|err| {
            tracing::error!(%err, "find_instance_types_by_ids");
            (StatusCode::INTERNAL_SERVER_ERROR, Html(err.to_string())).into_response()
        })?
        .into_inner()
        .instance_types;

    let mut result = HashMap::new();
    for instance_type in instance_types {
        if let Some(name) = instance_type.metadata.as_ref().map(|m| m.name.clone()) {
            result.insert(instance_type.id, name);
        }
    }

    Ok(result)
}

pub async fn fetch_machines(
    api: Arc<Api>,
    include_dpus: bool,
    include_history: bool,
) -> Result<forgerpc::MachineList, tonic::Status> {
    let request = tonic::Request::new(forgerpc::MachineSearchConfig {
        include_dpus,
        include_history: false,
        include_predicted_host: true,
        only_maintenance: false,
        exclude_hosts: false,
        only_quarantine: false,
        instance_type_id: None,
        mnnvl_only: false,
    });

    let machine_ids = api
        .find_machine_ids(request)
        .await?
        .into_inner()
        .machine_ids;

    let mut machines = Vec::new();
    let mut offset = 0;
    while offset != machine_ids.len() {
        const PAGE_SIZE: usize = 100;
        let page_size = PAGE_SIZE.min(machine_ids.len() - offset);
        let next_ids = &machine_ids[offset..offset + page_size];
        let next_vpcs = api
            .find_machines_by_ids(tonic::Request::new(forgerpc::MachinesByIdsRequest {
                machine_ids: next_ids.to_vec(),
                include_history,
            }))
            .await?
            .into_inner();

        machines.extend(next_vpcs.machines.into_iter());
        offset += page_size;
    }

    Ok(forgerpc::MachineList { machines })
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
    state_reason: Option<::rpc::forge::ControllerStateReason>,
    machine_type: String,
    is_host: bool,
    network_config: String,
    history: MachineStateHistoryTable,
    bios_version: String,
    board_version: String,
    product_name: String,
    product_serial: String,
    board_serial: String,
    chassis_serial: String,
    sys_vendor: String,
    maintenance_reference_is_link: bool,
    maintenance_reference: String,
    maintenance_start_time: String,
    interfaces: Vec<MachineInterfaceDisplay>,
    ib_interfaces: Vec<MachineIbInterfaceDisplay>,
    inventory: Vec<MachineInventorySoftwareComponent>,
    health: health_report::HealthReport,
    health_overrides: Vec<String>,
    bmc_info: Option<rpc::forge::BmcInfo>,
    discovery_info_json: String,
    metadata: rpc::forge::Metadata,
    version: String,
    capabilities: Vec<MachineCapability>,
    capabilities_json: String,
    validation_runs: Vec<ValidationRun>,
    hw_sku: String,
    quarantine_state: Option<ManagedHostQuarantineState>,
    quarantine_state_is_link: bool,
    instance_type_id: String,
    instance_type: String,
    has_instance_type: bool,
    nvlink_gpus: Vec<MachineNvLinkGpuDisplay>,
}

struct MachineCapability {
    ty: &'static str,
    name: String,
    count: u32,
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
    lid: String,
    fabric_id: String,
    associated_pkeys: Option<Vec<String>>,
    associated_partitions: Option<Vec<String>>,
    observed_at: String,
}

#[derive(Debug, Default)]
struct MachineNvLinkGpuDisplay {
    domain_uuid: String,
    nmx_m_id: String,
    tray_index: i32,
    slot_id: i32,
    device_instance: i32,
    guid: u64,
}

pub struct ValidationRun {
    pub status: String,
    pub context: String,
    pub validation_id: String,
    pub start_time: String,
    pub end_time: String,
    pub machine_id: String,
}

impl From<forgerpc::Machine> for MachineDetail {
    fn from(m: forgerpc::Machine) -> Self {
        let machine_id = m.id.map(|id| id.to_string()).unwrap_or_default();

        let mut history_records = Vec::new();
        for e in m.events.into_iter().rev() {
            history_records.push(MachineStateHistoryRecord {
                state: e.event,
                version: e.version,
            });
        }
        let history = MachineStateHistoryTable {
            records: history_records,
        };

        let mut interfaces = Vec::new();
        for (i, interface) in m.interfaces.into_iter().enumerate() {
            interfaces.push(MachineInterfaceDisplay {
                index: i,
                id: interface.id.unwrap_or_default().to_string(),
                dpu_id: interface
                    .attached_dpu_machine_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(super::invalid_machine_id),
                segment_id: interface.segment_id.unwrap_or_default().to_string(),
                domain_id: interface.domain_id.unwrap_or_default().to_string(),
                hostname: interface.hostname,
                primary: interface.primary_interface.to_string(),
                mac_address: interface.mac_address,
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
        let mut nvlink_gpus = Vec::new();

        let discovery_info_json = m
            .discovery_info
            .as_ref()
            .map(|info| {
                serde_json::to_string_pretty(info)
                    .unwrap_or_else(|e| format!("Formatting error: {e}"))
            })
            .unwrap_or_else(|| "null".to_string());

        if let Some(di) = m.discovery_info {
            if let Some(dmi) = di.dmi_data {
                product_name = dmi.product_name;
                product_serial = dmi.product_serial;
                board_serial = dmi.board_serial;
                chassis_serial = dmi.chassis_serial;
                sys_vendor = dmi.sys_vendor;
                bios_version = dmi.bios_version;
                board_version = dmi.board_version;
            }

            for iface in di.infiniband_interfaces.into_iter() {
                let mut iface_display = MachineIbInterfaceDisplay {
                    guid: iface.guid,
                    ..Default::default()
                };
                if let Some(props) = iface.pci_properties {
                    iface_display.device = props.device;
                    iface_display.vendor = props.vendor;
                    iface_display.slot = props.slot.clone().unwrap_or_default();
                }
                if let Some(ib_status) = m.ib_status.as_ref() {
                    iface_display.observed_at =
                        to_time(ib_status.observed_at, Some(&machine_id)).unwrap_or_default();

                    for iter_status in ib_status.ib_interfaces.iter() {
                        if Some(&iface_display.guid) == iter_status.guid.as_ref() {
                            iface_display.fabric_id =
                                iter_status.fabric_id.clone().unwrap_or_default();
                            iface_display.lid =
                                format!("0x{:x}", iter_status.lid.unwrap_or_default());

                            iface_display.associated_pkeys =
                                iter_status.associated_pkeys.clone().map(|list| list.items);
                            iface_display.associated_partitions = iter_status
                                .associated_partition_ids
                                .clone()
                                .map(|ids| ids.items);
                            break;
                        }
                    }
                }

                ib_interfaces.push(iface_display);
            }
            // Sort the IB interfaces in the same way the Instance allocation API
            // would sort them
            ib_interfaces.sort_by_key(|iface| iface.slot.clone());
        }
        if let Some(inv) = m.inventory {
            inventory.extend(inv.components);
        }

        if let Some(nvlink_info) = m.nvlink_info {
            nvlink_gpus = nvlink_info
                .gpus
                .into_iter()
                .map(|gpu| MachineNvLinkGpuDisplay {
                    domain_uuid: nvlink_info.domain_uuid.unwrap_or_default().to_string(),
                    nmx_m_id: gpu.nmx_m_id,
                    tray_index: gpu.tray_index,
                    slot_id: gpu.slot_id,
                    guid: gpu.guid,
                    device_instance: gpu.device_id,
                })
                .collect();
        }

        let quarantine_state = m
            .quarantine_state
            .and_then(|q| ManagedHostQuarantineState::try_from(q).ok());

        MachineDetail {
            id: machine_id.clone(),
            time_in_state: config_version::since_state_change_humanized(&m.state_version),
            state: m.state,
            state_version: m.state_version,
            state_sla: m
                .state_sla
                .as_ref()
                .and_then(|sla| sla.sla)
                .map(|sla| {
                    config_version::format_duration(
                        chrono::TimeDelta::try_from(sla).unwrap_or(chrono::TimeDelta::MAX),
                    )
                })
                .unwrap_or_default(),
            time_in_state_above_sla: m
                .state_sla
                .as_ref()
                .map(|sla| sla.time_in_state_above_sla)
                .unwrap_or_default(),
            last_reboot: to_time(m.last_reboot_time, Some(&machine_id))
                .unwrap_or("N/A".to_string()),
            state_reason: m.state_reason,
            version: m.version,
            metadata: m.metadata.unwrap_or_default(),
            machine_type: get_machine_type(&machine_id),
            is_host: m.machine_type == forgerpc::MachineType::Host as i32,
            network_config: String::new(), // filled in later
            bmc_info: m.bmc_info,
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
            maintenance_reference_is_link: m
                .maintenance_reference
                .as_ref()
                .map(|r| r.starts_with("http"))
                .unwrap_or_default(),
            maintenance_reference: m.maintenance_reference.unwrap_or_default(),
            maintenance_start_time: to_time(m.maintenance_start_time, Some(&machine_id))
                .unwrap_or_default(),
            host_id: m
                .associated_host_machine_id
                .map_or_else(String::default, |id| id.to_string()),
            health: m
                .health
                .map(|h| {
                    health_report::HealthReport::try_from(h)
                        .unwrap_or_else(health_report::HealthReport::malformed_report)
                })
                .unwrap_or_else(health_report::HealthReport::missing_report),
            health_overrides: m
                .health_overrides
                .iter()
                .map(|o| o.source.clone())
                .collect(),
            discovery_info_json,
            capabilities_json: m
                .capabilities
                .as_ref()
                .map(|set| serde_json::to_string_pretty(set).unwrap_or("Invalid JSON".to_string()))
                .unwrap_or_else(|| "{}".to_string()),
            capabilities: m
                .capabilities
                .map(|s| {
                    let mut caps = Vec::new();
                    for item in s.cpu {
                        caps.push(MachineCapability {
                            ty: "cpu",
                            name: item.name,
                            count: item.count,
                        })
                    }
                    for item in s.gpu {
                        caps.push(MachineCapability {
                            ty: "gpu",
                            name: item.name,
                            count: item.count,
                        })
                    }
                    for item in s.memory {
                        caps.push(MachineCapability {
                            ty: "memory",
                            name: item.name,
                            count: item.count,
                        })
                    }
                    for item in s.storage {
                        caps.push(MachineCapability {
                            ty: "storage",
                            name: item.name,
                            count: item.count,
                        })
                    }
                    for item in s.network {
                        caps.push(MachineCapability {
                            ty: "network",
                            name: item.name,
                            count: item.count,
                        })
                    }
                    for item in s.infiniband {
                        caps.push(MachineCapability {
                            ty: "infiniband",
                            name: item.name,
                            count: item.count,
                        })
                    }
                    for item in s.dpu {
                        caps.push(MachineCapability {
                            ty: "dpu",
                            name: item.name,
                            count: item.count,
                        })
                    }
                    caps
                })
                .unwrap_or_default(),
            validation_runs: Vec::new(),
            hw_sku: m.hw_sku.unwrap_or_default(),
            quarantine_state_is_link: quarantine_state
                .as_ref()
                .is_some_and(|r| r.reason_str().starts_with("http")),
            quarantine_state,
            has_instance_type: m.instance_type_id.is_some(),
            instance_type_id: m.instance_type_id.unwrap_or_default(),
            instance_type: "".to_string(),
            nvlink_gpus,
        }
    }
}

/// View machine
pub async fn detail(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
) -> Response {
    let (show_json, machine_id) = match machine_id.strip_suffix(".json") {
        Some(machine_id) => (true, machine_id.to_string()),
        None => (false, machine_id),
    };

    let machine_id = match machine_id.parse::<MachineId>() {
        Ok(machine_id) => machine_id,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    let machine = match fetch_machine(&state, machine_id).await {
        Ok(machine) => machine,
        Err(response) => return response,
    };

    if show_json {
        return (StatusCode::OK, Json(machine)).into_response();
    }

    let mut display: MachineDetail = machine.into();

    if display.has_instance_type {
        match fetch_instance_type_names(&state, vec![display.instance_type_id.clone()]).await {
            Ok(mut instance_types) => {
                display.instance_type = instance_types
                    .remove(&display.instance_type_id)
                    .unwrap_or_default()
            }
            Err(e) => return e,
        };
    }

    // Get validation results
    let validation_request = tonic::Request::new(rpc::forge::MachineValidationRunListGetRequest {
        machine_id: Some(machine_id),
        include_history: false,
    });

    let validation_runs = match state
        .get_machine_validation_runs(validation_request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(results) => results
            .runs
            .into_iter()
            .rev() // Show the most recent run first
            .map(|vr| ValidationRun {
                machine_id: vr.machine_id.map(|id| id.to_string()).unwrap_or_default(),
                status:format!("{:?}", vr.status.unwrap_or_default().machine_validation_state.unwrap_or(
                    rpc::forge::machine_validation_status::MachineValidationState::Completed(
                        rpc::forge::machine_validation_status::MachineValidationCompleted::Success.into(),
                    ),
                )),
                context: vr.context.unwrap_or_default(),
                validation_id: vr.validation_id.unwrap_or_default().to_string(),
                start_time: vr.start_time.unwrap_or_default().to_string(),
                end_time: vr.end_time.unwrap_or_default().to_string(),
            })
            .collect(),
        Err(err) => {
            tracing::warn!(%err, %machine_id, "get_machine_validation_runs failed");
            Vec::new() // Empty validation results on error
        }
    };

    display.validation_runs = validation_runs;

    if !display.is_host {
        let request = tonic::Request::new(forgerpc::ManagedHostNetworkConfigRequest {
            dpu_machine_id: Some(machine_id),
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
    MachineType::from_id_string(machine_id)
        .map(|t| t.to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

#[derive(Deserialize, Debug)]
pub struct MaintenanceAction {
    action: String,
    reference: Option<String>,
}

/// Enter / Exit maintenance mode
pub async fn maintenance(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
    Form(form): Form<MaintenanceAction>,
) -> Response {
    let view_url = format!("/admin/machine/{machine_id}");

    let machine_id = match machine_id.parse::<MachineId>() {
        Ok(machine_id) => machine_id,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    let req = if form.action == "enter" {
        forgerpc::MaintenanceRequest {
            operation: forgerpc::MaintenanceOperation::Enable.into(),
            host_id: Some(machine_id),
            reference: form.reference,
        }
    } else if form.action == "exit" {
        forgerpc::MaintenanceRequest {
            operation: forgerpc::MaintenanceOperation::Disable.into(),
            host_id: Some(machine_id),
            reference: None,
        }
    } else {
        tracing::error!("Expected action to be 'enter' or 'exit' but got neither");
        return Redirect::to(&view_url).into_response();
    };

    if machine_id.machine_type().is_dpu() {
        tracing::error!("Maintenance Mode can not be set on DPUs");
        return Redirect::to(&view_url).into_response();
    }

    if let Err(err) = state
        .set_maintenance(tonic::Request::new(req))
        .await
        .map(|response| response.into_inner())
    {
        tracing::error!(%err, %machine_id, "set_maintenance");
        return Redirect::to(&view_url).into_response();
    }

    Redirect::to(&view_url).into_response()
}

#[derive(Deserialize, Debug)]
pub struct QuarantineAction {
    action: String,
    mode: Option<String>,
    reason: Option<String>,
}

/// Enter / Exit quarantine
pub async fn quarantine(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
    Form(form): Form<QuarantineAction>,
) -> Response {
    let view_url = format!("/admin/machine/{machine_id}");
    let machine_id = match machine_id.parse::<MachineId>() {
        Ok(machine_id) => machine_id,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    let err = match form.action.as_str() {
        "enable" => {
            let mode = form
                .mode
                .as_deref()
                .and_then(forgerpc::ManagedHostQuarantineMode::from_str_name)
                .unwrap_or(forgerpc::ManagedHostQuarantineMode::BlockAllTraffic);
            state
                .set_managed_host_quarantine_state(tonic::Request::new(
                    forgerpc::SetManagedHostQuarantineStateRequest {
                        machine_id: Some(machine_id),
                        quarantine_state: Some(forgerpc::ManagedHostQuarantineState {
                            mode: mode as i32,
                            reason: form.reason,
                        }),
                    },
                ))
                .await
                .map(|_| ())
        }
        "disable" => state
            .clear_managed_host_quarantine_state(tonic::Request::new(machine_id.into()))
            .await
            .map(|_| ()),
        unknown => {
            tracing::error!("Expected action to be 'enable' or 'disable' but got {unknown}");
            return Redirect::to(&view_url).into_response();
        }
    };

    if let Err(error) = err {
        tracing::error!(%error, %machine_id, "quarantine");
    }

    Redirect::to(&view_url).into_response()
}

#[derive(Deserialize, Debug)]
pub struct SetDpuFirstBootOrderAction {
    bmc_ip: String,
    boot_interface_mac: String,
}

pub async fn set_dpu_first_boot_order(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
    Form(form): Form<SetDpuFirstBootOrderAction>,
) -> Response {
    let view_url = format!("/admin/machine/{machine_id}");

    if let Err(err) = state
        .set_dpu_first_boot_order(tonic::Request::new(
            rpc::forge::SetDpuFirstBootOrderRequest {
                machine_id: None,
                bmc_endpoint_request: Some(rpc::forge::BmcEndpointRequest {
                    ip_address: form.bmc_ip,
                    mac_address: None,
                }),
                boot_interface_mac: Some(form.boot_interface_mac),
            },
        ))
        .await
    {
        tracing::error!(%err, "set_dpu_first_boot_order failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, err.message().to_owned()).into_response();
    }

    Redirect::to(&view_url).into_response()
}
