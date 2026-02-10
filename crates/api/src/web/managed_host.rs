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

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use askama::Template;
use axum::Json;
use axum::extract::{Path as AxumPath, Query, State as AxumState};
use axum::response::{Html, IntoResponse, Redirect, Response};
use db::managed_host;
use hyper::http::StatusCode;
use itertools::Itertools;
use model;
use model::machine;
use model::machine::{LoadSnapshotOptions, Machine, ManagedHostStateSnapshot};
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as forgerpc};
use utils::managed_host_display::get_memory_details;
use utils::{ManagedHostMetadata, reason_to_user_string};

use super::filters;
use crate::api::Api;

const UNKNOWN: &str = "Unknown";

#[derive(Template)]
#[template(path = "managed_host_show.html")]
struct ManagedHostShow {
    hosts: Vec<ManagedHostRowDisplay>,
    grouped_hosts: Option<GroupedHosts>,
    active_group_by: String,
    active_health_alerts_filter: String,
    active_maintenance_filter: String,
    active_vendor_filter: String,
    active_model_filter: String,
    vendors: Vec<String>,
    models_per_vendor_json: String,
    active_state_filter: String,
    active_time_in_state_above_sla_filter: String,
    states: Vec<String>,
    gpus: Vec<String>,
    active_gpu_filter: String,
    ibs: Vec<String>,
    active_ib_filter: String,
    mems: Vec<(isize, String)>,
    active_mem_filter: isize,
    is_filtered: bool,
}

struct GroupedHosts {
    headers: Vec<&'static str>,
    groups: Vec<HostGroup>,
    total: usize,
}

struct HostGroup {
    num_in_group: usize,
    group_fields: Vec<String>,
    filter: String,
}

#[derive(PartialEq, Eq)]
pub struct ManagedHostRowDisplay {
    pub machine_id: String,
    pub state: String,
    pub time_in_state: String,
    pub time_in_state_above_sla: bool,
    pub state_reason: String,
    pub health_probe_alerts: Vec<health_report::HealthProbeAlert>,
    pub health_overrides: Vec<String>,
    pub host_admin_ip: String,
    pub host_admin_mac: String,
    pub host_bmc_ip: String,
    pub host_bmc_mac: String,
    pub vendor: String,
    pub model: String,
    pub num_gpus: usize,
    pub num_ib_ifs: usize,
    pub host_memory: String,
    pub is_link_ref: bool, // is maintenance_reference a URL?
    pub maintenance_reference: String,
    pub maintenance_start_time: String,
    pub dpus: Vec<AttachedDpuRowDisplay>,
}

impl From<ManagedHostStateSnapshot> for ManagedHostRowDisplay {
    fn from(item: ManagedHostStateSnapshot) -> Self {
        let ManagedHostStateSnapshot {
            host_snapshot,
            dpu_snapshots,
            aggregate_health,
            ..
        } = item;

        let (maintenance_reference, maintenance_start_time) = host_snapshot
            .health_report_overrides
            .maintenance_override()
            .map(|o| {
                (
                    o.maintenance_reference,
                    o.maintenance_start_time
                        .map(|t| t.to_string())
                        .unwrap_or_default(),
                )
            })
            .unwrap_or_default();

        // Decompose hardware_info into the pieces we want to show
        let (vendor, model, num_gpus, num_ib_ifs, host_memory) = host_snapshot
            .hardware_info
            .map(|hardware_info| {
                let (vendor, model) = hardware_info
                    .dmi_data
                    .map(|d| (d.sys_vendor, d.product_name))
                    .unwrap_or_default();

                (
                    vendor,
                    model,
                    hardware_info.gpus.len(),
                    hardware_info.infiniband_interfaces.len(),
                    get_memory_details(
                        &hardware_info
                            .memory_devices
                            .into_iter()
                            .map_into()
                            .collect(),
                    )
                    .unwrap_or_default(),
                )
            })
            .unwrap_or_default();
        let host_bmc_ip = host_snapshot.bmc_info.ip.unwrap_or_default();
        let host_bmc_mac = host_snapshot
            .bmc_info
            .mac
            .map(|m| m.to_string())
            .unwrap_or_default();

        let (host_admin_ip, host_admin_mac) = host_snapshot
            .interfaces
            .into_iter()
            .find(|i| i.primary_interface)
            .map(|i| {
                (
                    i.addresses
                        .first()
                        .map(|i| i.to_string())
                        .unwrap_or_default(),
                    i.mac_address.to_string(),
                )
            })
            .unwrap_or_default();

        Self {
            machine_id: host_snapshot.id.to_string(),
            state: host_snapshot.state.value.to_string(),
            time_in_state: host_snapshot.state.version.since_state_change_humanized(),
            time_in_state_above_sla: machine::state_sla(
                &host_snapshot.state.value,
                &host_snapshot.state.version,
            )
            .time_in_state_above_sla,
            state_reason: host_snapshot
                .controller_state_outcome
                .and_then(|o| reason_to_user_string(&o.into()))
                .unwrap_or_default(),
            health_probe_alerts: aggregate_health.alerts,
            health_overrides: host_snapshot
                .health_report_overrides
                .into_iter()
                .map(|(r, _)| r.source)
                .collect(),
            host_bmc_ip,
            host_bmc_mac,
            host_admin_ip,
            host_admin_mac,
            vendor,
            model,
            num_gpus,
            num_ib_ifs,
            host_memory,
            is_link_ref: maintenance_reference.starts_with("http"),
            maintenance_reference,
            maintenance_start_time,
            dpus: dpu_snapshots.into_iter().map_into().collect(),
        }
    }
}

impl From<model::machine::Machine> for AttachedDpuRowDisplay {
    fn from(item: Machine) -> Self {
        let bmc_ip = item.bmc_info.ip.unwrap_or_default();
        let bmc_mac = item.bmc_info.mac.map(|m| m.to_string()).unwrap_or_default();
        let primary_iface = item.interfaces.iter().find(|i| i.primary_interface);
        let oob_ip = primary_iface
            .and_then(|t| t.addresses.first().map(|a| a.to_string()))
            .unwrap_or_default();
        let oob_mac = primary_iface
            .map(|t| t.mac_address.to_string())
            .unwrap_or_default();
        Self {
            machine_id: item.id.to_string(),
            bmc_ip,
            bmc_mac,
            oob_ip,
            oob_mac,
        }
    }
}

impl PartialOrd for ManagedHostRowDisplay {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ManagedHostRowDisplay {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Since Machine IDs are unique, we don't have to compare by anything else
        self.machine_id.cmp(&other.machine_id)
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct AttachedDpuRowDisplay {
    pub machine_id: String,
    pub bmc_ip: String,
    pub bmc_mac: String,
    pub oob_ip: String,
    pub oob_mac: String,
}

enum DpuProperty {
    MachineId,
    BmcIp,
    BmcMac,
    OobIp,
    OobMac,
}

// derive PartialOrd will order them in the declared order, which for our purposes should be
// alphabetical except for Unknown which is last.
#[derive(Ord, PartialOrd, Eq, PartialEq, Copy, Clone)]
enum GroupingKey {
    Health,
    HostMemory,
    NumGPUs,
    NumIBIFs,
    State,
    Unknown,
}

impl GroupingKey {
    fn params_to_vec(s: &str) -> Vec<GroupingKey> {
        let mut v: Vec<GroupingKey> = s
            .split(',')
            .map(GroupingKey::from_param)
            .filter(|g| *g != GroupingKey::Unknown)
            .collect();
        // This sort is what makes the string match in the template (select/option) work
        v.sort_unstable();
        v
    }

    fn from_param(s: &str) -> GroupingKey {
        match s {
            "host_memory" => GroupingKey::HostMemory,
            "health" => GroupingKey::Health,
            "num_gpus" => GroupingKey::NumGPUs,
            "num_ib_ifs" => GroupingKey::NumIBIFs,
            "state" => GroupingKey::State,
            _ => GroupingKey::Unknown,
        }
    }

    fn vec_to_params(v: &[GroupingKey]) -> String {
        v.iter().map(|gk| gk.as_param()).join(",")
    }

    fn as_param(&self) -> &'static str {
        match self {
            GroupingKey::HostMemory => "host_memory",
            GroupingKey::Health => "health",
            GroupingKey::NumGPUs => "num_gpus",
            GroupingKey::NumIBIFs => "num_ib_ifs",
            GroupingKey::State => "state",
            GroupingKey::Unknown => "",
        }
    }

    fn filter_name(&self) -> &'static str {
        use GroupingKey::*;
        match self {
            Health => "health-alerts-filter",
            HostMemory => "mem-filter",
            NumGPUs => "gpu-filter",
            NumIBIFs => "ib-filter",
            State => "state-filter",
            Unknown => "",
        }
    }

    fn header(&self) -> &'static str {
        match self {
            GroupingKey::HostMemory => "Host Memory (GiB)",
            GroupingKey::Health => "Health",
            GroupingKey::NumGPUs => "GPU #",
            GroupingKey::NumIBIFs => "IB IFs #",
            GroupingKey::State => "State",
            GroupingKey::Unknown => "",
        }
    }
}

impl ManagedHostRowDisplay {
    fn dpu_properties(&self, property: DpuProperty) -> String {
        let lines: Vec<String> = match property {
            DpuProperty::MachineId => self
                .dpus
                .iter()
                .map(|d| {
                    filters::machine_id_link(d.machine_id.clone()).unwrap_or("UNKNOWN".to_string())
                })
                .collect(),
            DpuProperty::BmcIp => self
                .dpus
                .iter()
                .map(|d| {
                    format!(
                        "<a href=\"/admin/explored-endpoint/{}\">{}</a>",
                        d.bmc_ip, d.bmc_ip
                    )
                })
                .collect(),
            DpuProperty::BmcMac => self.dpus.iter().map(|d| d.bmc_mac.clone()).collect(),
            DpuProperty::OobIp => self.dpus.iter().map(|d| d.oob_ip.clone()).collect(),
            DpuProperty::OobMac => self.dpus.iter().map(|d| d.oob_mac.clone()).collect(),
        };
        lines.join("<br/>")
    }

    fn grouping_key(&self, cols: &[GroupingKey]) -> String {
        let mut k = Vec::with_capacity(cols.len());
        use GroupingKey::*;
        for col in cols {
            match col {
                HostMemory => k.push(mem_to_size(&self.host_memory).to_string()),
                Health => {
                    if self.health_probe_alerts.is_empty() {
                        k.push("Healthy".to_string())
                    } else {
                        k.push("Unhealthy".to_string())
                    }
                }
                NumGPUs => k.push(self.num_gpus.to_string()),
                NumIBIFs => k.push(self.num_ib_ifs.to_string()),
                State => k.push(short_state(&self.state).to_string()),
                Unknown => {}
            }
        }
        k.join(",")
    }
}

/// List managed hosts
pub async fn show_html(
    state: AxumState<Arc<Api>>,
    Query(mut params): Query<HashMap<String, String>>,
) -> Response {
    let host_health = state.runtime_config.host_health;
    let managed_hosts = match managed_host::load_all(
        &state.database_connection,
        LoadSnapshotOptions {
            include_history: false,
            include_instance_data: false,
            host_health_config: host_health,
        },
    )
    .await
    {
        Ok(hosts) => hosts,
        Err(err) => {
            tracing::error!(%err, "fetch_managed_hosts");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading managed hosts",
            )
                .into_response();
        }
    };

    let active_health_alerts_filter = params
        .remove("health-alerts-filter")
        .unwrap_or("all".to_string());
    let active_maintenance_filter = params
        .remove("maintenance-filter")
        .unwrap_or("all".to_string());
    let active_vendor_filter = params.remove("vendor-filter").unwrap_or("all".to_string());
    let active_model_filter = params.remove("model-filter").unwrap_or("all".to_string());
    let active_state_filter = params.remove("state-filter").unwrap_or("all".to_string());
    let active_gpu_filter = params.remove("gpu-filter").unwrap_or("all".to_string());
    let active_ib_filter = params.remove("ib-filter").unwrap_or("all".to_string());
    let active_mem_filter = params
        .remove("mem-filter")
        .and_then(|ms| ms.parse::<isize>().ok())
        .unwrap_or(-1);
    let active_time_in_state_above_sla_filter = params
        .remove("time-in-state-above-sla-filter")
        .unwrap_or("all".to_string());

    let group_by_param = params.remove("group-by").unwrap_or("none".to_string());
    let group_by = GroupingKey::params_to_vec(&group_by_param);

    let mut hosts = Vec::new();
    let mut models_per_vendor: HashMap<String, Vec<String>> = HashMap::new();
    let mut states = HashSet::new();
    let mut gpus = HashSet::new();
    let mut ibs = HashSet::new();
    let mut mems = HashSet::new();

    for mo in managed_hosts.into_iter() {
        let m: ManagedHostRowDisplay = mo.into();

        let vendor = m.vendor.to_lowercase().clone();
        let model = m.model.to_lowercase().clone();

        if !vendor.is_empty() {
            let models = models_per_vendor.entry(vendor).or_default();
            if !model.is_empty() && !models.contains(&model) {
                models.push(model);
            }
        }
        states.insert(short_state(&m.state).to_string());
        gpus.insert(m.num_gpus);
        ibs.insert(m.num_ib_ifs);
        let barry = mem_to_size(&m.host_memory);
        mems.insert((barry, format!("{barry} GiB")));

        if active_vendor_filter != "all" && active_vendor_filter != m.vendor.to_lowercase() {
            continue;
        }
        if active_model_filter != "all" && active_model_filter != m.model.to_lowercase() {
            continue;
        }
        if active_state_filter != "all"
            && active_state_filter != short_state(&m.state).to_lowercase()
        {
            continue;
        }
        if active_time_in_state_above_sla_filter != "all"
            && active_time_in_state_above_sla_filter != m.time_in_state_above_sla.to_string()
        {
            continue;
        }
        if active_gpu_filter != "all" {
            let Ok(gf) = active_gpu_filter.parse::<usize>() else {
                tracing::warn!("Invalid GPU filter: '{active_gpu_filter}'");
                continue;
            };
            if gf != m.num_gpus {
                continue;
            }
        }
        if active_ib_filter != "all" {
            let Ok(ibf) = active_ib_filter.parse::<usize>() else {
                tracing::warn!("Invalid IB IFs filter: '{active_ib_filter}'");
                continue;
            };
            if ibf != m.num_ib_ifs {
                continue;
            }
        }
        if active_mem_filter != -1 && active_mem_filter != barry {
            continue;
        }
        if active_health_alerts_filter != "all" {
            if active_health_alerts_filter == "healthy" && !m.health_probe_alerts.is_empty() {
                continue;
            }
            if active_health_alerts_filter == "unhealthy" && m.health_probe_alerts.is_empty() {
                continue;
            }
        }
        if active_maintenance_filter != "all" {
            if active_maintenance_filter == "active" && !m.maintenance_reference.is_empty() {
                continue;
            }
            if active_maintenance_filter == "maintenance" && m.maintenance_reference.is_empty() {
                continue;
            }
        }

        hosts.push(m);
    }

    hosts.sort_unstable();

    let vendors: Vec<String> = models_per_vendor
        .keys()
        .cloned()
        .sorted_unstable()
        .collect();

    for (_, models) in models_per_vendor.iter_mut() {
        models.sort_unstable();
    }

    let models_per_vendor_json = serde_json::to_string(&models_per_vendor).unwrap();

    let states: Vec<String> = states.into_iter().sorted_unstable().collect();

    let gpus: Vec<String> = gpus
        .into_iter()
        .map(|x| x.to_string())
        .sorted_unstable()
        .collect();

    let ibs: Vec<String> = ibs
        .into_iter()
        .map(|x| x.to_string())
        .sorted_unstable()
        .collect();

    let mems: Vec<(isize, String)> = mems
        .into_iter()
        .sorted_unstable_by(|(size_a, _), (size_b, _)| {
            size_a
                .partial_cmp(size_b)
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .collect();

    let is_filtered = active_health_alerts_filter != "all"
        || active_maintenance_filter != "all"
        || active_vendor_filter != "all"
        || active_model_filter != "all"
        || active_state_filter != "all"
        || active_time_in_state_above_sla_filter != "all"
        || active_gpu_filter != "all"
        || active_ib_filter != "all"
        || active_mem_filter != -1;

    let tmpl = ManagedHostShow {
        grouped_hosts: group_hosts(&hosts, &group_by),
        active_group_by: GroupingKey::vec_to_params(&group_by),
        active_health_alerts_filter,
        active_maintenance_filter,
        hosts,
        active_vendor_filter,
        active_model_filter,
        vendors,
        models_per_vendor_json,
        active_state_filter,
        active_time_in_state_above_sla_filter,
        states,
        gpus,
        active_gpu_filter,
        ibs,
        active_ib_filter,
        mems,
        active_mem_filter,
        is_filtered,
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

fn group_hosts(hosts: &[ManagedHostRowDisplay], group_by: &[GroupingKey]) -> Option<GroupedHosts> {
    if group_by.is_empty() || hosts.is_empty() {
        return None;
    }

    let mut count = HashMap::new();
    let mut groups = HashMap::new();
    for h in hosts {
        let k = h.grouping_key(group_by);
        count.entry(k.clone()).and_modify(|c| *c += 1).or_insert(1);
        groups.insert(k, h);
    }

    let mut total = 0;
    let mut groups = Vec::new();
    for (k, num) in count {
        let fields: Vec<String> = k.as_str().split(',').map(|s| s.to_string()).collect();
        let filter = filter_expr(group_by, &fields);
        groups.push(HostGroup {
            num_in_group: num,
            group_fields: fields,
            filter,
        });
        total += num;
    }
    groups.sort_unstable_by_key(|g| std::cmp::Reverse(g.num_in_group));

    let headers = group_by.iter().map(|c| c.header()).collect();
    Some(GroupedHosts {
        headers,
        groups,
        total,
    })
}

// keys: health,host_memory,num_gpus,num_ib_ifs,state
// OUT: state-filter=all&gpu-filter=all&ib-filter=all&mem-filter=all
fn filter_expr(keys: &[GroupingKey], values: &[String]) -> String {
    keys.iter()
        .zip(values.iter())
        .map(|(k, v)| format!("{}={}", k.filter_name(), v.to_lowercase()))
        .collect::<Vec<_>>()
        .join("&")
}

pub async fn show_all_json(state: AxumState<Arc<Api>>) -> Response {
    let mut managed_hosts = match fetch_managed_hosts_with_metadata(state, true).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "fetch_managed_hosts");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading managed hosts",
            )
                .into_response();
        }
    };
    managed_hosts.sort_unstable_by(|h1, h2| h1.machine_id.cmp(&h2.machine_id));
    (StatusCode::OK, Json(managed_hosts)).into_response()
}

/// Get all managed hosts, with expensive metadata like connected network devices, using information
/// from site explorer, redfish, etc. This is a very expensive call and should be used only for
/// cases which need all of this information.
async fn fetch_managed_hosts_with_metadata(
    AxumState(api): AxumState<Arc<Api>>,
    include_history: bool,
) -> eyre::Result<Vec<utils::ManagedHostOutput>> {
    let machine_ids = api
        .find_machine_ids(tonic::Request::new(forgerpc::MachineSearchConfig {
            include_dpus: true,
            include_history: false,
            include_predicted_host: true,
            only_maintenance: false,
            exclude_hosts: false,
            only_quarantine: false,
            instance_type_id: None,
            mnnvl_only: false,
        }))
        .await?
        .into_inner()
        .machine_ids;

    let mut all_machines = Vec::new();
    let mut offset = 0;
    while offset != machine_ids.len() {
        const PAGE_SIZE: usize = 100;
        let page_size = PAGE_SIZE.min(machine_ids.len() - offset);
        let next_ids = &machine_ids[offset..offset + page_size];
        let request = tonic::Request::new(forgerpc::MachinesByIdsRequest {
            machine_ids: next_ids.to_vec(),
            include_history,
        });
        let next_machines = api.find_machines_by_ids(request).await?.into_inner();

        all_machines.extend(next_machines.machines.into_iter());
        offset += page_size;
    }

    let managed_host_metadata = ManagedHostMetadata::lookup_from_api(all_machines, api).await;
    let managed_hosts = utils::get_managed_host_output(managed_host_metadata);
    Ok(managed_hosts)
}

/// View managed host details. This has been replaced by the Machine details page
pub async fn detail(
    AxumState(_state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
) -> Response {
    let view_url = format!("/admin/machine/{machine_id}");
    Redirect::to(&view_url).into_response()
}

fn mem_to_size(mem: &str) -> isize {
    if mem == UNKNOWN {
        return 0;
    }

    // The first number is the size, and the second part is the unit (GiB or TiB).
    // When memory details include a breakdown (e.g. "512 GiB (8x64 GiB)") we only
    // care about the leading pair of whitespace-separated tokens.
    let Some((Ok(size), unit)) = mem
        .split_whitespace()
        .take(2)
        .collect_tuple()
        .map(|(size, unit)| (size.parse::<f64>(), unit))
    else {
        tracing::warn!("Invalid memory format: '{mem}'");
        return 0;
    };

    (match unit {
        "GiB" => size,
        "TiB" => size * 1024.0,
        _ => {
            tracing::warn!("Invalid unit '{}' in mem string '{mem}'", unit);
            return 0;
        }
    }) as isize
}

fn short_state(s: &str) -> &str {
    s.split(' ').next().unwrap_or_default()
}
