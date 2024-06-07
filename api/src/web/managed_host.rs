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
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;
use http::StatusCode;
use itertools::Itertools;
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as forgerpc};
use serde::Deserialize;
use utils::managed_host_display::{DpuSwitchConnection, ManagedHostAttachedDpu};
use utils::ManagedHostMetadata;

use super::filters;
use crate::api::Api;

const UNKNOWN: &str = "Unknown";

#[derive(Template)]
#[template(path = "managed_host_show.html")]
struct ManagedHostShow {
    active: Vec<ManagedHostRowDisplay>,
    maintenance: Vec<ManagedHostRowDisplay>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct ManagedHostRowDisplay {
    machine_id: String,
    state: String,
    time_in_state: String,
    state_reason: String,
    is_network_healthy: bool,
    network_err_message: String,
    host_admin_ip: String,
    host_admin_mac: String,
    host_bmc_ip: String,
    host_bmc_mac: String,
    num_gpus: usize,
    num_ib_ifs: usize,
    host_memory: String,
    is_link_ref: bool, // is maintenance_reference a URL?
    maintenance_reference: String,
    maintenance_start_time: String,
    dpus: Vec<AttachedDpuRowDisplay>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct AttachedDpuRowDisplay {
    machine_id: String,
    bmc_ip: String,
    bmc_mac: String,
    oob_ip: String,
    oob_mac: String,
}

enum DpuProperty {
    MachineId,
    BmcIp,
    BmcMac,
    OobIp,
    OobMac,
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
            DpuProperty::BmcIp => {
                if self.is_network_healthy {
                    self.dpus
                        .iter()
                        .map(|d| {
                            format!(
                                "<a href=\"/admin/explored_endpoint/{}\">{}</a>",
                                d.bmc_ip, d.bmc_ip
                            )
                        })
                        .collect()
                } else {
                    self.dpus.iter().map(|d| d.bmc_ip.clone()).collect()
                }
            }
            DpuProperty::BmcMac => self.dpus.iter().map(|d| d.bmc_mac.clone()).collect(),
            DpuProperty::OobIp => self.dpus.iter().map(|d| d.oob_ip.clone()).collect(),
            DpuProperty::OobMac => self.dpus.iter().map(|d| d.oob_mac.clone()).collect(),
        };
        lines.join("<br/>")
    }
}

impl From<utils::ManagedHostOutput> for ManagedHostRowDisplay {
    fn from(o: utils::ManagedHostOutput) -> Self {
        let maint_ref = o.maintenance_reference.unwrap_or_default();
        ManagedHostRowDisplay {
            machine_id: o.machine_id.unwrap_or(UNKNOWN.to_string()),
            state: o.state,
            time_in_state: o.time_in_state,
            state_reason: o.state_reason,
            is_network_healthy: o.is_network_healthy,
            network_err_message: o.network_err_message.unwrap_or_default(),
            host_bmc_ip: o.host_bmc_ip.unwrap_or_default(),
            host_bmc_mac: o.host_bmc_mac.unwrap_or_default(),
            host_admin_ip: o.host_admin_ip.unwrap_or_default(),
            host_admin_mac: o.host_admin_mac.unwrap_or_default(),
            num_gpus: o.host_gpu_count,
            num_ib_ifs: o.host_ib_ifs_count,
            host_memory: o.host_memory.unwrap_or(UNKNOWN.to_string()),
            is_link_ref: maint_ref.starts_with("http"),
            maintenance_reference: maint_ref,
            maintenance_start_time: o.maintenance_start_time.unwrap_or_default(),
            dpus: o.dpus.into_iter().map_into().collect(),
        }
    }
}

impl From<ManagedHostAttachedDpu> for AttachedDpuRowDisplay {
    fn from(d: ManagedHostAttachedDpu) -> Self {
        Self {
            machine_id: d.machine_id.unwrap_or(UNKNOWN.to_string()),
            bmc_ip: d.bmc_ip.unwrap_or_default(),
            bmc_mac: d.bmc_mac.unwrap_or_default(),
            oob_ip: d.oob_ip.unwrap_or_default(),
            oob_mac: d.oob_mac.unwrap_or_default(),
        }
    }
}

/// List managed hosts
pub async fn show_html<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    state: AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let managed_hosts = match fetch_managed_hosts(state).await {
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
    let mut active = Vec::new();
    let mut maintenance = Vec::new();
    for mo in managed_hosts.into_iter() {
        let m: ManagedHostRowDisplay = mo.into();
        if m.maintenance_reference.is_empty() {
            active.push(m);
        } else {
            maintenance.push(m);
        }
    }
    active.sort_unstable();
    maintenance.sort_unstable();
    let tmpl = ManagedHostShow {
        active,
        maintenance,
    };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_json<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    state: AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let mut managed_hosts = match fetch_managed_hosts(state).await {
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

async fn fetch_managed_hosts<
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> eyre::Result<Vec<utils::ManagedHostOutput>> {
    let request = tonic::Request::new(forgerpc::MachineSearchQuery {
        id: None,
        fqdn: None,
        search_config: Some(forgerpc::MachineSearchConfig {
            include_dpus: true,
            include_history: true,
            include_predicted_host: true,
            only_maintenance: false,
            include_associated_machine_id: true,
            exclude_hosts: false,
        }),
    });
    let all_machines = state
        .find_machines(request)
        .await
        .map(|response| response.into_inner())?
        .machines;

    let managed_host_metadata = ManagedHostMetadata::lookup_from_api(all_machines, state).await;
    let managed_hosts = utils::get_managed_host_output(managed_host_metadata);
    Ok(managed_hosts)
}

#[derive(Template)]
#[template(path = "managed_host_detail.html")]
struct ManagedHostDetail {
    pub hostname: String,
    pub machine_id: String,
    pub state: String,
    pub time_in_state: String,
    pub state_reason: String,
    pub host_serial_number: String,
    pub host_bios_version: String,
    pub host_bmc_ip: String,
    pub host_bmc_mac: String,
    pub host_bmc_version: String,
    pub host_bmc_firmware_version: String,
    pub host_admin_ip: String,
    pub host_admin_mac: String,
    pub host_gpu_count: usize,
    pub host_ib_ifs_count: usize,
    pub host_memory: String,
    pub is_link_ref: bool,
    pub maintenance_reference: String,
    pub maintenance_start_time: String,
    pub host_last_reboot_time: String,
    pub is_network_healthy: bool,
    pub network_err_message: String,

    pub dpus: Vec<ManagedHostAttachedDpuDetail>,
}

struct ManagedHostAttachedDpuDetail {
    pub machine_id: String,
    pub serial_number: String,
    pub bios_version: String,
    pub bmc_ip: String,
    pub bmc_mac: String,
    pub bmc_version: String,
    pub bmc_firmware_version: String,
    pub oob_ip: String,
    pub oob_mac: String,
    pub last_reboot_time: String,
    pub last_observation_time: String,
    pub switch_connections: Vec<DpuSwitchConnectionDetail>,
}

impl ManagedHostAttachedDpuDetail {
    fn switch_connection_details(&self) -> String {
        self.switch_connections
            .clone()
            .into_iter()
            .map(|c| format!("{}/{}/{}", c.dpu_port, c.switch_id, c.switch_port))
            .join(", ")
    }
}

#[derive(Clone)]
struct DpuSwitchConnectionDetail {
    dpu_port: String,
    switch_id: String,
    switch_port: String,
}

impl From<utils::ManagedHostOutput> for ManagedHostDetail {
    fn from(m: utils::ManagedHostOutput) -> Self {
        let maint_ref = m.maintenance_reference.unwrap_or_default();
        Self {
            hostname: m.hostname.unwrap_or(UNKNOWN.to_string()),
            machine_id: m.machine_id.unwrap_or(UNKNOWN.to_string()),
            state: m.state,
            time_in_state: m.time_in_state,
            state_reason: m.state_reason,
            host_serial_number: m.host_serial_number.unwrap_or(UNKNOWN.to_string()),
            host_bios_version: m.host_bios_version.unwrap_or(UNKNOWN.to_string()),
            host_bmc_ip: m.host_bmc_ip.unwrap_or_default(),
            host_bmc_mac: m.host_bmc_mac.unwrap_or_default(),
            host_bmc_version: m.host_bmc_version.unwrap_or(UNKNOWN.to_string()),
            host_bmc_firmware_version: m.host_bmc_firmware_version.unwrap_or(UNKNOWN.to_string()),
            host_admin_ip: m.host_admin_ip.unwrap_or_default(),
            host_admin_mac: m.host_admin_mac.unwrap_or_default(),
            host_gpu_count: m.host_gpu_count,
            host_ib_ifs_count: m.host_ib_ifs_count,
            host_memory: m.host_memory.unwrap_or(UNKNOWN.to_string()),
            is_link_ref: maint_ref.starts_with("http"),
            maintenance_reference: maint_ref,
            maintenance_start_time: m.maintenance_start_time.unwrap_or_default(),
            host_last_reboot_time: m.host_last_reboot_time.unwrap_or(UNKNOWN.to_string()),
            is_network_healthy: m.is_network_healthy,
            network_err_message: m.network_err_message.unwrap_or(UNKNOWN.to_string()),

            dpus: m
                .dpus
                .into_iter()
                .map_into::<ManagedHostAttachedDpuDetail>()
                .collect::<Vec<_>>(),
        }
    }
}

impl From<ManagedHostAttachedDpu> for ManagedHostAttachedDpuDetail {
    fn from(d: ManagedHostAttachedDpu) -> Self {
        Self {
            machine_id: d.machine_id.unwrap_or(UNKNOWN.to_string()),
            serial_number: d.serial_number.unwrap_or(UNKNOWN.to_string()),
            bios_version: d.bios_version.unwrap_or(UNKNOWN.to_string()),
            bmc_ip: d.bmc_ip.unwrap_or(UNKNOWN.to_string()),
            bmc_mac: d.bmc_mac.unwrap_or(UNKNOWN.to_string()),
            bmc_version: d.bmc_version.unwrap_or(UNKNOWN.to_string()),
            bmc_firmware_version: d.bmc_firmware_version.unwrap_or(UNKNOWN.to_string()),
            oob_ip: d.oob_ip.unwrap_or(UNKNOWN.to_string()),
            oob_mac: d.oob_mac.unwrap_or(UNKNOWN.to_string()),
            last_reboot_time: d.last_reboot_time.unwrap_or(UNKNOWN.to_string()),
            last_observation_time: d.last_observation_time.unwrap_or(UNKNOWN.to_string()),
            switch_connections: d
                .switch_connections
                .into_iter()
                .map(DpuSwitchConnectionDetail::from)
                .collect_vec(),
        }
    }
}

impl From<DpuSwitchConnection> for DpuSwitchConnectionDetail {
    fn from(d: DpuSwitchConnection) -> Self {
        Self {
            dpu_port: d.dpu_port.unwrap_or(UNKNOWN.to_string()),
            switch_id: d.switch_id.unwrap_or(UNKNOWN.to_string()),
            switch_port: d.switch_port.unwrap_or(UNKNOWN.to_string()),
        }
    }
}

/// View managed host details
pub async fn detail<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
    AxumPath(machine_id): AxumPath<String>,
) -> Response {
    let request = tonic::Request::new(forgerpc::MachineSearchQuery {
        id: Some(rpc::MachineId {
            id: machine_id.clone(),
        }),
        fqdn: None,
        search_config: Some(forgerpc::MachineSearchConfig {
            include_predicted_host: true,
            include_dpus: true,
            include_associated_machine_id: true,
            ..Default::default()
        }),
    });

    let machine_details = match state
        .find_machines(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(m) => m,
        Err(err) if err.code() == tonic::Code::NotFound => {
            return super::not_found_response(machine_id);
        }
        Err(err) => {
            tracing::error!(%err, %machine_id, "find_machines");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading machines").into_response();
        }
    };

    let Some(host_machine) = machine_details.machines.first() else {
        return super::not_found_response(machine_id);
    };

    let dpu_machines = state
        .find_machines_by_ids(tonic::Request::new(forgerpc::MachineIdList {
            machine_ids: host_machine.associated_dpu_machine_ids.clone(),
        }))
        .await
        .map(|r| r.into_inner().machines)
        .inspect_err(|e| {
            tracing::error!(
                            %machine_id, %e, "finding associated DPU machines, skipping"
            )
        })
        .unwrap_or_default();
    let machines: Vec<rpc::Machine> = [vec![host_machine.clone()], dpu_machines].concat();

    let managed_host_metadata = ManagedHostMetadata::lookup_from_api(machines, state).await;
    let managed_host = utils::get_managed_host_output(managed_host_metadata)
        .into_iter()
        .next()
        .unwrap(); // safe, there's definitely one machine

    let tmpl: ManagedHostDetail = managed_host.into();
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

#[derive(Deserialize, Debug)]
pub struct MaintenanceAction {
    action: String,
    reference: Option<String>,
}

/// Enter / Exit maintenance mode
pub async fn maintenance<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
    AxumPath(machine_id): AxumPath<String>,
    Form(form): Form<MaintenanceAction>,
) -> impl IntoResponse {
    let view_url = format!("/admin/managed-host/{machine_id}");

    let req = if form.action == "enter" {
        forgerpc::MaintenanceRequest {
            operation: forgerpc::MaintenanceOperation::Enable.into(),
            host_id: Some(machine_id.clone().into()),
            reference: form.reference,
        }
    } else if form.action == "exit" {
        forgerpc::MaintenanceRequest {
            operation: forgerpc::MaintenanceOperation::Disable.into(),
            host_id: Some(machine_id.clone().into()),
            reference: None,
        }
    } else {
        tracing::error!("Expected action to be 'enter' or 'exit' but got neither");
        return Redirect::to(&view_url);
    };
    if let Err(err) = state
        .set_maintenance(tonic::Request::new(req))
        .await
        .map(|response| response.into_inner())
    {
        tracing::error!(%err, machine_id, "set_maintenance");
        return Redirect::to(&view_url);
    }

    Redirect::to(&view_url)
}
