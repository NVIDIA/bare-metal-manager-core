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
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use forge_secrets::certificates::CertificateProvider;
use forge_secrets::credentials::CredentialProvider;
use http::StatusCode;
use rpc::forge::forge_server::Forge;
use rpc::forge::{self as forgerpc, GetSiteExplorationRequest};
use serde::Deserialize;

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
    hostname: String,
    machine_id: String,
    dpu_machine_id: String,
    state: String,
    is_network_healthy: bool,
    network_err_message: String,
    dpu_bmc_ip: String,
    dpu_bmc_mac: String,
    dpu_oob_ip: String,
    dpu_oob_mac: String,
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
}

impl From<utils::ManagedHostOutput> for ManagedHostRowDisplay {
    fn from(o: utils::ManagedHostOutput) -> Self {
        let maint_ref = o.maintenance_reference.unwrap_or_default();
        ManagedHostRowDisplay {
            hostname: o.hostname.unwrap_or(UNKNOWN.to_string()),
            machine_id: o.machine_id.unwrap_or(UNKNOWN.to_string()),
            dpu_machine_id: o.dpu_machine_id.unwrap_or(UNKNOWN.to_string()),
            state: o.state,
            is_network_healthy: o.is_network_healthy,
            network_err_message: o.network_err_message.unwrap_or_default(),
            dpu_bmc_ip: o.dpu_bmc_ip.unwrap_or_default(),
            dpu_bmc_mac: o.dpu_bmc_mac.unwrap_or_default(),
            dpu_oob_ip: o.dpu_oob_ip.unwrap_or_default(),
            dpu_oob_mac: o.dpu_oob_mac.unwrap_or_default(),
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
    managed_hosts.sort_unstable_by(|h1, h2| h1.hostname.cmp(&h2.hostname));
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
        .map(|response| response.into_inner())?;

    let request = tonic::Request::new(GetSiteExplorationRequest {});
    let site_managed_hosts = state
        .get_site_exploration_report(request)
        .await
        .map(|response| response.into_inner())?
        .managed_hosts;

    Ok(utils::get_managed_host_output(
        all_machines.machines,
        site_managed_hosts,
    ))
}

#[derive(Template)]
#[template(path = "managed_host_detail.html")]
struct ManagedHostDetail {
    pub hostname: String,
    pub machine_id: String,
    pub state: String,
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

    pub dpu_machine_id: String,
    pub dpu_serial_number: String,
    pub dpu_bios_version: String,
    pub dpu_bmc_ip: String,
    pub dpu_bmc_mac: String,
    pub dpu_bmc_version: String,
    pub dpu_bmc_firmware_version: String,
    pub dpu_oob_ip: String,
    pub dpu_oob_mac: String,
    pub dpu_last_reboot_time: String,
    pub dpu_last_observation_time: String,
}

impl From<utils::ManagedHostOutput> for ManagedHostDetail {
    fn from(m: utils::ManagedHostOutput) -> Self {
        let maint_ref = m.maintenance_reference.unwrap_or_default();
        Self {
            hostname: m.hostname.unwrap_or(UNKNOWN.to_string()),
            machine_id: m.machine_id.unwrap_or(UNKNOWN.to_string()),
            state: m.state,
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

            dpu_machine_id: m.dpu_machine_id.unwrap_or(UNKNOWN.to_string()),
            dpu_serial_number: m.dpu_serial_number.unwrap_or(UNKNOWN.to_string()),
            dpu_bios_version: m.dpu_bios_version.unwrap_or(UNKNOWN.to_string()),
            dpu_bmc_ip: m.dpu_bmc_ip.unwrap_or_default(),
            dpu_bmc_mac: m.dpu_bmc_mac.unwrap_or_default(),
            dpu_bmc_version: m.dpu_bmc_version.unwrap_or(UNKNOWN.to_string()),
            dpu_bmc_firmware_version: m.dpu_bmc_firmware_version.unwrap_or(UNKNOWN.to_string()),
            dpu_oob_ip: m.dpu_oob_ip.unwrap_or_default(),
            dpu_oob_mac: m.dpu_oob_mac.unwrap_or_default(),
            dpu_last_reboot_time: m.dpu_last_reboot_time.unwrap_or(UNKNOWN.to_string()),
            dpu_last_observation_time: m.dpu_last_observation_time.unwrap_or(UNKNOWN.to_string()),
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
            return (StatusCode::NOT_FOUND, Html(machine_id.to_string())).into_response();
        }
        Err(err) => {
            tracing::error!(%err, %machine_id, "find_machines");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading machines").into_response();
        }
    };
    let Some(host_machine) = machine_details.machines.first() else {
        return (StatusCode::NOT_FOUND, "Machine not found").into_response();
    };

    let mut machines = vec![];
    for interface in host_machine.interfaces.iter() {
        if interface.primary_interface {
            if let Some(attached_machine_id) = interface.attached_dpu_machine_id.as_ref() {
                match get_dpu_machine(state.clone(), attached_machine_id).await {
                    Ok(attached_machine) => machines.push(attached_machine),
                    Err(err) => {
                        tracing::error!(%attached_machine_id, %err, "get_dpu_machine, skipping");
                    }
                }
            }
            break;
        }
    }
    machines.push(host_machine.clone());
    let request = tonic::Request::new(GetSiteExplorationRequest {});
    let site_managed_hosts = state
        .get_site_exploration_report(request)
        .await
        .map(|response| response.into_inner().managed_hosts)
        .unwrap_or(vec![]);

    let managed_host = utils::get_managed_host_output(machines, site_managed_hosts)
        .into_iter()
        .next()
        .unwrap(); // safe, there's definitely one machine

    let tmpl: ManagedHostDetail = managed_host.into();
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

async fn get_dpu_machine<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    state: Arc<Api<C1, C2>>,
    host_machine_id: &forgerpc::MachineId,
) -> eyre::Result<forgerpc::Machine> {
    let request = tonic::Request::new(forgerpc::MachineSearchQuery {
        id: Some(host_machine_id.clone()),
        fqdn: None,
        search_config: Some(forgerpc::MachineSearchConfig {
            include_dpus: true,
            ..Default::default()
        }),
    });

    let machine_details = state
        .find_machines(request)
        .await
        .map(|response| response.into_inner())?;

    let Some(machine) = machine_details.machines.into_iter().next() else {
        return Err(eyre::eyre!("Machine not found: {host_machine_id}"));
    };

    if machine.machine_type() == forgerpc::MachineType::Dpu {
        Ok(machine)
    } else {
        Err(eyre::eyre!("Unexpected machine type"))
    }
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
