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
#[template(path = "instance_show.html")]
struct InstanceShow {
    instances: Vec<InstanceDisplay>,
}

struct InstanceDisplay {
    id: String,
    machine_id: String,
    tenant_org: String,
    tenant_state: String,
    configs_synced: String,
    ip_addresses: String,
    num_eth_ifs: usize,
    num_ib_ifs: usize,
    num_keysets: usize,
}

impl From<forgerpc::Instance> for InstanceDisplay {
    fn from(instance: forgerpc::Instance) -> Self {
        let tenant_org = instance
            .config
            .as_ref()
            .and_then(|config| config.tenant.as_ref())
            .map(|tenant| tenant.tenant_organization_id.clone())
            .unwrap_or_default();

        let tenant_state = instance
            .status
            .as_ref()
            .and_then(|status| status.tenant.as_ref())
            .and_then(|tenant| forgerpc::TenantState::try_from(tenant.state).ok())
            .map(|state| format!("{:?}", state))
            .unwrap_or_default();

        let configs_synced = instance
            .status
            .as_ref()
            .and_then(|status| forgerpc::SyncState::try_from(status.configs_synced).ok())
            .map(|state| format!("{:?}", state))
            .unwrap_or_default();

        let instance_addresses: Vec<&str> = instance
            .status
            .as_ref()
            .and_then(|status| status.network.as_ref())
            .map(|network| network.interfaces.as_slice())
            .unwrap_or_default()
            .iter()
            .filter(|x| x.virtual_function_id.is_none())
            .flat_map(|status| status.addresses.iter().map(|addr| addr.as_str()))
            .collect();

        let num_eth_ifs = instance
            .config
            .as_ref()
            .and_then(|config| config.network.as_ref())
            .map(|network| network.interfaces.len())
            .unwrap_or_default();
        let num_ib_ifs = instance
            .config
            .as_ref()
            .and_then(|config| config.infiniband.as_ref())
            .map(|ib| ib.ib_interfaces.len())
            .unwrap_or_default();
        let num_keysets = instance
            .config
            .as_ref()
            .and_then(|config| config.tenant.as_ref())
            .map(|tenant: &rpc::TenantConfig| tenant.tenant_keyset_ids.len())
            .unwrap_or_default();

        Self {
            id: instance.id.unwrap_or_default().to_string(),
            machine_id: instance
                .machine_id
                .unwrap_or_else(super::invalid_machine_id)
                .to_string(),
            tenant_org,
            tenant_state,
            configs_synced,
            ip_addresses: instance_addresses.join(","),
            num_eth_ifs,
            num_ib_ifs,
            num_keysets,
        }
    }
}

/// List instances
pub async fn show_html<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let out = match fetch_instances(state).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "fetch_instances");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading instances").into_response();
        }
    };

    let mut instances: Vec<InstanceDisplay> = Vec::new();
    for rp in out.instances.into_iter() {
        instances.push(rp.into());
    }
    let tmpl = InstanceShow { instances };
    (StatusCode::OK, Html(tmpl.render().unwrap())).into_response()
}

pub async fn show_json<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
) -> Response {
    let out = match fetch_instances(state).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "fetch_instances");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading instances").into_response();
        }
    };
    (StatusCode::OK, Json(out)).into_response()
}

async fn fetch_instances<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    api: Arc<Api<C1, C2>>,
) -> Result<forgerpc::InstanceList, tonic::Status> {
    let request = tonic::Request::new(forgerpc::InstanceSearchQuery {
        id: None,
        label: None,
    });
    api.find_instances(request)
        .await
        .map(|response| response.into_inner())
}

#[derive(Template)]
#[template(path = "instance_detail.html")]
struct InstanceDetail {
    id: String,
    machine_id: String,
    tenant_org: String,
    tenant_state: String,
    tenant_state_details: String,
    configs_synced: String,
    network_config_synced: String,
    network_config_version: String,
    config_version: String,
    interfaces: Vec<InstanceInterface>,
    ib_interfaces: Vec<InstanceIbInterface>,
    os: InstanceOs,
    keysets: Vec<String>,
}

#[derive(Default)]
struct InstanceOs {
    ipxe_script: String,
    userdata: String,
    always_boot_with_ipxe: bool,
    phone_home_enabled: bool,
}

struct InstanceInterface {
    function_type: String,
    vf_id: String,
    segment_id: String,
    mac_address: String,
    addresses: String,
}

struct InstanceIbInterface {
    device: String,
    vendor: String,
    device_instance: u32,
    function_type: String,
    vf_id: String,
    ib_partition_id: String,

    pf_guid: String,
    guid: String,
    lid: u32,
}

impl From<forgerpc::Instance> for InstanceDetail {
    fn from(instance: forgerpc::Instance) -> Self {
        let mut interfaces = Vec::new();
        let if_configs = instance
            .config
            .as_ref()
            .and_then(|config| config.network.as_ref())
            .map(|config| config.interfaces.as_slice())
            .unwrap_or_default();
        let if_status = instance
            .status
            .as_ref()
            .and_then(|status| status.network.as_ref())
            .map(|status| status.interfaces.as_slice())
            .unwrap_or_default();
        if if_configs.len() == if_status.len() {
            for (i, interface) in if_configs.iter().enumerate() {
                let status = &if_status[i];
                interfaces.push(InstanceInterface {
                    function_type: forgerpc::InterfaceFunctionType::try_from(
                        interface.function_type,
                    )
                    .ok()
                    .map(|ty| format!("{:?}", ty))
                    .unwrap_or_else(|| "INVALID".to_string()),
                    vf_id: status
                        .virtual_function_id
                        .map(|id| id.to_string())
                        .unwrap_or_default(),
                    segment_id: interface
                        .network_segment_id
                        .clone()
                        .unwrap_or_else(super::default_uuid)
                        .to_string(),
                    mac_address: status.mac_address.clone().unwrap_or_default(),
                    addresses: status.addresses.clone().join(", "),
                });
            }
        }

        let mut ib_interfaces = Vec::new();
        let ib_if_configs = instance
            .config
            .as_ref()
            .and_then(|config| config.infiniband.as_ref())
            .map(|config| config.ib_interfaces.as_slice())
            .unwrap_or_default();
        let ib_if_status = instance
            .status
            .as_ref()
            .and_then(|status| status.infiniband.as_ref())
            .map(|status: &rpc::InstanceInfinibandStatus| status.ib_interfaces.as_slice())
            .unwrap_or_default();
        if ib_if_configs.len() == ib_if_status.len() {
            for (i, config) in ib_if_configs.iter().enumerate() {
                let status = &ib_if_status[i];
                ib_interfaces.push(InstanceIbInterface {
                    device: config.device.clone(),
                    vendor: config.vendor.clone().unwrap_or_default(),
                    device_instance: config.device_instance,
                    function_type: forgerpc::InterfaceFunctionType::try_from(config.function_type)
                        .ok()
                        .map(|ty| format!("{:?}", ty))
                        .unwrap_or_else(|| "INVALID".to_string()),
                    vf_id: config
                        .virtual_function_id
                        .map(|id| id.to_string())
                        .unwrap_or_default(),
                    ib_partition_id: config
                        .ib_partition_id
                        .as_ref()
                        .map(|id| id.to_string())
                        .unwrap_or_default(),
                    pf_guid: status.pf_guid.clone().unwrap_or_default(),
                    guid: status.guid.clone().unwrap_or_default(),
                    lid: status.lid,
                })
            }
        }

        let os = instance
            .config
            .as_ref()
            .and_then(|config| config.os.as_ref())
            .map(|os| match &os.variant {
                Some(os_variant) => match os_variant {
                    forgerpc::operating_system::Variant::Ipxe(ipxe) => InstanceOs {
                        ipxe_script: ipxe.ipxe_script.clone(),
                        userdata: ipxe.user_data.clone().unwrap_or_default(),
                        always_boot_with_ipxe: ipxe.always_boot_with_ipxe,
                        phone_home_enabled: os.phone_home_enabled,
                    },
                },
                None => InstanceOs::default(),
            })
            .unwrap_or_default();

        let keysets = instance
            .config
            .as_ref()
            .and_then(|config| config.tenant.as_ref())
            .map(|tenant| tenant.tenant_keyset_ids.clone())
            .unwrap_or_default();

        Self {
            id: instance.id.clone().unwrap_or_default().value,
            machine_id: instance.machine_id.clone().unwrap_or_default().id,
            tenant_org: instance
                .config
                .as_ref()
                .and_then(|config| config.tenant.as_ref())
                .map(|tenant| tenant.tenant_organization_id.clone())
                .unwrap_or_default(),
            tenant_state: instance
                .status
                .as_ref()
                .and_then(|status| status.tenant.as_ref())
                .and_then(|tenant| forgerpc::TenantState::try_from(tenant.state).ok())
                .map(|state| format!("{:?}", state))
                .unwrap_or_default(),
            tenant_state_details: instance
                .status
                .as_ref()
                .and_then(|status| status.tenant.as_ref())
                .map(|tenant| tenant.state_details.clone())
                .unwrap_or_default(),
            configs_synced: instance
                .status
                .as_ref()
                .and_then(|status| forgerpc::SyncState::try_from(status.configs_synced).ok())
                .map(|state| format!("{:?}", state))
                .unwrap_or_default(),
            network_config_synced: instance
                .status
                .as_ref()
                .and_then(|status| status.network.as_ref())
                .and_then(|status| forgerpc::SyncState::try_from(status.configs_synced).ok())
                .map(|state| format!("{:?}", state))
                .unwrap_or_default(),
            network_config_version: instance.network_config_version,
            config_version: instance.config_version,
            os,
            interfaces,
            ib_interfaces,
            keysets,
        }
    }
}

/// View instance
pub async fn detail<C1: CredentialProvider + 'static, C2: CertificateProvider + 'static>(
    AxumState(state): AxumState<Arc<Api<C1, C2>>>,
    AxumPath(instance_id): AxumPath<String>,
) -> Response {
    let request = tonic::Request::new(forgerpc::InstanceSearchQuery {
        id: Some(rpc::Uuid {
            value: instance_id.clone(),
        }),
        label: None,
    });
    let mut instances = match state
        .find_instances(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(x) => x,
        Err(err) if err.code() == tonic::Code::NotFound => {
            return super::not_found_response(instance_id);
        }
        Err(err) => {
            tracing::error!(%err, %instance_id, "find_instances");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading instances").into_response();
        }
    };
    if instances.instances.len() != 1 {
        tracing::error!(%instance_id, "Expected exactly 1 match, found {}", instances.instances.len());
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not find exactly one matching instance",
        )
            .into_response();
    }

    let instance = instances.instances.pop().unwrap(); // safe, we checked above
    let display: InstanceDetail = instance.into();
    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}
