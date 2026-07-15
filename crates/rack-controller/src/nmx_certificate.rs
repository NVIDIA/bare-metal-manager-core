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

//! Switch certificate configuration for NMX cluster maintenance via Component Manager.

use std::net::IpAddr;
use std::str::FromStr;
use std::sync::Arc;

use carbide_secrets::credentials::Credentials;
use carbide_utils::none_if_empty::NoneIfEmpty;
use carbide_uuid::switch::SwitchId;
use component_manager::component_manager::ComponentManager;
use component_manager::nv_switch_manager::SwitchEndpoint;
use mac_address::MacAddress;
use model::component_manager::ConfigureSwitchCertificateState;
use model::rack::{FirmwareUpgradeDeviceInfo, SwitchConfigureCertificateJob};

pub fn switch_endpoint_from_firmware_device(
    device: &FirmwareUpgradeDeviceInfo,
) -> Result<SwitchEndpoint, String> {
    let bmc_mac = MacAddress::from_str(&device.mac)
        .map_err(|error| format!("switch {} has invalid BMC MAC: {error}", device.node_id))?;
    let bmc_ip = IpAddr::from_str(&device.bmc_ip)
        .map_err(|error| format!("switch {} has invalid BMC IP: {error}", device.node_id))?;
    let nvos_mac = MacAddress::from_str(device.os_mac.as_deref().unwrap_or_default())
        .map_err(|error| format!("switch {} has invalid NVOS MAC: {error}", device.node_id))?;
    let nvos_ip = IpAddr::from_str(device.os_ip.as_deref().unwrap_or_default())
        .map_err(|error| format!("switch {} has invalid NVOS IP: {error}", device.node_id))?;

    let bmc_credentials = Credentials::UsernamePassword {
        username: device.bmc_username.clone(),
        password: device.bmc_password.clone(),
    };
    let nvos_credentials = Credentials::UsernamePassword {
        username: device
            .os_username
            .clone()
            .unwrap_or_else(|| device.bmc_username.clone()),
        password: device
            .os_password
            .clone()
            .unwrap_or_else(|| device.bmc_password.clone()),
    };

    Ok(SwitchEndpoint {
        bmc_ip,
        bmc_mac,
        nvos_ip,
        nvos_mac,
        bmc_credentials,
        nvos_credentials,
        nvos_host_name: device.os_hostname.clone().none_if_empty(),
    })
}

pub async fn start_configure_nmx_cluster_certificate(
    component_manager: &Arc<ComponentManager>,
    primary_switch: &FirmwareUpgradeDeviceInfo,
    domain_name: Option<&str>,
    switch_mtls_services: &[i32],
) -> Result<SwitchConfigureCertificateJob, String> {
    let switch_id = SwitchId::from_str(&primary_switch.node_id)
        .map_err(|error| format!("switch {} has invalid id: {error}", primary_switch.node_id))?;
    let endpoint = switch_endpoint_from_firmware_device(primary_switch)?;
    let job_id = component_manager
        .configure_switch_certificate(&endpoint, domain_name, Some(switch_mtls_services))
        .await
        .map_err(|error| {
            format!(
                "failed to start switch certificate configuration for {}: {error}",
                primary_switch.node_id
            )
        })?;

    tracing::info!(
        switch_id = %switch_id,
        %job_id,
        "Started NMX cluster primary switch certificate configuration"
    );
    Ok(SwitchConfigureCertificateJob { switch_id, job_id })
}

pub enum ConfigureNmxClusterCertificatePollOutcome {
    Completed,
    Failed(String),
    InProgress,
}

pub async fn poll_configure_nmx_cluster_certificate_jobs(
    component_manager: &Arc<ComponentManager>,
    jobs: &[SwitchConfigureCertificateJob],
) -> Result<ConfigureNmxClusterCertificatePollOutcome, String> {
    let mut in_progress = false;

    for job in jobs {
        let status = component_manager
            .get_configure_switch_certificate_job_status(&job.job_id)
            .await
            .map_err(|error| {
                format!(
                    "failed to get switch certificate job status for switch {} job {}: {error}",
                    job.switch_id, job.job_id
                )
            })?;

        match status.state {
            ConfigureSwitchCertificateState::Completed => {}
            ConfigureSwitchCertificateState::Failed => {
                let cause = status.error.unwrap_or_else(|| {
                    format!(
                        "switch certificate configuration failed for switch {}",
                        job.switch_id
                    )
                });
                return Ok(ConfigureNmxClusterCertificatePollOutcome::Failed(cause));
            }
            ConfigureSwitchCertificateState::Started
            | ConfigureSwitchCertificateState::InProgress => {
                in_progress = true;
            }
        }
    }

    if in_progress {
        Ok(ConfigureNmxClusterCertificatePollOutcome::InProgress)
    } else {
        Ok(ConfigureNmxClusterCertificatePollOutcome::Completed)
    }
}
