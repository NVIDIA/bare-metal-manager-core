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
use std::collections::HashSet;
use std::path::Path;

use carbide_uuid::machine::MachineId;
use carbide_uuid::machine_validation::MachineValidationId;
use lazy_static::lazy_static;
use rpc::forge::{ForgeAgentControlResponse, MachineArchitecture};
use tempfile::TempDir;
use uuid::Uuid;

use crate::api_client::ClientApiError;
use crate::config::MachineATronContext;
use crate::host_machine::HostMachineHandle;
use crate::machine_state_machine::AddressConfigError;

lazy_static! {
    static ref BMC_MOCK_SOCKET_TEMP_DIR: TempDir = tempfile::Builder::new()
        .prefix("bmc-mock")
        .tempdir()
        .unwrap();
}

#[derive(Debug, Clone)]
pub enum PxeResponse {
    Exit,
    Scout,    // PXE script is booting scout.efi
    DpuAgent, // PXE script is booting carbide.efi
}

#[derive(thiserror::Error, Debug)]
pub enum PxeError {
    #[error("API Client error running PXE request: {0}")]
    ClientApi(#[from] ClientApiError),
    #[error("PXE Request failed with status: {0}")]
    PxeRequest(#[from] tonic::Status),
    #[error("Error sending PXE request: {0}")]
    Reqwest(#[from] reqwest::Error),
}

pub async fn forge_agent_control(
    app_context: &MachineATronContext,
    machine_id: MachineId,
) -> Option<ForgeAgentControlResponse> {
    match app_context
        .forge_api_client
        .forge_agent_control(machine_id)
        .await
    {
        Ok(response) => Some(response),
        Err(e) => {
            if e.code() == tonic::Code::NotFound {
                return None;
            }
            tracing::warn!("Error getting control action: {e}");
            Some(ForgeAgentControlResponse::noop())
        }
    }
}

pub fn get_validation_id(response: &ForgeAgentControlResponse) -> Option<MachineValidationId> {
    if let Some(rpc::forge::forge_agent_control_response::Action::MachineValidation(
        machine_validation,
    )) = &response.action
    {
        machine_validation.validation_id
    } else {
        None
    }
}

pub async fn send_pxe_boot_request(
    app_context: &MachineATronContext,
    arch: MachineArchitecture,
    client_ip: std::net::IpAddr,
    product: Option<String>,
) -> Result<PxeResponse, PxeError> {
    let pxe_script = app_context
        .forge_api_client
        .get_pxe_instructions(rpc::forge::PxeInstructionRequest {
            arch: arch.into(),
            product,
            client_ip: Some(client_ip.to_string()),
            ..Default::default()
        })
        .await?
        .pxe_script;
    tracing::info!("PXE Request successful");

    let response = if pxe_script.contains("exit") {
        tracing::info!("PXE Request is EXIT");
        PxeResponse::Exit
    } else if let Some(kernel_url) = pxe_script
        .lines()
        .find(|l| l.starts_with("kernel"))
        .and_then(|l| l.split(" ").nth(1))
    {
        if kernel_url.ends_with("/carbide.efi") {
            PxeResponse::DpuAgent
        } else if kernel_url.ends_with("/scout.efi") {
            PxeResponse::Scout
        } else {
            tracing::error!(
                "Could not determine what to do with kernel URL returned by PXE script, will treat as 'exit': {}",
                pxe_script
            );
            PxeResponse::Exit
        }
    } else {
        tracing::error!(
            "Could not determine what to do with PXE script (no kernel line, no exit line), will treat as 'exit': {}",
            pxe_script
        );
        PxeResponse::Exit
    };

    Ok(response)
}

pub async fn get_next_free_machine(
    machine_handles: &Vec<HostMachineHandle>,
    assigned_mat_ids: &HashSet<Uuid>,
) -> Option<HostMachineHandle> {
    for machine in machine_handles {
        if assigned_mat_ids.contains(&machine.mat_id()) {
            continue;
        }
        let state = machine.api_state().await.ok()?;
        if state == "Ready" {
            return Some(machine.clone());
        }
    }
    None
}

pub async fn add_address_to_interface(
    address: &str,
    interface: &str,
) -> Result<(), AddressConfigError> {
    if interface_has_address(interface, address).await? {
        tracing::info!(
            "Skipping adding address {} to interface {}, as it is already configured.",
            address,
            interface
        );
        return Ok(());
    }

    tracing::info!("Adding address {} to interface {}", address, interface);
    let wrapper_cmd = find_sudo_command();
    let mut cmd = tokio::process::Command::new(wrapper_cmd);
    #[cfg(not(target_os = "macos"))]
    let output = cmd
        .args(["ip", "a", "add", address, "dev", interface])
        .output()
        .await?;
    #[cfg(target_os = "macos")]
    let output = cmd
        .args([
            // Prevent sudo from trying to read password.
            "--non-interactive",
            "ifconfig",
            interface,
            "add",
            address,
            "up",
        ])
        .output()
        .await?;

    if !output.status.success() {
        return Err(AddressConfigError::CommandFailure(Box::new(cmd), output));
    }

    Ok(())
}
#[cfg(target_os = "macos")]
async fn interface_has_address(
    _interface: &str,
    _address: &str,
) -> Result<bool, AddressConfigError> {
    Ok(false)
}

#[cfg(not(target_os = "macos"))]
async fn interface_has_address(interface: &str, address: &str) -> Result<bool, AddressConfigError> {
    let mut cmd = tokio::process::Command::new("/usr/bin/env");

    let output = cmd
        .args([
            "ip",
            "a",
            "s",
            "to",
            &[address, "32"].join("/"),
            "dev",
            interface,
        ])
        .output()
        .await?;

    if !output.status.success() {
        return Err(AddressConfigError::CommandFailure(Box::new(cmd), output));
    }
    if output.stdout.is_empty() {
        Ok(false)
    } else {
        Ok(true)
    }
}

fn find_sudo_command() -> &'static str {
    std::env::var("PATH")
        .ok()
        .and_then(|path| {
            path.split(":").find_map(|dir| {
                if std::fs::exists(Path::new(dir).join("sudo")).unwrap_or(false) {
                    Some("sudo")
                } else if std::fs::exists(Path::new(dir).join("doas")).unwrap_or(false) {
                    Some("doas")
                } else {
                    None
                }
            })
        })
        .unwrap_or_else(|| {
            tracing::warn!("could not find sudo or doas in PATH, falling back on /usr/bin/env");
            "/usr/bin/env"
        })
}
