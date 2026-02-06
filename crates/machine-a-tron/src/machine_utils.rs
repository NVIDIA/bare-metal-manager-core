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

use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use lazy_static::lazy_static;
use rcgen::{CertifiedKey, generate_simple_self_signed};
use reqwest::{ClientBuilder, StatusCode};
use rpc::forge::{ForgeAgentControlResponse, MachineArchitecture};
use rpc::forge_agent_control_response::Action;
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
    PxeRequest(StatusCode),
    #[error("Error sending PXE request: {0}")]
    Reqwest(#[from] reqwest::Error),
}

pub async fn forge_agent_control(
    app_context: &MachineATronContext,
    machine_id: MachineId,
) -> ForgeAgentControlResponse {
    app_context
        .forge_api_client
        .forge_agent_control(machine_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Error getting control action: {e}");
            ForgeAgentControlResponse {
                action: Action::Noop as i32,
                data: None,
            }
        })
}

pub fn get_fac_action(
    response: &ForgeAgentControlResponse,
) -> rpc::forge::forge_agent_control_response::Action {
    rpc::forge::forge_agent_control_response::Action::try_from(response.action).unwrap()
}

pub fn get_validation_id(response: &ForgeAgentControlResponse) -> Option<rpc::common::Uuid> {
    response.data.as_ref().and_then(|d| {
        d.pair.iter().find_map(|pair| {
            if pair.key.eq("ValidationId") {
                Some(rpc::common::Uuid {
                    value: pair.value.clone(),
                })
            } else {
                None
            }
        })
    })
}

pub async fn send_pxe_boot_request(
    app_context: &MachineATronContext,
    arch: MachineArchitecture,
    interface_id: MachineInterfaceId,
    product: Option<String>,
    forward_ip: Option<String>,
) -> Result<PxeResponse, PxeError> {
    let pxe_script: String =
        if app_context.app_config.use_pxe_api {
            let response = app_context
                .api_client()
                .get_pxe_instructions(arch, interface_id, product)
                .await?;
            tracing::info!("PXE Request successful");
            response.pxe_script
        } else {
            let url =
                format!(
                    "http://{}:{}/api/v0/pxe/boot?uuid={}&buildarch={}",
                    app_context.app_config.pxe_server_host.as_ref().expect(
                        "Config error: use_pxe_api is false but pxe_server_host is not set"
                    ),
                    app_context.app_config.pxe_server_port.as_ref().expect(
                        "Config error: use_pxe_api is false but pxe_server_port is not set"
                    ),
                    interface_id,
                    match arch {
                        MachineArchitecture::X86 => "x86_64",
                        MachineArchitecture::Arm => "arm64",
                    }
                );

            let mut request = ClientBuilder::new().build().unwrap().get(&url);
            if let Some(forward_ip) = forward_ip {
                request = request.header("X-Forwarded-For", forward_ip);
            }

            let response = request.send().await?;
            if !response.status().is_success() {
                tracing::error!("Request failed with status: {}", response.status());
                return Err(PxeError::PxeRequest(response.status()));
            }
            tracing::info!("PXE Request successful with status: {}", response.status());
            response.text().await.unwrap()
        };

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

pub fn create_random_self_signed_cert() -> Vec<u8> {
    let subject_alt_names = vec!["hello.world.example".to_string(), "localhost".to_string()];

    let CertifiedKey { cert, .. } = generate_simple_self_signed(subject_alt_names).expect(
        "BUG: Keypair generation should not fail, subject alt names are static and must be valid",
    );

    cert.der().to_vec()
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
