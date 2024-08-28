use rpc::{forge::ForgeAgentControlResponse, forge_agent_control_response::Action};

use crate::{api_client, config::MachineATronContext};

use crate::api_client::ClientApiError;
use crate::host_machine::HostMachineActor;
use crate::machine_state_machine::AddressConfigError;
use lazy_static::lazy_static;
use reqwest::{ClientBuilder, StatusCode};
use rpc::forge::MachineArchitecture;
use std::collections::HashSet;
use tempfile::TempDir;
use uuid::Uuid;

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
    machine_id: rpc::common::MachineId,
) -> ForgeAgentControlResponse {
    api_client::forge_agent_control(app_context, machine_id)
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
    interface_id: rpc::Uuid,
    forward_ip: Option<String>,
) -> Result<PxeResponse, PxeError> {
    let pxe_script: String =
        if app_context.app_config.use_pxe_api {
            let response =
                api_client::get_pxe_instructions(app_context, arch, interface_id).await?;
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
    machine_actors: &Vec<HostMachineActor>,
    assigned_mat_ids: &HashSet<Uuid>,
) -> Option<HostMachineActor> {
    for machine in machine_actors {
        if assigned_mat_ids.contains(&machine.mat_id) {
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
    sudo_command: &Option<String>,
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
    let wrapper_cmd = sudo_command
        .as_ref()
        .map(|s| s.to_string())
        .unwrap_or("/usr/bin/env".to_string());
    let mut cmd = tokio::process::Command::new(&wrapper_cmd);
    let output = cmd
        .args(["ip", "a", "add", address, "dev", interface])
        .output()
        .await
        .map_err(AddressConfigError::IoError)?;

    if !output.status.success() {
        return Err(AddressConfigError::CommandFailure(cmd, output));
    }

    Ok(())
}

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
        .await
        .map_err(AddressConfigError::IoError)?;

    if !output.status.success() {
        return Err(AddressConfigError::CommandFailure(cmd, output));
    }
    if output.stdout.is_empty() {
        Ok(false)
    } else {
        Ok(true)
    }
}
