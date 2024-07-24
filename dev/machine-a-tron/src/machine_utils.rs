use rpc::{forge::ForgeAgentControlResponse, forge_agent_control_response::Action};

use crate::{api_client, config::MachineATronContext};

use crate::machine_state_machine::AddressConfigError;
use lazy_static::lazy_static;
use reqwest::ClientBuilder;
use rpc::forge::MachineArchitecture;
use tempfile::TempDir;

lazy_static! {
    static ref BMC_MOCK_SOCKET_TEMP_DIR: TempDir = tempfile::Builder::new()
        .prefix("bmc-mock")
        .tempdir()
        .unwrap();
}

pub enum PXEresponse {
    Exit,
    Efi,
    Error,
}

pub enum MockMachineType {
    Host,
    Dpu,
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
) -> PXEresponse {
    if app_context.app_config.use_pxe_api {
        let Ok(response) = api_client::get_pxe_instructions(app_context, arch, interface_id)
            .await
            .inspect_err(|e| {
                tracing::error!("PXE Request failed: {}", e);
            })
        else {
            return PXEresponse::Error;
        };

        tracing::info!("PXE Request successful");

        if response.pxe_script.contains("exit") {
            tracing::info!("PXE Request is EXIT");
            PXEresponse::Exit
        } else {
            tracing::info!("PXE Request is EFI");
            PXEresponse::Efi
        }
    } else {
        let url = format!(
            "http://{}:{}/api/v0/pxe/boot?uuid={}&buildarch={}",
            app_context
                .app_config
                .pxe_server_host
                .as_ref()
                .expect("Config error: use_pxe_api is false but pxe_server_host is not set"),
            app_context
                .app_config
                .pxe_server_port
                .as_ref()
                .expect("Config error: use_pxe_api is false but pxe_server_port is not set"),
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
        let response = request.send().await;

        match response {
            Ok(res) => {
                if res.status().is_success() {
                    tracing::info!("PXE Request successful with status: {}", res.status());

                    let result = res.text().await.unwrap();
                    if result.contains("exit") {
                        tracing::info!("PXE Request is EXIT");
                        PXEresponse::Exit
                    } else {
                        tracing::info!("PXE Request is EFI");
                        PXEresponse::Efi
                    }
                } else {
                    tracing::error!("Request failed with status: {}", res.status());
                    PXEresponse::Error
                }
            }
            Err(e) => {
                tracing::error!("PXE Request failed: {}", e);
                PXEresponse::Error
            }
        }
    }
}

pub async fn get_api_state(
    app_context: &MachineATronContext,
    machine_id: Option<&rpc::common::MachineId>,
) -> String {
    let Some(machine_id) = machine_id else {
        return "Unknown".to_string();
    };

    api_client::get_machine(app_context, machine_id.clone())
        .await
        .map_or_else(
            |e| {
                tracing::warn!("Error getting API state: {e}");
                "<ERROR>".to_owned()
            },
            |machine| {
                if let Some(m) = machine {
                    m.state
                } else {
                    "<No Machine>".to_owned()
                }
            },
        )
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
