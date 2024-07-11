use ::rpc::Timestamp;
use mac_address::MacAddress;
use rpc::{forge::ForgeAgentControlResponse, forge_agent_control_response::Action};

use crate::{api_client, config::MachineATronContext, host_machine::AddressConfigError};

use std::sync::atomic::{AtomicU32, Ordering};

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

static NEXT_MAC_ADDRESS: AtomicU32 = AtomicU32::new(1);

pub enum PXEresponse {
    Exit,
    Efi,
    Error,
}

pub fn next_mac() -> MacAddress {
    let next_mac_num = NEXT_MAC_ADDRESS.fetch_add(1, Ordering::Acquire);

    let bytes: Vec<u8> = [0x02u8, 0x01]
        .into_iter()
        .chain(next_mac_num.to_be_bytes())
        .collect();

    let mac_bytes = <[u8; 6]>::try_from(bytes).unwrap();

    MacAddress::from(mac_bytes)
}

pub async fn get_fac_action(
    app_context: &MachineATronContext,
    machine_id: rpc::common::MachineId,
) -> rpc::forge::forge_agent_control_response::Action {
    let response = api_client::forge_agent_control(app_context, machine_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Error getting control action: {e}");
            ForgeAgentControlResponse {
                action: Action::Noop as i32,
                data: None,
            }
        });

    rpc::forge::forge_agent_control_response::Action::try_from(response.action).unwrap()
}

pub async fn get_validation_id(
    app_context: &MachineATronContext,
    machine_id: rpc::common::MachineId,
) -> Option<rpc::common::Uuid> {
    let response = api_client::forge_agent_control(app_context, machine_id)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Error getting control action: {e}");
            ForgeAgentControlResponse {
                action: Action::Noop as i32,
                data: None,
            }
        });

    response.data.and_then(|d| {
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

pub fn reboot_requested_for_machine(
    machine: &rpc::forge::Machine,
    m_a_t_last_known_reboot_request: Option<&Timestamp>,
) -> bool {
    let mut rr = false;

    if let Some(last_reboot_requested_time) = machine.last_reboot_requested_time.as_ref() {
        // if the machine's last known reboot request in m_a_t is None but the request received from API is not, it indicates
        // the machine's first reboot.
        rr = m_a_t_last_known_reboot_request
            .map(|lrr| *last_reboot_requested_time > *lrr)
            .unwrap_or(true);
    }

    if rr {
        tracing::info!(
            "reboot requested for {}",
            machine.id.as_ref().map_or("", |id| { id.id.as_str() })
        );
    }
    rr
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
    machine_id: &rpc::common::MachineId,
    m_a_t_last_known_reboot_request: &mut Option<Timestamp>,
) -> (String, bool) {
    api_client::get_machine(app_context, machine_id.clone())
        .await
        .map_or_else(
            |e| {
                tracing::warn!("Error getting API state: {e}");
                ("<ERROR>".to_owned(), false)
            },
            |machine| {
                if let Some(ref m) = machine {
                    let state = m.state.clone();
                    let rr =
                        reboot_requested_for_machine(m, m_a_t_last_known_reboot_request.as_ref());
                    *m_a_t_last_known_reboot_request = m.last_reboot_requested_time.clone();

                    (state, rr)
                } else {
                    ("<No Machine>".to_owned(), false)
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
