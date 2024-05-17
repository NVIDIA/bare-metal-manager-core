use mac_address::MacAddress;
use rpc::{forge::ForgeAgentControlResponse, forge_agent_control_response::Action};

use crate::{api_client, config::MachineATronContext, host_machine::AddressConfigError};

use std::sync::atomic::{AtomicU32, Ordering};

static NEXT_MAC_ADDRESS: AtomicU32 = AtomicU32::new(1);

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
    machine_id: rpc::forge::MachineId,
) -> rpc::forge::forge_agent_control_response::Action {
    let response = api_client::forge_agent_control(app_context, machine_id.clone())
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Error getting control action: {e}");
            ForgeAgentControlResponse {
                action: Action::Noop as i32,
            }
        });

    rpc::forge::forge_agent_control_response::Action::try_from(response.action).unwrap()
}

pub async fn reboot_requested(
    app_context: &MachineATronContext,
    machine_id: &rpc::forge::MachineId,
) -> bool {
    let Ok(machine) = api_client::get_machine(app_context, machine_id.clone()).await else {
        tracing::warn!("get_machine failed");
        return false;
    };

    machine.map(reboot_requested_for_machine).unwrap_or(false)
}

pub fn reboot_requested_for_machine(machine: rpc::forge::Machine) -> bool {
    let mut rr = false;
    if let Some(last_reboot_requested_time) = machine.last_reboot_requested_time {
        if let Some(last_reboot_time) = machine.last_reboot_time {
            let last_reboot_requested_time =
                chrono::DateTime::try_from(last_reboot_requested_time).unwrap();
            let last_reboot_time = chrono::DateTime::try_from(last_reboot_time).unwrap();

            rr = last_reboot_requested_time > last_reboot_time;
        }
    }
    if rr {
        tracing::info!(
            "reboot requested for {}",
            machine.id.as_ref().map_or("", |id| { id.id.as_str() })
        );
    }
    rr
}

pub async fn get_api_state(
    app_context: &MachineATronContext,
    machine_id: &rpc::forge::MachineId,
) -> (String, bool) {
    api_client::get_machine(app_context, machine_id.clone())
        .await
        .map_or_else(
            |e| {
                tracing::warn!("Error getting API state: {e}");
                ("<ERROR>".to_owned(), false)
            },
            |machine| {
                if let Some(m) = machine {
                    let state = m.state.clone();
                    let rr = reboot_requested_for_machine(m);
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
