use std::{fmt::Display, time::Duration};

use mac_address::MacAddress;
use rpc::forge::ManagedHostNetworkConfigResponse;
use tokio::time::Instant;
use uuid::Uuid;

use crate::{
    api_client,
    config::{MachineATronContext, MachineConfig},
    dhcp_relay::{DhcpRelayClient, DhcpResponseInfo},
    host_machine::MachineState,
    machine_utils::{get_api_state, next_mac, reboot_requested},
};

#[derive(Debug, Clone)]
pub struct DpuMachine {
    pub mat_id: Uuid,
    pub config: MachineConfig,
    pub app_context: MachineATronContext,
    pub local_state: MachineState,
    pub api_state: String,
    pub mac_address: MacAddress,
    pub host_mac_address: MacAddress,
    pub machine_dhcp_info: Option<DhcpResponseInfo>,
    last_dhcp_update: Option<Instant>,
    last_dhcp_request: Instant,
    pub machine_discovery_result: Option<rpc::forge::MachineDiscoveryResult>,
    pub last_network_status_update: Option<Instant>,
    pub network_config_response: Option<ManagedHostNetworkConfigResponse>,

    pub bmc_mat_id: Uuid,
    pub bmc_mac_address: MacAddress,
    pub bmc_dhcp_info: Option<DhcpResponseInfo>,
}

impl DpuMachine {
    pub fn new(app_context: MachineATronContext, config: MachineConfig) -> Self {
        DpuMachine {
            mat_id: Uuid::new_v4(),
            config,
            app_context,

            local_state: MachineState::BmcInit,
            api_state: "Unknown".to_owned(),

            mac_address: next_mac(),
            host_mac_address: next_mac(),
            machine_dhcp_info: None,
            last_dhcp_update: None,
            last_dhcp_request: Instant::now(),
            machine_discovery_result: None,
            last_network_status_update: None,
            network_config_response: None,
            bmc_mat_id: Uuid::new_v4(),
            bmc_mac_address: next_mac(),
            bmc_dhcp_info: None,
        }
    }

    pub fn update_dhcp_record(&mut self, dhcp_info: DhcpResponseInfo) {
        match dhcp_info.mat_id {
            mat_id if mat_id == self.bmc_mat_id => {
                self.last_dhcp_update = Some(Instant::now());
                self.bmc_dhcp_info = Some(dhcp_info);
            }
            mat_id if mat_id == self.mat_id => {
                self.last_dhcp_update = Some(Instant::now());
                self.machine_dhcp_info = Some(dhcp_info);
            }
            _ => {
                tracing::warn!("Unknown mat id: {}", dhcp_info.mat_id);
            }
        }
    }

    pub fn get_machine_id(&self) -> rpc::forge::MachineId {
        self.get_machine_id_opt().unwrap()
    }

    pub fn get_machine_id_opt(&self) -> Option<rpc::forge::MachineId> {
        self.machine_dhcp_info
            .as_ref()
            .and_then(|info| info.machine_id.clone())
            .or_else(|| {
                self.machine_discovery_result
                    .as_ref()
                    .and_then(|mdr| mdr.machine_id.clone())
            })
            .or_else(|| {
                self.bmc_dhcp_info
                    .as_ref()
                    .and_then(|info| info.machine_id.clone())
            })
    }

    pub fn get_machine_id_str(&self) -> String {
        match self
            .machine_dhcp_info
            .as_ref()
            .map_or_else(
                || {
                    self.machine_discovery_result
                        .as_ref()
                        .and_then(|mdr| mdr.machine_id.clone())
                },
                |info| info.machine_id.clone(),
            )
            .or_else(|| {
                self.bmc_dhcp_info
                    .as_ref()
                    .and_then(|info| info.machine_id.clone())
            }) {
            Some(machine_id) => machine_id.id,
            None => self.mac_address.to_string(),
        }
    }

    pub async fn process_state(&mut self, dhcp_client: &mut DhcpRelayClient) -> bool {
        let template_dir = self.config.template_dir.as_str();

        if let Some(machine_id) = self.get_machine_id_opt() {
            self.api_state = get_api_state(&self.app_context, &machine_id).await;
        }

        match self.local_state {
            MachineState::BmcInit => {
                if self.bmc_dhcp_info.is_none() {
                    if self.last_dhcp_request.elapsed() > Duration::from_secs(5) {
                        self.last_dhcp_request = Instant::now();
                        tracing::info!(
                            "DPU {}: Sending BMC DHCP Request for {} through {}",
                            self.get_machine_id_str(),
                            self.bmc_mac_address,
                            self.config.oob_dhcp_relay_address
                        );
                        dhcp_client
                            .request_ip(
                                self.bmc_mat_id,
                                &self.bmc_mac_address,
                                &self.config.oob_dhcp_relay_address,
                                "NVIDIA/BF/BMC",
                                self.config.template_dir.clone(),
                                None,
                            )
                            .await;
                        true
                    } else {
                        false
                    }
                } else {
                    self.local_state = MachineState::Init;
                    true
                }
            }
            MachineState::Init => {
                if self.machine_dhcp_info.is_none() {
                    if self.last_dhcp_request.elapsed() > Duration::from_secs(5) {
                        self.last_dhcp_request = Instant::now();
                        tracing::info!(
                            "DPU {}: Sending Admin DHCP Request for {} through {}",
                            self.get_machine_id_str(),
                            self.mac_address,
                            self.config.oob_dhcp_relay_address
                        );
                        dhcp_client
                            .request_ip(
                                self.mat_id,
                                &self.mac_address,
                                &self.config.oob_dhcp_relay_address,
                                "PXEClient",
                                self.config.template_dir.clone(),
                                None,
                            )
                            .await;
                        true
                    } else {
                        false
                    }
                } else if self.last_dhcp_update.is_some_and(|t| {
                    t.elapsed() < Duration::from_secs(self.config.boot_delay as u64)
                }) {
                    false
                } else {
                    self.local_state = MachineState::DhcpComplete;
                    true
                }
            }
            MachineState::DhcpComplete => {
                let machine_interface_id = rpc::Uuid::from(
                    *self
                        .bmc_dhcp_info
                        .as_ref()
                        .unwrap()
                        .interface_id
                        .as_ref()
                        .unwrap(),
                );

                self.machine_discovery_result = Some(
                    api_client::discover_machine(
                        &self.app_context,
                        template_dir,
                        rpc::forge::MachineType::Dpu,
                        machine_interface_id,
                        vec![self.mac_address.to_string()],
                        self.mac_address.to_string().replace(':', ""),
                        self.host_mac_address.to_string(),
                    )
                    .await
                    .unwrap(),
                );

                self.local_state = MachineState::HardwareDiscoveryComplete;
                true
            }
            MachineState::HardwareDiscoveryComplete => {
                let machine_id = self.get_machine_id();
                //log_api_state(&self.app_context.app_config, &machine_id, &self.machine_state).await;
                api_client::update_bmc_metadata(
                    &self.app_context,
                    template_dir,
                    rpc::forge::MachineType::Dpu,
                    machine_id,
                )
                .await
                .unwrap();
                self.local_state = MachineState::BmcUpdateComplete;
                true
            }

            MachineState::BmcUpdateComplete => {
                let machine_id = self.get_machine_id();
                api_client::discovery_complete(&self.app_context, machine_id)
                    .await
                    .unwrap();
                self.local_state = MachineState::DiscoveryComplete;
                true
            }

            MachineState::DiscoveryComplete => {
                let machine_id = self.get_machine_id();
                get_fac_action(&self.app_context, machine_id).await;

                self.local_state = MachineState::ControlComplete;
                true
            }
            MachineState::ControlComplete => {
                if self.api_state == "DPU/WaitingForNetworkConfig"
                    || self.api_state.starts_with("Host")
                    || self.api_state == "Ready"
                {
                    self.local_state = MachineState::GetNetworkConfig;
                    true
                } else {
                    false
                }
            }
            MachineState::GetNetworkConfig => {
                let machine_id = self.get_machine_id();

                let network_config = api_client::get_managed_host_network_config(
                    &self.app_context,
                    machine_id.clone(),
                )
                .await
                .unwrap();
                self.network_config_response = Some(network_config);

                if reboot_requested(&self.app_context, &machine_id).await {
                    self.local_state = MachineState::Init;
                } else {
                    self.local_state = MachineState::MachineUp;
                }
                true
            }
            MachineState::MachineUp => {
                let machine_id = self.get_machine_id();
                let elapsed = self
                    .last_network_status_update
                    .unwrap_or_else(|| Instant::now() - Duration::from_secs(10 * 60))
                    .elapsed();
                let version = self
                    .network_config_response
                    .as_ref()
                    .map(|config| config.managed_host_config_version.clone());
                if elapsed > Duration::from_secs(60) {
                    api_client::record_dpu_network_status(
                        &self.app_context,
                        machine_id.clone(),
                        version,
                    )
                    .await
                    .unwrap();
                    self.last_network_status_update = Some(Instant::now());
                }
                if reboot_requested(&self.app_context, &machine_id).await {
                    self.local_state = MachineState::Init;
                    return true;
                }

                match self.api_state.as_str() {
                    "DPU/WaitingForNetworkConfig" => {
                        self.local_state = MachineState::GetNetworkConfig;
                        false
                    }
                    "DPU/INIT" => {
                        self.local_state = MachineState::Init;
                        true
                    }
                    _ => false,
                }
            }
        }
    }

    pub fn get_state(&self) -> MachineState {
        self.local_state.clone()
    }
}

impl Display for DpuMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = self
            .machine_dhcp_info
            .as_ref()
            .and_then(|dhcp_info| dhcp_info.hostname.clone())
            .unwrap_or_else(|| self.get_machine_id_str());

        write!(f, "{}: mac: {:?}", name, self.mac_address)?;

        if let Some(dhcp_info) = self.bmc_dhcp_info.as_ref() {
            write!(f, " ip: {}", dhcp_info.ip_address)?;
            if let Some(prefix) = dhcp_info.subnet {
                write!(f, " prefix: {}", prefix)?;
            }
        }
        Ok(())
    }
}

async fn get_fac_action(
    app_context: &MachineATronContext,
    machine_id: rpc::forge::MachineId,
) -> rpc::forge::forge_agent_control_response::Action {
    let response = api_client::forge_agent_control(app_context, machine_id.clone())
        .await
        .unwrap();
    let action =
        rpc::forge::forge_agent_control_response::Action::try_from(response.action).unwrap();

    tracing::info!("{}: control action: {}", machine_id, action.as_str_name());

    action
}

/*
async fn reboot_requested(
    app_context: &MachineATronContext,
    machine_id: &rpc::forge::MachineId,
) -> bool {
    let machine = api_client::get_machine(app_context, machine_id.clone())
        .await
        .unwrap();

    let mut reboot_requested = false;

    if let Some(m) = machine {
        if let Some(last_reboot_requested_time) = m.last_reboot_requested_time {
            if let Some(last_reboot_time) = m.last_reboot_time {
                let last_reboot_requested_time =
                    chrono::DateTime::try_from(last_reboot_requested_time).unwrap();
                let last_reboot_time = chrono::DateTime::try_from(last_reboot_time).unwrap();

                reboot_requested = last_reboot_requested_time > last_reboot_time;
            }
        }
    }
    if reboot_requested {
        tracing::info!("reboot requested for {}", machine_id,);
    }
    reboot_requested
}
*/
