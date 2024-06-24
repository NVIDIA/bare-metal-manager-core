use std::{fmt::Display, path::PathBuf, time::Duration};

use ::rpc::Timestamp;
use mac_address::MacAddress;
use rpc::forge::ManagedHostNetworkConfigResponse;
use tokio::time::Instant;
use uuid::Uuid;

use crate::{
    api_client,
    bmc::Bmc,
    config::{MachineATronContext, MachineConfig},
    dhcp_relay::{DhcpRelayClient, DhcpResponseInfo},
    host_machine::{MachineState, MachineStateError},
    machine_utils::{add_address_to_interface, get_api_state, get_fac_action, next_mac},
};

#[derive(Debug)]
pub struct DpuMachine {
    pub mat_id: Uuid,
    pub config: MachineConfig,
    pub app_context: MachineATronContext,
    pub mat_state: MachineState,
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
    pub bmc_port: u16,
    bmc: Option<Bmc>,
    last_reboot: Instant,
    m_a_t_last_known_reboot_request: Option<Timestamp>,
}

impl DpuMachine {
    pub fn new(app_context: MachineATronContext, config: MachineConfig) -> Self {
        let bmc_port = app_context
            .next_bmc_port
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        DpuMachine {
            mat_id: Uuid::new_v4(),
            config,
            app_context,

            mat_state: MachineState::BmcInit,
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
            bmc_port,
            bmc: None,
            last_reboot: Instant::now(),
            m_a_t_last_known_reboot_request: None,
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

    pub fn get_machine_id(&self) -> Result<rpc::forge::MachineId, MachineStateError> {
        self.get_machine_id_opt()
            .ok_or(MachineStateError::MissingMachineId)
    }

    pub fn get_machine_id_opt(&self) -> Option<rpc::forge::MachineId> {
        self.machine_discovery_result
            .as_ref()
            .and_then(|mdr| mdr.machine_id.clone())
            .or_else(|| {
                self.machine_dhcp_info
                    .as_ref()
                    .and_then(|info| info.machine_id.clone())
            })
    }

    pub fn get_machine_id_str(&self) -> String {
        if let Some(machine_id) = self.get_machine_id_opt() {
            machine_id.id
        } else {
            self.mac_address.to_string()
        }
    }

    pub async fn process_state(
        &mut self,
        dhcp_client: &mut DhcpRelayClient,
        logs: &mut Vec<String>,
    ) -> Result<bool, MachineStateError> {
        let template_dir = self.config.template_dir.as_str();

        if let Some(machine_id) = self.get_machine_id_opt() {
            let (api_state, reboot_requested) = get_api_state(
                &self.app_context,
                &machine_id,
                &mut self.m_a_t_last_known_reboot_request,
            )
            .await;
            self.api_state = api_state;
            if reboot_requested {
                self.last_reboot = Instant::now();
                logs.push(format!(
                    "DPU: Reboot requested: new state: {} api state: {}",
                    self.mat_state, self.api_state
                ));
                self.mat_state = MachineState::Rebooting;
            } else {
                logs.push(format!(
                    "D: start: mat state: {} api state: {}",
                    self.mat_state, self.api_state
                ));
            }
        } else {
            logs.push(format!(
                "D: start: mat state: {} api state: <No Machine Id>",
                self.mat_state
            ));
        }

        let result = match self.mat_state {
            MachineState::BmcInit => {
                if self.bmc_dhcp_info.is_none() {
                    if self.last_dhcp_request.elapsed() > Duration::from_secs(5) {
                        self.last_dhcp_request = Instant::now();
                        tracing::debug!(
                            "DPU {}: Sending BMC DHCP Request for {} through {}",
                            self.get_machine_id_str(),
                            self.bmc_mac_address,
                            self.config.oob_dhcp_relay_address
                        );
                        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

                        dhcp_client
                            .request_ip(
                                self.bmc_mat_id,
                                &self.bmc_mac_address,
                                &self.config.oob_dhcp_relay_address,
                                "NVIDIA/BF/BMC",
                                self.config.template_dir.clone(),
                                response_tx,
                            )
                            .await;

                        let Ok(Some(dhcp_response_info)) = response_rx.await else {
                            tracing::warn!("Failed waiting on dhcp response");
                            return Ok(false);
                        };

                        let listen_ip = dhcp_response_info.ip_address.to_string();
                        //let listen_ip = self.app_context.app_config.bmc_ip.clone();

                        self.update_dhcp_record(dhcp_response_info);

                        let log = format!(
                            "D: bmc machine_id: {}",
                            self.bmc_dhcp_info
                                .as_ref()
                                .and_then(|info| info.machine_id.clone())
                                .unwrap_or_default()
                        );
                        tracing::info!(log);
                        logs.push(log);

                        let cert_path = PathBuf::from(
                            self.app_context.forge_client_config.root_ca_path.clone(),
                        )
                        .parent()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap();

                        add_address_to_interface(
                            &listen_ip,
                            &self.app_context.app_config.interface,
                            &self.app_context.app_config.sudo_command,
                        )
                        .await
                        .inspect_err(|e| tracing::warn!("{}", e))
                        .map_err(MachineStateError::ListenAddressConfigError)?;

                        let mut bmc = Bmc::new(
                            listen_ip,
                            self.app_context.app_config.bmc_starting_port,
                            self.config.dpu_bmc_redfish_template_dir.clone(),
                            cert_path,
                        );
                        bmc.start()?;
                        self.bmc = Some(bmc);

                        Ok(true)
                    } else {
                        Ok(true)
                    }
                } else {
                    self.mat_state = MachineState::Init;
                    self.last_dhcp_request = Instant::now() - Duration::from_secs(10);
                    Ok(true)
                }
            }
            MachineState::Init => {
                if self.machine_dhcp_info.is_none() {
                    if self.last_dhcp_request.elapsed() > Duration::from_secs(5) {
                        self.last_dhcp_request = Instant::now();
                        let log = format!(
                            "DPU {}: Sending Admin DHCP Request for {} through {}",
                            self.get_machine_id_str(),
                            self.mac_address,
                            self.config.oob_dhcp_relay_address
                        );
                        tracing::debug!(log);
                        logs.push(log);

                        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

                        dhcp_client
                            .request_ip(
                                self.mat_id,
                                &self.mac_address,
                                &self.config.oob_dhcp_relay_address,
                                "PXEClient",
                                self.config.template_dir.clone(),
                                response_tx,
                            )
                            .await;

                        match response_rx.await {
                            Ok(Some(dhcp_response_info)) => {
                                self.update_dhcp_record(dhcp_response_info);
                                let log = format!(
                                    "D: machine machine_id: {}",
                                    self.machine_dhcp_info
                                        .as_ref()
                                        .and_then(|info| info.machine_id.clone())
                                        .unwrap_or_default()
                                );
                                tracing::info!(log);
                                logs.push(log);
                                Ok(true)
                            }
                            Ok(None) => {
                                let log = "D: No dhcp info".to_string();
                                tracing::warn!(log);
                                logs.push(log);
                                Ok(false)
                            }
                            Err(e) => {
                                let log = format!("D: Failed waiting for dhcp response: {e}");
                                tracing::warn!(log);
                                logs.push(log);
                                Ok(false)
                            }
                        }
                    } else {
                        Ok(false)
                    }
                } else if self.last_dhcp_update.is_some_and(|t| {
                    t.elapsed() > Duration::from_secs(self.config.boot_delay as u64)
                }) {
                    self.mat_state = MachineState::DhcpComplete;
                    Ok(true)
                } else {
                    Ok(true)
                }
            }
            MachineState::Rebooting => {
                if self.last_reboot.elapsed() > Duration::from_secs(self.config.dpu_reboot_delay) {
                    self.mat_state = MachineState::Init;
                    self.last_reboot = Instant::now();
                }
                return Ok(true);
            }
            MachineState::DhcpComplete => {
                let Some(machine_interface_id) = self
                    .bmc_dhcp_info
                    .as_ref()
                    .and_then(|i| i.interface_id)
                    .as_ref()
                    .map(|id| rpc::Uuid::from(*id))
                else {
                    let log = String::from(
                        "D: discover_machine failed: Missing interface_id from BMC dhcp info",
                    );
                    tracing::warn!(log);
                    logs.push(log);
                    return Ok(false);
                };

                match api_client::discover_machine(
                    &self.app_context,
                    template_dir,
                    rpc::forge::MachineType::Dpu,
                    machine_interface_id,
                    vec![self.mac_address.to_string()],
                    self.mac_address.to_string().replace(':', ""),
                    self.host_mac_address.to_string(),
                )
                .await
                {
                    Ok(machine_discovery_result) => {
                        self.machine_discovery_result = Some(machine_discovery_result);
                        let log = format!(
                            "D: discover_machine machine_id: {}",
                            self.machine_discovery_result
                                .as_ref()
                                .and_then(|info| info.machine_id.clone())
                                .unwrap_or_default()
                        );
                        tracing::info!(log);
                        logs.push(log);
                        self.mat_state = MachineState::HardwareDiscoveryComplete;
                        Ok(true)
                    }
                    Err(e) => {
                        let log = format!("D: discover_machine failed: {e}");
                        tracing::warn!(log);
                        logs.push(log);
                        Ok(false)
                    }
                }
            }
            MachineState::HardwareDiscoveryComplete => {
                let machine_id = self.get_machine_id()?;

                // let bmc_host_and_port =
                //     format!("{}:{}", self.app_context.app_config.bmc_ip, self.bmc_port);
                let Some(dhcp_info) = self.bmc_dhcp_info.as_ref() else {
                    tracing::warn!("D: missing dhcp_response_info");
                    return Ok(false);
                };

                if let Err(e) = api_client::update_bmc_metadata(
                    &self.app_context,
                    template_dir,
                    rpc::forge::MachineType::Dpu,
                    machine_id,
                    Some(dhcp_info.ip_address),
                    Some(self.app_context.app_config.bmc_starting_port),
                )
                .await
                {
                    let log = format!("D: update_bmc_metadata failed: {e}");
                    tracing::warn!(log);
                    logs.push(log);
                    Ok(false)
                } else {
                    self.mat_state = MachineState::BmcUpdateComplete;
                    Ok(true)
                }
            }

            MachineState::BmcUpdateComplete => {
                let machine_id = self.get_machine_id()?;
                if let Err(e) = api_client::discovery_complete(&self.app_context, machine_id).await
                {
                    let log = format!("D: discovery_complete failed: {e}");
                    tracing::warn!(log);
                    logs.push(log);
                    Ok(false)
                } else {
                    self.mat_state = MachineState::DiscoveryComplete;
                    Ok(true)
                }
            }

            MachineState::DiscoveryComplete => {
                let machine_id = self.get_machine_id()?;
                get_fac_action(&self.app_context, machine_id).await;

                self.mat_state = MachineState::ControlComplete;
                Ok(true)
            }
            MachineState::ControlComplete => {
                if self.api_state == "DPU/WaitingForNetworkConfig"
                    || self.api_state.starts_with("Host")
                    || self.api_state == "Ready"
                {
                    self.mat_state = MachineState::GetNetworkConfig;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            MachineState::GetNetworkConfig => {
                let machine_id = self.get_machine_id()?;

                match api_client::get_managed_host_network_config(
                    &self.app_context,
                    machine_id.clone(),
                )
                .await
                {
                    Ok(network_config) => {
                        self.network_config_response = Some(network_config);
                        self.mat_state = MachineState::MachineUp;
                        Ok(true)
                    }
                    Err(e) => {
                        let log = format!("D: get_managed_host_network_config failed: {e}");
                        tracing::warn!(log);
                        logs.push(log);
                        Ok(false)
                    }
                }
            }
            MachineState::MachineUp => {
                let machine_id = self.get_machine_id()?;
                let elapsed = self
                    .last_network_status_update
                    .unwrap_or_else(|| Instant::now() - Duration::from_secs(10 * 60))
                    .elapsed();
                let version = self
                    .network_config_response
                    .as_ref()
                    .map(|config| config.managed_host_config_version.clone());
                if elapsed > Duration::from_secs(120) {
                    if let Err(e) = api_client::record_dpu_network_status(
                        &self.app_context,
                        machine_id.clone(),
                        version,
                    )
                    .await
                    {
                        let log = format!("D: record_dpu_network_status failed: {e}");
                        tracing::warn!(log);
                        logs.push(log);
                        return Ok(false);
                    }
                    self.last_network_status_update = Some(Instant::now());
                }
                match self.api_state.as_str() {
                    "DPU/WaitingForNetworkConfig" => {
                        self.mat_state = MachineState::GetNetworkConfig;
                        Ok(true)
                    }
                    "DPU/INIT" => {
                        self.mat_state = MachineState::Init;
                        Ok(true)
                    }
                    _ => Ok(false),
                }
            }
        };

        logs.push(format!(
            "D: end: mat state {} api state {}",
            self.mat_state, self.api_state
        ));

        result
    }

    pub fn get_state(&self) -> MachineState {
        self.mat_state.clone()
    }
}

impl Display for DpuMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}:", self.get_machine_id_str())?;
        writeln!(f, "    Local State: {}", self.mat_state)?;
        writeln!(f, "    API State: {}", self.api_state)?;

        writeln!(f, "    Machine MAC: {}", self.mac_address)?;
        if let Some(dhcp_info) = self.machine_dhcp_info.as_ref() {
            writeln!(f, "    Machine IP: {}", dhcp_info.ip_address)?;
        }

        writeln!(f, "    BMC MAC: {}", self.bmc_mac_address)?;
        if let Some(dhcp_info) = self.bmc_dhcp_info.as_ref() {
            writeln!(f, "    BMC IP: {}", dhcp_info.ip_address)?;
        }
        Ok(())
    }
}
