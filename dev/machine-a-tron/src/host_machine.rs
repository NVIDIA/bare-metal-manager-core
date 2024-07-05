use axum::Router;
use std::net::SocketAddr;
use std::{
    collections::HashMap,
    convert::From,
    fmt::{Debug, Display},
    time::{Duration, SystemTime},
};

use ::rpc::Timestamp;
use chrono::{DateTime, Local};
use mac_address::MacAddress;
use rpc::forge_agent_control_response::Action;
use tokio::time::Instant;
use uuid::Uuid;

use crate::api_client::ClientApiError;
use crate::bmc_mock_wrapper::{BmcMockWrapper, HostBmcInfo, MockBmcInfo};
use crate::{
    api_client,
    config::{MachineATronContext, MachineConfig},
    dhcp_relay::{DhcpRelayClient, DhcpResponseInfo},
    dpu_machine::DpuMachine,
    machine_utils::{get_api_state, get_fac_action, next_mac, send_pxe_boot_request, PXEresponse},
    tui::{HostDetails, UiEvent},
};

const MAX_LOG_LINES: usize = 20;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineState {
    BmcInit,
    Init,
    DhcpComplete,
    HardwareDiscoveryComplete,
    BmcUpdateComplete,
    DiscoveryComplete,
    ControlComplete,
    GetNetworkConfig,
    MachineUp(SendRebootCompleted),
    Rebooting,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SendRebootCompleted(pub bool);

#[derive(thiserror::Error, Debug)]
pub enum MachineStateError {
    #[error(
        "Invalid Machine state: Missing machine_id for this machine in machine discovery results"
    )]
    MissingMachineId,
    #[error("{0}")]
    InvalidAddress(String),
    #[error("Error launching BMC mock service: {0}")]
    BmcMockServiceError(String),
    #[error("Error configuring listening address: {0}")]
    ListenAddressConfigError(AddressConfigError),
    #[error("Could not find certificates at {0}")]
    MissingCertificates(String),
    #[error("Error calling forge API: {0}")]
    ClientApi(#[from] ClientApiError),
}

#[derive(thiserror::Error, Debug)]
pub enum AddressConfigError {
    #[error("Error running ip command: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Error running ip command: {0:?}, output: {1:?}")]
    CommandFailure(tokio::process::Command, std::process::Output),
}

impl Display for MachineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

#[derive(Debug)]
pub struct HostMachine {
    pub mat_id: Uuid,
    pub config: MachineConfig,
    pub app_context: MachineATronContext,
    pub mat_state: MachineState,
    pub api_state: String,

    pub machine_discovery_result: Option<rpc::forge::MachineDiscoveryResult>,
    pub machine_dhcp_info: Option<DhcpResponseInfo>,
    pub dpu_machines: Vec<DpuMachine>,
    pub dpu_machine_index: HashMap<Uuid, usize>,

    pub bmc_mat_id: Uuid,
    pub bmc_mac_address: MacAddress,
    pub bmc_dhcp_info: Option<DhcpResponseInfo>,

    ui_event_tx: Option<tokio::sync::mpsc::Sender<UiEvent>>,

    pub logs: Vec<String>,

    dpus_previously_ready: bool,
    bmc: Option<BmcMockWrapper>,

    last_reboot: Instant,
    m_a_t_last_known_reboot_request: Option<Timestamp>,

    host_bmc_mock_router: Router,
}

impl Display for HostMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let machine_id = self.get_machine_id_str();
        writeln!(f, "ID: {}", machine_id)?;
        writeln!(f, "Local State: {}", self.mat_state)?;
        writeln!(f, "API State: {}", self.api_state)?;
        writeln!(
            f,
            "Machine IP: {}",
            self.machine_dhcp_info.as_ref().map_or_else(
                || "Unknown".to_owned(),
                |bmc_dhcp_info| bmc_dhcp_info.ip_address.to_string()
            )
        )?;
        writeln!(
            f,
            "BMC IP: {}",
            self.bmc_dhcp_info.as_ref().map_or_else(
                || "Unknown".to_owned(),
                |bmc_dhcp_info| bmc_dhcp_info.ip_address.to_string()
            )
        )?;
        writeln!(f, "DPUs:")?;
        for (dpu_index, dpu) in self.dpu_machines.iter().enumerate() {
            writeln!(f, "{}: {}", dpu_index, dpu)?
        }
        Ok(())
    }
}

impl HostMachine {
    fn log(&mut self, msg: String) {
        let log_time = DateTime::<Local>::from(SystemTime::now());
        let log_str = format!("{} {}", log_time, msg);
        tracing::info!(log_str);
        self.logs.push(log_str);

        let over = self.logs.len().saturating_sub(MAX_LOG_LINES);
        if over > 0 {
            self.logs.drain(..over);
        }
    }
    pub async fn get_name_and_state(&self) -> String {
        let state = self.api_state.clone();
        let state = if let Some((v1, _)) = state.split_once(' ') {
            v1.to_owned()
        } else {
            state
        };
        let mut name = self.get_machine_id_str();
        name.truncate(16);
        name.push_str("...");
        let mut status = format!("Host {}: {} {}", name, state, self.mat_state);

        for (dpu_index, dpu) in self.dpu_machines.iter().enumerate() {
            let dpu_state = dpu.get_state();
            status.push_str(&format!(
                "\n  DPU {}: {} {}",
                dpu_index, dpu.api_state, dpu_state
            ));
        }
        status
    }

    pub fn new(
        app_context: MachineATronContext,
        config: MachineConfig,
        ui_event_tx: Option<tokio::sync::mpsc::Sender<UiEvent>>,
        host_bmc_mock_router: Router,
        dpu_bmc_mock_router: Router,
    ) -> Self {
        let mut dpus = Vec::default();
        let mut dpu_index = HashMap::default();

        for d_index in 0..config.dpu_per_host_count as usize {
            let dpu = DpuMachine::new(
                app_context.clone(),
                config.clone(),
                dpu_bmc_mock_router.clone(),
            );
            dpu_index.insert(dpu.mat_id, d_index);
            dpu_index.insert(dpu.bmc_mat_id, d_index);
            dpus.push(dpu);
        }

        HostMachine {
            mat_id: Uuid::new_v4(),
            config,
            app_context,
            dpu_machines: dpus,
            dpu_machine_index: dpu_index,

            mat_state: MachineState::BmcInit,
            api_state: "Unknown".to_owned(),

            machine_discovery_result: None,
            machine_dhcp_info: None,

            bmc_mat_id: Uuid::new_v4(),
            bmc_mac_address: next_mac(),
            bmc_dhcp_info: None,
            ui_event_tx,

            logs: Vec::default(),
            dpus_previously_ready: false,
            bmc: None,
            last_reboot: Instant::now(),
            m_a_t_last_known_reboot_request: None,
            host_bmc_mock_router,
        }
    }

    pub fn update_dhcp_info(&mut self, dhcp_info: DhcpResponseInfo) {
        match dhcp_info.mat_id {
            mat_id if mat_id == self.bmc_mat_id => {
                self.bmc_dhcp_info = Some(dhcp_info);
            }
            mat_id if mat_id == self.mat_id => {
                self.machine_dhcp_info = Some(dhcp_info);
            }
            mat_id => {
                tracing::warn!("could not update dhcp info; unknown mat_id {}", mat_id);
            }
        }
    }

    pub async fn process_state(
        &mut self,
        dhcp_client: &mut DhcpRelayClient,
    ) -> Result<bool, MachineStateError> {
        let mut work_done = false;
        let mut dpus_ready = true;
        let template_dir = self.config.template_dir.clone();

        if let Some(machine_id) = self.get_machine_id_opt() {
            let old_api_state = self.api_state.clone();
            let (api_state, reboot_requested) = get_api_state(
                &self.app_context,
                &machine_id,
                &mut self.m_a_t_last_known_reboot_request,
            )
            .await;
            self.api_state = api_state.clone();
            if reboot_requested {
                self.last_reboot = Instant::now();
                self.log(format!(
                    "Host: Reboot requested: new state: {} api state: {}",
                    self.mat_state, self.api_state
                ));
                self.mat_state = MachineState::Rebooting;
                work_done = true;
            }
            if api_state.contains("MachineValidating") {
                api_client::machine_validation_complete(&self.app_context, &machine_id).await?;
                work_done = true;
            }
            if old_api_state != self.api_state {
                work_done = true;
            }
        }

        let mut logs = Vec::default();
        for dpu in self.dpu_machines.iter_mut() {
            work_done |= match dpu.process_state(dhcp_client, &mut logs).await {
                Ok(dpu_work_done) => dpu_work_done,
                Err(err) => {
                    tracing::error!("Internal machine-a-tron state error for mock DPU machine {}, will skip it: {}", dpu.mat_id, err);
                    false
                }
            };
            if let MachineState::MachineUp(_) = dpu.get_state() {
                dpus_ready = true;
            }
        }
        for l in logs {
            self.log(l);
        }

        // give the API time to update the host after the dpus did something
        if !self.dpus_previously_ready && dpus_ready {
            self.dpus_previously_ready = true;
            return Ok(true);
        }

        work_done |= if dpus_ready {
            match self.mat_state {
                MachineState::BmcInit => {
                    if self.bmc_dhcp_info.is_none() {
                        tracing::debug!(
                            "Host {}: Sending BMC DHCP Request for {}",
                            self.get_machine_id_str(),
                            self.bmc_mac_address
                        );
                        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
                        let start = Instant::now();
                        dhcp_client
                            .request_ip(
                                self.bmc_mat_id,
                                &self.bmc_mac_address,
                                &self.config.oob_dhcp_relay_address,
                                "iDRAC",
                                self.config.template_dir.clone(),
                                response_tx,
                            )
                            .await;

                        let Ok(Some(dhcp_response_info)) = response_rx.await else {
                            tracing::warn!("Failed waiting for dhcp response");
                            return Ok(false);
                        };

                        let bmc_mock_address = SocketAddr::new(
                            dhcp_response_info.ip_address.into(),
                            self.app_context.app_config.bmc_mock_port,
                        );
                        let mut bmc = BmcMockWrapper::new(
                            MockBmcInfo::Host(self.bmc_info()),
                            self.host_bmc_mock_router.clone(),
                            bmc_mock_address,
                            self.app_context.clone(),
                        );

                        bmc.start().await?;
                        self.bmc = Some(bmc);
                        self.update_dhcp_info(dhcp_response_info);
                        self.log(format!(
                            "BMC DHCP Request for {} took {}ms",
                            self.bmc_mac_address,
                            start.elapsed().as_millis()
                        ));

                        Ok::<bool, MachineStateError>(true)
                    } else {
                        self.mat_state = MachineState::Init;
                        Ok::<bool, MachineStateError>(true)
                    }
                }
                MachineState::Init => {
                    if self.machine_dhcp_info.is_none() {
                        let Some(mac_address) =
                            self.dpu_machines.first().map(|d| d.host_mac_address)
                        else {
                            tracing::warn!("Machine {} has no dpu_machines", self.mat_id);
                            return Ok(false);
                        };
                        tracing::debug!(
                            "Host {}: Sending Admin DHCP Request for {}",
                            self.get_machine_id_str(),
                            mac_address
                        );
                        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
                        let start = Instant::now();
                        dhcp_client
                            .request_ip(
                                self.mat_id,
                                &mac_address,
                                &self.config.admin_dhcp_relay_address,
                                "PXEClient:Arch:00007:UNDI:003000",
                                self.config.template_dir.clone(),
                                response_tx,
                            )
                            .await;
                        self.log(format!(
                            "Admin DHCP Request for {} took {}ms",
                            mac_address,
                            start.elapsed().as_millis()
                        ));

                        let Ok(Some(dhcp_response_info)) = response_rx.await else {
                            tracing::warn!("Failed waiting on dhcp response");
                            return Ok(false);
                        };
                        self.update_dhcp_info(dhcp_response_info);

                        Ok(true)
                    } else {
                        self.mat_state = MachineState::DhcpComplete;
                        Ok(true)
                    }
                }
                MachineState::Rebooting => {
                    if self.last_reboot.elapsed()
                        > Duration::from_secs(self.config.host_reboot_delay)
                    {
                        self.mat_state = MachineState::Init;
                        self.last_reboot = Instant::now();
                    }
                    Ok(true)
                }
                MachineState::DhcpComplete => {
                    let Some(first_mac_address) =
                        self.dpu_machines.first().map(|d| d.host_mac_address)
                    else {
                        tracing::warn!("Machine {} has no dpu_machines", self.mat_id);
                        return Ok(false);
                    };
                    let mac_addresses = self
                        .dpu_machines
                        .iter()
                        .map(|dpus| dpus.host_mac_address.to_string())
                        .collect();

                    let Some(machine_interface_id) = self
                        .machine_dhcp_info
                        .as_ref()
                        .cloned()
                        .and_then(|i| i.interface_id)
                        .map(rpc::Uuid::from)
                    else {
                        tracing::warn!(
                            "Machine {} has no machine_dhcp_info.interface_id",
                            self.mat_id
                        );
                        return Ok(false);
                    };

                    let url = format!(
                        "http://{}:{}/api/v0/pxe/boot?uuid={}&buildarch=x86_64",
                        self.app_context.app_config.pxe_server_host,
                        self.app_context.app_config.pxe_server_port,
                        machine_interface_id
                    );

                    let forward_ip = self
                        .machine_dhcp_info
                        .as_ref()
                        .map(|info| info.ip_address)
                        .unwrap()
                        .to_string();

                    match send_pxe_boot_request(url, forward_ip).await {
                        PXEresponse::Exit => {
                            self.mat_state = MachineState::MachineUp(SendRebootCompleted(true));
                        }
                        PXEresponse::Error => {
                            tracing::warn!("PXE request failed. Retrying...");
                            return Ok(false);
                        }
                        PXEresponse::Efi => {
                            // Continue to the next state
                        }
                    }

                    let start = Instant::now();
                    let Ok(machine_discovery_result) = api_client::discover_machine(
                        &self.app_context,
                        &template_dir,
                        rpc::forge::MachineType::Host,
                        machine_interface_id,
                        mac_addresses,
                        first_mac_address.to_string().replace(':', ""),
                        "".to_owned(),
                    )
                    .await
                    else {
                        tracing::warn!("discover_machine failed");
                        return Ok(false);
                    };

                    self.log(format!(
                        "discover_machine took {}ms",
                        start.elapsed().as_millis()
                    ));
                    self.machine_discovery_result = Some(machine_discovery_result);
                    self.mat_state = MachineState::HardwareDiscoveryComplete;
                    Ok(true)
                }
                MachineState::HardwareDiscoveryComplete => {
                    let machine_id = self.get_machine_id()?;
                    let Some(dhcp_info) = self.bmc_dhcp_info.as_ref() else {
                        tracing::warn!("missing dhcp_response_info");
                        return Ok(false);
                    };

                    let start = Instant::now();
                    if let Err(e) = api_client::update_bmc_metadata(
                        &self.app_context,
                        &template_dir,
                        rpc::forge::MachineType::Host,
                        machine_id,
                        dhcp_info.ip_address,
                    )
                    .await
                    {
                        tracing::warn!("update_bmc_metadata failed: {e}");
                        return Ok(false);
                    }

                    self.log(format!(
                        "update_bmc_metadata took {}ms",
                        start.elapsed().as_millis()
                    ));

                    self.mat_state = MachineState::BmcUpdateComplete;
                    Ok(true)
                }
                MachineState::BmcUpdateComplete => {
                    let machine_id = self.get_machine_id()?;
                    let start = Instant::now();

                    let action = get_fac_action(&self.app_context, machine_id.clone()).await;
                    self.log(format!(
                        "get action took {}ms; action={:?} (ignored)",
                        start.elapsed().as_millis(),
                        action,
                    ));

                    let start = Instant::now();
                    if let Err(e) =
                        api_client::discovery_complete(&self.app_context, machine_id).await
                    {
                        tracing::warn!("discovery_complete failed: {e}");
                        return Ok(false);
                    }
                    self.log(format!(
                        "discovery_complete took {}ms",
                        start.elapsed().as_millis()
                    ));

                    self.mat_state = MachineState::DiscoveryComplete;
                    Ok(true)
                }
                MachineState::DiscoveryComplete => {
                    let machine_id = self.get_machine_id()?;
                    let start = Instant::now();
                    let action = get_fac_action(&self.app_context, machine_id.clone()).await;
                    self.log(format!(
                        "get action took {}ms; action={:?} (ignored)",
                        start.elapsed().as_millis(),
                        action,
                    ));

                    self.mat_state = MachineState::ControlComplete;
                    Ok(true)
                }
                MachineState::ControlComplete => {
                    self.mat_state = MachineState::MachineUp(SendRebootCompleted(true));
                    Ok(true)
                }
                MachineState::GetNetworkConfig => Ok(false),
                MachineState::MachineUp(SendRebootCompleted(send_reboot_complete)) => {
                    let machine_id = self.get_machine_id()?;
                    let start = Instant::now();
                    let action = get_fac_action(&self.app_context, machine_id.clone()).await;
                    self.log(format!(
                        "get action took {}ms; action={:?}",
                        start.elapsed().as_millis(),
                        action,
                    ));

                    if action == Action::Discovery {
                        self.log("Starting discovery".to_string());
                        self.mat_state = MachineState::DhcpComplete;
                        return Ok(true);
                    }

                    if send_reboot_complete {
                        api_client::reboot_completed(&self.app_context, machine_id.clone()).await?;
                        self.mat_state = MachineState::MachineUp(SendRebootCompleted(false));
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                }
            }
        } else {
            Ok(false)
        }?;

        if let Some(ui_event_tx) = self.ui_event_tx.as_ref() {
            if work_done {
                let details = HostDetails::from(self as &HostMachine);
                _ = ui_event_tx
                    .send(UiEvent::MachineUpdate(details))
                    .await
                    .inspect_err(|e| tracing::warn!("Error sending TUI event: {}", e));
            }
        }
        Ok(work_done)
    }

    pub fn get_machine_id(&self) -> Result<rpc::common::MachineId, MachineStateError> {
        self.get_machine_id_opt()
            .ok_or(MachineStateError::MissingMachineId)
    }

    pub fn get_machine_id_opt(&self) -> Option<rpc::common::MachineId> {
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
            None => self
                .dpu_machines
                .first()
                .map(|m| m.host_mac_address.to_string())
                .unwrap_or(String::from("<unknown>")),
        }
    }

    pub fn bmc_info(&self) -> HostBmcInfo {
        HostBmcInfo {
            bmc_mac_address: self.bmc_mac_address,
            serial: self.bmc_mac_address.to_string().replace(':', ""),
            dpus: self.dpu_machines.iter().map(|d| d.bmc_info()).collect(),
        }
    }
}
