use std::{
    collections::HashMap,
    convert::From,
    fmt::{Debug, Display},
    path::PathBuf,
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Local};
use mac_address::MacAddress;
use rpc::forge_agent_control_response::Action;
use tokio::time::Instant;
use uuid::Uuid;

use crate::{
    api_client,
    bmc::Bmc,
    config::{MachineATronContext, MachineConfig},
    dhcp_relay::{DhcpRelayClient, DhcpResponseInfo},
    dpu_machine::DpuMachine,
    machine_utils::{get_api_state, get_fac_action, next_mac},
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
    MachineUp,
}

impl Display for MachineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

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

    bmc: Option<Bmc>,

    last_reboot: Instant,
}

impl Display for HostMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let machine_id = self.get_machine_id_str();
        writeln!(f, "ID: {}", machine_id).unwrap();
        writeln!(f, "Local State: {}", self.mat_state).unwrap();
        writeln!(f, "API State: {}", self.api_state).unwrap();
        writeln!(
            f,
            "Machine IP: {}",
            self.machine_dhcp_info.as_ref().map_or_else(
                || "Unknown".to_owned(),
                |bmc_dhcp_info| bmc_dhcp_info.ip_address.to_string()
            )
        )
        .unwrap();
        writeln!(
            f,
            "BMC IP: {}",
            self.bmc_dhcp_info.as_ref().map_or_else(
                || "Unknown".to_owned(),
                |bmc_dhcp_info| bmc_dhcp_info.ip_address.to_string()
            )
        )
        .unwrap();
        writeln!(f, "DPUs:").unwrap();
        for (dpu_index, dpu) in self.dpu_machines.iter().enumerate() {
            writeln!(f, "{}: {}", dpu_index, dpu).unwrap()
        }
        Ok(())
    }
}

impl HostMachine {
    fn log(&mut self, msg: String) {
        let log_time = DateTime::<Local>::from(SystemTime::now());
        self.logs.push(format!("{} {}", log_time, msg));

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
    ) -> Self {
        let mut dpus = Vec::default();
        let mut dpu_index = HashMap::default();
        // let bmc_port = app_context
        //     .next_bmc_port
        //     .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        for d_index in 0..config.dpu_per_host_count as usize {
            let dpu = DpuMachine::new(app_context.clone(), config.clone());
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

    pub async fn process_state(&mut self, dhcp_client: &mut DhcpRelayClient) -> bool {
        let mut work_done = false;
        let mut dpus_ready = true;
        let template_dir = self.config.template_dir.clone();

        if let Some(machine_id) = self.get_machine_id_opt() {
            let old_api_state = self.api_state.clone();
            let (api_state, reboot_requested) = get_api_state(&self.app_context, &machine_id).await;
            self.api_state = api_state;
            if reboot_requested && self.last_reboot.elapsed() > Duration::from_secs(60) {
                self.last_reboot = Instant::now();
                self.mat_state = MachineState::Init;
                return false;
            }
            if old_api_state != self.api_state {
                work_done = true;
            }
        }

        let mut logs = Vec::default();
        for dpu in self.dpu_machines.iter_mut() {
            work_done |= dpu.process_state(dhcp_client, &mut logs).await;
            dpus_ready &= dpu.get_state() == MachineState::MachineUp;
        }
        for l in logs {
            self.log(l);
        }

        // give the API time to update the host after the dpus did something
        if !self.dpus_previously_ready && dpus_ready {
            self.dpus_previously_ready = true;
            return true;
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
                            return false;
                        };

                        let listen_ip = dhcp_response_info.ip_address.to_string();
                        //let listen_ip = self.app_context.app_config.bmc_ip.clone();
                        self.update_dhcp_info(dhcp_response_info);
                        self.log(format!(
                            "BMC DHCP Request for {} took {}ms",
                            self.bmc_mac_address,
                            start.elapsed().as_millis()
                        ));

                        let cert_path = PathBuf::from(
                            self.app_context.forge_client_config.root_ca_path.clone(),
                        )
                        .parent()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap();

                        let add_ip_result = tokio::process::Command::new("/usr/bin/ip")
                            .args([
                                "a",
                                "add",
                                &listen_ip,
                                "dev",
                                &self.app_context.app_config.interface,
                            ])
                            .output()
                            .await;
                        if let Err(result) = add_ip_result {
                            tracing::warn!("Failed to add ip to interface: {result}");
                        }
                        let mut bmc = Bmc::new(
                            listen_ip,
                            self.app_context.app_config.bmc_starting_port,
                            self.config.host_bmc_redfish_template_dir.clone(),
                            cert_path,
                        );
                        bmc.start();
                        self.bmc = Some(bmc);
                        true
                    } else {
                        self.mat_state = MachineState::Init;
                        true
                    }
                }
                MachineState::Init => {
                    if self.machine_dhcp_info.is_none() {
                        let mac_address = self.dpu_machines.first().unwrap().host_mac_address;
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
                            return false;
                        };
                        self.update_dhcp_info(dhcp_response_info);

                        true
                    } else {
                        self.mat_state = MachineState::DhcpComplete;
                        true
                    }
                }
                MachineState::DhcpComplete => {
                    let first_mac_address = self.dpu_machines.first().unwrap().host_mac_address;
                    let mac_addresses = self
                        .dpu_machines
                        .iter()
                        .map(|dpus| dpus.host_mac_address.to_string())
                        .collect();

                    let machine_interface_id = rpc::Uuid::from(
                        self.machine_dhcp_info
                            .as_ref()
                            .cloned()
                            .unwrap()
                            .interface_id
                            .unwrap(),
                    );

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
                        return false;
                    };

                    self.log(format!(
                        "discover_machine took {}ms",
                        start.elapsed().as_millis()
                    ));
                    self.machine_discovery_result = Some(machine_discovery_result);
                    self.mat_state = MachineState::HardwareDiscoveryComplete;
                    true
                }
                MachineState::HardwareDiscoveryComplete => {
                    let machine_id = self.get_machine_id();
                    // let bmc_host_and_port =
                    //     format!("{}:{}", self.app_context.app_config.bmc_ip, self.bmc_port);
                    let Some(dhcp_info) = self.bmc_dhcp_info.as_ref() else {
                        tracing::warn!("missing dhcp_response_info");
                        return false;
                    };
                    let bmc_host_and_port = format!(
                        "{}:{}",
                        dhcp_info.ip_address, self.app_context.app_config.bmc_starting_port
                    );

                    // let bmc_host_and_port =
                    //     format!("{}:{}", self.app_context.app_config.bmc_ip, self.bmc_port);
                    let start = Instant::now();
                    if let Err(e) = api_client::update_bmc_metadata(
                        &self.app_context,
                        &template_dir,
                        rpc::forge::MachineType::Host,
                        machine_id,
                        Some(bmc_host_and_port),
                    )
                    .await
                    {
                        tracing::warn!("update_bmc_metadata failed: {e}");
                        return false;
                    }

                    self.log(format!(
                        "update_bmc_metadata took {}ms",
                        start.elapsed().as_millis()
                    ));

                    self.mat_state = MachineState::BmcUpdateComplete;
                    true
                }
                MachineState::BmcUpdateComplete => {
                    let machine_id = self.get_machine_id();
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
                        return false;
                    }
                    self.log(format!(
                        "discovery_complete took {}ms",
                        start.elapsed().as_millis()
                    ));

                    self.mat_state = MachineState::DiscoveryComplete;
                    true
                }
                MachineState::DiscoveryComplete => {
                    let machine_id = self.get_machine_id();
                    let start = Instant::now();
                    let action = get_fac_action(&self.app_context, machine_id.clone()).await;
                    self.log(format!(
                        "get action took {}ms; action={:?} (ignored)",
                        start.elapsed().as_millis(),
                        action,
                    ));

                    self.mat_state = MachineState::ControlComplete;
                    true
                }
                MachineState::ControlComplete => {
                    self.mat_state = MachineState::MachineUp;
                    true
                }
                MachineState::GetNetworkConfig => false,
                MachineState::MachineUp => {
                    let machine_id = self.get_machine_id();
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
                        true
                    } else {
                        false
                    }
                }
            }
        } else {
            false
        };

        if let Some(ui_event_tx) = self.ui_event_tx.as_ref() {
            if work_done {
                let details = HostDetails::from(self as &HostMachine);
                ui_event_tx
                    .send(UiEvent::MachineUpdate(details))
                    .await
                    .unwrap();
            }
        }
        work_done
    }

    pub fn get_machine_id(&self) -> rpc::forge::MachineId {
        self.get_machine_id_opt().unwrap()
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
                .unwrap()
                .host_mac_address
                .to_string(),
        }
    }
}
