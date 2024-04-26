use std::{collections::HashMap, fmt::Display};

use mac_address::MacAddress;
use rpc::forge_agent_control_response::Action;
use uuid::Uuid;

use crate::{
    api_client,
    config::{MachineATronContext, MachineConfig},
    dhcp_relay::{DhcpRelayClient, DhcpResponseInfo},
    dpu_machine::DpuMachine,
    machine_utils::{get_api_state, get_fac_action, next_mac, reboot_requested},
};

#[allow(dead_code)]
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

#[derive(Clone)]
pub struct HostMachine {
    pub mat_id: Uuid,
    pub config: MachineConfig,
    pub app_context: MachineATronContext,
    pub local_state: MachineState,
    pub api_state: String,

    pub machine_id: Option<rpc::forge::MachineId>,
    pub machine_discovery_result: Option<rpc::forge::MachineDiscoveryResult>,
    pub machine_dhcp_info: Option<DhcpResponseInfo>,
    pub dpu_machines: Vec<DpuMachine>,
    pub dpu_machine_index: HashMap<Uuid, usize>,

    pub bmc_mat_id: Uuid,
    pub bmc_mac_address: MacAddress,
    pub bmc_dhcp_info: Option<DhcpResponseInfo>,
}

impl Display for HostMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let machine_id = self
            .machine_id
            .as_ref()
            .map_or_else(|| "<unknown>".to_owned(), |id| id.id.clone());

        writeln!(f, "ID: {}", machine_id).unwrap();
        writeln!(f, "Local State: {}", self.local_state).unwrap();
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
            writeln!(
                f,
                "  {}: {} {} {}",
                dpu_index,
                dpu.get_machine_id_str(),
                dpu.local_state,
                dpu.api_state
            )
            .unwrap()
        }
        Ok(())
    }
}

impl HostMachine {
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
        let mut status = format!("Host {}: {} {}", name, state, self.local_state);

        for (dpu_index, dpu) in self.dpu_machines.iter().enumerate() {
            let dpu_state = dpu.get_state();
            status.push_str(&format!(
                "\n  DPU {}: {} {}",
                dpu_index, dpu.api_state, dpu_state
            ));
        }
        status
    }

    pub fn new(app_context: MachineATronContext, config: MachineConfig) -> Self {
        let mut dpus = Vec::default();
        let mut dpu_index = HashMap::default();

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
            machine_id: None,
            dpu_machines: dpus,
            dpu_machine_index: dpu_index,

            local_state: MachineState::BmcInit,
            api_state: "Unknown".to_owned(),

            machine_discovery_result: None,
            machine_dhcp_info: None,

            bmc_mat_id: Uuid::new_v4(),
            bmc_mac_address: next_mac(),
            bmc_dhcp_info: None,
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
                if let Some(d) = self.dpu_machine_index.get(&mat_id) {
                    if let Some(dpu) = self.dpu_machines.get_mut(*d) {
                        dpu.update_dhcp_record(dhcp_info);
                    } else {
                        tracing::warn!("Could not update dhcp info; missing dpu for id {}", mat_id);
                    }
                } else {
                    tracing::warn!("could not update dhcp info; unknown mat_id {}", mat_id);
                }
            }
        }
    }

    pub async fn process_state(&mut self, dhcp_client: &mut DhcpRelayClient) -> bool {
        let mut work_done = false;
        let mut dpus_ready = true;
        let template_dir = self.config.template_dir.as_str();

        if let Some(machine_id) = self.machine_id.as_ref() {
            self.api_state = get_api_state(&self.app_context, machine_id).await;
            tracing::info!("{}: current local state: {}", machine_id, self.local_state);
        }

        for dpu in self.dpu_machines.iter_mut() {
            work_done |= dpu.process_state(dhcp_client).await;
            dpus_ready &= dpu.get_state() == MachineState::MachineUp;
        }

        work_done |= if dpus_ready {
            match self.local_state {
                MachineState::BmcInit => {
                    if self.bmc_dhcp_info.is_none() {
                        tracing::info!(
                            "Host {}: Sending BMC DHCP Request for {}",
                            self.get_machine_id_str(),
                            self.bmc_mac_address
                        );
                        dhcp_client
                            .request_ip(
                                self.bmc_mat_id,
                                &self.bmc_mac_address,
                                &self.config.oob_dhcp_relay_address,
                                "iDRAC",
                                self.config.template_dir.clone(),
                                None,
                            )
                            .await;
                        false
                    } else {
                        self.local_state = MachineState::Init;
                        true
                    }
                }
                MachineState::Init => {
                    if self.machine_dhcp_info.is_none() {
                        let mac_address = self.dpu_machines.first().unwrap().host_mac_address;
                        tracing::info!(
                            "Host {}: Sending Admin DHCP Request for {}",
                            self.get_machine_id_str(),
                            mac_address
                        );
                        dhcp_client
                            .request_ip(
                                self.mat_id,
                                &mac_address,
                                &self.config.admin_dhcp_relay_address,
                                "PXEClient:Arch:00007:UNDI:003000",
                                self.config.template_dir.clone(),
                                None,
                            )
                            .await;
                        false
                    } else {
                        self.local_state = MachineState::DhcpComplete;
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

                    self.machine_discovery_result = Some(
                        api_client::discover_machine(
                            &self.app_context,
                            template_dir,
                            rpc::forge::MachineType::Host,
                            machine_interface_id,
                            mac_addresses,
                            first_mac_address.to_string().replace(':', ""),
                            "".to_owned(),
                        )
                        .await
                        .unwrap(),
                    );
                    self.machine_id = self
                        .machine_discovery_result
                        .as_ref()
                        .and_then(|mdr| mdr.machine_id.clone());

                    self.local_state = MachineState::HardwareDiscoveryComplete;
                    true
                }
                MachineState::HardwareDiscoveryComplete => {
                    if let Some(machine_id) = self.machine_id.clone() {
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
                    } else {
                        false
                    }
                }
                MachineState::BmcUpdateComplete => {
                    if let Some(machine_id) = self.machine_id.clone() {
                        get_fac_action(&self.app_context, machine_id.clone()).await;

                        api_client::discovery_complete(&self.app_context, machine_id)
                            .await
                            .unwrap();
                        self.local_state = MachineState::DiscoveryComplete;
                        true
                    } else {
                        tracing::info!("No machine id");
                        false
                    }
                }
                MachineState::DiscoveryComplete => {
                    if let Some(machine_id) = self.machine_id.as_ref() {
                        get_fac_action(&self.app_context, machine_id.clone()).await;

                        self.local_state = MachineState::ControlComplete;
                        true
                    } else {
                        tracing::info!("No machine id for host");
                        false
                    }
                }
                MachineState::ControlComplete => {
                    self.local_state = MachineState::MachineUp;
                    true
                }
                MachineState::GetNetworkConfig => false,
                MachineState::MachineUp => {
                    if let Some(machine_id) = self.machine_id.as_ref() {
                        let action = get_fac_action(&self.app_context, machine_id.clone()).await;
                        if action == Action::Discovery {
                            self.local_state = MachineState::DhcpComplete;
                            return true;
                        }
                        if reboot_requested(&self.app_context, machine_id).await {
                            self.local_state = MachineState::BmcInit;
                            true
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                }
            }
        } else {
            false
        };

        work_done
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
            None => self
                .dpu_machines
                .first()
                .unwrap()
                .host_mac_address
                .to_string(),
        }
    }
}
