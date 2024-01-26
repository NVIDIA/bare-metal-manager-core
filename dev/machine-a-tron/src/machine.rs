use std::{
    fmt::Display,
    sync::atomic::{AtomicU32, Ordering},
    time::Duration,
};

use rpc::{forge::ManagedHostNetworkConfigResponse, forge_agent_control_response::Action};
use tokio::time::Instant;

use crate::{api_client, AppConfig};

#[allow(dead_code)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MachineState {
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
    pub app_config: AppConfig,
    pub dpu_machines: Vec<DpuMachine>,
    pub machine_state: MachineState,
    pub dhcp_record: Option<rpc::forge::DhcpRecord>,
    pub machine_discovery_result: Option<rpc::forge::MachineDiscoveryResult>,
}

impl HostMachine {
    pub fn new(app_config: AppConfig) -> Self {
        let mut dpus = Vec::default();
        for _ in 0..app_config.num_dpus_per_host {
            dpus.push(DpuMachine::new(app_config.clone()));
        }

        HostMachine {
            app_config,
            dpu_machines: dpus,
            machine_state: MachineState::Init,
            dhcp_record: None,
            machine_discovery_result: None,
        }
    }

    pub fn get_machine_id(&self) -> rpc::forge::MachineId {
        if let Some(mdr) = self.machine_discovery_result.as_ref() {
            mdr.machine_id.as_ref().unwrap().clone()
        } else if let Some(machine_id) = self
            .dhcp_record
            .as_ref()
            .and_then(|dhcp_record| dhcp_record.machine_id.as_ref())
        {
            machine_id.clone()
        } else {
            rpc::forge::MachineId {
                id: String::default(),
            }
        }
    }

    pub async fn process_state(&mut self) -> bool {
        let mut work_done = false;
        let mut dpus_ready = true;
        for dpu in self.dpu_machines.iter_mut() {
            work_done |= dpu.process_state().await;
            dpus_ready &= dpu.get_state() == MachineState::MachineUp;
        }

        work_done |= if dpus_ready {
            match self.machine_state {
                MachineState::Init => {
                    let mac_address = self.dpu_machines[0].host_mac_address.clone();
                    self.dhcp_record = Some(
                        api_client::discover_dhcp(
                            &self.app_config,
                            mac_address,
                            self.app_config.circuit_id.clone(),
                        )
                        .await
                        .unwrap(),
                    );
                    self.machine_state = MachineState::DhcpComplete;
                    true
                }
                MachineState::DhcpComplete => {
                    let mac_address = self.dpu_machines[0].host_mac_address.clone();

                    let machine_interface_id = self
                        .dhcp_record
                        .as_ref()
                        .cloned()
                        .unwrap()
                        .machine_interface_id
                        .unwrap();
                    self.machine_discovery_result = Some(
                        api_client::discover_machine(
                            &self.app_config,
                            rpc::forge::MachineType::Host,
                            machine_interface_id,
                            vec![mac_address.clone()],
                            mac_address.replace(':', ""),
                            "".to_owned(),
                        )
                        .await
                        .unwrap(),
                    );

                    self.machine_state = MachineState::HardwareDiscoveryComplete;
                    true
                }
                MachineState::HardwareDiscoveryComplete => {
                    let machine_id = self.get_machine_id();
                    log_api_state(&self.app_config, &machine_id, &self.machine_state).await;
                    api_client::update_bmc_metadata(
                        &self.app_config,
                        rpc::forge::MachineType::Dpu,
                        machine_id,
                    )
                    .await
                    .unwrap();
                    self.machine_state = MachineState::BmcUpdateComplete;
                    true
                }
                MachineState::BmcUpdateComplete => {
                    let machine_id = self.get_machine_id();
                    get_fac_action(&self.app_config, machine_id.clone()).await;

                    api_client::discovery_complete(&self.app_config, machine_id)
                        .await
                        .unwrap();
                    self.machine_state = MachineState::DiscoveryComplete;
                    true
                }
                MachineState::DiscoveryComplete => {
                    let machine_id = self.get_machine_id();
                    get_fac_action(&self.app_config, machine_id.clone()).await;
                    log_api_state(&self.app_config, &machine_id, &self.machine_state).await;

                    self.machine_state = MachineState::ControlComplete;
                    true
                }
                MachineState::ControlComplete => {
                    let machine_id = self.get_machine_id();
                    log_api_state(&self.app_config, &machine_id, &self.machine_state).await;
                    self.machine_state = MachineState::MachineUp;
                    false
                }
                MachineState::GetNetworkConfig => false,
                MachineState::MachineUp => {
                    let machine_id = self.get_machine_id();
                    log_api_state(&self.app_config, &machine_id, &self.machine_state).await;

                    let action = get_fac_action(&self.app_config, machine_id.clone()).await;
                    if action == Action::Discovery {
                        self.machine_state = MachineState::DhcpComplete;
                        return true;
                    }
                    if reboot_requested(&self.app_config, &self.get_machine_id()).await {
                        self.machine_state = MachineState::Init;
                        true
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
}

#[derive(Debug, Clone)]
pub struct DpuMachine {
    pub app_config: AppConfig,
    machine_state: MachineState,
    pub mac_address: String,
    pub host_mac_address: String,
    pub dhcp_record: Option<rpc::forge::DhcpRecord>,
    pub machine_discovery_result: Option<rpc::forge::MachineDiscoveryResult>,
    pub last_network_status_update: Option<Instant>,
    pub network_config_response: Option<ManagedHostNetworkConfigResponse>,
}

impl DpuMachine {
    pub fn new(app_config: AppConfig) -> Self {
        DpuMachine {
            app_config,
            machine_state: MachineState::Init,
            mac_address: next_mac(),
            host_mac_address: next_mac(),
            dhcp_record: None,
            machine_discovery_result: None,
            last_network_status_update: None,
            network_config_response: None,
        }
    }

    pub fn get_machine_id(&self) -> rpc::forge::MachineId {
        if let Some(mdr) = self.machine_discovery_result.as_ref() {
            mdr.machine_id.as_ref().unwrap().clone()
        } else if let Some(machine_id) = self
            .dhcp_record
            .as_ref()
            .and_then(|dhcp_record| dhcp_record.machine_id.as_ref())
        {
            machine_id.clone()
        } else {
            rpc::forge::MachineId {
                id: String::default(),
            }
        }
    }

    pub async fn process_state(&mut self) -> bool {
        match self.machine_state {
            MachineState::Init => {
                self.dhcp_record = Some(
                    api_client::discover_dhcp(&self.app_config, self.mac_address.clone(), None)
                        .await
                        .unwrap(),
                );
                self.machine_state = MachineState::DhcpComplete;
                true
            }
            MachineState::DhcpComplete => {
                let machine_interface_id = self
                    .dhcp_record
                    .as_ref()
                    .unwrap()
                    .machine_interface_id
                    .as_ref()
                    .unwrap()
                    .clone();
                self.machine_discovery_result = Some(
                    api_client::discover_machine(
                        &self.app_config,
                        rpc::forge::MachineType::Dpu,
                        machine_interface_id,
                        vec![self.mac_address.clone()],
                        self.mac_address.replace(':', ""),
                        self.host_mac_address.clone(),
                    )
                    .await
                    .unwrap(),
                );

                self.machine_state = MachineState::HardwareDiscoveryComplete;
                true
            }
            MachineState::HardwareDiscoveryComplete => {
                let machine_id = self.get_machine_id();
                log_api_state(&self.app_config, &machine_id, &self.machine_state).await;
                api_client::update_bmc_metadata(
                    &self.app_config,
                    rpc::forge::MachineType::Dpu,
                    machine_id,
                )
                .await
                .unwrap();
                self.machine_state = MachineState::BmcUpdateComplete;
                true
            }

            MachineState::BmcUpdateComplete => {
                let machine_id = self.get_machine_id();
                api_client::discovery_complete(&self.app_config, machine_id)
                    .await
                    .unwrap();
                self.machine_state = MachineState::DiscoveryComplete;
                true
            }

            MachineState::DiscoveryComplete => {
                let machine_id = self.get_machine_id();
                get_fac_action(&self.app_config, machine_id).await;

                self.machine_state = MachineState::ControlComplete;
                true
            }
            MachineState::ControlComplete => {
                let machine_id = self.get_machine_id();
                let state = log_api_state(&self.app_config, &machine_id, &self.machine_state).await;
                if state == "DPU/WaitingForNetworkConfig" || state.starts_with("Host") {
                    self.machine_state = MachineState::GetNetworkConfig;
                    true
                } else {
                    false
                }
            }
            MachineState::GetNetworkConfig => {
                let network_config = api_client::get_managed_host_network_config(
                    &self.app_config,
                    self.get_machine_id(),
                )
                .await
                .unwrap();
                self.network_config_response = Some(network_config);

                if reboot_requested(&self.app_config, &self.get_machine_id()).await {
                    self.machine_state = MachineState::Init;
                } else {
                    self.machine_state = MachineState::MachineUp;
                }
                true
            }
            MachineState::MachineUp => {
                let elapsed = self
                    .last_network_status_update
                    .unwrap_or_else(|| Instant::now() - Duration::from_secs(10 * 60))
                    .elapsed();
                let version = self
                    .network_config_response
                    .as_ref()
                    .map(|config| config.managed_host_config_version.clone());
                let machine_id = self.get_machine_id();
                if elapsed > Duration::from_secs(60) {
                    api_client::record_dpu_network_status(
                        &self.app_config,
                        machine_id.clone(),
                        version,
                    )
                    .await
                    .unwrap();
                    self.last_network_status_update = Some(Instant::now());
                }
                let state = log_api_state(&self.app_config, &machine_id, &self.machine_state).await;

                if state == "DPU/INIT"
                    || reboot_requested(&self.app_config, &self.get_machine_id()).await
                {
                    self.machine_state = MachineState::Init;
                    true
                } else {
                    false
                }
            }
        }
    }

    pub fn get_state(&self) -> MachineState {
        self.machine_state.clone()
    }
}

impl Display for DpuMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = if let Some(dhcp_record) = self.dhcp_record.as_ref() {
            &dhcp_record.fqdn
        } else {
            &self.mac_address
        };

        write!(f, "{}: mac: {:?}", name, self.mac_address)?;

        if let Some(dhcp_record) = self.dhcp_record.as_ref() {
            write!(f, " ip: {}", dhcp_record.address)?;
            write!(f, " prefix: {}", dhcp_record.prefix)?;
        }
        Ok(())
    }
}

static NEXT_MAC_ADDRESS: AtomicU32 = AtomicU32::new(1);

fn next_mac() -> String {
    let next_mac_num = NEXT_MAC_ADDRESS.fetch_add(1, Ordering::Acquire);

    let mac_bytes: Vec<u8> = [0x02u8, 0x01]
        .into_iter()
        .chain(next_mac_num.to_be_bytes())
        .collect();

    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac_bytes[0], mac_bytes[1], mac_bytes[2], mac_bytes[3], mac_bytes[4], mac_bytes[5],
    )
}

async fn get_fac_action(
    app_config: &AppConfig,
    machine_id: rpc::forge::MachineId,
) -> rpc::forge::forge_agent_control_response::Action {
    let response = api_client::forge_agent_control(app_config, machine_id.clone())
        .await
        .unwrap();
    let action =
        rpc::forge::forge_agent_control_response::Action::try_from(response.action).unwrap();

    tracing::info!("{}: control action: {}", machine_id, action.as_str_name());

    action
}

async fn reboot_requested(app_config: &AppConfig, machine_id: &rpc::forge::MachineId) -> bool {
    let machine = api_client::get_machine(app_config, machine_id.clone())
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

async fn log_api_state(
    app_config: &AppConfig,
    machine_id: &rpc::forge::MachineId,
    local_state: &MachineState,
) -> String {
    let machine = api_client::get_machine(&app_config, machine_id.clone())
        .await
        .unwrap();

    if let Some(m) = machine {
        tracing::info!("{}: {} {}", machine_id, m.state, local_state);
        m.state
    } else {
        "".to_owned()
    }
}
