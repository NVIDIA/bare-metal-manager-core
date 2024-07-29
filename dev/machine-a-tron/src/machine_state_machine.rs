use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use mac_address::MacAddress;
use rand::Rng;
use tokio::sync::mpsc;
use tokio::time::Instant;
use uuid::Uuid;

use crate::api_client;
use crate::api_client::{record_dpu_network_status, ClientApiError, MockDiscoveryData};
use crate::bmc_mock_wrapper::{BmcMockAddressRegistry, BmcMockWrapper, ListenMode};
use crate::config::{MachineATronContext, MachineConfig};
use crate::dhcp_relay::{DhcpRelayClient, DhcpResponseInfo};
use crate::logging::LogSink;
use crate::machine_state_machine::MachineStateError::MissingMachineId;
use crate::machine_utils::{
    forge_agent_control, get_fac_action, get_validation_id, send_pxe_boot_request, PXEresponse,
};
use bmc_mock::{BmcCommand, MachineInfo};
use rpc::forge::{MachineArchitecture, MachineDiscoveryResult, MachineType};

/// MachineStateMachine (yo dawg) models the state machine of a machine endpoint
///
/// This code is in common between DPUs and Hosts.(ie. anything that has a BMC, boots via DHCP, can
/// receive PXE instructions, etc.)
#[derive(Debug)]
pub struct MachineStateMachine {
    state: MachineState,

    machine_info: MachineInfo,
    machine_dhcp_id: Uuid,
    bmc_dhcp_id: Uuid,
    bmc_command_channel: mpsc::UnboundedSender<BmcCommand>,

    config: MachineConfig,
    app_context: MachineATronContext,
    dhcp_client: DhcpRelayClient,
    logger: LogSink,
    bmc_address_registry: Option<BmcMockAddressRegistry>,
}

#[derive(Debug)]
pub enum MachineState {
    BmcInit,
    MachineDown(MachineDownState),
    Init(BmcInitializedState),
    DhcpComplete(DhcpCompleteState),
    HardwareDiscoveryComplete(HardwareDiscoveryCompleteState),
    MachineUp(MachineUpState),
}

enum NextState {
    Some(MachineState),
    SleepFor(Duration),
    UpdateAndDelay(MachineState, Duration),
}

impl MachineStateMachine {
    pub fn new(
        machine_info: MachineInfo,
        config: MachineConfig,
        app_context: MachineATronContext,
        dhcp_client: DhcpRelayClient,
        logger: LogSink,
        bmc_command_channel: mpsc::UnboundedSender<BmcCommand>,
        bmc_address_registry: Option<BmcMockAddressRegistry>,
    ) -> MachineStateMachine {
        MachineStateMachine {
            state: MachineState::BmcInit,
            machine_info,
            bmc_command_channel,
            machine_dhcp_id: Uuid::new_v4(),
            bmc_dhcp_id: Uuid::new_v4(),
            config,
            app_context,
            dhcp_client,
            logger,
            bmc_address_registry,
        }
    }

    pub async fn advance(&mut self, nic_available: bool) -> Duration {
        let next_state = self.next_state(nic_available).await;
        match next_state {
            Ok(NextState::Some(next_state)) => {
                self.state = next_state;
                self.config.run_interval_working
            }
            Ok(NextState::SleepFor(duration)) => duration,
            Ok(NextState::UpdateAndDelay(next_state, duration)) => {
                self.state = next_state;
                duration
            }
            Err(e) => {
                // TODO:
                // For now, any unhandled errors will just retry in the same state after sleeping
                // for a random interval (in this case, between 5 and 15 seconds.) Going forward we
                // should strive to emulate real machinese in these cases: For instance, failing to
                // get DHCP may mean we just boot to the host OS (ie. PXE boot failure), the correct
                // state for which depends on whether we've installed forge-agent or not, etc.
                self.logger
                    .error(format!("Error running state machine, will retry: {e}"));
                let jitter_ms = rand::thread_rng().gen::<u64>() % 10_000;
                Duration::from_millis(jitter_ms + 5_000)
            }
        }
    }

    async fn next_state(&self, nic_available: bool) -> Result<NextState, MachineStateError> {
        match &self.state {
            MachineState::BmcInit => {
                self.logger.debug(format!(
                    "Sending BMC DHCP Request for {}",
                    self.machine_info.bmc_mac_address(),
                ));
                let (response_tx, response_rx) = tokio::sync::oneshot::channel();
                let start = Instant::now();
                self.dhcp_client
                    .request_ip(
                        self.bmc_dhcp_id,
                        &self.machine_info.bmc_mac_address(),
                        &self.config.oob_dhcp_relay_address,
                        match self.machine_info {
                            MachineInfo::Host(_) => "iDRAC",
                            MachineInfo::Dpu(_) => "NVIDIA/BF/BMC",
                        },
                        self.config.template_dir.clone(),
                        response_tx,
                    )
                    .await;

                let Ok(Some(dhcp_info)) = response_rx.await else {
                    return Err(MachineStateError::DhcpError);
                };

                self.logger.info(format!(
                    "BMC DHCP Request for {} took {}ms",
                    self.machine_info.bmc_mac_address(),
                    start.elapsed().as_millis()
                ));

                let mut bmc_mock = if self.app_context.app_config.bmc_mock_dynamic_ports {
                    BmcMockWrapper::new(
                        self.machine_info.clone(),
                        self.bmc_command_channel.clone(),
                        self.app_context.clone(),
                        ListenMode::LocalhostWithDynamicPort,
                    )
                } else {
                    let address = SocketAddr::new(
                        dhcp_info.ip_address.into(),
                        self.app_context.app_config.bmc_mock_port,
                    );
                    BmcMockWrapper::new(
                        self.machine_info.clone(),
                        self.bmc_command_channel.clone(),
                        self.app_context.clone(),
                        ListenMode::SpecifiedAddress {
                            address,
                            add_ip_alias: true,
                        },
                    )
                };
                let listen_addr = bmc_mock.start().await?;

                // Inform the registry of this bmc-mock's address
                if let Some(registry) = self.bmc_address_registry.as_ref() {
                    registry
                        .write()
                        .await
                        .insert(dhcp_info.ip_address, listen_addr);
                }

                Ok(NextState::Some(MachineState::Init(BmcInitializedState {
                    bmc_mock: Arc::new(bmc_mock),
                    bmc_dhcp_info: dhcp_info,
                })))
            }
            MachineState::MachineDown(inner_state) => {
                let reboot_delay_secs = match self.machine_info {
                    MachineInfo::Dpu(_) => self.config.dpu_reboot_delay,
                    MachineInfo::Host(_) => self.config.host_reboot_delay,
                };
                let elapsed = inner_state.since.elapsed();
                let delay = Duration::from_secs(reboot_delay_secs);
                if elapsed >= delay {
                    Ok(NextState::Some(MachineState::Init(
                        inner_state.bmc_state.clone(),
                    )))
                } else {
                    Ok(NextState::SleepFor(delay - elapsed))
                }
            }
            MachineState::Init(inner_state) => {
                if !nic_available {
                    self.logger
                        .info("Machine NIC not available yet, not initializing".to_string());
                    return Ok(NextState::SleepFor(Duration::from_secs(5)));
                }
                let Some(primary_mac) = self.machine_info.dhcp_mac_addresses().first().cloned()
                else {
                    return Err(MachineStateError::NoMachineMacAddress);
                };
                self.logger
                    .debug(format!("Sending Admin DHCP Request for {}", primary_mac));
                let (response_tx, response_rx) = tokio::sync::oneshot::channel();
                let start = Instant::now();
                self.dhcp_client
                    .request_ip(
                        self.machine_dhcp_id,
                        &primary_mac,
                        &self.config.admin_dhcp_relay_address,
                        "PXEClient:Arch:00007:UNDI:003000",
                        self.config.template_dir.clone(),
                        response_tx,
                    )
                    .await;
                self.logger.info(format!(
                    "Admin DHCP Request for {} took {}ms",
                    primary_mac,
                    start.elapsed().as_millis()
                ));

                let Ok(Some(machine_dhcp_info)) = response_rx.await else {
                    return Err(MachineStateError::DhcpError);
                };

                let next_state = MachineState::DhcpComplete(DhcpCompleteState {
                    bmc_state: inner_state.clone(),
                    machine_dhcp_info,
                });
                Ok(NextState::Some(next_state))
            }
            MachineState::DhcpComplete(inner_state) => {
                let Some(machine_interface_id) = inner_state
                    .machine_dhcp_info
                    .interface_id
                    .as_ref()
                    .map(|u| rpc::Uuid {
                        value: u.to_string(),
                    })
                else {
                    return Err(MachineStateError::MissingInterfaceId);
                };

                let architecture = match self.machine_info {
                    MachineInfo::Dpu(_) => MachineArchitecture::Arm,
                    MachineInfo::Host(_) => MachineArchitecture::X86,
                };
                match send_pxe_boot_request(
                    &self.app_context,
                    architecture,
                    machine_interface_id.clone(),
                    Some(inner_state.machine_dhcp_info.ip_address.to_string()),
                )
                .await
                {
                    PXEresponse::Exit => {
                        let next_state = MachineState::MachineUp(MachineUpState {
                            machine_dhcp_info: inner_state.machine_dhcp_info.clone(),
                            bmc_state: inner_state.bmc_state.clone(),
                            machine_discovery_result: None,
                            last_network_status_update: None,
                        });
                        return Ok(NextState::Some(next_state));
                    }
                    PXEresponse::Error => {
                        return Err(MachineStateError::PxeError);
                    }
                    PXEresponse::Efi => {
                        // Continue to the next state
                    }
                }

                let start = Instant::now();
                let machine_discovery_result = api_client::discover_machine(
                    &self.app_context,
                    &self.config.template_dir,
                    rpc_machine_type(&self.machine_info),
                    MockDiscoveryData {
                        machine_interface_id,
                        network_interface_macs: self
                            .machine_info
                            .dhcp_mac_addresses()
                            .iter()
                            .map(MacAddress::to_string)
                            .collect(),
                        product_serial: self.machine_info.product_serial(),
                        chassis_serial: self.machine_info.chassis_serial(),
                        host_mac_address: self
                            .machine_info
                            .host_mac_address()
                            .map(|m| m.to_string()),
                    },
                )
                .await?;

                self.logger.info(format!(
                    "discover_machine took {}ms",
                    start.elapsed().as_millis()
                ));
                let next_state =
                    MachineState::HardwareDiscoveryComplete(HardwareDiscoveryCompleteState {
                        machine_discovery_result,
                        bmc_state: inner_state.bmc_state.clone(),
                        machine_dhcp_info: inner_state.machine_dhcp_info.clone(),
                    });
                Ok(NextState::Some(next_state))
            }
            MachineState::HardwareDiscoveryComplete(inner_state) => {
                let machine_id = self.machine_id()?;

                let start = Instant::now();
                api_client::update_bmc_metadata(
                    &self.app_context,
                    &self.config.template_dir,
                    rpc_machine_type(&self.machine_info),
                    machine_id.clone(),
                    inner_state.bmc_state.bmc_dhcp_info.ip_address,
                    self.machine_info.bmc_mac_address(),
                )
                .await?;

                self.logger.info(format!(
                    "update_bmc_metadata took {}ms",
                    start.elapsed().as_millis()
                ));

                let control_response =
                    forge_agent_control(&self.app_context, machine_id.clone()).await;
                let action = get_fac_action(&control_response);
                self.logger.info(format!(
                    "get action took {}ms; action={:?} (ignored)",
                    start.elapsed().as_millis(),
                    action,
                ));

                let start = Instant::now();
                api_client::discovery_complete(&self.app_context, machine_id.clone()).await?;
                self.logger.info(format!(
                    "discovery_complete took {}ms",
                    start.elapsed().as_millis()
                ));

                // Hosts will send a validation report after sending discovery info
                if let MachineInfo::Host(_) = self.machine_info {
                    let machine_id = self.machine_id()?;
                    let start = Instant::now();
                    let control_response =
                        forge_agent_control(&self.app_context, machine_id.clone()).await;
                    let action = get_fac_action(&control_response);
                    self.logger.info(format!(
                        "get action took {}ms; action={:?} (ignored)",
                        start.elapsed().as_millis(),
                        action,
                    ));

                    if let Some(validation_id) = get_validation_id(&control_response) {
                        api_client::machine_validation_complete(
                            &self.app_context,
                            machine_id,
                            validation_id,
                        )
                        .await?;
                    }
                }

                api_client::reboot_completed(&self.app_context, machine_id).await?;

                let next_state = MachineState::MachineUp(MachineUpState {
                    machine_dhcp_info: inner_state.machine_dhcp_info.clone(),
                    bmc_state: inner_state.bmc_state.clone(),
                    machine_discovery_result: Some(inner_state.machine_discovery_result.clone()),
                    last_network_status_update: None,
                });
                Ok(NextState::Some(next_state))
            }
            MachineState::MachineUp(inner_state) => {
                if let MachineInfo::Host(_) = self.machine_info {
                    // Hosts don't run forge-agent, return. We're now booted up, so we don't need to
                    // run again until we get rebooted.
                    return Ok(NextState::SleepFor(Duration::MAX));
                }

                let wait = match inner_state.last_network_status_update {
                    Some(instant) => {
                        let elapsed = instant.elapsed();
                        if elapsed >= self.config.network_status_run_interval {
                            Duration::default()
                        } else {
                            self.config.network_status_run_interval - elapsed
                        }
                    }
                    None => Duration::default(),
                };

                if wait > Duration::default() {
                    return Ok(NextState::SleepFor(wait));
                }

                let Ok(machine_id) = self.machine_id() else {
                    // When a DPU first boots it doesn't have a machine-id allocated yet. So we
                    // can't send any network config. Wait until we get rebooted.
                    return Ok(NextState::SleepFor(Duration::MAX));
                };

                let network_config = api_client::get_managed_host_network_config(
                    &self.app_context,
                    machine_id.clone(),
                )
                .await?;

                record_dpu_network_status(
                    &self.app_context,
                    machine_id.clone(),
                    network_config.managed_host_config_version,
                )
                .await?;

                let next_state = MachineState::MachineUp(MachineUpState {
                    last_network_status_update: Some(Instant::now()),
                    bmc_state: inner_state.bmc_state.clone(),
                    machine_dhcp_info: inner_state.machine_dhcp_info.clone(),
                    machine_discovery_result: inner_state.machine_discovery_result.clone(),
                });

                // Wake us up again to do more network status updates.
                Ok(NextState::UpdateAndDelay(
                    next_state,
                    self.config.network_status_run_interval,
                ))
            }
        }
    }

    pub fn power_down(&mut self) {
        let bmc_state = match &self.state {
            MachineState::BmcInit => return,
            MachineState::MachineDown(s) => &s.bmc_state,
            MachineState::Init(s) => s,
            MachineState::DhcpComplete(s) => &s.bmc_state,
            MachineState::HardwareDiscoveryComplete(s) => &s.bmc_state,
            MachineState::MachineUp(s) => &s.bmc_state,
        };
        self.state = MachineState::MachineDown(MachineDownState {
            since: Instant::now(),
            bmc_state: bmc_state.clone(),
        })
    }

    pub fn machine_id(&self) -> Result<rpc::MachineId, MachineStateError> {
        match &self.state {
            MachineState::BmcInit => None,
            MachineState::MachineDown(state) => state.bmc_state.bmc_dhcp_info.machine_id.as_ref(),
            MachineState::Init(state) => state.bmc_dhcp_info.machine_id.as_ref(),
            MachineState::DhcpComplete(state) => state.machine_dhcp_info.machine_id.as_ref(),
            MachineState::HardwareDiscoveryComplete(state) => state
                .machine_discovery_result
                .machine_id
                .as_ref()
                .or(state.machine_dhcp_info.machine_id.as_ref()),
            MachineState::MachineUp(state) => state
                .machine_discovery_result
                .as_ref()
                .and_then(|r| r.machine_id.as_ref())
                .or(state.machine_dhcp_info.machine_id.as_ref()),
        }
        .cloned()
        .ok_or(MissingMachineId)
    }

    pub fn machine_ip(&self) -> Option<Ipv4Addr> {
        match &self.state {
            MachineState::BmcInit => None,
            MachineState::MachineDown(_) => None,
            MachineState::Init(_) => None,
            MachineState::DhcpComplete(s) => Some(s.machine_dhcp_info.ip_address),
            MachineState::HardwareDiscoveryComplete(s) => Some(s.machine_dhcp_info.ip_address),
            MachineState::MachineUp(s) => Some(s.machine_dhcp_info.ip_address),
        }
    }

    pub fn bmc_ip(&self) -> Option<Ipv4Addr> {
        match &self.state {
            MachineState::BmcInit => None,
            MachineState::MachineDown(s) => Some(s.bmc_state.bmc_dhcp_info.ip_address),
            MachineState::Init(s) => Some(s.bmc_dhcp_info.ip_address),
            MachineState::DhcpComplete(s) => Some(s.bmc_state.bmc_dhcp_info.ip_address),
            MachineState::HardwareDiscoveryComplete(s) => {
                Some(s.bmc_state.bmc_dhcp_info.ip_address)
            }
            MachineState::MachineUp(s) => Some(s.bmc_state.bmc_dhcp_info.ip_address),
        }
    }

    /// Return the actual address that BmcMock is listening on, if it's up (this may be different than the assigned DHCP ID, like in integration tests.)
    pub fn bmc_mock_address(&self) -> Option<SocketAddr> {
        match &self.state {
            MachineState::BmcInit => None,
            MachineState::MachineDown(s) => s.bmc_state.bmc_mock.active_address(),
            MachineState::Init(s) => s.bmc_mock.active_address(),
            MachineState::DhcpComplete(s) => s.bmc_state.bmc_mock.active_address(),
            MachineState::HardwareDiscoveryComplete(s) => s.bmc_state.bmc_mock.active_address(),
            MachineState::MachineUp(s) => s.bmc_state.bmc_mock.active_address(),
        }
    }

    pub fn is_up(&self) -> bool {
        matches!(self.state, MachineState::MachineUp(_))
    }
}

// MARK: - Associated state definitions
#[derive(Debug, Clone)]
pub struct BmcInitializedState {
    bmc_dhcp_info: DhcpResponseInfo,
    bmc_mock: Arc<BmcMockWrapper>,
}

#[derive(Debug, Clone)]
pub struct MachineDownState {
    since: Instant,
    bmc_state: BmcInitializedState,
}

#[derive(Debug, Clone)]
pub struct DhcpCompleteState {
    machine_dhcp_info: DhcpResponseInfo,
    bmc_state: BmcInitializedState,
}

#[derive(Debug, Clone)]
pub struct HardwareDiscoveryCompleteState {
    machine_dhcp_info: DhcpResponseInfo,
    bmc_state: BmcInitializedState,
    machine_discovery_result: MachineDiscoveryResult,
}

#[derive(Debug, Clone)]
pub struct MachineUpState {
    machine_dhcp_info: DhcpResponseInfo,
    bmc_state: BmcInitializedState,
    machine_discovery_result: Option<MachineDiscoveryResult>,
    last_network_status_update: Option<Instant>,
}

impl Display for MachineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str_repr = match self {
            Self::BmcInit => "BmcInit",
            Self::MachineDown(_) => "MachineDown",
            Self::Init(_) => "Init",
            Self::DhcpComplete(_) => "DhcpComplete",
            Self::HardwareDiscoveryComplete(_) => "HardwareDiscoveryComplete",
            Self::MachineUp(_) => "MachineUp",
        };
        write!(f, "{str_repr}")
    }
}

impl Display for MachineStateMachine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.state.fmt(f)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum MachineStateError {
    #[error(
        "Invalid Machine state: Missing interface_id for this machine in machine discovery results"
    )]
    MissingInterfaceId,
    #[error(
        "Invalid Machine state: Missing machine_id for this machine in machine discovery results"
    )]
    MissingMachineId,
    #[error("No mac addresses specified for machine")]
    NoMachineMacAddress,
    #[error("Error configuring listening address: {0}")]
    ListenAddressConfigError(#[from] AddressConfigError),
    #[error("Could not find certificates at {0}")]
    MissingCertificates(String),
    #[error("Error calling forge API: {0}")]
    ClientApi(#[from] ClientApiError),
    #[error("Failed to get DHCP address")]
    DhcpError,
    #[error("Failed to get PXE response")]
    PxeError,
}

#[derive(thiserror::Error, Debug)]
pub enum AddressConfigError {
    #[error("Error running ip command: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Error running ip command: {0:?}, output: {1:?}")]
    CommandFailure(tokio::process::Command, std::process::Output),
}

fn rpc_machine_type(machine_info: &MachineInfo) -> MachineType {
    match machine_info {
        MachineInfo::Dpu(_) => MachineType::Dpu,
        MachineInfo::Host(_) => MachineType::Host,
    }
}
