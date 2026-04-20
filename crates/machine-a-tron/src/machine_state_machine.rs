/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::borrow::Cow;
use std::collections::VecDeque;
use std::convert::identity;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bmc_mock::{
    BmcCommand, BmcState, BootOptionKind, Callbacks, HostMachineInfo, HostnameQuerying,
    MachineInfo, MockPowerState, POWER_CYCLE_DELAY, SetSystemPowerError, SetSystemPowerResult,
    SystemPowerControl,
};
use carbide_network::virtualization::build_dual_stack_list;
use carbide_uuid::machine::MachineId;
use rpc::forge::{MachineArchitecture, MachineDiscoveryResult, ManagedHostNetworkConfigResponse};
use rpc::forge_agent_control_response::Action;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use uuid::Uuid;

use crate::api_client::{ClientApiError, DpuNetworkStatusArgs, MockDiscoveryData};
use crate::bmc_mock_wrapper::{BmcMockRegistry, BmcMockWrapper, BmcMockWrapperHandle};
use crate::config::{MachineATronContext, MachineConfig};
use crate::dhcp_wrapper::{
    DhcpRelayError, DhcpRelayResult, DhcpRequestInfo, DhcpResponseInfo, DpuDhcpRelay,
};
use crate::machine_fsm::{Action as FsmAction, DhcpType, Event, MachineFsm, Timer};
use crate::machine_state_machine::MachineStateError::MissingMachineId;
use crate::machine_utils::{
    PxeError, PxeResponse, forge_agent_control, get_fac_action, get_validation_id,
    send_pxe_boot_request,
};
use crate::{PersistedDpuMachine, PersistedHostMachine, dhcp_wrapper};

pub type DpuDhcpRelayHandle = oneshot::Sender<()>;

/// MachineStateMachine (yo dawg) models the state machine of a machine endpoint
///
/// This code is in common between DPUs and Hosts.(ie. anything that has a BMC, boots via DHCP, can
/// receive PXE instructions, etc.)
pub struct MachineStateMachine {
    pub live_state: Arc<RwLock<LiveState>>,
    pub machine_dhcp_id: Uuid,
    pub bmc_dhcp_id: Uuid,
    pub mat_host_id: Uuid,
    pub installed_os: OsImage,

    fsm: MachineFsm,
    bmc_mock: Option<Arc<BmcMockWrapperHandle>>,
    bmc_state: Option<BmcState>,
    power_cycle_deadline: Option<Instant>,
    machine_on_deadline: Option<Instant>,
    agent_polling_deadline: Option<(Instant, Timer)>,
    bmc_dhcp_info: Option<DhcpResponseInfo>,
    machine_dhcp_info: Option<DhcpResponseInfo>,
    machine_discovery_result: Option<MachineDiscoveryResult>,

    actions: VecDeque<FsmAction>,
    machine_info: MachineInfo,
    bmc_command_channel: mpsc::UnboundedSender<BmcCommand>,
    config: Arc<MachineConfig>,
    app_context: Arc<MachineATronContext>,
    dpu_dhcp_relay: Option<DpuDhcpRelay>,
    dpu_dhcp_relay_handle: Option<DpuDhcpRelayHandle>,
}

#[derive(Debug, Clone)]
pub struct LiveStateCallbacks {
    state: Arc<RwLock<LiveState>>,
    command_channel: mpsc::UnboundedSender<BmcCommand>,
}

impl LiveStateCallbacks {
    pub fn new(
        state: Arc<RwLock<LiveState>>,
        command_channel: mpsc::UnboundedSender<BmcCommand>,
    ) -> Self {
        Self {
            state,
            command_channel,
        }
    }
}

impl Callbacks for LiveStateCallbacks {
    fn get_power_state(&self) -> MockPowerState {
        self.state.read().unwrap().power_state
    }

    fn send_power_command(
        &self,
        reset_type: SystemPowerControl,
    ) -> Result<(), SetSystemPowerError> {
        self.command_channel
            .send(BmcCommand::SetSystemPower {
                request: reset_type,
                reply: None,
            })
            .map_err(|err| SetSystemPowerError::CommandSendError(err.to_string()))
    }

    fn state_refresh_indication(&self) {
        let _ = self
            .command_channel
            .send(BmcCommand::StateRefreshIndication);
    }
}

#[derive(Debug, Clone)]
pub struct LiveStateHostnameQuery(pub Arc<RwLock<LiveState>>);

impl HostnameQuerying for LiveStateHostnameQuery {
    fn get_hostname(&'_ self) -> Cow<'_, str> {
        self.0
            .read()
            .unwrap()
            .observed_machine_id
            .as_ref()
            .map(|id| Cow::Owned(id.to_string()))
            .unwrap_or(Cow::Borrowed("localhost"))
    }
}

/// Represents state which changes over time with this machine. This is kept in an `Arc<RwLock>` so
/// that callers can query it at any time. It is updated after every state transition.
#[derive(Debug)]
pub struct LiveState {
    pub is_up: bool,
    pub power_state: MockPowerState, // reflects the "desired" power state of the machine. Affects whether next_state will boot the machine or not.
    pub observed_machine_id: Option<MachineId>,
    pub machine_ip: Option<Ipv4Addr>,
    pub bmc_ip: Option<Ipv4Addr>,
    pub booted_os: MaybeOsImage,
    pub next_boot_kind: Option<BootOptionKind>,
    pub installed_os: OsImage,
    pub state_string: Option<&'static str>,
    pub api_state: String,
    pub tpm_ek_certificate: Option<Vec<u8>>,
    pub ssh_host_key: Option<String>,
}

impl Default for LiveState {
    fn default() -> Self {
        let power_state = MockPowerState::default();
        LiveState {
            is_up: matches!(power_state, MockPowerState::On),
            power_state: MockPowerState::default(),
            observed_machine_id: None,
            machine_ip: None,
            bmc_ip: None,
            booted_os: Default::default(),
            next_boot_kind: None,
            installed_os: Default::default(),
            state_string: None,
            api_state: "Unknown".to_string(),
            tpm_ek_certificate: None,
            ssh_host_key: None,
        }
    }
}

impl LiveState {
    pub fn ui_next_boot_kind(&self) -> &'static str {
        match self.next_boot_kind {
            Some(BootOptionKind::Disk) => "Disk",
            Some(BootOptionKind::Network) => "Network",
            None => "Unknown",
        }
    }
}

/// BmcRegistrationMode configures how each mock machine registers its BMC mock so that carbide can find it.
#[derive(Debug, Clone)]
pub enum BmcRegistrationMode {
    /// BackingInstance: Register the axum Router of the mock into a shared registry. This is used
    /// when running machine-a-tron as a kubernetes service, where we can only listen on a single
    /// IP/port but need to mock multiple BMC's. A shared BMC mock is expected to be running, and
    /// will delegate to these Routers for each BMC mock based on the `Forwarded` header in the
    /// request from carbide-api.
    BackingInstance(BmcMockRegistry),
    /// None: Don't register anything, but instead listen on the actual IP address given via DHCP.
    /// This is the most true-to-production mode, where we configure a real IP alias on a configured
    /// interface for every BMC mock, and carbide talks to the BMC's real IP address. It requires
    /// carbide to be able to reach these aliases, so it is only /// suitable for local use where
    /// carbide and machine-a-tron are on the same host.
    None(u16),
}

pub enum PersistedMachine {
    Host(PersistedHostMachine),
    Dpu(PersistedDpuMachine),
}

impl MachineStateMachine {
    pub fn from_persisted(
        persisted_machine: PersistedMachine,
        config: Arc<MachineConfig>,
        app_context: Arc<MachineATronContext>,
        bmc_command_channel: mpsc::UnboundedSender<BmcCommand>,
        dpu_dhcp_relay: Option<DpuDhcpRelay>,
        mat_host_id: Uuid,
    ) -> MachineStateMachine {
        let (initial_os_image, tpm_ek_certificate, bmc_dhcp_id, machine_dhcp_id, machine_info) =
            match persisted_machine {
                PersistedMachine::Host(h) => (
                    h.installed_os,
                    h.tpm_ek_certificate,
                    h.bmc_dhcp_id,
                    h.machine_dhcp_id,
                    MachineInfo::Host(HostMachineInfo {
                        hw_type: h.hw_type.unwrap_or_default(),
                        bmc_mac_address: h.bmc_mac_address,
                        serial: h.serial,
                        dpus: h.dpus.into_iter().map(Into::into).collect(),
                        non_dpu_mac_address: h.non_dpu_mac_address,
                    }),
                ),
                PersistedMachine::Dpu(d) => (
                    d.installed_os,
                    None,
                    d.bmc_dhcp_id,
                    d.machine_dhcp_id,
                    MachineInfo::Dpu(d.into()),
                ),
            };
        let (fsm, actions) = MachineFsm::init(true, Self::is_bmc_only(&machine_info, &config));
        MachineStateMachine {
            fsm,
            actions: actions.into_iter().collect(),
            bmc_mock: None,
            bmc_state: None,
            power_cycle_deadline: None,
            machine_on_deadline: None,
            agent_polling_deadline: None,
            bmc_dhcp_info: None,
            machine_dhcp_info: None,
            machine_discovery_result: None,
            installed_os: initial_os_image,
            live_state: Arc::new(RwLock::new(LiveState {
                power_state: MockPowerState::On,
                tpm_ek_certificate,
                ..Default::default()
            })),
            bmc_dhcp_id,
            machine_info,
            bmc_command_channel,
            machine_dhcp_id,
            config,
            app_context,
            dpu_dhcp_relay,
            dpu_dhcp_relay_handle: None,
            mat_host_id,
        }
    }

    pub fn new(
        machine_info: MachineInfo,
        config: Arc<MachineConfig>,
        app_context: Arc<MachineATronContext>,
        bmc_command_channel: mpsc::UnboundedSender<BmcCommand>,
        tpm_ek_certificate: Option<Vec<u8>>,
        dpu_dhcp_relay: Option<DpuDhcpRelay>,
        mat_host_id: Uuid,
    ) -> MachineStateMachine {
        let (fsm, actions) = MachineFsm::init(false, Self::is_bmc_only(&machine_info, &config));
        MachineStateMachine {
            live_state: Arc::new(RwLock::new(LiveState {
                power_state: MockPowerState::Off,
                tpm_ek_certificate,
                ..Default::default()
            })),
            fsm,
            actions: actions.into_iter().collect(),
            bmc_dhcp_info: None,
            bmc_mock: None,
            bmc_state: None,
            machine_dhcp_info: None,
            machine_discovery_result: None,
            machine_on_deadline: None,
            agent_polling_deadline: None,
            power_cycle_deadline: None,
            bmc_dhcp_id: Uuid::new_v4(),
            installed_os: OsImage::default(),
            machine_info,
            bmc_command_channel,
            machine_dhcp_id: Uuid::new_v4(),
            config,
            app_context,
            dpu_dhcp_relay,
            dpu_dhcp_relay_handle: None,
            mat_host_id,
        }
    }

    pub async fn advance(&mut self) -> Duration {
        if let Some(duration) = self.process_actions().await {
            duration
        } else {
            let now = Instant::now();
            if let Some(power_cycle_deadline) = self.power_cycle_deadline
                && now > power_cycle_deadline
            {
                self.power_cycle_deadline = None;
                self.fsm_event(Event::TimerAlert(Timer::PowerCycle));
            }
            if let Some(machine_on_deadline) = self.machine_on_deadline
                && now > machine_on_deadline
            {
                self.machine_on_deadline = None;
                self.fsm_event(Event::TimerAlert(Timer::MachineOn));
            }
            if let Some((agent_polling_deadline, timer)) = self.agent_polling_deadline
                && now > agent_polling_deadline
            {
                self.agent_polling_deadline = None;
                self.fsm_event(Event::TimerAlert(timer));
            }

            if let Some(duration) = self.process_actions().await {
                duration
            } else {
                [
                    self.machine_on_deadline,
                    self.power_cycle_deadline,
                    self.agent_polling_deadline.map(|v| v.0),
                ]
                .iter()
                .flatten()
                .min()
                .map(|nearest| nearest.saturating_duration_since(now))
                .unwrap_or(self.config.run_interval_idle)
            }
        }
    }

    pub async fn process_actions(&mut self) -> Option<Duration> {
        while let Some(action) = self.actions.front() {
            self.update_live_state();
            match action {
                FsmAction::SetupBmc => match self.setup_bmc().await {
                    Ok((bmc_mock, bmc_state)) => {
                        self.bmc_mock = bmc_mock;
                        self.bmc_state = Some(bmc_state);
                        self.actions.pop_front();
                    }
                    Err(_) => return Some(self.config.run_interval_working),
                },
                FsmAction::SetTimer(Timer::PowerCycle) => {
                    self.power_cycle_deadline = Some(Instant::now() + POWER_CYCLE_DELAY);
                    self.actions.pop_front();
                }
                FsmAction::SetTimer(Timer::MachineOn) => {
                    let delay = match self.machine_info {
                        MachineInfo::Dpu(_) => self.config.dpu_reboot_delay,
                        MachineInfo::Host(_) => self.config.host_reboot_delay,
                    };
                    self.machine_on_deadline = Some(Instant::now() + Duration::from_secs(delay));
                    self.actions.pop_front();
                }
                FsmAction::SetTimer(Timer::ScoutAgentControlPoll) => {
                    self.agent_polling_deadline = Some((
                        Instant::now() + self.config.scout_run_interval,
                        Timer::ScoutAgentControlPoll,
                    ));
                    self.actions.pop_front();
                }
                FsmAction::SetTimer(Timer::DpuAgentControlPoll) => {
                    self.agent_polling_deadline = Some((
                        Instant::now() + self.config.network_status_run_interval,
                        Timer::DpuAgentControlPoll,
                    ));
                    self.actions.pop_front();
                }
                FsmAction::Dhcp(DhcpType::Bmc) => match self.bmc_dhcp_discovery().await {
                    Ok(bmc_dhcp_info) => {
                        self.bmc_dhcp_info = Some(bmc_dhcp_info);
                        self.actions.pop_front();
                        self.fsm_event(Event::DhcpComplete(DhcpType::Bmc))
                    }
                    Err(_) => return Some(self.config.run_interval_working),
                },
                FsmAction::Dhcp(DhcpType::Machine) => match self.machine_dhcp_discovery().await {
                    Ok(machine_dhcp_info) => {
                        self.machine_dhcp_info = Some(machine_dhcp_info);
                        self.actions.pop_front();
                        self.fsm_event(Event::DhcpComplete(DhcpType::Machine))
                    }
                    Err(_) => return Some(self.config.run_interval_working),
                },
                FsmAction::PxeBootRequest => match self.pxe_boot_request().await {
                    Ok(os_image) => {
                        self.actions.pop_front();
                        self.fsm_event(Event::PxeComplete(os_image))
                    }
                    Err(_) => return Some(self.config.run_interval_working),
                },
                FsmAction::BmcEvent(event) => {
                    if let Some(bmc_state) = &self.bmc_state {
                        bmc_state.on_event(event)
                    }
                    self.actions.pop_front();
                }
                FsmAction::InitialDiscoveryRequest(os_image) => {
                    match self.initial_discovery_request(*os_image).await {
                        Ok(None) => {
                            self.actions.pop_front();
                            self.fsm_event(Event::MachineNotFound)
                        }
                        Ok(Some(machine_discovery_result)) => {
                            self.installed_os = *os_image;
                            self.machine_discovery_result = Some(machine_discovery_result);
                            self.actions.pop_front();
                            self.fsm_event(Event::InitialDiscoveryCompleted)
                        }
                        Err(_) => return Some(self.config.run_interval_working),
                    }
                }
                FsmAction::AgentControlRequest(os_image) => {
                    match self.agent_control_request(*os_image).await {
                        Ok(_) => {
                            self.actions.pop_front();
                            self.fsm_event(Event::AgentControlCompleted)
                        }
                        Err(MachineStateError::MachineNotFound(machine_id)) => {
                            tracing::warn!(%machine_id, "Machine not found during agent control, likely force deleted");
                            self.actions.pop_front();
                            self.fsm_event(Event::MachineNotFound)
                        }
                        Err(_) => return Some(self.config.run_interval_working),
                    }
                }
                FsmAction::DpuAgentNetworkObservation => {
                    match self.dpu_agent_network_observation().await {
                        Ok(maybe_dhcp_relay_handle) => {
                            if let Some(dhcp_relay_handle) = maybe_dhcp_relay_handle {
                                self.dpu_dhcp_relay_handle = Some(dhcp_relay_handle);
                            }
                            self.actions.pop_front();
                            self.fsm_event(Event::NetworkObservationCompleted)
                        }
                        Err(MachineStateError::MachineNotFound(machine_id)) => {
                            tracing::warn!(%machine_id, "Machine not found during network observation, likely force deleted");
                            self.actions.pop_front();
                            self.fsm_event(Event::MachineNotFound)
                        }
                        Err(_) => return Some(self.config.run_interval_working),
                    }
                }
                FsmAction::CleanupOnPowerOff => {
                    self.actions.pop_front();
                    self.machine_discovery_result = None;
                    self.dpu_dhcp_relay_handle = None;
                }
            }
        }
        self.update_live_state();
        None
    }

    fn fsm_event(&mut self, event: Event) {
        let old_state = self.fsm;
        let (new_state, actions) = self.fsm.event(event);
        tracing::info!(?old_state, ?event, ?new_state, ?actions, "machine FSM step");
        actions
            .into_iter()
            .for_each(|action| self.actions.push_back(action));
        self.fsm = new_state;
    }

    async fn setup_bmc(
        &self,
    ) -> Result<(Option<Arc<BmcMockWrapperHandle>>, BmcState), MachineStateError> {
        let Some(dhcp_info) = &self.bmc_dhcp_info else {
            return Err(MachineStateError::NoBmcDhcpInfo);
        };
        self.run_bmc_mock(dhcp_info.ip_address).await
    }

    async fn bmc_dhcp_discovery(&self) -> DhcpRelayResult<DhcpResponseInfo> {
        let start = Instant::now();
        dhcp_wrapper::request_ip(
            self.app_context.api_client(),
            DhcpRequestInfo {
                mac_address: self.machine_info.bmc_mac_address(),
                relay_address: self.config.oob_dhcp_relay_address,
                template_dir: self.config.template_dir.clone(),
            },
        )
        .await
        .inspect(|_| {
            tracing::debug!(
                "BMC DHCP Request for {} took {}ms",
                self.machine_info.bmc_mac_address(),
                start.elapsed().as_millis()
            );
        })
        .inspect_err(|err| {
            tracing::warn!(
                "BMC DHCP Request failed after {}ms: {err}",
                start.elapsed().as_millis()
            );
        })
    }

    async fn machine_dhcp_discovery(&self) -> Result<DhcpResponseInfo, MachineStateError> {
        let Some(primary_mac) = self.machine_info.dhcp_mac_addresses().first().copied() else {
            return Err(MachineStateError::NoMachineMacAddress);
        };

        tracing::debug!("Sending Admin DHCP Request for {}", primary_mac);
        let start = Instant::now();
        let machine_dhcp_info_result = if let Some(DpuDhcpRelay::HostEnd(relay_tx)) =
            &self.dpu_dhcp_relay
        {
            let (reply_tx, reply_rx) = oneshot::channel();
            match relay_tx.send(reply_tx).map_err(|_| {
                DhcpRelayError::DpuRelayError("Error sending request, channel closed".to_string())
            }) {
                Ok(_) => reply_rx
                    .await
                    .map_err(|_| {
                        DhcpRelayError::DpuRelayError(
                            "Error reading reply, channel closed".to_string(),
                        )
                    })
                    .and_then(identity),
                Err(err) => Err(err),
            }
        } else {
            dhcp_wrapper::request_ip(
                self.app_context.api_client(),
                DhcpRequestInfo {
                    mac_address: primary_mac,
                    relay_address: self.config.admin_dhcp_relay_address,
                    template_dir: self.config.template_dir.clone(),
                },
            )
            .await
        };
        machine_dhcp_info_result
            .inspect(|_| {
                tracing::debug!(
                    "Admin DHCP Request for {} took {}ms",
                    primary_mac,
                    start.elapsed().as_millis()
                );
            })
            .map_err(|err| {
                tracing::debug!(
                    "Admin DHCP Request for {} failed after {}ms: {err}",
                    primary_mac,
                    start.elapsed().as_millis()
                );
                err.into()
            })
    }

    async fn pxe_boot_request(&self) -> Result<OsImage, MachineStateError> {
        let Some(machine_interface_id) = self
            .machine_dhcp_info
            .as_ref()
            .and_then(|info| info.interface_id.as_ref())
        else {
            return Err(MachineStateError::MissingInterfaceId);
        };

        let (architecture, product) = match self.machine_info {
            MachineInfo::Dpu(_) => (
                MachineArchitecture::Arm,
                "Machine-A-Tron Bluefield".to_string(),
            ),
            MachineInfo::Host(_) => (
                MachineArchitecture::X86,
                "Machine-A-Tron X86 Host".to_string(),
            ),
        };

        let pxe_response = send_pxe_boot_request(
            &self.app_context,
            architecture,
            *machine_interface_id,
            Some(product),
            self.machine_dhcp_info
                .as_ref()
                .map(|info| info.ip_address.to_string()),
        )
        .await?;

        let os = match pxe_response {
            PxeResponse::Exit => self.installed_os,
            PxeResponse::Scout => OsImage::Scout,
            PxeResponse::DpuAgent => OsImage::DpuAgent,
        };
        match os {
            OsImage::None => Ok(os),
            OsImage::DpuAgent => {
                if matches!(self.machine_info, MachineInfo::Host(_)) {
                    Err(MachineStateError::WrongOsForMachine(
                        "ERROR: Running DpuAgent OS on a host machine, this should not happen."
                            .to_string(),
                    ))
                } else {
                    Ok(os)
                }
            }
            OsImage::Scout => {
                if matches!(self.machine_info, MachineInfo::Dpu(_)) {
                    tracing::warn!(
                        "ERROR: Running Scout OS on a DPU machine, this should not happen."
                    );
                    Err(MachineStateError::WrongOsForMachine(
                        "ERROR: Running Scout OS on a DPU machine, this should not happen."
                            .to_string(),
                    ))
                } else {
                    Ok(os)
                }
            }
        }
    }

    async fn initial_discovery_request(
        &self,
        os_image: OsImage,
    ) -> Result<Option<MachineDiscoveryResult>, MachineStateError> {
        let Some(machine_dhcp_info) = self.machine_dhcp_info.as_ref() else {
            return Err(MachineStateError::NoMachineDhcpInfo);
        };
        // No machine_discovery_result means we just booted. Run discovery now.
        tracing::trace!("Running initial discovery after boot");
        match self.run_machine_discovery(machine_dhcp_info).await {
            Ok(result) => {
                if os_image == OsImage::Scout {
                    let machine_id = result.machine_id.as_ref().ok_or(MissingMachineId)?;
                    // Inform the API that we have finished our reboot (ie. scout is now running)
                    self.app_context
                        .forge_api_client
                        .reboot_completed(*machine_id)
                        .await?;
                }
                Ok(Some(result))
            }
            Err(MachineStateError::ClientApi(ClientApiError::InvocationError(status))) => {
                match status.code() {
                    tonic::Code::InvalidArgument => {
                        tracing::error!(error=%status, "Invalid argument return by discovery, likely not ingested yet.");
                        Ok(None)
                    }
                    tonic::Code::NotFound => {
                        tracing::warn!(error=%status, "Machine not found in discovery, likely force deleted.");
                        Ok(None)
                    }
                    _ => Err(MachineStateError::ClientApi(
                        ClientApiError::InvocationError(status),
                    )),
                }
            }
            Err(e) => Err(e),
        }
    }

    async fn agent_control_request(&self, os_image: OsImage) -> Result<(), MachineStateError> {
        let machine_id = self
            .machine_discovery_result
            .as_ref()
            .and_then(|result| result.machine_id)
            .ok_or(MissingMachineId)?;

        // Ask the API server what to do next
        let start = Instant::now();
        let Some(control_response) = forge_agent_control(&self.app_context, machine_id).await
        else {
            return Err(MachineStateError::MachineNotFound(machine_id));
        };
        let action = get_fac_action(&control_response);
        tracing::trace!(
            "get action took {}ms; action={:?}",
            start.elapsed().as_millis(),
            action,
        );

        match action {
            Action::Discovery => self.send_discovery_complete(&machine_id).await?,
            Action::MachineValidation if os_image == OsImage::Scout => {
                if let Some(validation_id) = get_validation_id(&control_response) {
                    self.app_context
                        .api_client()
                        .machine_validation_complete(&machine_id, validation_id)
                        .await?;
                }
            }
            Action::Reset if os_image == OsImage::Scout => {
                tracing::debug!("Got Reset action in scout image, sending cleanup_complete");
                // Wait a bit before confirming the cleanup in order to mimic real
                // cleanup and give the tests a higher chance to observe teh cleanup state
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                self.app_context
                    .api_client()
                    .cleanup_complete(&machine_id)
                    .await?;
            }
            Action::Noop => {}
            _ => {
                tracing::warn!(
                    "Unknown action from forge_agent_control: {action:?} for OS image {os_image}"
                );
            }
        }
        Ok(())
    }
    pub async fn dpu_agent_network_observation(
        &self,
    ) -> Result<Option<DpuDhcpRelayHandle>, MachineStateError> {
        let machine_id = self
            .machine_discovery_result
            .as_ref()
            .and_then(|result| result.machine_id)
            .ok_or(MissingMachineId)?;

        let network_config = match self
            .app_context
            .forge_api_client
            .get_managed_host_network_config(machine_id)
            .await
        {
            Ok(config) => config,
            Err(status) if status.code() == tonic::Code::NotFound => {
                return Err(MachineStateError::MachineNotFound(machine_id));
            }
            Err(status) => return Err(status.into()),
        };

        // DPUs send network status periodically
        self.send_network_status_observation(machine_id.to_owned(), &network_config)
            .await?;

        // Launch a DHCP server for the HostMachine to call, if it's not already running.
        if let (Some(DpuDhcpRelay::DpuEnd(dhcp_relay)), true) = (
            self.dpu_dhcp_relay.clone(),
            self.dpu_dhcp_relay_handle.is_none(),
        ) {
            Ok(Some(dhcp_relay.spawn(network_config.clone())))
        } else {
            Ok(None)
        }
    }

    pub fn update_live_state(&self) {
        let mut live_state = self.live_state.write().unwrap();
        live_state.is_up = self.fsm.is_up();
        live_state.machine_ip = self.machine_ip();
        live_state.bmc_ip = self.bmc_ip();
        live_state.installed_os = self.installed_os;
        if let Some(machine_id) = self.machine_id()
            && live_state.observed_machine_id != Some(machine_id)
        {
            live_state.observed_machine_id = Some(machine_id)
        }
        live_state.state_string = Some(self.fsm.state_string());
        live_state.power_state = self.fsm.power_state();
        live_state.booted_os = self.booted_os();
        live_state.next_boot_kind = self
            .bmc_state
            .as_ref()
            .and_then(|state| state.system_state.resolve_current_boot_selection());
    }

    async fn run_machine_discovery(
        &self,
        machine_dhcp_info: &DhcpResponseInfo,
    ) -> Result<MachineDiscoveryResult, MachineStateError> {
        let Some(machine_interface_id) = machine_dhcp_info.interface_id else {
            return Err(MachineStateError::MissingInterfaceId);
        };

        let start = Instant::now();
        let tpm_ek_certificate = self.live_state.read().unwrap().tpm_ek_certificate.clone();
        let machine_discovery_result = self
            .app_context
            .api_client()
            .discover_machine(
                &self.machine_info,
                MockDiscoveryData {
                    machine_interface_id,
                    tpm_ek_certificate,
                },
            )
            .await?;

        tracing::trace!("discover_machine took {}ms", start.elapsed().as_millis());
        Ok(machine_discovery_result)
    }

    async fn send_network_status_observation(
        &self,
        machine_id: MachineId,
        network_config: &ManagedHostNetworkConfigResponse,
    ) -> Result<(), MachineStateError> {
        let mut instance_network_config_version: Option<String> = None;
        let instance_config_version: Option<String> = None;
        let mut interfaces = vec![];

        if network_config.use_admin_network {
            let iface = network_config
                .admin_interface
                .as_ref()
                .expect("use_admin_network true so admin_interface should be Some");
            let addresses = build_dual_stack_list(
                iface.ip.clone(),
                iface.ipv6_interface_config.as_ref().map(|v6| v6.ip.clone()),
            );
            let prefixes = build_dual_stack_list(
                iface.interface_prefix.clone(),
                iface
                    .ipv6_interface_config
                    .as_ref()
                    .map(|v6| v6.interface_prefix.clone()),
            );
            interfaces = vec![rpc::forge::InstanceInterfaceStatusObservation {
                function_type: iface.function_type,
                virtual_function_id: None,
                mac_address: self.machine_info.host_mac_address().map(|a| a.to_string()),
                addresses,
                prefixes,
                gateways: vec![iface.gateway.clone()],
                network_security_group: None,
                internal_uuid: None,
            }]
        } else {
            instance_network_config_version =
                Some(network_config.instance_network_config_version.clone());

            for iface in network_config.tenant_interfaces.iter() {
                let addresses = build_dual_stack_list(
                    iface.ip.clone(),
                    iface.ipv6_interface_config.as_ref().map(|v6| v6.ip.clone()),
                );
                let prefixes = build_dual_stack_list(
                    iface.interface_prefix.clone(),
                    iface
                        .ipv6_interface_config
                        .as_ref()
                        .map(|v6| v6.interface_prefix.clone()),
                );
                interfaces.push(rpc::forge::InstanceInterfaceStatusObservation {
                    function_type: iface.function_type,
                    virtual_function_id: iface.virtual_function_id,
                    mac_address: self.machine_info.host_mac_address().map(|a| a.to_string()),
                    addresses,
                    prefixes,
                    gateways: vec![iface.gateway.clone()],
                    network_security_group: iface.network_security_group.as_ref().map(|s| {
                        rpc::forge::NetworkSecurityGroupStatus {
                            source: s.source,
                            id: s.id.clone(),
                            version: s.version.clone(),
                        }
                    }),
                    internal_uuid: None,
                });
            }
        };

        self.app_context
            .api_client()
            .record_dpu_network_status(DpuNetworkStatusArgs {
                dpu_machine_id: machine_id,
                network_config_version: network_config.managed_host_config_version.clone(),
                instance_network_config_version,
                instance_config_version,
                instance_id: network_config.instance_id,
                interfaces,
                machine_config: &self.config,
            })
            .await?;
        Ok(())
    }

    pub fn set_system_power(&mut self, request: SystemPowerControl) -> SetSystemPowerResult {
        use SystemPowerControl::*;
        match request {
            On | ForceOn => self.fsm_event(Event::PowerOn),
            GracefulRestart | ForceRestart | PowerCycle => self.fsm_event(Event::PowerCycle),
            GracefulShutdown | ForceOff => self.fsm_event(Event::PowerOff),
            PushPowerButton | Nmi | Suspend | Pause | Resume => {
                let msg = format!("Machine-a-tron mock: unsupported power request {request:?}",);
                tracing::warn!("{msg}");
                return Err(SetSystemPowerError::BadRequest(msg));
            }
        };
        self.update_live_state();
        Ok(())
    }

    pub fn machine_id(&self) -> Option<MachineId> {
        self.machine_discovery_result
            .as_ref()
            .and_then(|result| result.machine_id)
    }

    pub fn machine_ip(&self) -> Option<Ipv4Addr> {
        self.machine_dhcp_info.as_ref().map(|v| v.ip_address)
    }

    pub fn bmc_ip(&self) -> Option<Ipv4Addr> {
        self.bmc_dhcp_info.as_ref().map(|v| v.ip_address)
    }

    pub fn booted_os(&self) -> MaybeOsImage {
        MaybeOsImage(self.fsm.booted_os())
    }

    async fn run_bmc_mock(
        &self,
        ip_address: Ipv4Addr,
    ) -> Result<(Option<Arc<BmcMockWrapperHandle>>, BmcState), MachineStateError> {
        let mut bmc_mock = BmcMockWrapper::new(
            self.machine_info.clone(),
            self.app_context.clone(),
            Arc::new(LiveStateCallbacks::new(
                self.live_state.clone(),
                self.bmc_command_channel.clone(),
            )),
            Arc::new(LiveStateHostnameQuery(self.live_state.clone())),
            self.mat_host_id,
        );

        let maybe_bmc_mock_handle = match &self.app_context.bmc_registration_mode {
            BmcRegistrationMode::None(port) => {
                let address = SocketAddr::new(ip_address.into(), *port);
                let handle = bmc_mock.start(address, true).await?;
                self.live_state.write().unwrap().ssh_host_key =
                    handle.ssh_handle.as_ref().map(|h| h.host_pubkey.clone());
                Some(Arc::new(handle))
            }
            BmcRegistrationMode::BackingInstance(registry) => {
                // Assume something has already launched a BMC-mock, our job is to just
                // insert this bmc-mock's router into the registry so it can delegate to it
                // by looking it up from the `Forwarded` header.
                registry
                    .write()
                    .await
                    .insert(ip_address.to_string(), bmc_mock.router().clone());
                None
            }
        };
        Ok((maybe_bmc_mock_handle, bmc_mock.state().clone()))
    }

    async fn send_discovery_complete(&self, machine_id: &MachineId) -> Result<(), ClientApiError> {
        let start = Instant::now();
        self.app_context
            .forge_api_client
            .discovery_completed(*machine_id)
            .await
            .map_err(ClientApiError::InvocationError)?;
        tracing::trace!("discovery_complete took {}ms", start.elapsed().as_millis());
        Ok(())
    }

    fn is_bmc_only(info: &MachineInfo, config: &MachineConfig) -> bool {
        matches!(info, MachineInfo::Dpu(_)) && config.dpus_in_nic_mode
    }
}

impl Display for MachineStateMachine {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.fsm.state_string().fmt(f)
    }
}

/// Represents the image that can be booted to via PXE or installed on-device
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OsImage {
    /// Default installed OS, will sleep forever when booted to.
    #[default]
    None,
    /// This is the carbide.efi image and should only run on DPUs. It can be run via PXE or installed.
    DpuAgent,
    /// This is the scout image and can be run on hosts via PXE but should not be installed
    Scout,
}

impl Display for OsImage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            OsImage::DpuAgent => f.write_str("Dpu Agent"),
            OsImage::Scout => f.write_str("Scout"),
            OsImage::None => f.write_str("No OS"),
        }
    }
}

#[derive(Debug, Default)]
pub struct MaybeOsImage(pub Option<OsImage>);

impl Display for MaybeOsImage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            None => f.write_str("<None>"),
            Some(os_image) => write!(f, "{os_image}"),
        }
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
    #[error("No DHCP info for BMC. This is bug.")]
    NoBmcDhcpInfo,
    #[error("No DHCP info for machine. This is bug.")]
    NoMachineDhcpInfo,
    #[error("Error configuring listening address: {0}")]
    ListenAddressConfigError(#[from] AddressConfigError),
    #[error("Could not find certificates at {0}")]
    MissingCertificates(String),
    #[error("Error calling forge API: {0}")]
    ClientApi(#[from] ClientApiError),
    #[error("Failed to get DHCP address: {0:?}")]
    DhcpError(#[from] DhcpRelayError),
    #[error("Failed to get PXE response: {0}")]
    PxeError(#[from] PxeError),
    #[error("BMC mock TLS error: {0}")]
    BmcMockTls(#[from] bmc_mock::tls::Error),
    #[error("Mock SSH server error: {0}")]
    MockSshServer(String),
    #[error("{0}")]
    WrongOsForMachine(String),
    #[error("Machine not found: {0}")]
    MachineNotFound(MachineId),
}
impl From<tonic::Status> for MachineStateError {
    fn from(err: tonic::Status) -> Self {
        MachineStateError::ClientApi(ClientApiError::InvocationError(err))
    }
}
#[derive(thiserror::Error, Debug)]
pub enum AddressConfigError {
    #[error("Error running ip command: {0}")]
    Io(#[from] std::io::Error),
    #[error("Error running ip command: {0:?}, output: {1:?}")]
    CommandFailure(Box<tokio::process::Command>, std::process::Output),
}
