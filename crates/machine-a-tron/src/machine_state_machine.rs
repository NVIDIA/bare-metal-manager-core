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
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bmc_mock::{
    BmcCommand, HostMachineInfo, HostnameQuerying, MachineInfo, MockPowerState, POWER_CYCLE_DELAY,
    PowerControl, SetSystemPowerError, SetSystemPowerResult, SystemPowerControl,
};
use carbide_uuid::machine::MachineId;
use mac_address::MacAddress;
use rand::Rng;
use rpc::forge::{
    MachineArchitecture, MachineDiscoveryResult, MachineType, ManagedHostNetworkConfigResponse,
};
use rpc::forge_agent_control_response::Action;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Instant;
use uuid::Uuid;

use crate::api_client::{ClientApiError, DpuNetworkStatusArgs, MockDiscoveryData};
use crate::bmc_mock_wrapper::{BmcMockRegistry, BmcMockWrapper, BmcMockWrapperHandle};
use crate::config::{MachineATronContext, MachineConfig};
use crate::dhcp_wrapper::{DhcpRelayError, DhcpRequestInfo, DhcpResponseInfo, DpuDhcpRelay};
use crate::machine_state_machine::MachineStateError::MissingMachineId;
use crate::machine_utils::{
    PxeError, PxeResponse, forge_agent_control, get_fac_action, get_validation_id,
    send_pxe_boot_request,
};
use crate::{PersistedDpuMachine, PersistedHostMachine, dhcp_wrapper};

/// MachineStateMachine (yo dawg) models the state machine of a machine endpoint
///
/// This code is in common between DPUs and Hosts.(ie. anything that has a BMC, boots via DHCP, can
/// receive PXE instructions, etc.)
#[derive(Debug)]
pub struct MachineStateMachine {
    pub live_state: Arc<RwLock<LiveState>>,
    pub initial_os_image: OsImage,
    pub machine_dhcp_id: Uuid,
    pub bmc_dhcp_id: Uuid,
    pub mat_host_id: Uuid,

    state: MachineState,
    machine_info: MachineInfo,
    bmc_command_channel: mpsc::UnboundedSender<BmcCommand>,
    config: Arc<MachineConfig>,
    app_context: Arc<MachineATronContext>,
    dpu_dhcp_relay: Option<DpuDhcpRelay>,
}

#[derive(Debug, Clone)]
pub struct LiveStatePowerControl {
    state: Arc<RwLock<LiveState>>,
    command_channel: mpsc::UnboundedSender<BmcCommand>,
}

impl LiveStatePowerControl {
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

impl PowerControl for LiveStatePowerControl {
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
    pub installed_os: OsImage,
    pub state_string: String,
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
            installed_os: Default::default(),
            state_string: MachineState::BmcInit.to_string(),
            api_state: "Unknown".to_string(),
            tpm_ek_certificate: None,
            ssh_host_key: None,
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

#[derive(Debug)]
enum MachineState {
    BmcInit,
    BmcOnly(BmcInitializedState),
    MachineDown(MachineDownState),
    Init(InitState),
    DhcpComplete(DhcpCompleteState),
    MachineUp(Box<MachineUpState>), // avoid large enum variants
}

enum NextState {
    Advance(MachineState),
    SleepFor(Duration),
    AdvanceAndSleepFor(MachineState, Duration),
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

        MachineStateMachine {
            state: MachineState::BmcInit,
            initial_os_image,
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
        MachineStateMachine {
            live_state: Arc::new(RwLock::new(LiveState {
                power_state: MockPowerState::Off,
                tpm_ek_certificate,
                ..Default::default()
            })),
            state: MachineState::BmcInit,
            bmc_dhcp_id: Uuid::new_v4(),
            initial_os_image: OsImage::default(),
            machine_info,
            bmc_command_channel,
            machine_dhcp_id: Uuid::new_v4(),
            config,
            app_context,
            dpu_dhcp_relay,
            mat_host_id,
        }
    }

    pub async fn advance(&mut self) -> Duration {
        if let MockPowerState::PowerCycling { since } = self.live_state.read().unwrap().power_state
        {
            let elapsed = since.elapsed();
            if elapsed > POWER_CYCLE_DELAY {
                self.live_state.write().unwrap().power_state = MockPowerState::On;
            } else {
                tracing::info!("Simulating 5-second power cycle");
                return POWER_CYCLE_DELAY - elapsed;
            }
        }

        let next_state = self.next_state().await;
        let duration = match next_state {
            Ok(NextState::Advance(next_state)) => {
                self.state = next_state;
                self.config.run_interval_working
            }
            Ok(NextState::SleepFor(duration)) => duration,
            Ok(NextState::AdvanceAndSleepFor(next_state, duration)) => {
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
                tracing::error!(
                    error = %e,
                    "Error running state machine, will retry",
                );
                let jitter_ms = rand::rng().random::<u64>() % 10_000;
                Duration::from_millis(jitter_ms + 5_000)
            }
        };

        // Update self.live_state with new values after every state transition
        {
            let mut live_state = self.live_state.write().unwrap();
            live_state.is_up = matches!(
                &self.state,
                MachineState::MachineUp(_) | MachineState::BmcOnly(_)
            );
            live_state.machine_ip = self.machine_ip();
            live_state.bmc_ip = self.bmc_ip();
            live_state.installed_os = self.installed_os();
            if let Some(machine_id) = self.machine_id()
                && live_state.observed_machine_id.as_ref() != Some(machine_id)
            {
                live_state.observed_machine_id = Some(*machine_id)
            }
            live_state.state_string = self.state.to_string();
            live_state.booted_os = self.booted_os();
        }

        duration
    }

    async fn next_state(&self) -> Result<NextState, MachineStateError> {
        match &self.state {
            MachineState::BmcInit => {
                tracing::trace!(
                    "Sending BMC DHCP Request for {}",
                    self.machine_info.bmc_mac_address(),
                );

                let start = Instant::now();
                let dhcp_info = dhcp_wrapper::request_ip(
                    self.app_context.api_client(),
                    DhcpRequestInfo {
                        mac_address: self.machine_info.bmc_mac_address(),
                        relay_address: self.config.oob_dhcp_relay_address,
                        template_dir: self.config.template_dir.clone(),
                    },
                )
                .await?;

                tracing::trace!(
                    "BMC DHCP Request for {} took {}ms",
                    self.machine_info.bmc_mac_address(),
                    start.elapsed().as_millis()
                );

                let maybe_bmc_mock_handle = self.run_bmc_mock(dhcp_info.ip_address).await?;

                if self.is_nic_mode_dpu() {
                    tracing::info!("DPU Running in NicMode, will only run BMC and not PXE boot");
                    Ok(NextState::Advance(MachineState::BmcOnly(
                        BmcInitializedState {
                            _bmc_mock_handle: maybe_bmc_mock_handle,
                            bmc_dhcp_info: dhcp_info,
                        },
                    )))
                } else {
                    let bmc_state = BmcInitializedState {
                        _bmc_mock_handle: maybe_bmc_mock_handle,
                        bmc_dhcp_info: dhcp_info,
                    };
                    Ok(NextState::Advance(
                        match self.live_state.read().unwrap().power_state {
                            MockPowerState::On => MachineState::Init(InitState {
                                bmc_state,
                                installed_os: self.initial_os_image,
                            }),
                            MockPowerState::Off | MockPowerState::PowerCycling { .. } => {
                                MachineState::MachineDown(MachineDownState {
                                    since: start,
                                    bmc_state,
                                    installed_os: self.initial_os_image,
                                    bmc_only: false,
                                })
                            }
                        },
                    ))
                }
            }
            MachineState::BmcOnly(_) => Ok(NextState::SleepFor(Duration::MAX)),
            MachineState::MachineDown(inner_state) => {
                match self.live_state.read().unwrap().power_state {
                    MockPowerState::Off => {
                        tracing::info!("Power is off, will wait for power signal");
                        return Ok(NextState::SleepFor(Duration::MAX));
                    }
                    MockPowerState::PowerCycling { since } => {
                        // Technically this should never be hit, since `advance()` will never call
                        // next_state until the delay is over and the power is back on.
                        tracing::info!("Power is cycling, will wait for a delay");
                        return Ok(NextState::SleepFor(POWER_CYCLE_DELAY - since.elapsed()));
                    }
                    _ => {}
                }
                let reboot_delay_secs = match self.machine_info {
                    MachineInfo::Dpu(_) => self.config.dpu_reboot_delay,
                    MachineInfo::Host(_) => self.config.host_reboot_delay,
                };
                let elapsed = inner_state.since.elapsed();
                let delay = Duration::from_secs(reboot_delay_secs);
                if elapsed >= delay {
                    Ok(NextState::Advance(inner_state.power_on()))
                } else {
                    Ok(NextState::SleepFor(delay - elapsed))
                }
            }
            MachineState::Init(inner_state) => {
                let Some(primary_mac) = self.machine_info.dhcp_mac_addresses().first().copied()
                else {
                    return Err(MachineStateError::NoMachineMacAddress);
                };
                tracing::debug!("Sending Admin DHCP Request for {}", primary_mac);

                let start = Instant::now();

                let machine_dhcp_info =
                    if let Some(DpuDhcpRelay::HostEnd(relay_tx)) = &self.dpu_dhcp_relay {
                        let (reply_tx, reply_rx) = oneshot::channel();
                        relay_tx.send(reply_tx).map_err(|_| {
                            DhcpRelayError::DpuRelayError(
                                "Error sending request, channel closed".to_string(),
                            )
                        })?;
                        reply_rx.await.map_err(|_| {
                            DhcpRelayError::DpuRelayError(
                                "Error reading reply, channel closed".to_string(),
                            )
                        })??
                    } else {
                        dhcp_wrapper::request_ip(
                            self.app_context.api_client(),
                            DhcpRequestInfo {
                                mac_address: primary_mac,
                                relay_address: self.config.admin_dhcp_relay_address,
                                template_dir: self.config.template_dir.clone(),
                            },
                        )
                        .await?
                    };
                tracing::debug!(
                    "Admin DHCP Request for {} took {}ms",
                    primary_mac,
                    start.elapsed().as_millis()
                );

                Ok(NextState::Advance(
                    inner_state.dhcp_complete(machine_dhcp_info),
                ))
            }
            MachineState::DhcpComplete(inner_state) => {
                let Some(machine_interface_id) = inner_state.machine_dhcp_info.interface_id else {
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
                    machine_interface_id,
                    Some(product),
                    Some(inner_state.machine_dhcp_info.ip_address.to_string()),
                )
                .await?;

                let booted_os = match pxe_response {
                    PxeResponse::Exit => inner_state.installed_os,
                    PxeResponse::Scout => OsImage::Scout,
                    PxeResponse::DpuAgent => OsImage::DpuAgent,
                };

                Ok(NextState::Advance(inner_state.machine_up(booted_os)))
            }
            MachineState::MachineUp(inner_state) => match inner_state.booted_os {
                OsImage::DpuAgent => self.run_dpu_agent_iteration(inner_state).await,
                OsImage::Scout => self.run_scout_iteration(inner_state).await,
                // Now we install bfb via redfish, so this is expected.
                OsImage::None if matches!(self.machine_info, MachineInfo::Dpu(_)) => {
                    self.run_scout_iteration(inner_state).await
                }
                OsImage::None => {
                    tracing::debug!("Host booted to tenant OS");
                    Ok(NextState::SleepFor(Duration::MAX))
                }
            },
        }
    }

    /// Pretend we're the Dpu Agent image (carbide.efi), performing discovery and sending network health checks
    async fn run_dpu_agent_iteration(
        &self,
        machine_up_state: &MachineUpState,
    ) -> Result<NextState, MachineStateError> {
        if matches!(self.machine_info, MachineInfo::Host(_)) {
            return Err(MachineStateError::WrongOsForMachine(
                "ERROR: Running DpuAgent OS on a host machine, this should not happen.".to_string(),
            ));
        }

        // Run discovery once to get the machine ID
        let Some(machine_discovery_result) = machine_up_state.machine_discovery_result.as_ref()
        else {
            // No machine_discovery_result means we just booted. Run discovery now.
            let machine_discovery_result = match self
                .run_machine_discovery(&machine_up_state.machine_dhcp_info)
                .await
            {
                Ok(result) => result,
                Err(MachineStateError::ClientApi(ClientApiError::InvocationError(status))) => {
                    return match status.code() {
                        tonic::Code::InvalidArgument => {
                            tracing::error!(error=%status, "Invalid argument running dpu agent iteration, likely not ingested yet. Will sleep until we are rebooted");
                            Ok(NextState::SleepFor(Duration::MAX))
                        }
                        _ => Err(MachineStateError::ClientApi(
                            ClientApiError::InvocationError(status),
                        )),
                    };
                }
                Err(e) => return Err(e),
            };
            // Put the DpuAgent image as the installed_os so that we can boot to it when PXE tells us to local.
            return Ok(NextState::Advance(
                machine_up_state
                    .install_os_with_discovery_result(OsImage::DpuAgent, machine_discovery_result),
            ));
        };

        let machine_id = machine_discovery_result
            .machine_id
            .as_ref()
            .ok_or(MissingMachineId)?;

        // Ask the API server what to do next
        let start = Instant::now();
        let control_response = forge_agent_control(&self.app_context, *machine_id).await;
        let action = get_fac_action(&control_response);
        tracing::trace!(
            "get action took {}ms; action={:?}",
            start.elapsed().as_millis(),
            action,
        );

        match action {
            Action::Discovery => self.send_discovery_complete(machine_id).await?,
            Action::Noop => {}
            _ => {
                tracing::warn!(
                    "Dpu agent got unknown action from forge_agent_control: {:?}",
                    action
                );
            }
        }

        let network_config = self
            .app_context
            .forge_api_client
            .get_managed_host_network_config(*machine_id)
            .await?;

        // DPUs send network status periodically
        self.send_network_status_observation(machine_id.to_owned(), &network_config)
            .await?;

        // Launch a DHCP server for the HostMachine to call, if it's not already running.
        if let (Some(DpuDhcpRelay::DpuEnd(dhcp_relay)), true) = (
            self.dpu_dhcp_relay.clone(),
            machine_up_state.dpu_dhcp_relay_handle.is_none(),
        ) {
            // The relay will stop when this is dropped (ie. when we move out of `MachineUp`)
            let relay_handle = dhcp_relay.spawn(network_config.clone());
            Ok(NextState::AdvanceAndSleepFor(
                MachineState::MachineUp(
                    machine_up_state
                        .with_dpu_dhcp_relay_handle(relay_handle)
                        .into(),
                ),
                self.config.network_status_run_interval,
            ))
        } else {
            Ok(NextState::SleepFor(self.config.network_status_run_interval))
        }
    }

    /// Pretend we're the Scout image (which hosts can PXE boot too but don't install), which performs discovery and periodically runs actions via ForgeAgentControl.
    async fn run_scout_iteration(
        &self,
        machine_up_state: &MachineUpState,
    ) -> Result<NextState, MachineStateError> {
        if matches!(self.machine_info, MachineInfo::Dpu(_)) {
            tracing::warn!("ERROR: Running Scout OS on a DPU machine, this should not happen.");
            return Ok(NextState::Advance(MachineState::MachineDown(
                MachineDownState {
                    since: Instant::now(),
                    bmc_state: machine_up_state.bmc_state.clone(),
                    installed_os: machine_up_state.installed_os,
                    bmc_only: false,
                },
            )));
        }

        let Some(machine_discovery_result) = machine_up_state.machine_discovery_result.as_ref()
        else {
            // No machine_discovery_result means scout has not yet run this boot. Run discovery now.
            tracing::trace!("Running initial discovery after boot");
            let machine_discovery_result = match self
                .run_machine_discovery(&machine_up_state.machine_dhcp_info)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(error=%e, "Error running discovery after booting scout image. Will sleep until we are rebooted");
                    return Ok(NextState::SleepFor(Duration::MAX));
                }
            };
            let machine_id = machine_discovery_result
                .machine_id
                .as_ref()
                .ok_or(MissingMachineId)?;

            // Inform the API that we have finished our reboot (ie. scout is now running)
            self.app_context
                .forge_api_client
                .reboot_completed(*machine_id)
                .await?;

            return Ok(NextState::Advance(
                machine_up_state
                    .install_os_with_discovery_result(OsImage::None, machine_discovery_result),
            ));
        };

        let machine_id = machine_discovery_result
            .machine_id
            .as_ref()
            .ok_or(MissingMachineId)?;

        // Ask the API server what to do next
        let start = Instant::now();
        let control_response = forge_agent_control(&self.app_context, *machine_id).await;
        let action = get_fac_action(&control_response);
        tracing::trace!(
            "get action took {}ms; action={:?}",
            start.elapsed().as_millis(),
            action,
        );

        match action {
            Action::Discovery => self.send_discovery_complete(machine_id).await?,
            Action::MachineValidation => {
                if let Some(validation_id) = get_validation_id(&control_response) {
                    self.app_context
                        .api_client()
                        .machine_validation_complete(machine_id, validation_id)
                        .await?;
                }
            }
            Action::Reset => {
                tracing::debug!("Got Reset action in scout image, sending cleanup_complete");
                // Wait a bit before confirming the cleanup in order to mimic real
                // cleanup and give the tests a higher chance to observe teh cleanup state
                tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                self.app_context
                    .api_client()
                    .cleanup_complete(machine_id)
                    .await?;
            }
            Action::Noop => {}
            _ => {
                tracing::warn!(
                    "Scout image got unknown action from forge_agent_control: {:?}",
                    action
                );
            }
        }

        Ok(NextState::SleepFor(self.config.scout_run_interval))
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
                    product_serial: Some(self.machine_info.product_serial().clone()),
                    chassis_serial: Some("Unspecified Chassis Board Serial Number".to_string()),
                    host_mac_address: self.machine_info.host_mac_address(),
                    tpm_ek_certificate,
                    dpu_nic_version: if let MachineInfo::Dpu(d) = &self.machine_info {
                        d.firmware_versions.nic.clone()
                    } else {
                        None
                    },
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
            interfaces = vec![rpc::forge::InstanceInterfaceStatusObservation {
                function_type: iface.function_type,
                virtual_function_id: None,
                mac_address: self.machine_info.host_mac_address().map(|a| a.to_string()),
                addresses: vec![iface.ip.clone()],
                prefixes: vec![iface.interface_prefix.clone()],
                gateways: vec![iface.gateway.clone()],
                network_security_group: None,
                internal_uuid: None,
            }]
        } else {
            instance_network_config_version =
                Some(network_config.instance_network_config_version.clone());

            for iface in network_config.tenant_interfaces.iter() {
                interfaces.push(rpc::forge::InstanceInterfaceStatusObservation {
                    function_type: iface.function_type,
                    virtual_function_id: iface.virtual_function_id,
                    mac_address: self.machine_info.host_mac_address().map(|a| a.to_string()),
                    addresses: vec![iface.ip.clone()],
                    prefixes: vec![iface.interface_prefix.clone()],
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
        let bmc_only = self.is_nic_mode_dpu();
        use SystemPowerControl::*;
        let (new_machine_state, new_power_state) = match (
            request,
            self.live_state.read().unwrap().power_state,
        ) {
            // If we're off and we get an on or power-cycle signal, turn on.
            // Ditto if we're on and get a power-cycle or restart signal.
            (On | ForceOn | PushPowerButton | PowerCycle, power_state @ MockPowerState::Off)
            | (PowerCycle | GracefulRestart | ForceRestart, power_state @ MockPowerState::On) => {
                if matches!(power_state, MockPowerState::Off) {
                    tracing::debug!("Powering on machine");
                } else {
                    tracing::debug!("Power cycling machine");
                }

                let new_power_state = match request {
                    PowerCycle => MockPowerState::PowerCycling {
                        since: Instant::now(),
                    },
                    _ => MockPowerState::On,
                };

                // If we haven't initialized the BMC yet, no-op, as we haven't booted yet either.
                let maybe_machine_state = self.bmc_state().map(|bmc_state| {
                    // Set the time the machine has been down since to now, so that reboot_delay is respected.
                    MachineState::MachineDown(MachineDownState {
                        since: Instant::now(),
                        bmc_state: bmc_state.clone(),
                        installed_os: self.installed_os(),
                        bmc_only,
                    })
                });

                (maybe_machine_state, new_power_state)
            }
            (GracefulShutdown | ForceOff | PushPowerButton, MockPowerState::On) => {
                tracing::debug!("Powering off machine");
                let maybe_machine_state = self.bmc_state().map(|bmc_state| {
                    MachineState::MachineDown(MachineDownState {
                        since: Instant::now(),
                        bmc_state: bmc_state.clone(),
                        installed_os: self.installed_os(),
                        bmc_only,
                    })
                });
                (maybe_machine_state, MockPowerState::Off)
            }
            (GracefulShutdown | ForceOff | GracefulRestart | ForceRestart, MockPowerState::Off) => {
                let msg =
                    "Machine-a-tron mock: cannot power off machine, it is already off".to_string();
                tracing::warn!("{msg}");
                return Err(SetSystemPowerError::BadRequest(msg));
            }
            (On | ForceOn, MockPowerState::On) => {
                let msg =
                    "Machine-a-tron mock: cannot power on machine, it is already on".to_string();
                tracing::warn!("{msg}");
                return Err(SetSystemPowerError::BadRequest(msg));
            }
            (Nmi | Suspend | Pause | Resume, _) => {
                let msg = format!("Machine-a-tron mock: unsupported power request {request:?}",);
                tracing::warn!("{msg}");
                return Err(SetSystemPowerError::BadRequest(msg));
            }
            (request, MockPowerState::PowerCycling { .. }) => {
                let msg = format!(
                    "Machine-a-tron mock: Got power request while in the middle of power cycling {request:?}"
                );
                tracing::warn!("{msg}");
                return Err(SetSystemPowerError::BadRequest(msg));
            }
        };

        self.live_state.write().unwrap().power_state = new_power_state;
        if let Some(new_machine_state) = new_machine_state {
            self.state = new_machine_state;
        }

        Ok(())
    }

    pub fn machine_id(&self) -> Option<&MachineId> {
        match &self.state {
            MachineState::BmcInit | MachineState::BmcOnly(_) => None,
            MachineState::MachineDown(_) => None,
            MachineState::Init(_) => None,
            MachineState::DhcpComplete(_) => None,
            MachineState::MachineUp(s) => s
                .machine_discovery_result
                .as_ref()
                .and_then(|m| m.machine_id.as_ref()),
        }
    }

    pub fn machine_ip(&self) -> Option<Ipv4Addr> {
        match &self.state {
            MachineState::BmcInit | MachineState::BmcOnly(_) => None,
            MachineState::MachineDown(_) => None,
            MachineState::Init(_) => None,
            MachineState::DhcpComplete(s) => Some(s.machine_dhcp_info.ip_address),
            MachineState::MachineUp(s) => Some(s.machine_dhcp_info.ip_address),
        }
    }

    pub fn bmc_ip(&self) -> Option<Ipv4Addr> {
        self.bmc_state().map(|b| b.bmc_dhcp_info.ip_address)
    }

    pub fn booted_os(&self) -> MaybeOsImage {
        if let MachineState::MachineUp(machine_up_state) = &self.state {
            MaybeOsImage(Some(machine_up_state.booted_os))
        } else {
            MaybeOsImage(None)
        }
    }

    fn bmc_state(&self) -> Option<&BmcInitializedState> {
        let bmc_state = match &self.state {
            MachineState::BmcInit => return None,
            MachineState::BmcOnly(s) => s,
            MachineState::MachineDown(s) => &s.bmc_state,
            MachineState::Init(s) => &s.bmc_state,
            MachineState::DhcpComplete(s) => &s.bmc_state,
            MachineState::MachineUp(s) => &s.bmc_state,
        };
        Some(bmc_state)
    }

    pub fn installed_os(&self) -> OsImage {
        match &self.state {
            MachineState::BmcInit | MachineState::BmcOnly(_) => self.initial_os_image,
            MachineState::MachineDown(s) => s.installed_os,
            MachineState::Init(s) => s.installed_os,
            MachineState::DhcpComplete(s) => s.installed_os,
            MachineState::MachineUp(s) => s.installed_os,
        }
    }

    async fn run_bmc_mock(
        &self,
        ip_address: Ipv4Addr,
    ) -> Result<Option<Arc<BmcMockWrapperHandle>>, MachineStateError> {
        let mut bmc_mock = BmcMockWrapper::new(
            self.machine_info.clone(),
            self.app_context.clone(),
            Arc::new(LiveStatePowerControl::new(
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
        Ok(maybe_bmc_mock_handle)
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

    fn is_nic_mode_dpu(&self) -> bool {
        matches!(self.machine_info, MachineInfo::Dpu(_)) && self.config.dpus_in_nic_mode
    }
}

// MARK: - Associated state definitions
#[derive(Debug, Clone)]
struct BmcInitializedState {
    bmc_dhcp_info: DhcpResponseInfo,
    _bmc_mock_handle: Option<Arc<BmcMockWrapperHandle>>,
}

#[derive(Debug, Clone)]
struct MachineDownState {
    since: Instant,
    bmc_state: BmcInitializedState,
    installed_os: OsImage,
    bmc_only: bool,
}

impl MachineDownState {
    fn power_on(&self) -> MachineState {
        if self.bmc_only {
            MachineState::BmcOnly(self.bmc_state.clone())
        } else {
            MachineState::Init(InitState {
                bmc_state: self.bmc_state.clone(),
                installed_os: self.installed_os,
            })
        }
    }
}

#[derive(Debug, Clone)]
struct InitState {
    bmc_state: BmcInitializedState,
    installed_os: OsImage,
}

impl InitState {
    fn dhcp_complete(&self, machine_dhcp_info: DhcpResponseInfo) -> MachineState {
        MachineState::DhcpComplete(DhcpCompleteState {
            machine_dhcp_info,
            bmc_state: self.bmc_state.clone(),
            installed_os: self.installed_os,
        })
    }
}

#[derive(Debug, Clone)]
struct DhcpCompleteState {
    machine_dhcp_info: DhcpResponseInfo,
    bmc_state: BmcInitializedState,
    installed_os: OsImage,
}

impl DhcpCompleteState {
    fn machine_up(&self, os: OsImage) -> MachineState {
        MachineState::MachineUp(
            MachineUpState {
                machine_dhcp_info: self.machine_dhcp_info.clone(),
                bmc_state: self.bmc_state.clone(),
                machine_discovery_result: None,
                booted_os: os,
                installed_os: self.installed_os,
                dpu_dhcp_relay_handle: None,
            }
            .into(),
        )
    }
}

#[derive(Debug)]
struct MachineUpState {
    machine_dhcp_info: DhcpResponseInfo,
    bmc_state: BmcInitializedState,
    machine_discovery_result: Option<MachineDiscoveryResult>,
    booted_os: OsImage,
    installed_os: OsImage,
    dpu_dhcp_relay_handle: Option<oneshot::Sender<()>>,
}

impl MachineUpState {
    fn with_dpu_dhcp_relay_handle(&self, handle: oneshot::Sender<()>) -> Self {
        Self {
            machine_dhcp_info: self.machine_dhcp_info.clone(),
            bmc_state: self.bmc_state.clone(),
            machine_discovery_result: self.machine_discovery_result.clone(),
            booted_os: self.booted_os,
            installed_os: self.installed_os,
            dpu_dhcp_relay_handle: Some(handle),
        }
    }
}

impl MachineUpState {
    fn install_os_with_discovery_result(
        &self,
        installed_os: OsImage,
        machine_discovery_result: MachineDiscoveryResult,
    ) -> MachineState {
        MachineState::MachineUp(
            MachineUpState {
                machine_dhcp_info: self.machine_dhcp_info.clone(),
                bmc_state: self.bmc_state.clone(),
                booted_os: self.booted_os,
                installed_os,
                machine_discovery_result: Some(machine_discovery_result),
                dpu_dhcp_relay_handle: None,
            }
            .into(),
        )
    }
}

impl Display for MachineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str_repr = match self {
            Self::BmcInit => "BmcInit",
            Self::BmcOnly(_) => "BmcOnly",
            Self::MachineDown(_) => "MachineDown",
            Self::Init(_) => "Init",
            Self::DhcpComplete(_) => "DhcpComplete",
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

/// Represents the image that can be booted to via PXE or installed on-device
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
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

fn rpc_machine_type(machine_info: &MachineInfo) -> MachineType {
    match machine_info {
        MachineInfo::Dpu(_) => MachineType::Dpu,
        MachineInfo::Host(_) => MachineType::Host,
    }
}
