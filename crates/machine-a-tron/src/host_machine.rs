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
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bmc_mock::{
    BmcCommand, HostHardwareType, HostMachineInfo, MachineInfo, SetSystemPowerResult,
    SystemPowerControl,
};
use carbide_uuid::machine::MachineId;
use eyre::Context;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Interval;
use tracing::instrument;
use uuid::Uuid;

use crate::api_client::ApiClient;
use crate::bmc_mock_wrapper::convert_power_state;
use crate::config::{MachineATronContext, MachineConfig, PersistedHostMachine};
use crate::dhcp_wrapper::{DhcpRelayResult, DhcpResponseInfo, DpuDhcpRelay};
use crate::dpu_machine::{DpuMachine, DpuMachineHandle};
use crate::machine_state_machine::{LiveState, MachineStateMachine, PersistedMachine};
use crate::machine_utils::create_random_self_signed_cert;
use crate::saturating_add_duration_to_instant;
use crate::tui::{HostDetails, UiUpdate};

#[derive(Debug)]
pub struct HostMachine {
    mat_id: Uuid,
    machine_config_section: String,
    host_info: HostMachineInfo,
    app_context: Arc<MachineATronContext>,
    live_state: Arc<RwLock<LiveState>>,
    state_machine: MachineStateMachine,
    api_state: String,
    tui_event_tx: Option<mpsc::Sender<UiUpdate>>,

    dpus: Vec<DpuMachineHandle>,

    bmc_control_rx: mpsc::UnboundedReceiver<BmcCommand>,
    // This will be populated with callers waiting for the host to be MachineUp/Ready
    state_waiters: HashMap<String, Vec<oneshot::Sender<()>>>,
    paused: bool,
    api_refresh_interval: Interval,
    sleep_until: Instant,
}

impl HostMachine {
    pub fn from_persisted(
        persisted_host_machine: PersistedHostMachine,
        machine_config_section: String,
        app_context: Arc<MachineATronContext>,
        config: Arc<MachineConfig>,
    ) -> Self {
        let mat_id = persisted_host_machine.mat_id;
        let (bmc_control_tx, bmc_control_rx) = mpsc::unbounded_channel();
        let (dpu_dhcp_tx, dpu_dhcp_rx) =
            mpsc::unbounded_channel::<oneshot::Sender<DhcpRelayResult<DhcpResponseInfo>>>();
        let mut dpu_dhcp_rx = Some(dpu_dhcp_rx);
        let dpus_in_nic_mode = config.dpus_in_nic_mode;

        let dpu_machines = persisted_host_machine
            .dpus
            .iter()
            .map(|dpu| {
                DpuMachine::from_persisted(
                    dpu.clone(),
                    persisted_host_machine.mat_id,
                    app_context.clone(),
                    config.clone(),
                    if dpus_in_nic_mode {
                        None
                    } else {
                        dpu_dhcp_rx.take()
                    },
                )
            })
            .collect::<Vec<_>>();
        let host_info = HostMachineInfo {
            hw_type: persisted_host_machine
                .hw_type
                .unwrap_or(HostHardwareType::DellPowerEdgeR750),
            bmc_mac_address: persisted_host_machine.bmc_mac_address,
            serial: persisted_host_machine.serial.clone(),
            dpus: persisted_host_machine
                .dpus
                .iter()
                .cloned()
                .map(Into::into)
                .collect(),
            non_dpu_mac_address: persisted_host_machine.non_dpu_mac_address,
        };
        let dpus = dpu_machines
            .into_iter()
            .map(|d| d.start(true))
            .collect::<Vec<_>>();

        let state_machine = MachineStateMachine::from_persisted(
            PersistedMachine::Host(persisted_host_machine),
            config,
            app_context.clone(),
            bmc_control_tx,
            if !dpus.is_empty() && !dpus_in_nic_mode {
                Some(DpuDhcpRelay::HostEnd(dpu_dhcp_tx))
            } else {
                None
            },
            mat_id,
        );

        HostMachine {
            mat_id,
            machine_config_section,
            host_info,
            live_state: state_machine.live_state.clone(),
            state_machine,
            dpus,
            api_state: "Unknown".to_owned(),

            bmc_control_rx,
            state_waiters: HashMap::new(),
            tui_event_tx: None,
            paused: true,
            sleep_until: Instant::now(),
            api_refresh_interval: tokio::time::interval(
                app_context.app_config.api_refresh_interval,
            ),
            app_context,
        }
    }

    pub fn new(
        app_context: Arc<MachineATronContext>,
        machine_config_section: String,
        config: Arc<MachineConfig>,
    ) -> Self {
        let mat_id = Uuid::new_v4();
        let (bmc_control_tx, bmc_control_rx) = mpsc::unbounded_channel();
        let (dpu_dhcp_tx, dpu_dhcp_rx) =
            mpsc::unbounded_channel::<oneshot::Sender<DhcpRelayResult<DhcpResponseInfo>>>();
        let mut dpu_dhcp_rx = Some(dpu_dhcp_rx);
        let dpus_in_nic_mode = config.dpus_in_nic_mode;

        let dpu_machines = (1..=config.dpu_per_host_count as u8)
            .map(|index| {
                DpuMachine::new(
                    mat_id,
                    index,
                    app_context.clone(),
                    config.clone(),
                    if dpus_in_nic_mode {
                        None
                    } else {
                        dpu_dhcp_rx.take()
                    },
                )
            })
            .collect::<Vec<_>>();
        let host_info = HostMachineInfo::new(
            config.hw_type,
            dpu_machines.iter().map(|d| d.dpu_info().clone()).collect(),
        );
        let dpus = dpu_machines
            .into_iter()
            .map(|d| d.start(true))
            .collect::<Vec<_>>();

        let state_machine = MachineStateMachine::new(
            MachineInfo::Host(host_info.clone()),
            config,
            app_context.clone(),
            bmc_control_tx,
            Some(create_random_self_signed_cert()),
            if !dpus.is_empty() && !dpus_in_nic_mode {
                Some(DpuDhcpRelay::HostEnd(dpu_dhcp_tx))
            } else {
                None
            },
            mat_id,
        );

        HostMachine {
            mat_id,
            machine_config_section,
            host_info,
            live_state: state_machine.live_state.clone(),
            state_machine,
            dpus,
            api_state: "Unknown".to_owned(),

            bmc_control_rx,
            state_waiters: HashMap::new(),
            tui_event_tx: None,
            paused: true,
            sleep_until: Instant::now(),
            api_refresh_interval: tokio::time::interval(
                app_context.app_config.api_refresh_interval,
            ),
            app_context,
        }
    }

    #[instrument(skip_all, fields(mat_host_id = %self.mat_id))]
    pub fn start(mut self, paused: bool) -> HostMachineHandle {
        self.paused = paused;
        let (message_tx, mut message_rx) = mpsc::unbounded_channel();
        let live_state = self.live_state.clone();
        let mat_id = self.mat_id;
        let host_info = self.host_info.clone();
        let dpus = self.dpus.clone();
        let machine_config_section = self.machine_config_section.clone();
        let bmc_dhcp_id = self.state_machine.bmc_dhcp_id;
        let machine_dhcp_id = self.state_machine.machine_dhcp_id;

        if !paused {
            self.resume_dpus();
        }

        let join_handle = tokio::task::Builder::new()
            .name(&format!("Host {}", self.mat_id))
            .spawn({
                let message_tx = message_tx.clone();
                async move {
                    loop {
                        if !self.run_iteration(&mut message_rx, &message_tx).await {
                            break;
                        }
                    }
                }
            })
            .unwrap();

        HostMachineHandle(Arc::new(HostMachineActor {
            message_tx,
            live_state,
            mat_id,
            host_info,
            dpus,
            machine_config_section,
            bmc_dhcp_id,
            machine_dhcp_id,

            join_handle: Mutex::new(Some(join_handle)),
        }))
    }

    #[instrument(skip_all, fields(mat_host_id = %self.mat_id, api_state = %self.api_state, state = %self.state_machine, booted_os = %self.state_machine.booted_os()))]
    async fn run_iteration(
        &mut self,
        actor_message_rx: &mut mpsc::UnboundedReceiver<HostMachineMessage>,
        actor_message_tx: &mpsc::UnboundedSender<HostMachineMessage>,
    ) -> bool {
        self.maybe_update_tui().await;

        // If the host is up, and if anyone is waiting for the current state to be
        // reached, notify them.
        if self.live_state.read().unwrap().is_up
            && let Some(waiters) = self.state_waiters.remove(&self.api_state)
        {
            for waiter in waiters.into_iter() {
                _ = waiter.send(());
            }
        }

        tokio::select! {
            _ = tokio::time::sleep_until(self.sleep_until.into()) => {}
            _ = self.api_refresh_interval.tick() => {
                // Wake up to refresh the API state and UI
                if let Some(machine_id) = self.live_state.read().unwrap().observed_machine_id {
                    let actor_message_tx = actor_message_tx.clone();
                    self.app_context.api_throttler.get_machine(machine_id, move |machine| {
                        if let Some(machine) = machine {
                            // Write the API state back using the actor channel, since we can't just write to self
                            _ = actor_message_tx.send(HostMachineMessage::SetApiState(machine.state));
                        }
                    })
                }
                return true; // go back to sleeping
            }
            result = actor_message_rx.recv() => {
                let Some(cmd) = result else {
                    tracing::info!("Command channel gone, stopping Host");
                    return false;
                };
                match self.handle_actor_message(cmd).await {
                    HandleMessageResult::ContinuePolling => return true,
                    HandleMessageResult::ProcessStateNow => {},
                }
            }
            Some(cmd) = self.bmc_control_rx.recv() => {
                match cmd {
                    BmcCommand::SetSystemPower { request, reply } => {
                        let response = self.set_system_power(request);
                        if let Some(reply) = reply {
                            _ = reply.send(response);
                        }
                    }
                }
                // continue to process_state
            }
        }

        let sleep_duration = self.process_state().await;

        self.sleep_until = saturating_add_duration_to_instant(Instant::now(), sleep_duration);
        true
    }

    async fn process_state(&mut self) -> Duration {
        if self.paused {
            return Duration::MAX;
        }

        let sleep_duration = self.state_machine.advance().await;
        tracing::trace!("state_machine.advance end");
        sleep_duration
    }

    async fn handle_actor_message(&mut self, message: HostMachineMessage) -> HandleMessageResult {
        match message {
            HostMachineMessage::WaitUntilMachineUpWithApiState(state, reply) => {
                if let Some(state_waiters) = self.state_waiters.get_mut(&state) {
                    state_waiters.push(reply);
                } else {
                    self.state_waiters.insert(state, vec![reply]);
                }
                HandleMessageResult::ContinuePolling
            }
            HostMachineMessage::AttachToUI(tui_event_tx) => {
                self.tui_event_tx = tui_event_tx;
                self.maybe_update_tui().await;
                HandleMessageResult::ContinuePolling
            }
            HostMachineMessage::SetPaused(value) => {
                if value {
                    self.pause()
                } else {
                    self.resume()
                }
                HandleMessageResult::ProcessStateNow
            }
            HostMachineMessage::GetApiState(reply) => {
                _ = reply.send(self.api_state.clone());
                HandleMessageResult::ContinuePolling
            }
            HostMachineMessage::SetApiState(api_state) => {
                self.api_state = api_state;
                HandleMessageResult::ContinuePolling
            }
        }
    }

    fn set_system_power(&mut self, request: SystemPowerControl) -> SetSystemPowerResult {
        tracing::debug!("Host set_system_power request: {request:?}");

        match request {
            // Force-restart does not restart DPUs
            SystemPowerControl::ForceRestart => {}
            // Other power actions happen on the DPUs too (power cycle, force-off, etc.)
            _ => {
                // Graceful restart might not restart DPUs if an OS is running (let's emulate that)
                if matches!(request, SystemPowerControl::GracefulRestart)
                    && self.live_state.read().unwrap().booted_os.0.is_some()
                {
                    tracing::debug!(
                        "Got graceful restart when host is booted to an OS, will not reboot DPUs"
                    );
                } else {
                    for (dpu_index, dpu) in self.dpus.iter_mut().enumerate() {
                        _ = dpu.set_system_power(request).inspect_err(|e| {
                            tracing::error!(
                                error = %e,
                                "Could not send power request to DPU {dpu_index}",
                            )
                        });
                    }
                }
            }
        }
        self.state_machine.set_system_power(request)
    }

    async fn maybe_update_tui(&self) {
        let Some(tui_event_tx) = self.tui_event_tx.as_ref() else {
            return;
        };
        _ = tui_event_tx
            .send(UiUpdate::Machine(self.host_details()))
            .await
            .inspect_err(|e| tracing::warn!(error = %e, "Error sending TUI event"));
    }

    // Note: We can't implment From<HostMachine> for HostDetails, because we need this to be async
    // in order to query DPU state.
    fn host_details(&self) -> HostDetails {
        let mut dpu_details = Vec::with_capacity(self.dpus.len());
        for dpu in &self.dpus {
            dpu_details.push(dpu.host_details());
        }

        let live_state = self.live_state.read().unwrap();

        HostDetails {
            mat_id: self.mat_id,
            machine_id: self
                .live_state
                .read()
                .unwrap()
                .observed_machine_id
                .as_ref()
                .map(|m| m.to_string()),
            mat_state: self.state_machine.to_string(),
            api_state: self.api_state.clone(),
            oob_ip: live_state
                .bmc_ip
                .as_ref()
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            machine_ip: live_state
                .machine_ip
                .as_ref()
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            dpus: dpu_details,
            booted_os: live_state.booted_os.to_string(),
            power_state: convert_power_state(live_state.power_state),
        }
    }

    fn pause(&mut self) {
        let was_paused = self.paused;
        self.paused = true;
        if !was_paused {
            tracing::info!("Pausing state operations");
            for dpu in &self.dpus {
                _ = dpu.pause().inspect_err(|e| {
                    tracing::error!(error=%e, "Could not pause DPU when pausing host");
                });
            }
        }
    }

    fn resume(&mut self) {
        let was_paused = self.paused;
        self.paused = false;
        if was_paused {
            tracing::info!("Resuming state operations");
            self.resume_dpus();
        }
    }

    fn resume_dpus(&self) {
        for dpu in &self.dpus {
            _ = dpu.resume().inspect_err(
                |e| tracing::error!(error=%e, "Could not resume DPU when resuming Host"),
            );
        }
    }
}

// Shared with DpuMachine
pub enum HandleMessageResult {
    ContinuePolling,
    ProcessStateNow,
}

enum HostMachineMessage {
    GetApiState(oneshot::Sender<String>),
    WaitUntilMachineUpWithApiState(String, oneshot::Sender<()>),
    AttachToUI(Option<mpsc::Sender<UiUpdate>>),
    SetPaused(bool),
    SetApiState(String),
}

#[derive(Debug)]
struct HostMachineActor {
    message_tx: mpsc::UnboundedSender<HostMachineMessage>,
    join_handle: Mutex<Option<JoinHandle<()>>>,
    live_state: Arc<RwLock<LiveState>>,
    mat_id: Uuid,
    host_info: HostMachineInfo,
    dpus: Vec<DpuMachineHandle>,
    machine_config_section: String,
    bmc_dhcp_id: Uuid,
    machine_dhcp_id: Uuid,
}

#[derive(Debug, Clone)]
pub struct HostMachineHandle(Arc<HostMachineActor>);

impl HostMachineHandle {
    pub fn mat_id(&self) -> Uuid {
        self.0.mat_id
    }

    pub fn observed_machine_id(&self) -> Option<MachineId> {
        self.0
            .live_state
            .read()
            .unwrap()
            .observed_machine_id
            .as_ref()
            .map(|m| m.to_owned())
    }

    pub async fn api_state(&self) -> eyre::Result<String> {
        let (tx, rx) = oneshot::channel();
        self.0
            .message_tx
            .send(HostMachineMessage::GetApiState(tx))?;
        Ok(rx.await?)
    }

    pub async fn wait_until_machine_up_with_api_state(
        &self,
        state: &str,
        timeout: Duration,
    ) -> eyre::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.0
            .message_tx
            .send(HostMachineMessage::WaitUntilMachineUpWithApiState(
                state.to_owned(),
                tx,
            ))?;
        tokio::time::timeout(timeout, rx).await?.wrap_err(format!(
            "timed out waiting for machine up with state {state}"
        ))
    }

    pub fn attach_to_tui(&self, tui_event_tx: Option<mpsc::Sender<UiUpdate>>) -> eyre::Result<()> {
        Ok(self
            .0
            .message_tx
            .send(HostMachineMessage::AttachToUI(tui_event_tx))?)
    }

    pub fn pause(&self) -> eyre::Result<()> {
        self.0
            .message_tx
            .send(HostMachineMessage::SetPaused(true))?;
        Ok(())
    }

    pub fn resume(&self) -> eyre::Result<()> {
        self.0
            .message_tx
            .send(HostMachineMessage::SetPaused(false))?;
        Ok(())
    }

    pub fn host_info(&self) -> &HostMachineInfo {
        &self.0.host_info
    }

    pub fn persisted(&self) -> PersistedHostMachine {
        let live_state = self.0.live_state.read().unwrap();
        PersistedHostMachine {
            hw_type: Some(self.0.host_info.hw_type),
            mat_id: self.0.mat_id,
            machine_config_section: self.0.machine_config_section.clone(),
            bmc_mac_address: self.0.host_info.bmc_mac_address,
            serial: self.0.host_info.serial.clone(),
            dpus: self.0.dpus.iter().map(|d| d.persisted()).collect(),
            non_dpu_mac_address: self.0.host_info.non_dpu_mac_address,
            observed_machine_id: live_state.observed_machine_id,
            installed_os: live_state.installed_os,
            tpm_ek_certificate: live_state.tpm_ek_certificate.clone(),
            machine_dhcp_id: self.0.machine_dhcp_id,
            bmc_dhcp_id: self.0.bmc_dhcp_id,
        }
    }

    pub fn dpus(&self) -> &[DpuMachineHandle] {
        &self.0.dpus
    }

    pub async fn delete_from_api(self, api_client: ApiClient) -> eyre::Result<()> {
        let delete_by = match self
            .0
            .live_state
            .read()
            .unwrap()
            .observed_machine_id
            .as_ref()
        {
            Some(machine_id) => {
                tracing::info!(
                    "Attempting to delete machine with id: {} from db.",
                    machine_id
                );
                machine_id.to_string()
            }
            None => {
                // force_delete_machine also supports sending MAC address (which could break if there is 0 DPUs on this host)
                match self.0.host_info.system_mac_address() {
                    Some(mac) => {
                        tracing::info!("Attempting to delete machine with mac: {} from db.", mac);
                        mac.to_string()
                    }
                    None => {
                        tracing::info!(
                            "Not deleting machine as we have not seen a machine ID for it, and it has no known MAC addresses (no DPUs)",
                        );
                        return Ok(());
                    }
                }
            }
        };

        api_client.force_delete_machine(delete_by).await?;
        Ok(())
    }

    pub fn abort(&self) {
        for dpu in &self.0.dpus {
            dpu.abort();
        }
        if let Some(join_handle) = self.0.join_handle.lock().unwrap().take() {
            join_handle.abort();
        }
    }

    pub fn bmc_ssh_host_pubkey(&self) -> Option<String> {
        self.0.live_state.read().unwrap().ssh_host_key.clone()
    }

    pub fn bmc_ip(&self) -> Option<Ipv4Addr> {
        self.0.live_state.read().unwrap().bmc_ip
    }
}
