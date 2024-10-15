use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Interval;
use tracing::instrument;
use uuid::Uuid;

use crate::api_throttler::ApiThrottler;
use crate::dpu_machine::DpuMachineActor;
use crate::machine_state_machine::{BmcRegistrationMode, MachineStateMachine};
use crate::machine_utils::create_random_self_signed_cert;
use crate::{
    api_client,
    config::{MachineATronContext, MachineConfig},
    dhcp_relay::DhcpRelayClient,
    dpu_machine::DpuMachine,
    saturating_add_duration_to_instant,
    tui::{HostDetails, UiEvent},
};
use bmc_mock::{BmcCommand, HostMachineInfo, MachineInfo};
use rpc::MachineId;

#[derive(Debug)]
pub struct HostMachine {
    mat_id: Uuid,
    host_info: HostMachineInfo,
    app_context: MachineATronContext,
    state_machine: MachineStateMachine,
    api_state: String,
    tui_event_tx: Option<mpsc::Sender<UiEvent>>,

    dpus: Vec<DpuMachineActor>,

    dpus_previously_ready: bool,
    bmc_control_rx: mpsc::UnboundedReceiver<BmcCommand>,
    // This will go from None to Some when we enter a state where we have a MachineId allocated. It
    // may change for instance if we go from a predicted host to a regular host.
    observed_machine_id: Option<MachineId>,
    // This will be populated with callers waiting for the host to be MachineUp/Ready
    state_waiters: HashMap<String, Vec<oneshot::Sender<()>>>,
    paused: bool,
    api_refresh_interval: Interval,
    sleep_until: Instant,
    api_throttler: ApiThrottler,
}

impl HostMachine {
    pub fn new(
        app_context: MachineATronContext,
        config: MachineConfig,
        dhcp_client: DhcpRelayClient,
        bmc_listen_mode: BmcRegistrationMode,
        api_throttler: ApiThrottler,
    ) -> Self {
        let mat_id = Uuid::new_v4();

        let dpu_machines = (1..=config.dpu_per_host_count as u8)
            .map(|index| {
                DpuMachine::new(
                    mat_id,
                    index,
                    app_context.clone(),
                    config.clone(),
                    dhcp_client.clone(),
                    bmc_listen_mode.clone(),
                    api_throttler.clone(),
                )
            })
            .collect::<Vec<_>>();
        let host_info =
            HostMachineInfo::new(dpu_machines.iter().map(|d| d.dpu_info().clone()).collect());
        let dpus = dpu_machines.into_iter().map(|d| d.start(true)).collect();

        let (bmc_control_tx, bmc_control_rx) = mpsc::unbounded_channel();

        let state_machine = MachineStateMachine::new(
            MachineInfo::Host(host_info.clone()),
            config.clone(),
            app_context.clone(),
            dhcp_client.clone(),
            bmc_control_tx.clone(),
            bmc_listen_mode,
            Some(create_random_self_signed_cert().unwrap()),
        );

        HostMachine {
            mat_id,
            host_info,
            state_machine,
            app_context,
            dpus,
            api_state: "Unknown".to_owned(),

            dpus_previously_ready: false,
            bmc_control_rx,
            observed_machine_id: None,
            state_waiters: HashMap::new(),
            tui_event_tx: None,
            paused: true,
            sleep_until: Instant::now(),
            api_refresh_interval: tokio::time::interval(Duration::from_secs(2)),
            api_throttler,
        }
    }

    #[instrument(skip_all, fields(mat_host_id = %self.mat_id))]
    pub fn start(mut self, paused: bool) -> HostMachineActor {
        self.paused = paused;
        let (actor_message_tx, mut actor_message_rx) = mpsc::unbounded_channel();
        let host_machine_info = self.host_info.clone();
        let mat_id = self.mat_id;

        if !paused {
            self.resume_dpus();
        }

        tokio::task::Builder::new()
            .name(&format!("Host {}", self.mat_id))
            .spawn({
                let actor_message_tx = actor_message_tx.clone();
                async move {
                    loop {
                        if !self
                            .run_iteration(&mut actor_message_rx, &actor_message_tx)
                            .await
                        {
                            break;
                        }
                    }
                }
            })
            .unwrap();

        HostMachineActor {
            mat_id,
            host_machine_info,
            message_tx: actor_message_tx,
        }
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
        if self.state_machine.is_up() {
            if let Some(waiters) = self.state_waiters.remove(&self.api_state) {
                for waiter in waiters.into_iter() {
                    _ = waiter.send(());
                }
            }
        }

        tokio::select! {
            _ = tokio::time::sleep_until(self.sleep_until.into()) => {}
            _ = self.api_refresh_interval.tick() => {
                // Wake up to refresh the API state and UI
                if let Some(machine_id) = self.observed_machine_id.as_ref() {
                    let actor_message_tx = actor_message_tx.clone();
                    self.api_throttler.get_machine(machine_id.clone(), move |machine| {
                        if let Some(machine) = machine {
                            // Write the API state back using the actor channel, since we can't just write to self
                            _ = actor_message_tx.send(HostMachineMessage::SetApiState(machine.state));
                        }
                    })
                }
                return true; // go back to sleeping
            }
            Some(cmd) = actor_message_rx.recv() => {
                match self.handle_actor_message(cmd).await {
                    HandleMessageResult::ContinuePolling => return true,
                    HandleMessageResult::ProcessStateNow => {},
                    HandleMessageResult::Stop => return false,
                }
            }
            Some(cmd) = self.bmc_control_rx.recv() => {
                match cmd {
                    BmcCommand::Reboot(time) => {
                        self.reboot(time);
                    }
                }
                // continue to process_state
            }
        }

        let sleep_duration = self.process_state().await;

        self.sleep_until = saturating_add_duration_to_instant(Instant::now(), sleep_duration);
        return true;
    }

    async fn process_state(&mut self) -> Duration {
        if self.paused {
            return Duration::MAX;
        }

        let mut dpus_ready = Vec::<bool>::new();
        for dpu in &self.dpus {
            dpus_ready.push(
                dpu.is_up()
                    .await
                    .inspect_err(|e| {
                        tracing::error!(
                            error = %e,
                            "Internal error checking if DPU is up (will proceed without it)",
                        )
                    })
                    .unwrap_or(true),
            );
        }

        // give the API time to update the host after the dpus did something
        let dpus_ready = dpus_ready.into_iter().all(|r| r);
        if !self.dpus_previously_ready && dpus_ready {
            self.dpus_previously_ready = true;
            return Duration::from_secs(5);
        }

        let sleep_duration = self.state_machine.advance(dpus_ready).await;
        tracing::trace!("state_machine.advance end");

        if let Some(machine_id) = self.state_machine.machine_id() {
            self.observed_machine_id = Some(machine_id.to_owned());
        }

        sleep_duration
    }

    async fn handle_actor_message(&mut self, message: HostMachineMessage) -> HandleMessageResult {
        match message {
            HostMachineMessage::GetObservedMachineID(reply) => {
                _ = reply.send(self.observed_machine_id.clone());
                HandleMessageResult::ContinuePolling
            }
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
            HostMachineMessage::Stop(delete_from_api, reply) => {
                for dpu in self.dpus.drain(0..) {
                    _ = dpu.stop().await;
                }
                if delete_from_api {
                    _ = self.delete_from_api().await.inspect_err(|e| {
                        tracing::error!("Force delete Api call failed with {}", e)
                    });
                }
                _ = reply.send(());
                HandleMessageResult::Stop
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

    fn reboot(&mut self, time: DateTime<Utc>) {
        tracing::debug!("Host reboot requested at {time}");
        for (dpu_index, dpu) in self.dpus.iter_mut().enumerate() {
            _ = dpu.reboot(time).inspect_err(|e| {
                tracing::error!(
                    error = %e,
                    "Could not reboot DPU {dpu_index}",
                )
            });
        }
        self.state_machine.power_down()
    }

    async fn maybe_update_tui(&self) {
        let Some(tui_event_tx) = self.tui_event_tx.as_ref() else {
            return;
        };
        _ = tui_event_tx
            .send(UiEvent::MachineUpdate(self.host_details().await))
            .await
            .inspect_err(|e| tracing::warn!(error = %e, "Error sending TUI event"));
    }

    // Note: We can't implment From<HostMachine> for HostDetails, because we need this to be async
    // in order to query DPU state.
    async fn host_details(&self) -> HostDetails {
        let mut dpu_details = Vec::with_capacity(self.dpus.len());
        for dpu in &self.dpus {
            dpu_details.push(dpu.host_details().await.unwrap_or_default());
        }

        HostDetails {
            mat_id: self.mat_id,
            machine_id: self.observed_machine_id.as_ref().map(|m| m.to_string()),
            mat_state: self.state_machine.to_string(),
            api_state: self.api_state.clone(),
            oob_ip: self
                .state_machine
                .bmc_ip()
                .as_ref()
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            machine_ip: self
                .state_machine
                .machine_ip()
                .as_ref()
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            dpus: dpu_details,
            booted_os: self.state_machine.booted_os().to_string(),
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

    async fn delete_from_api(&self) -> eyre::Result<()> {
        let delete_by = match self.observed_machine_id.as_ref() {
            Some(machine_id) => {
                tracing::info!(
                    "Attempting to delete machine with id: {} from db.",
                    machine_id
                );
                machine_id.to_string()
            }
            None => {
                // force_delete_machine also supports sending MAC address (which could break if there is 0 DPUs on this host)
                match self.host_info.system_mac_address() {
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

        api_client::force_delete_machine(&self.app_context.clone(), delete_by).await?;
        Ok(())
    }
}

// Shared with DpuMachine
pub enum HandleMessageResult {
    ContinuePolling,
    ProcessStateNow,
    Stop,
}

enum HostMachineMessage {
    GetObservedMachineID(oneshot::Sender<Option<rpc::MachineId>>),
    GetApiState(oneshot::Sender<String>),
    WaitUntilMachineUpWithApiState(String, oneshot::Sender<()>),
    AttachToUI(Option<mpsc::Sender<UiEvent>>),
    SetPaused(bool),
    SetApiState(String),
    Stop(bool, oneshot::Sender<()>),
}

#[derive(Debug, Clone)]
pub struct HostMachineActor {
    // Optimization: These are immutable, so we can keep it in the Actor and not have to query.
    pub mat_id: Uuid,
    pub host_machine_info: HostMachineInfo,

    message_tx: mpsc::UnboundedSender<HostMachineMessage>,
}

impl HostMachineActor {
    pub async fn observed_machine_id(&self) -> eyre::Result<Option<rpc::MachineId>> {
        let (tx, rx) = oneshot::channel();
        self.message_tx
            .send(HostMachineMessage::GetObservedMachineID(tx))?;
        Ok(rx.await?)
    }

    pub async fn api_state(&self) -> eyre::Result<String> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(HostMachineMessage::GetApiState(tx))?;
        Ok(rx.await?)
    }

    pub async fn wait_until_machine_up_with_api_state(&self, state: &str) -> eyre::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.message_tx
            .send(HostMachineMessage::WaitUntilMachineUpWithApiState(
                state.to_owned(),
                tx,
            ))?;
        Ok(rx.await?)
    }

    pub async fn stop(self, delete_from_api: bool) -> eyre::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.message_tx
            .send(HostMachineMessage::Stop(delete_from_api, tx))?;
        Ok(rx.await?)
    }

    pub fn attach_to_tui(&self, tui_event_tx: Option<mpsc::Sender<UiEvent>>) -> eyre::Result<()> {
        Ok(self
            .message_tx
            .send(HostMachineMessage::AttachToUI(tui_event_tx))?)
    }

    pub fn pause(&self) -> eyre::Result<()> {
        self.message_tx.send(HostMachineMessage::SetPaused(true))?;
        Ok(())
    }

    pub fn resume(&self) -> eyre::Result<()> {
        self.message_tx.send(HostMachineMessage::SetPaused(false))?;
        Ok(())
    }
}
