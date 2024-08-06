use chrono::{DateTime, Utc};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::dpu_machine::DpuMachineActor;
use crate::logging::{LogCollector, LogSink};
use crate::machine_state_machine::{BmcRegistrationMode, MachineStateMachine};
use crate::{
    api_client,
    config::{MachineATronContext, MachineConfig},
    dhcp_relay::DhcpRelayClient,
    dpu_machine::DpuMachine,
    machine_utils::get_api_state,
    saturating_add_duration_to_instant,
    tui::{HostDetails, UiEvent},
};
use bmc_mock::{BmcCommand, HostMachineInfo, MachineInfo};
use rpc::MachineId;

const MAX_LOG_LINES: usize = 40;

#[derive(Debug)]
pub struct HostMachine {
    mat_id: Uuid,
    host_info: HostMachineInfo,
    app_context: MachineATronContext,
    state_machine: MachineStateMachine,
    api_state: String,
    logs: Vec<String>,
    tui_event_tx: Option<mpsc::Sender<UiEvent>>,

    dpus: Vec<DpuMachineActor>,

    dpus_previously_ready: bool,
    bmc_control_rx: mpsc::UnboundedReceiver<BmcCommand>,
    log_collector: LogCollector,
    logger: LogSink,
    // This will go from None to Some when we enter a state where we have a MachineId allocated. It
    // may change for instance if we go from a predicted host to a regular host.
    observed_machine_id: Option<MachineId>,
    // This will be populated with callers waiting for the host to be MachineUp/Ready
    ready_waiters: Option<Vec<oneshot::Sender<()>>>,
    paused: bool,
}

impl HostMachine {
    pub fn new(
        app_context: MachineATronContext,
        config: MachineConfig,
        dhcp_client: DhcpRelayClient,
        bmc_listen_mode: BmcRegistrationMode,
    ) -> Self {
        let log_collector = LogCollector::new();

        let dpu_machines = (1..=config.dpu_per_host_count)
            .map(|index| {
                DpuMachine::new(
                    app_context.clone(),
                    config.clone(),
                    dhcp_client.clone(),
                    log_collector.log_sink(Some(format!("D{index}:"))),
                    bmc_listen_mode.clone(),
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
            log_collector.log_sink(Some("H:".to_string())),
            bmc_control_tx.clone(),
            bmc_listen_mode,
        );

        HostMachine {
            mat_id: Uuid::new_v4(),
            host_info,
            state_machine,
            app_context,
            dpus,
            api_state: "Unknown".to_owned(),

            logs: Vec::default(),
            dpus_previously_ready: false,
            bmc_control_rx,
            logger: log_collector.log_sink(Some("H:".to_string())),
            log_collector,
            observed_machine_id: None,
            ready_waiters: None,
            tui_event_tx: None,
            paused: true,
        }
    }

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
            .spawn(async move {
                self.maybe_update_tui().await;

                let mut api_state_refresh_interval = tokio::time::interval(Duration::from_secs(2));
                let mut sleep_until = Instant::now();
                loop {
                    self.logs.extend_from_slice(
                        self.log_collector
                            .get_last_logs()
                            .into_iter()
                            .map(|m| m.to_string())
                            .collect::<Vec<_>>()
                            .as_slice(),
                    );
                    let over = self.logs.len().saturating_sub(MAX_LOG_LINES);
                    if over > 0 {
                        self.logs.drain(..over);
                    }
                    self.maybe_update_tui().await;

                    if self.is_up_and_ready() {
                        if let Some(waiters) = self.ready_waiters.take() {
                            for waiter in waiters.into_iter() {
                                _ = waiter.send(());
                            }
                        }
                    }

                    tokio::select! {
                        _ = tokio::time::sleep_until(sleep_until.into()) => {}
                        _ = api_state_refresh_interval.tick() => {
                            // Wake up to refresh the API state and UI
                            self.api_state = get_api_state(
                                &self.app_context,
                                self.state_machine.machine_id().ok().as_ref(),
                            )
                            .await;
                            continue; // go back to sleeping
                        }
                        Some(cmd) = actor_message_rx.recv() => {
                            match self.handle_actor_message(cmd).await {
                                HandleMessageResult::ContinuePolling => continue,
                                HandleMessageResult::ProcessStateNow => {},
                                HandleMessageResult::Stop => break,
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

                    sleep_until =
                        saturating_add_duration_to_instant(Instant::now(), sleep_duration);
                }
            })
            .unwrap();

        HostMachineActor {
            mat_id,
            host_machine_info,
            message_tx: actor_message_tx,
        }
    }

    async fn process_state(&mut self) -> Duration {
        self.logger.info(format!(
            "start: mat state: {} api state: {}",
            self.state_machine, self.api_state
        ));
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
                            "Internal error checking if DPU is up (will proceed without it): {e}"
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
        self.logger.info(format!(
            "end: mat state {} api state {}",
            self.state_machine, self.api_state
        ));

        if let Ok(machine_id) = self.state_machine.machine_id() {
            self.observed_machine_id = Some(machine_id);
        }

        sleep_duration
    }

    async fn handle_actor_message(&mut self, message: HostMachineMessage) -> HandleMessageResult {
        match message {
            HostMachineMessage::GetObservedMachineID(reply) => {
                _ = reply.send(self.observed_machine_id.clone());
                HandleMessageResult::ContinuePolling
            }
            HostMachineMessage::WaitUntilReady(reply) => {
                if let Some(ready_waiters) = self.ready_waiters.as_mut() {
                    ready_waiters.push(reply);
                } else {
                    self.ready_waiters = Some(vec![reply]);
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
        }
    }

    fn reboot(&mut self, time: DateTime<Utc>) {
        self.logger.info(format!(
            "Host reboot requested at {}: new state: {} api state: {}",
            time, self.state_machine, self.api_state
        ));
        for (dpu_index, dpu) in self.dpus.iter_mut().enumerate() {
            _ = dpu.reboot(time).inspect_err(|e| {
                self.logger
                    .error(format!("Could not reboot DPU {dpu_index}: {e}"))
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
            .inspect_err(|e| tracing::warn!("Error sending TUI event: {}", e));
    }

    fn is_up_and_ready(&self) -> bool {
        self.state_machine.is_up() && self.api_state.eq("Ready")
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
            logs: self.logs.clone(),
        }
    }

    fn pause(&mut self) {
        let was_paused = self.paused;
        self.paused = true;
        if !was_paused {
            self.logger.info("Pausing state operations".to_string());
            for dpu in &self.dpus {
                _ = dpu.pause().inspect_err(|e| {
                    self.logger
                        .error(format!("Could not pause DPU when pausing Host: {e}"))
                });
            }
        }
    }

    fn resume(&mut self) {
        let was_paused = self.paused;
        self.paused = false;
        if was_paused {
            self.logger.info("Resuming state operations".to_string());
            self.resume_dpus();
        }
    }

    fn resume_dpus(&self) {
        for dpu in &self.dpus {
            _ = dpu.resume().inspect_err(|e| {
                self.logger
                    .error(format!("Could not resume DPU when resuming Host: {e}"))
            });
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
                    "Not deleting machine {} as we have not seen a machine ID for it, and it has no known MAC addresses (no DPUs)",
                    self.mat_id,
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
    WaitUntilReady(oneshot::Sender<()>),
    AttachToUI(Option<mpsc::Sender<UiEvent>>),
    SetPaused(bool),
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

    pub async fn wait_until_ready(&self) -> eyre::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.message_tx
            .send(HostMachineMessage::WaitUntilReady(tx))?;
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
