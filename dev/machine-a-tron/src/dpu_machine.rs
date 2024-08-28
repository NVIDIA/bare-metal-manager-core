use chrono::{DateTime, Utc};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Interval;
use tracing::instrument;
use uuid::Uuid;

use crate::api_throttler::ApiThrottler;
use crate::host_machine::HandleMessageResult;
use crate::machine_state_machine::{BmcRegistrationMode, MachineStateMachine};
use crate::tui::HostDetails;
use crate::{
    api_client::identify_serial,
    config::{MachineATronContext, MachineConfig},
    dhcp_relay::DhcpRelayClient,
    saturating_add_duration_to_instant,
};
use bmc_mock::{BmcCommand, DpuMachineInfo, MachineInfo};

#[derive(Debug)]
pub struct DpuMachine {
    mat_id: Uuid,
    // The mat_id of the host that owns this DPU
    host_id: Uuid,
    // Our index within this host
    dpu_index: u8,
    state_machine: MachineStateMachine,

    dpu_info: DpuMachineInfo,
    app_context: MachineATronContext,
    api_state: String,
    bmc_control_rx: mpsc::UnboundedReceiver<BmcCommand>,
    reboot_requested: Option<DateTime<Utc>>,
    observed_machine_id: Option<rpc::MachineId>,
    paused: bool,
    sleep_until: Instant,
    api_throttler: ApiThrottler,
    api_refresh_interval: Interval,
}

impl DpuMachine {
    pub fn new(
        mat_host: Uuid,
        dpu_index: u8,
        app_context: MachineATronContext,
        config: MachineConfig,
        dhcp_client: DhcpRelayClient,
        bmc_listen_mode: BmcRegistrationMode,
        api_throttler: ApiThrottler,
    ) -> Self {
        let mat_id = Uuid::new_v4();
        let (bmc_control_tx, bmc_control_rx) = mpsc::unbounded_channel();
        let dpu_info = DpuMachineInfo::new();
        let state_machine = MachineStateMachine::new(
            MachineInfo::Dpu(dpu_info.clone()),
            config,
            app_context.clone(),
            dhcp_client,
            bmc_control_tx.clone(),
            bmc_listen_mode,
        );
        DpuMachine {
            mat_id,
            dpu_index,
            host_id: mat_host,
            dpu_info,
            state_machine,
            app_context,

            api_state: "Unknown".to_string(),
            bmc_control_rx,
            reboot_requested: None,
            observed_machine_id: None,
            paused: true,
            sleep_until: Instant::now(),
            api_refresh_interval: tokio::time::interval(Duration::from_secs(2)),
            api_throttler,
        }
    }

    #[instrument(skip_all, fields(mat_host_id = %self.host_id, dpu_index = self.dpu_index))]
    pub fn start(mut self, paused: bool) -> DpuMachineActor {
        self.paused = paused;
        let (actor_message_tx, mut actor_message_rx) = mpsc::unbounded_channel();
        tokio::task::Builder::new()
            .name(&format!("DPU {}", self.mat_id))
            .spawn({
                let actor_message_tx = actor_message_tx.clone();
                async move {
                    loop {
                        // Run the actual iterations in a separate function so that #[instrument] can
                        // create spans with the current values for all fields.
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

        DpuMachineActor {
            message_tx: actor_message_tx,
        }
    }

    #[instrument(skip_all, fields(mat_host_id = %self.host_id, dpu_index = self.dpu_index, api_state = %self.api_state, state = %self.state_machine, booted_os = %self.state_machine.booted_os()))]
    async fn run_iteration(
        &mut self,
        actor_message_rx: &mut mpsc::UnboundedReceiver<DpuMachineMessage>,
        actor_message_tx: &mpsc::UnboundedSender<DpuMachineMessage>,
    ) -> bool {
        tokio::select! {
            _ = tokio::time::sleep_until(self.sleep_until.into()) => {},
            _ = self.api_refresh_interval.tick() => {
                // Wake up to refresh the API state and UI
                if let Some(machine_id) = self.observed_machine_id.as_ref() {
                    let actor_message_tx = actor_message_tx.clone();
                    self.api_throttler.get_machine(machine_id.clone(), move |machine| {
                        if let Some(machine) = machine {
                            // Write the API state back using the actor channel, since we can't just write to self
                            _ = actor_message_tx.send(DpuMachineMessage::SetApiState(machine.state));
                        }
                    })
                }
                return true; // go back to sleeping
            }
            Some(cmd) = self.bmc_control_rx.recv() => {
                match cmd {
                    BmcCommand::Reboot(time) => {
                        self.request_reboot(time);
                    }
                }
            }
            Some(cmd) = actor_message_rx.recv() => {
                match self.handle_actor_message(cmd).await {
                    HandleMessageResult::ProcessStateNow => {},
                    HandleMessageResult::ContinuePolling => return true,
                    HandleMessageResult::Stop => return false,
                };
            }
        }

        let sleep_duration = self.process_state().await;

        self.sleep_until = saturating_add_duration_to_instant(Instant::now(), sleep_duration);
        true
    }

    async fn handle_actor_message(&mut self, message: DpuMachineMessage) -> HandleMessageResult {
        match message {
            DpuMachineMessage::Reboot(time) => {
                self.request_reboot(time);
                HandleMessageResult::ProcessStateNow
            }
            DpuMachineMessage::IsUp(reply) => {
                _ = reply.send(self.is_up());
                HandleMessageResult::ContinuePolling
            }
            DpuMachineMessage::GetHostDetails(reply) => {
                _ = reply.send(HostDetails::from(&*self));
                HandleMessageResult::ContinuePolling
            }
            DpuMachineMessage::SetPaused(is_paused) => {
                if is_paused {
                    tracing::info!("Pausing state operations");
                    self.paused = true;
                } else {
                    tracing::info!("Resuming state operations");
                    self.paused = false;
                }
                HandleMessageResult::ProcessStateNow
            }
            DpuMachineMessage::Stop(reply) => {
                _ = reply.send(());
                HandleMessageResult::Stop
            }
            DpuMachineMessage::SetApiState(api_state) => {
                self.api_state = api_state;
                HandleMessageResult::ContinuePolling
            }
        }
    }

    async fn process_state(&mut self) -> Duration {
        if self.paused {
            return Duration::MAX;
        }

        if let Some(time) = self.reboot_requested.take() {
            tracing::info!("reboot requested at {time}",);
            self.state_machine.power_down()
        }

        tracing::trace!("state_machine.advance start");
        let result = self.state_machine.advance(true).await;
        tracing::trace!("state_machine.advance end");

        if let Some(machine_id) = self.state_machine.machine_id() {
            self.observed_machine_id = Some(machine_id.to_owned());
        } else if self.observed_machine_id.is_none() {
            if let Ok(machine) =
                identify_serial(&self.app_context, self.dpu_info.serial.clone()).await
            {
                tracing::trace!("dpu's machine id: {}", machine.id);
                self.observed_machine_id = Some(machine);
            }
        }

        result
    }

    fn request_reboot(&mut self, time: DateTime<Utc>) {
        tracing::debug!("DPU reboot requested at {time}",);
        self.reboot_requested = Some(time);
    }

    fn is_up(&self) -> bool {
        self.state_machine.is_up()
    }

    pub fn dpu_info(&self) -> &DpuMachineInfo {
        &self.dpu_info
    }
}

enum DpuMachineMessage {
    Reboot(DateTime<Utc>),
    Stop(oneshot::Sender<()>),
    GetHostDetails(oneshot::Sender<HostDetails>),
    IsUp(oneshot::Sender<bool>),
    SetPaused(bool),
    SetApiState(String),
}

/// DpuMachineActor presents a friendly, actor-style interface for various methods a HostMachine
/// needs to call while a DpuMachine is running.
///
/// This is needed because DpuMachine runs its own control loop inside a Tokio Task, which consumes
/// self, and it is not thread-safe to query the DPU while it's running. Instead, the control loop
/// will poll for any DpuMachineCommands sent to it (in addition to periodically running
/// process_state) and reply to them. DpuMachineHandle abstracts these commands/replies into simple
/// async methods.
#[derive(Debug, Clone)]
pub struct DpuMachineActor {
    message_tx: mpsc::UnboundedSender<DpuMachineMessage>,
}

impl DpuMachineActor {
    pub fn reboot(&self, time: DateTime<Utc>) -> eyre::Result<()> {
        Ok(self.message_tx.send(DpuMachineMessage::Reboot(time))?)
    }

    pub async fn is_up(&self) -> eyre::Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(DpuMachineMessage::IsUp(tx))?;
        Ok(rx.await?)
    }

    pub async fn host_details(&self) -> eyre::Result<HostDetails> {
        let (tx, rx) = oneshot::channel();
        self.message_tx
            .send(DpuMachineMessage::GetHostDetails(tx))?;
        Ok(rx.await?)
    }

    pub async fn stop(self) -> eyre::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(DpuMachineMessage::Stop(tx))?;
        Ok(rx.await?)
    }

    pub fn pause(&self) -> eyre::Result<()> {
        self.message_tx.send(DpuMachineMessage::SetPaused(true))?;
        Ok(())
    }

    pub fn resume(&self) -> eyre::Result<()> {
        self.message_tx.send(DpuMachineMessage::SetPaused(false))?;
        Ok(())
    }
}

impl From<&DpuMachine> for HostDetails {
    fn from(val: &DpuMachine) -> Self {
        HostDetails {
            mat_id: val.mat_id,
            machine_id: val.observed_machine_id.as_ref().map(|m| m.to_string()),
            mat_state: val.state_machine.to_string(),
            api_state: val.api_state.clone(),
            oob_ip: val
                .state_machine
                .bmc_ip()
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            machine_ip: val
                .state_machine
                .machine_ip()
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            dpus: Vec::default(),
            booted_os: val.state_machine.booted_os().to_string(),
        }
    }
}
