use eyre::Context;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio::time::Interval;
use tracing::instrument;
use uuid::Uuid;

use crate::config::PersistedDpuMachine;
use crate::host_machine::HandleMessageResult;
use crate::machine_state_machine::{MachineStateMachine, PersistedMachine};
use crate::tui::HostDetails;
use crate::{
    MachineConfig, config::MachineATronContext, dhcp_relay::DhcpRelayClient,
    saturating_add_duration_to_instant,
};
use bmc_mock::{BmcCommand, DpuMachineInfo, MachineInfo, SetSystemPowerReq, SetSystemPowerResult};
use rpc::MachineId;

#[derive(Debug)]
pub struct DpuMachine {
    mat_id: Uuid,
    // The mat_id of the host that owns this DPU
    host_id: Uuid,
    // Our index within this host
    dpu_index: u8,
    state_machine: MachineStateMachine,

    dpu_info: DpuMachineInfo,
    app_context: Arc<MachineATronContext>,
    api_state: String,
    bmc_control_rx: mpsc::UnboundedReceiver<BmcCommand>,
    observed_machine_id: Option<rpc::MachineId>,
    paused: bool,
    sleep_until: Instant,
    api_refresh_interval: Interval,
    // This will be populated with callers waiting for the DPU to be in a specific state
    state_waiters: HashMap<String, Vec<oneshot::Sender<()>>>,
}

impl DpuMachine {
    pub fn from_persisted(
        persisted_dpu_machine: PersistedDpuMachine,
        mat_host: Uuid,
        app_context: Arc<MachineATronContext>,
        config: Arc<MachineConfig>,
        dhcp_client: DhcpRelayClient,
    ) -> Self {
        let mat_id = persisted_dpu_machine.mat_id;
        let dpu_index = persisted_dpu_machine.dpu_index;
        let (bmc_control_tx, bmc_control_rx) = mpsc::unbounded_channel();

        let dpu_info = DpuMachineInfo {
            bmc_mac_address: persisted_dpu_machine.bmc_mac_address,
            host_mac_address: persisted_dpu_machine.host_mac_address,
            oob_mac_address: persisted_dpu_machine.oob_mac_address,
            serial: persisted_dpu_machine.serial.clone(),
            nic_mode: persisted_dpu_machine.nic_mode,
            firmware_versions: persisted_dpu_machine.firmware_versions.clone(),
        };
        let state_machine = MachineStateMachine::from_persisted(
            PersistedMachine::Dpu(persisted_dpu_machine),
            config,
            app_context.clone(),
            dhcp_client,
            bmc_control_tx.clone(),
        );
        DpuMachine {
            mat_id,
            dpu_index,
            host_id: mat_host,
            dpu_info,
            state_machine,

            api_state: "Unknown".to_string(),
            bmc_control_rx,
            observed_machine_id: None,
            paused: true,
            sleep_until: Instant::now(),
            api_refresh_interval: tokio::time::interval(
                app_context.app_config.api_refresh_interval,
            ),
            state_waiters: HashMap::new(),
            app_context,
        }
    }

    pub fn new(
        mat_host: Uuid,
        dpu_index: u8,
        app_context: Arc<MachineATronContext>,
        config: Arc<MachineConfig>,
        dhcp_client: DhcpRelayClient,
    ) -> Self {
        let mat_id = Uuid::new_v4();
        let (bmc_control_tx, bmc_control_rx) = mpsc::unbounded_channel();

        // Prefer the configured firmware versions, but if any of the version fields are None, use
        // the ones the server wants.
        let firmware_versions = config
            .dpu_firmware_versions
            .clone()
            .unwrap_or_default()
            .fill_missing_from_desired_firmware(&app_context.desired_firmware_versions);

        let dpu_info = DpuMachineInfo::new(config.dpus_in_nic_mode, firmware_versions.into());
        let state_machine = MachineStateMachine::new(
            MachineInfo::Dpu(dpu_info.clone()),
            config,
            app_context.clone(),
            dhcp_client,
            bmc_control_tx.clone(),
            None,
        );
        DpuMachine {
            mat_id,
            dpu_index,
            host_id: mat_host,
            dpu_info,
            state_machine,

            api_state: "Unknown".to_string(),
            bmc_control_rx,
            observed_machine_id: None,
            paused: true,
            sleep_until: Instant::now(),
            api_refresh_interval: tokio::time::interval(
                app_context.app_config.api_refresh_interval,
            ),
            state_waiters: HashMap::new(),
            app_context,
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
        // If the dpu is up, and if anyone is waiting for the current state to be
        // reached, notify them.
        if self.state_machine.is_up() {
            if let Some(waiters) = self.state_waiters.remove(&self.api_state) {
                for waiter in waiters.into_iter() {
                    _ = waiter.send(());
                }
            }
        }

        tokio::select! {
            _ = tokio::time::sleep_until(self.sleep_until.into()) => {},
            _ = self.api_refresh_interval.tick() => {
                // Wake up to refresh the API state and UI
                if let Some(machine_id) = self.observed_machine_id.as_ref() {
                    let actor_message_tx = actor_message_tx.clone();
                    self.app_context.api_throttler.get_machine(machine_id.clone(), move |machine| {
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
                    BmcCommand::SetSystemPower {request, reply} => {
                        let response = self.state_machine.set_system_power(request);
                        if let Some(reply) = reply {
                            _ = reply.send(response)
                        }
                    }
                    BmcCommand::GetSystemPower(reply) => {
                        _ = reply.send(self.state_machine.redfish_power_state());
                        return true; // go back to sleeping
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
            DpuMachineMessage::SetSystemPower { request, reply } => {
                let response = self.state_machine.set_system_power(request);
                if let Some(reply) = reply {
                    _ = reply.send(response);
                }
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
            DpuMachineMessage::GetObservedMachineId(reply) => {
                reply.send(self.observed_machine_id.clone()).ok();
                HandleMessageResult::ContinuePolling
            }
            DpuMachineMessage::WaitUntilMachineUpWithApiState(state, reply) => {
                if let Some(state_waiters) = self.state_waiters.get_mut(&state) {
                    state_waiters.push(reply);
                } else {
                    self.state_waiters.insert(state, vec![reply]);
                }
                HandleMessageResult::ContinuePolling
            }
            DpuMachineMessage::GetPersisted(reply) => {
                reply.send(self.persisted()).ok();
                HandleMessageResult::ContinuePolling
            }
        }
    }

    async fn process_state(&mut self) -> Duration {
        if self.paused {
            return Duration::MAX;
        }

        tracing::trace!("state_machine.advance start");
        let result = self.state_machine.advance(true).await;
        tracing::trace!("state_machine.advance end");

        if let Some(machine_id) = self.state_machine.machine_id() {
            self.observed_machine_id = Some(machine_id.to_owned());
        } else if self.observed_machine_id.is_none() {
            if let Ok(Some(machine_id)) = self
                .app_context
                .forge_api_client
                .identify_serial(self.dpu_info.serial.clone())
                .await
                .map(|r| r.machine_id)
            {
                tracing::trace!("dpu's machine id: {}", machine_id);
                self.observed_machine_id = Some(machine_id);
            }
        }

        result
    }

    fn is_up(&self) -> bool {
        self.state_machine.is_up()
    }

    pub fn dpu_info(&self) -> &DpuMachineInfo {
        &self.dpu_info
    }

    fn persisted(&self) -> PersistedDpuMachine {
        PersistedDpuMachine {
            mat_id: self.mat_id,
            bmc_mac_address: self.dpu_info.bmc_mac_address,
            host_mac_address: self.dpu_info.host_mac_address,
            oob_mac_address: self.dpu_info.oob_mac_address,
            serial: self.dpu_info.serial.clone(),
            nic_mode: self.dpu_info.nic_mode,
            firmware_versions: self.dpu_info.firmware_versions.clone(),
            installed_os: self.state_machine.installed_os(),
            dpu_index: self.dpu_index,
            bmc_dhcp_id: self.state_machine.bmc_dhcp_id,
            machine_dhcp_id: self.state_machine.machine_dhcp_id,
        }
    }
}

enum DpuMachineMessage {
    SetSystemPower {
        request: SetSystemPowerReq,
        reply: Option<oneshot::Sender<SetSystemPowerResult>>,
    },
    Stop(oneshot::Sender<()>),
    GetHostDetails(oneshot::Sender<HostDetails>),
    GetObservedMachineId(oneshot::Sender<Option<rpc::MachineId>>),
    WaitUntilMachineUpWithApiState(String, oneshot::Sender<()>),
    IsUp(oneshot::Sender<bool>),
    SetPaused(bool),
    SetApiState(String),
    GetPersisted(oneshot::Sender<PersistedDpuMachine>),
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
    pub fn set_system_power(&self, request: SetSystemPowerReq) -> eyre::Result<()> {
        Ok(self.message_tx.send(DpuMachineMessage::SetSystemPower {
            request,
            reply: None,
        })?)
    }

    pub async fn is_up(&self) -> eyre::Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(DpuMachineMessage::IsUp(tx))?;
        Ok(rx.await?)
    }

    pub async fn observed_machine_id(&self) -> eyre::Result<Option<MachineId>> {
        let (tx, rx) = oneshot::channel();
        self.message_tx
            .send(DpuMachineMessage::GetObservedMachineId(tx))?;
        Ok(rx.await?)
    }

    pub async fn wait_until_machine_up_with_api_state(
        &self,
        state: &str,
        timeout: Duration,
    ) -> eyre::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.message_tx
            .send(DpuMachineMessage::WaitUntilMachineUpWithApiState(
                state.to_owned(),
                tx,
            ))?;
        tokio::time::timeout(timeout, rx).await?.wrap_err(format!(
            "timed out waiting for machine up with state {state}"
        ))
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

    pub async fn persisted(&self) -> eyre::Result<PersistedDpuMachine> {
        let (tx, rx) = oneshot::channel();
        self.message_tx.send(DpuMachineMessage::GetPersisted(tx))?;
        Ok(rx.await?)
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
            power_state: val.state_machine.redfish_power_state(),
        }
    }
}
