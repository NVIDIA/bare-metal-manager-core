use chrono::{DateTime, Utc};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

use crate::bmc_mock_wrapper::BmcMockAddressRegistry;
use crate::logging::LogSink;
use crate::machine_state_machine::MachineStateMachine;
use crate::tui::HostDetails;
use crate::{
    config::{MachineATronContext, MachineConfig},
    dhcp_relay::DhcpRelayClient,
    machine_utils::get_api_state,
    saturating_add_duration_to_instant,
};
use bmc_mock::{BmcCommand, DpuMachineInfo, MachineInfo};

#[derive(Debug)]
pub struct DpuMachine {
    pub mat_id: Uuid,
    state_machine: MachineStateMachine,

    dpu_info: DpuMachineInfo,
    app_context: MachineATronContext,
    api_state: String,
    bmc_control_rx: mpsc::UnboundedReceiver<BmcCommand>,
    reboot_requested: Option<DateTime<Utc>>,
    logger: LogSink,
}

impl DpuMachine {
    pub fn new(
        app_context: MachineATronContext,
        config: MachineConfig,
        dhcp_client: DhcpRelayClient,
        logger: LogSink,
        bmc_address_registry: Option<BmcMockAddressRegistry>,
    ) -> Self {
        let (bmc_control_tx, bmc_control_rx) = mpsc::unbounded_channel();
        let dpu_info = DpuMachineInfo::new();
        let state_machine = MachineStateMachine::new(
            MachineInfo::Dpu(dpu_info.clone()),
            config,
            app_context.clone(),
            dhcp_client,
            logger.clone(),
            bmc_control_tx.clone(),
            bmc_address_registry,
        );
        DpuMachine {
            mat_id: Uuid::new_v4(),
            dpu_info,
            state_machine,
            app_context,

            api_state: "Unknown".to_string(),
            bmc_control_rx,
            reboot_requested: None,
            logger,
        }
    }

    pub fn start(mut self) -> DpuMachineHandle {
        let (control_tx, mut control_rx) = mpsc::unbounded_channel();
        tokio::task::Builder::new()
            .name(&format!("DPU {}", self.mat_id))
            .spawn(async move {
                let mut sleep_until = Instant::now();
                loop {
                    tokio::select! {
                        _ = tokio::time::sleep_until(sleep_until.into()) => {},
                        Some(cmd) = self.bmc_control_rx.recv() => {
                            match cmd {
                                BmcCommand::Reboot(time) => {
                                    self.request_reboot(time);
                                }
                            }
                        }
                        Some(cmd) = control_rx.recv() => {
                            if let DpuMachineCommand::Stop(reply) = cmd {
                                _ = reply.send(());
                                break;
                            }
                            self.handle_command(cmd).await;
                            continue; // go back to sleeping
                        }
                    }

                    let sleep_duration = self.process_state().await;

                    sleep_until =
                        saturating_add_duration_to_instant(Instant::now(), sleep_duration);
                }
            })
            .unwrap();

        DpuMachineHandle { control_tx }
    }

    async fn handle_command(&mut self, command: DpuMachineCommand) {
        match command {
            DpuMachineCommand::Reboot(time) => self.request_reboot(time),
            DpuMachineCommand::IsUp(reply) => {
                _ = reply.send(self.is_up());
            }
            DpuMachineCommand::GetHostDetails(reply) => {
                _ = reply.send(HostDetails::from(&*self));
            }
            DpuMachineCommand::Stop(_) => {
                panic!("BUG: Stop should have been handled directly in control loop!")
            }
        }
    }

    pub async fn process_state(&mut self) -> Duration {
        self.api_state = get_api_state(
            &self.app_context,
            self.state_machine.machine_id().ok().as_ref(),
        )
        .await;

        if let Some(time) = self.reboot_requested.take() {
            self.logger.info(format!(
                "Reboot requested at {}: new state: {} api state: {}",
                time, self.state_machine, self.api_state
            ));
            self.state_machine.power_down()
        }

        self.logger.info(format!(
            "start: mat state: {} api state: {}",
            self.state_machine, self.api_state
        ));

        let result = self.state_machine.advance(true).await;

        self.logger.info(format!(
            "end: mat state {} api state {}",
            self.state_machine, self.api_state
        ));

        result
    }

    pub fn request_reboot(&mut self, time: DateTime<Utc>) {
        self.logger.info(format!(
            "DPU reboot requested at {}: new state: {} api state: {}",
            time, self.state_machine, self.api_state
        ));
        self.reboot_requested = Some(time);
    }

    pub fn is_up(&self) -> bool {
        self.state_machine.is_up()
    }

    pub fn dpu_info(&self) -> &DpuMachineInfo {
        &self.dpu_info
    }

    pub fn get_bmc_ip(&self) -> Option<Ipv4Addr> {
        self.state_machine.bmc_ip()
    }

    pub fn active_bmc_mock_address(&self) -> Option<SocketAddr> {
        self.state_machine.bmc_mock_address()
    }
}

enum DpuMachineCommand {
    Reboot(DateTime<Utc>),
    Stop(oneshot::Sender<()>),
    GetHostDetails(oneshot::Sender<HostDetails>),
    IsUp(oneshot::Sender<bool>),
}

/// DpuMachineHandle presents a friendly, actor-style interface for various methods a HostMachine
/// needs to call while a DpuMachine is running.
///
/// This is needed because DpuMachine runs its own control loop inside a Tokio Task, which consumes
/// self, and it is not thread-safe to query the DPU while it's running. Instead, the control loop
/// will poll for any DpuMachineCommands sent to it (in addition to periodically running
/// process_state) and reply to them. DpuMachineHandle abstracts these commands/replies into simple
/// async methods.
#[derive(Debug, Clone)]
pub struct DpuMachineHandle {
    control_tx: mpsc::UnboundedSender<DpuMachineCommand>,
}

impl DpuMachineHandle {
    pub fn reboot(&self, time: DateTime<Utc>) -> eyre::Result<()> {
        Ok(self.control_tx.send(DpuMachineCommand::Reboot(time))?)
    }

    pub async fn is_up(&self) -> eyre::Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.control_tx.send(DpuMachineCommand::IsUp(tx))?;
        Ok(rx.await?)
    }

    pub async fn host_details(&self) -> eyre::Result<HostDetails> {
        let (tx, rx) = oneshot::channel();
        self.control_tx
            .send(DpuMachineCommand::GetHostDetails(tx))?;
        Ok(rx.await?)
    }

    pub async fn stop(self) -> eyre::Result<()> {
        let (tx, rx) = oneshot::channel();
        self.control_tx.send(DpuMachineCommand::Stop(tx))?;
        Ok(rx.await?)
    }
}

impl From<&DpuMachine> for HostDetails {
    fn from(val: &DpuMachine) -> Self {
        HostDetails {
            mat_id: val.mat_id,
            machine_id: val.state_machine.machine_id().ok().map(|id| id.to_string()),
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
            logs: Vec::default(),
        }
    }
}
