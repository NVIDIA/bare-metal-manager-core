use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use uuid::Uuid;

use crate::bmc_mock_wrapper::BmcMockAddressRegistry;
use crate::dpu_machine::DpuMachineHandle;
use crate::logging::{LogCollector, LogSink};
use crate::machine_state_machine::MachineStateMachine;
use crate::{
    config::{MachineATronContext, MachineConfig},
    dhcp_relay::DhcpRelayClient,
    dpu_machine::DpuMachine,
    machine_utils::get_api_state,
    saturating_add_duration_to_instant,
    tui::{HostDetails, UiEvent},
};
use bmc_mock::{BmcCommand, HostMachineInfo, MachineInfo};

const MAX_LOG_LINES: usize = 40;

#[derive(Debug)]
pub struct HostMachine {
    mat_id: Uuid,
    host_info: HostMachineInfo,
    app_context: MachineATronContext,
    state_machine: MachineStateMachine,
    api_state: String,
    logs: Vec<String>,

    dpu_run_state: DpuRunState,

    dpus_previously_ready: bool,
    bmc_control_rx: mpsc::UnboundedReceiver<BmcCommand>,
    log_collector: LogCollector,
    logger: LogSink,
}

#[derive(Debug)]
enum DpuRunState {
    Idle(Vec<DpuMachine>),
    Running(Vec<DpuMachineHandle>),
}

impl HostMachine {
    pub fn new(
        app_context: MachineATronContext,
        config: MachineConfig,
        dhcp_client: DhcpRelayClient,
        bmc_address_registry: Option<BmcMockAddressRegistry>,
    ) -> Self {
        let log_collector = LogCollector::new();

        let dpus = (1..=config.dpu_per_host_count)
            .map(|index| {
                DpuMachine::new(
                    app_context.clone(),
                    config.clone(),
                    dhcp_client.clone(),
                    log_collector.log_sink(Some(format!("D{index}:"))),
                    bmc_address_registry.clone(),
                )
            })
            .collect::<Vec<_>>();

        let (bmc_control_tx, bmc_control_rx) = mpsc::unbounded_channel();

        let host_info = HostMachineInfo::new(dpus.iter().map(|d| d.dpu_info().clone()).collect());

        let state_machine = MachineStateMachine::new(
            MachineInfo::Host(host_info.clone()),
            config.clone(),
            app_context.clone(),
            dhcp_client.clone(),
            log_collector.log_sink(Some("H:".to_string())),
            bmc_control_tx.clone(),
            bmc_address_registry,
        );

        HostMachine {
            mat_id: Uuid::new_v4(),
            host_info,
            state_machine,
            app_context,
            dpu_run_state: DpuRunState::Idle(dpus),
            api_state: "Unknown".to_owned(),

            logs: Vec::default(),
            dpus_previously_ready: false,
            bmc_control_rx,
            logger: log_collector.log_sink(Some("H:".to_string())),
            log_collector,
        }
    }

    pub fn start(
        mut self,
        mut stop_rx: oneshot::Receiver<()>,
        ui_event_tx: Option<mpsc::Sender<UiEvent>>,
        stop_when_ready: bool,
    ) -> JoinHandle<()> {
        // Start DPUs
        let DpuRunState::Idle(dpu_machines) = self.dpu_run_state else {
            panic!("BUG: DPU machines already started?")
        };
        let mut dpu_handles = dpu_machines
            .into_iter()
            .map(|d| d.start())
            .collect::<Vec<_>>();
        self.dpu_run_state = DpuRunState::Running(dpu_handles.clone());

        tokio::task::Builder::new()
            .name(&format!("Host {}", self.mat_id))
            .spawn(async move {
                self.maybe_update_tui(ui_event_tx.as_ref()).await;

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
                    self.maybe_update_tui(ui_event_tx.as_ref()).await;

                    if stop_when_ready && self.is_up_and_ready() {
                        tracing::info!(
                                    "Machine {} has made it to Ready/MachineUp, all done.",
                                    self.machine_id_with_fallback()
                                );
                        break;
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

                        _ = &mut stop_rx => {
                            for dpu_handle in dpu_handles {
                                _ = dpu_handle.stop().await;
                            }
                            break;
                        },

                        Some(cmd) = self.bmc_control_rx.recv() => {
                            match cmd {
                                BmcCommand::Reboot(time) => {
                                    self.logger.info(format!(
                                        "Host reboot requested at {}: new state: {} api state: {}",
                                        time, self.state_machine, self.api_state
                                    ));
                                    for (dpu_index, dpu_handle) in dpu_handles.iter_mut().enumerate() {
                                        _ = dpu_handle.reboot(time).inspect_err(|e| self.logger.error(format!("Could not reboot DPU {dpu_index}: {e}")));
                                    }
                                    self.state_machine.power_down()
                                }
                            }
                            // continue to process_state
                        }
                    }

                    let sleep_duration = self
                        .process_state(&dpu_handles)
                        .await;

                    sleep_until =
                        saturating_add_duration_to_instant(Instant::now(), sleep_duration);
                }
            })
            .unwrap()
    }

    pub async fn process_state(&mut self, dpu_handles: &[DpuMachineHandle]) -> Duration {
        self.logger.info(format!(
            "start: mat state: {} api state: {}",
            self.state_machine, self.api_state
        ));

        let mut dpus_ready = Vec::<bool>::new();
        for dpu in dpu_handles {
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

        sleep_duration
    }

    pub async fn maybe_update_tui(&self, ui_event_tx: Option<&mpsc::Sender<UiEvent>>) {
        let Some(ui_event_tx) = ui_event_tx else {
            return;
        };
        _ = ui_event_tx
            .send(UiEvent::MachineUpdate(self.host_details().await))
            .await
            .inspect_err(|e| tracing::warn!("Error sending TUI event: {}", e));
    }

    pub fn machine_id_with_fallback(&self) -> String {
        self.state_machine
            .machine_id()
            .map(|m| m.to_string())
            .ok()
            .or(self.host_info.system_mac_address().map(|m| m.to_string()))
            .unwrap_or("<unknown>".to_string())
    }

    pub fn active_bmc_mock_address(&self) -> Option<SocketAddr> {
        self.state_machine.bmc_mock_address()
    }

    pub fn host_machine_info(&self) -> &HostMachineInfo {
        &self.host_info
    }

    pub fn is_up_and_ready(&self) -> bool {
        self.state_machine.is_up() && self.api_state.eq("Ready")
    }

    pub fn bmc_ip(&self) -> Option<Ipv4Addr> {
        self.state_machine.bmc_ip()
    }

    // Note: We can't implment From<HostMachine> for HostDetails, because we need this to be async
    // in order to query DPU state.
    pub async fn host_details(&self) -> HostDetails {
        let dpus = match &self.dpu_run_state {
            DpuRunState::Running(dpu_handles) => {
                let mut dpus = Vec::with_capacity(dpu_handles.len());
                for dpu_handle in dpu_handles {
                    dpus.push(dpu_handle.host_details().await.unwrap_or_default());
                }
                dpus
            }
            DpuRunState::Idle(dpu_machines) => dpu_machines.iter().map(|d| d.into()).collect(),
        };

        HostDetails {
            mat_id: self.mat_id,
            machine_id: self.state_machine.machine_id().ok().map(|i| i.to_string()),
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
            dpus,
            logs: self.logs.clone(),
        }
    }
}
