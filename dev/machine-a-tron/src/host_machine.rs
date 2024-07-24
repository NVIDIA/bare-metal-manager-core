use std::fmt::{Debug, Display};
use std::net::{Ipv4Addr, SocketAddr};

use rpc::MachineId;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::logging::{LogCollector, LogSink};
use crate::machine_state_machine::{MachineStateError, MachineStateMachine};
use crate::{
    config::{MachineATronContext, MachineConfig},
    dhcp_relay::DhcpRelayClient,
    dpu_machine::DpuMachine,
    machine_utils::get_api_state,
    tui::{HostDetails, UiEvent},
};
use bmc_mock::{HostMachineInfo, MachineCommand, MachineInfo};

const MAX_LOG_LINES: usize = 40;

#[derive(Debug)]
pub struct HostMachine {
    pub dpu_machines: Vec<DpuMachine>,

    mat_id: Uuid,
    host_info: HostMachineInfo,
    app_context: MachineATronContext,
    state_machine: MachineStateMachine,
    api_state: String,
    ui_event_tx: Option<tokio::sync::mpsc::Sender<UiEvent>>,
    logs: Vec<String>,

    dpus_previously_ready: bool,
    control_rx: mpsc::UnboundedReceiver<MachineCommand>,
    log_collector: LogCollector,
    logger: LogSink,
}

impl Display for HostMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let machine_id = self
            .state_machine
            .machine_id()
            .as_ref()
            .map(MachineId::to_string)
            .ok()
            .unwrap_or("Unknown".to_string());
        writeln!(f, "ID: {}", machine_id)?;
        writeln!(f, "Local State: {}", self.state_machine)?;
        writeln!(f, "API State: {}", self.api_state)?;
        writeln!(
            f,
            "Machine IP: {}",
            self.state_machine
                .machine_ip()
                .as_ref()
                .map(Ipv4Addr::to_string)
                .unwrap_or("<Unknown>".to_string()),
        )?;
        writeln!(
            f,
            "BMC IP: {}",
            self.state_machine
                .bmc_ip()
                .as_ref()
                .map(Ipv4Addr::to_string)
                .unwrap_or("<Unknown>".to_string()),
        )?;
        writeln!(f)?;
        writeln!(f, "DPUs:")?;
        writeln!(f)?;
        for (dpu_index, dpu) in self.dpu_machines.iter().enumerate() {
            writeln!(f, "{}: {}", dpu_index, dpu)?
        }
        Ok(())
    }
}

impl HostMachine {
    pub fn new(
        app_context: MachineATronContext,
        config: MachineConfig,
        ui_event_tx: Option<tokio::sync::mpsc::Sender<UiEvent>>,
        dhcp_client: DhcpRelayClient,
    ) -> Self {
        let log_collector = LogCollector::new();

        let dpus = (1..=config.dpu_per_host_count)
            .map(|index| {
                DpuMachine::new(
                    app_context.clone(),
                    config.clone(),
                    dhcp_client.clone(),
                    log_collector.log_sink(Some(format!("D{index}:"))),
                )
            })
            .collect::<Vec<_>>();

        let (control_tx, control_rx) = mpsc::unbounded_channel();

        let host_info = HostMachineInfo::new(dpus.iter().map(|d| d.dpu_info().clone()).collect());

        let state_machine = MachineStateMachine::new(
            MachineInfo::Host(host_info.clone()),
            config.clone(),
            app_context.clone(),
            dhcp_client.clone(),
            log_collector.log_sink(Some("H:".to_string())),
            control_tx,
        );

        HostMachine {
            mat_id: Uuid::new_v4(),
            host_info,
            state_machine,
            app_context,
            dpu_machines: dpus,
            api_state: "Unknown".to_owned(),

            ui_event_tx,

            logs: Vec::default(),
            dpus_previously_ready: false,
            control_rx,
            logger: log_collector.log_sink(Some("H:".to_string())),
            log_collector,
        }
    }

    pub async fn process_state(&mut self) -> Result<bool, MachineStateError> {
        let result = self.process_state_inner().await;

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
        result
    }

    pub async fn process_state_inner(&mut self) -> Result<bool, MachineStateError> {
        let mut work_done = false;
        self.api_state = get_api_state(
            &self.app_context,
            self.state_machine.machine_id().ok().as_ref(),
        )
        .await;

        // Consume all pending commands in case we got multiple reboot attempts
        while let Ok(command) = self.control_rx.try_recv() {
            match command {
                MachineCommand::Reboot(time) => {
                    self.logger.info(format!(
                        "Host: Reboot requested at {}: new state: {} api state: {}",
                        time, self.state_machine, self.api_state
                    ));
                    for dpu_machine in self.dpu_machines.iter_mut() {
                        dpu_machine.request_reboot(time);
                    }
                    self.state_machine.power_down()
                }
            }
        }

        self.logger.info(format!(
            "start: mat state: {} api state: {}",
            self.state_machine, self.api_state
        ));

        let mut dpus_ready = Vec::<bool>::new();
        for dpu in self.dpu_machines.iter_mut() {
            work_done |= match dpu.process_state().await {
                Ok(dpu_work_done) => dpu_work_done,
                Err(err) => {
                    tracing::error!("Internal machine-a-tron state error for mock DPU machine {}, will skip it: {}", dpu.mat_id, err);
                    false
                }
            };
            dpus_ready.push(dpu.is_up());
        }

        // give the API time to update the host after the dpus did something
        let dpus_ready = dpus_ready.into_iter().all(|r| r);
        if !self.dpus_previously_ready && dpus_ready {
            self.dpus_previously_ready = true;
            return Ok(true);
        }

        work_done |= self.state_machine.advance(dpus_ready).await?;
        self.logger.info(format!(
            "end: mat state {} api state {}",
            self.state_machine, self.api_state
        ));

        Ok(work_done)
    }

    pub async fn update_tui(&self) {
        let Some(ui_event_tx) = self.ui_event_tx.as_ref() else {
            return;
        };
        _ = ui_event_tx
            .send(UiEvent::MachineUpdate(HostDetails::from(self)))
            .await
            .inspect_err(|e| tracing::warn!("Error sending TUI event: {}", e));
    }

    pub fn machine_id_with_fallback(&self) -> String {
        self.state_machine
            .machine_id()
            .map(|m| m.to_string())
            .ok()
            .or(self
                .dpu_machines
                .first()
                .map(|d| d.dpu_info().host_mac_address.to_string()))
            .unwrap_or("<unknown>".to_string())
    }

    pub fn active_bmc_mock_address(&self) -> Option<SocketAddr> {
        self.state_machine.bmc_mock_address()
    }

    pub fn connect_ui_events(&mut self, ui_event_tx: Option<tokio::sync::mpsc::Sender<UiEvent>>) {
        self.ui_event_tx = ui_event_tx;
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
}

impl From<&HostMachine> for HostDetails {
    fn from(value: &HostMachine) -> Self {
        let mut dpus = Vec::with_capacity(value.dpu_machines.len());
        value.dpu_machines.iter().for_each(|d| dpus.push(d.into()));

        HostDetails {
            mat_id: value.mat_id,
            machine_id: value.state_machine.machine_id().ok().map(|i| i.to_string()),
            mat_state: value.state_machine.to_string(),
            api_state: value.api_state.clone(),
            oob_ip: value
                .state_machine
                .bmc_ip()
                .as_ref()
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            machine_ip: value
                .state_machine
                .machine_ip()
                .as_ref()
                .map(|ip| ip.to_string())
                .unwrap_or_default(),
            dpus,
            logs: value.logs.clone(),
        }
    }
}
