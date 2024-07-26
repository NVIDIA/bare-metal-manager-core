use std::fmt::Display;
use std::net::{Ipv4Addr, SocketAddr};

use chrono::{DateTime, Utc};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::bmc_mock_wrapper::BmcMockAddressRegistry;
use crate::logging::LogSink;
use crate::machine_state_machine::MachineStateMachine;
use crate::tui::HostDetails;
use crate::{
    config::{MachineATronContext, MachineConfig},
    dhcp_relay::DhcpRelayClient,
    machine_state_machine::MachineStateError,
    machine_utils::get_api_state,
};
use bmc_mock::{DpuMachineInfo, MachineCommand, MachineInfo};

#[derive(Debug)]
pub struct DpuMachine {
    pub mat_id: Uuid,
    state_machine: MachineStateMachine,

    dpu_info: DpuMachineInfo,
    app_context: MachineATronContext,
    api_state: String,
    control_rx: mpsc::UnboundedReceiver<MachineCommand>,
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
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let dpu_info = DpuMachineInfo::new();
        let state_machine = MachineStateMachine::new(
            MachineInfo::Dpu(dpu_info.clone()),
            config,
            app_context.clone(),
            dhcp_client,
            logger.clone(),
            control_tx.clone(),
            bmc_address_registry,
        );
        DpuMachine {
            mat_id: Uuid::new_v4(),
            dpu_info,
            state_machine,
            app_context,

            api_state: "Unknown".to_string(),
            control_rx,
            reboot_requested: None,
            logger,
        }
    }

    pub async fn process_state(&mut self) -> Result<bool, MachineStateError> {
        self.api_state = get_api_state(
            &self.app_context,
            self.state_machine.machine_id().ok().as_ref(),
        )
        .await;

        while let Ok(command) = self.control_rx.try_recv() {
            match command {
                MachineCommand::Reboot(time) => {
                    self.reboot_requested = Some(time);
                }
            }
        }

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

impl Display for DpuMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "{}:",
            self.state_machine
                .machine_id()
                .map(|m| m.to_string())
                .ok()
                .unwrap_or("Unknown".to_string())
        )?;
        writeln!(f, "    Local State: {}", self.state_machine)?;
        writeln!(f, "    API State: {}", self.api_state)?;
        writeln!(f, "    Machine MAC: {}", self.dpu_info.oob_mac_address)?;
        if let Some(ip) = self.state_machine.machine_ip().as_ref() {
            writeln!(f, "    Machine IP: {}", ip)?;
        }
        writeln!(f, "    BMC MAC: {}", self.dpu_info.bmc_mac_address)?;
        if let Some(ip) = self.state_machine.bmc_ip().as_ref() {
            writeln!(f, "    BMC IP: {}", ip)?;
        }
        Ok(())
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
