/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::net::{IpAddr, SocketAddr};
use std::{collections::HashMap, fmt::Display, net::Ipv4Addr};

use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use health_override::HealthReportOverrides;
use health_report::HealthReport;
use libredfish::SystemPowerControl;
use mac_address::MacAddress;
use rpc::forge::HealthOverrideOrigin;
use rpc::forge_agent_control_response::{Action, ForgeAgentControlExtraInfo};
use serde::{Deserialize, Serialize};

use self::network::{MachineNetworkStatusObservation, ManagedHostNetworkConfig};
use super::{
    bmc_info::BmcInfo, controller_outcome::PersistentStateHandlerOutcome,
    hardware_info::MachineInventory, instance::snapshot::InstanceSnapshot, StateSla,
};
use crate::cfg::HardwareHealthReportsConfig;
use crate::{
    cfg::FirmwareComponentType, model::hardware_info::HardwareInfo,
    state_controller::state_handler::StateHandlerError, CarbideError,
};
use ::rpc::errors::RpcDataConversionError;
use forge_uuid::{
    domain::DomainId, machine::MachineId, machine::MachineInterfaceId,
    machine::RpcMachineTypeWrapper, network::NetworkSegmentId,
};

mod slas;

pub mod health_override;
pub mod machine_id;
pub mod network;
pub mod storage;
pub mod upgrade_policy;
use strum_macros::EnumIter;

pub fn get_display_ids(machines: &[MachineSnapshot]) -> String {
    machines
        .iter()
        .map(|x| x.machine_id.to_string())
        .collect::<Vec<String>>()
        .join("/")
}

fn default_true() -> bool {
    true
}

/// Represents the current state of `Machine`
#[derive(Debug, Clone)]
pub struct ManagedHostStateSnapshot {
    pub host_snapshot: MachineSnapshot,
    pub dpu_snapshots: Vec<MachineSnapshot>,
    /// If there is an instance provisioned on top of the machine, this holds
    /// its state
    pub instance: Option<InstanceSnapshot>,
    pub managed_state: ManagedHostState,
    /// Aggregated health. This is calculated based on the health of Hosts and DPUs
    pub aggregate_health: health_report::HealthReport,
}

/// Reasons why a Machine is not allocatable
#[derive(thiserror::Error, Clone, PartialEq, Eq, Debug)]
pub enum NotAllocatableReason {
    #[error("The Machine is in a state other than `Ready`: {0:?}")]
    InvalidState(Box<ManagedHostState>),
    #[error("The Machine has a pending instance creation request, that has not yet been processed by the state handler")]
    PendingInstanceCreation,
    #[error("There are no dpu_snapshots, but associated_dpu_machine_ids is non-empty")]
    NoDpuSnapshots,
    #[error("The Machine is in Maintenance Mode")]
    MaintenanceMode,
    #[error("A Health Alert prevents the Machine from being allocated: {0:?}")]
    HealthAlert(Box<health_report::HealthProbeAlert>),
}

#[derive(Debug, thiserror::Error)]
pub enum ManagedHostStateSnapshotError {
    #[error("Missing attached dpu id in primary interface. Machine id: {0}")]
    AttachedDpuIdMissing(MachineId),

    #[error("Missing dpu with primary dpu id. Machine id: {0}, DPU ID: {1}")]
    MissingPrimaryDpu(MachineId, MachineId),
}

impl ManagedHostStateSnapshot {
    /// Returns `Ok` if the Host can be used as an instance
    ///
    /// This requires
    /// - the Machine to be in `Ready` state
    /// - the Machine has not yet been target of an instance creation request
    /// - no health alerts which classification `PreventAllocations` to be set
    /// - the machine not to be in Maintenance Mode
    pub fn is_usable_as_instance(&self) -> Result<(), NotAllocatableReason> {
        if !matches!(self.managed_state, ManagedHostState::Ready) {
            return Err(NotAllocatableReason::InvalidState(Box::new(
                self.managed_state.clone(),
            )));
        }

        // A new instance can be created only in Ready state.
        // This is possible that a instance is created by user, but still not picked by state machine.
        // To avoid that race condition, need to check if db has any entry with given machine id.
        if self.instance.is_some() {
            return Err(NotAllocatableReason::PendingInstanceCreation);
        }

        if self.dpu_snapshots.is_empty()
            && !self.host_snapshot.associated_dpu_machine_ids().is_empty()
        {
            return Err(NotAllocatableReason::NoDpuSnapshots);
        }

        if let Some(alert) = self.aggregate_health.find_alert_by_classification(
            &health_report::HealthAlertClassification::prevent_allocations(),
        ) {
            return Err(NotAllocatableReason::HealthAlert(Box::new(alert.clone())));
        }

        if self.host_snapshot.is_maintenance_mode() {
            return Err(NotAllocatableReason::MaintenanceMode);
        }

        Ok(())
    }

    /// Derives the aggregate health of the Managed Host based on individual
    /// health reports
    pub fn derive_aggregate_health(
        &mut self,
        hardware_health_reports_config: HardwareHealthReportsConfig,
    ) {
        // TODO: In the future we will also take machine-validation results into consideration

        let source = "aggregate-host-health".to_string();
        let observed_at = Some(chrono::Utc::now());

        // If there is an [`OverrideMode::Replace`] health report override on
        // the host, then use that.
        if let Some(mut over) = self.host_snapshot.health_report_overrides.replace.clone() {
            over.source = source;
            over.observed_at = observed_at;
            self.aggregate_health = over;
            return;
        }

        let mut output = health_report::HealthReport::empty("".to_string());
        output.merge(&self.host_snapshot.machine_validation_health_report);

        if let Some(report) = self.host_snapshot.site_explorer_health_report.as_ref() {
            output.merge(report);
        }

        let merge_or_timeout =
            |output: &mut HealthReport, input: &Option<HealthReport>, target: String| {
                if let Some(input) = input {
                    output.merge(input);
                } else {
                    output.merge(&HealthReport::heartbeat_timeout(
                        "".to_string(),
                        target,
                        "".to_string(),
                    ));
                }
            };

        // Merge hardware health if configured.
        use HardwareHealthReportsConfig as HWConf;
        match hardware_health_reports_config {
            HWConf::Disabled => {}
            HWConf::MonitorOnly => {
                // If MonitorOnly, clear all alert classifications.
                if let Some(h) = &mut self.host_snapshot.hardware_health_report {
                    for alert in &mut h.alerts {
                        alert.classifications.clear();
                    }
                    output.merge(h)
                }
            }
            HWConf::Enabled => {
                // If hw_health_reports are enabled, then add a heartbeat timeout
                // if the report is missing.
                merge_or_timeout(
                    &mut output,
                    &self.host_snapshot.hardware_health_report,
                    "hardware-health".to_string(),
                );
            }
        }

        // Merge DPU's
        for snapshot in self.dpu_snapshots.iter() {
            merge_or_timeout(
                &mut output,
                &snapshot.dpu_agent_health_report,
                "forge-dpu-agent".to_string(),
            );
            if let Some(report) = snapshot.site_explorer_health_report.as_ref() {
                output.merge(report);
            }
            for over in snapshot.health_report_overrides.merges.values() {
                output.merge(over);
            }
        }

        for over in self.host_snapshot.health_report_overrides.merges.values() {
            output.merge(over);
        }

        output.source = source;
        output.observed_at = observed_at;
        self.aggregate_health = output;
    }

    /// Creates an RPC Machine representation for either the Host or one of the DPUs
    pub fn rpc_machine_state(
        &self,
        dpu_machine_id: Option<&MachineId>,
    ) -> Option<rpc::forge::Machine> {
        match dpu_machine_id {
            None => {
                let mut rpc_machine: rpc::forge::Machine = self.host_snapshot.clone().into();
                rpc_machine.health = Some(self.aggregate_health.clone().into());
                Some(rpc_machine)
            }
            Some(dpu_machine_id) => {
                let dpu_snapshot = self
                    .dpu_snapshots
                    .iter()
                    .find(|dpu| dpu.machine_id == *dpu_machine_id)?;
                let mut rpc_machine: rpc::forge::Machine = dpu_snapshot.clone().into();
                // In case the DPU does not know the associated Host - we can backfill the data here
                rpc_machine.associated_host_machine_id =
                    Some(self.host_snapshot.machine_id.to_string().into());
                Some(rpc_machine)
            }
        }
    }

    /// Returns true if the desired managedhost networking configuration had been synced
    /// to **all** DPUs.
    pub fn managed_host_network_config_version_synced(&self) -> bool {
        for dpu_snapshot in self.dpu_snapshots.iter() {
            if !dpu_snapshot.managed_host_network_config_version_synced() {
                return false;
            }
        }

        true
    }

    /// Sort the dpu snapshots in a way that primary DPU remains at first position.
    pub fn sort_dpu_snapshots(&mut self) -> Result<(), ManagedHostStateSnapshotError> {
        let primary_dpu_id = self
            .host_snapshot
            .interfaces
            .iter()
            .find_map(|x| {
                if x.is_primary {
                    Some(x.attached_dpu_machine_id.clone())
                } else {
                    None
                }
            })
            .flatten();

        if let Some(primary_dpu_id) = primary_dpu_id {
            let index = self
                .dpu_snapshots
                .iter()
                .position(|x| x.machine_id == primary_dpu_id)
                .ok_or_else(|| {
                    ManagedHostStateSnapshotError::MissingPrimaryDpu(
                        self.host_snapshot.machine_id.clone(),
                        primary_dpu_id,
                    )
                })?;

            if index != 0 {
                let snapshot = self.dpu_snapshots.remove(index);
                self.dpu_snapshots.insert(0, snapshot);
            }
        } else if !self.dpu_snapshots.is_empty() {
            // If it is not Zero-DPU case, return failure.
            return Err(ManagedHostStateSnapshotError::AttachedDpuIdMissing(
                self.host_snapshot.machine_id.clone(),
            ));
        };

        Ok(())
    }

    pub fn create(
        host_snapshot: MachineSnapshot,
        dpu_snapshots: Vec<MachineSnapshot>,
        instance: Option<InstanceSnapshot>,
        managed_state: ManagedHostState,
        hardware_health: HardwareHealthReportsConfig,
    ) -> Result<Self, ManagedHostStateSnapshotError> {
        let mut snapshot = ManagedHostStateSnapshot {
            host_snapshot,
            dpu_snapshots,
            instance,
            managed_state,
            aggregate_health: health_report::HealthReport::empty("".to_string()),
        };

        snapshot.sort_dpu_snapshots()?;
        snapshot.derive_aggregate_health(hardware_health);

        Ok(snapshot)
    }
}

impl TryFrom<ManagedHostStateSnapshot> for Option<rpc::Instance> {
    type Error = RpcDataConversionError;

    fn try_from(mut snapshot: ManagedHostStateSnapshot) -> Result<Self, Self::Error> {
        let Some(instance) = snapshot.instance.take() else {
            return Ok(None);
        };

        // TODO: If multiple DPUs have reprovisioning requested, we might not get
        // the expected response
        let mut reprovision_request = snapshot.host_snapshot.reprovision_requested.clone();
        for dpu in &snapshot.dpu_snapshots {
            if let Some(reprovision_requested) = dpu.reprovisioning_requested() {
                reprovision_request = Some(reprovision_requested.clone());
            }
        }

        let status = instance.derive_status(snapshot.managed_state.clone(), reprovision_request)?;

        Ok(Some(rpc::Instance {
            id: Some(instance.id.into()),
            machine_id: Some(instance.machine_id.to_string().into()),
            config: Some(instance.config.try_into()?),
            status: Some(status.try_into()?),
            config_version: instance.config_version.version_string(),
            network_config_version: instance.network_config_version.version_string(),
            ib_config_version: instance.ib_config_version.version_string(),
            storage_config_version: instance.storage_config_version.version_string(),
            metadata: Some(instance.metadata.try_into()?),
        }))
    }
}

/// Represents the last_reboot_requested data
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MachineLastRebootRequestedMode {
    Reboot,
    PowerOff,
    PowerOn,
    GracefulShutdown,
}

impl From<SystemPowerControl> for MachineLastRebootRequestedMode {
    fn from(value: SystemPowerControl) -> Self {
        match value {
            SystemPowerControl::On => Self::PowerOn,
            SystemPowerControl::GracefulShutdown => Self::PowerOff,
            SystemPowerControl::ForceOff => Self::PowerOff,
            SystemPowerControl::GracefulRestart => Self::Reboot,
            SystemPowerControl::ForceRestart => Self::Reboot,
        }
    }
}

impl Display for MachineLastRebootRequestedMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineLastRebootRequested {
    pub time: DateTime<Utc>,
    pub mode: MachineLastRebootRequestedMode,
}

impl Default for MachineLastRebootRequested {
    fn default() -> Self {
        MachineLastRebootRequested {
            time: Default::default(),
            mode: MachineLastRebootRequestedMode::Reboot,
        }
    }
}

/// Represents the current state of `Machine`
#[derive(Debug, Clone)]
pub struct MachineSnapshot {
    /// Machine ID
    pub machine_id: MachineId,
    /// Hardware Information that was discovered about this Machine
    pub hardware_info: Option<HardwareInfo>,
    /// Inventory related to a DPU machine.
    /// Software and versions installed on the machine.
    pub agent_reported_inventory: MachineInventory,
    /// The desired network configuration for this machine
    /// Includes the loopback_ip address. Do not query that
    /// directly, use `.loopback_ip()` instead.
    pub network_config: Versioned<ManagedHostNetworkConfig>,
    /// The actual network configuration, as reported by forge-dpu-agent
    pub network_status_observation: Option<MachineNetworkStatusObservation>,
    /// BMC related information
    pub bmc_info: BmcInfo,
    pub bmc_vendor: bmc_vendor::BMCVendor,
    /// Network interfaces
    pub interfaces: Vec<MachineInterfaceSnapshot>,
    /// Desired state of the machine
    pub current: CurrentMachineState,
    /// Last discovery request from scout.
    pub last_discovery_time: Option<DateTime<Utc>>,
    /// Last reboot time. Calculated from forge_agent_control call.
    pub last_reboot_time: Option<DateTime<Utc>>,
    /// Last reboot requested time.
    pub last_reboot_requested: Option<MachineLastRebootRequested>,
    /// Last cleanup completed message received from scout.
    pub last_cleanup_time: Option<DateTime<Utc>>,
    /// URL of the reference tracking this machine's maintenance (e.g. JIRA)
    /// Some(_) means the machine is in maintenance mode.
    /// None means not in maintenance mode.
    pub maintenance_reference: Option<String>,
    /// What time was this machine set into maintenance mode?
    pub maintenance_start_time: Option<DateTime<Utc>>,
    /// Failure cause. Needed to move machine in failed state.
    pub failure_details: FailureDetails,
    /// Reprovisioning is needed?
    pub reprovision_requested: Option<ReprovisionRequest>,
    pub host_reprovision_requested: Option<HostReprovisionRequest>,
    pub bios_password_set_time: Option<DateTime<Utc>>,
    /// Last host validation finished.
    pub last_machine_validation_time: Option<DateTime<Utc>>,
    /// current discovery validation id.
    pub discovery_machine_validation_id: Option<uuid::Uuid>,
    /// current cleanup validation id.
    pub cleanup_machine_validation_id: Option<uuid::Uuid>,
    /// Last time when machine reprovisioning_requested.
    pub reprovisioning_requested: Option<ReprovisionRequest>,
    /// Latest health report received by forge-dpu-agent
    pub dpu_agent_health_report: Option<HealthReport>,
    /// Latest health report generated by validation tests
    pub machine_validation_health_report: HealthReport,
    /// Latest health report generated by Site Explorer
    pub site_explorer_health_report: Option<HealthReport>,
    /// Override to enable or disable firmware auto update
    pub firmware_autoupdate: Option<bool>,
    /// Latest health report received by hardware health
    pub hardware_health_report: Option<HealthReport>,

    // TODO: These fields are not needed every time we load a Machine
    // and might be migrated somewher else.
    // For simplicity reasons, they are however referenced here for the moment
    /// A list of [MachineStateHistory] that this machine has experienced
    pub history: Vec<MachineStateHistory>,

    /// Latest active health overrides set in the database
    /// An override with [`OverrideMode::Override`] can only be set on the host.
    pub health_report_overrides: HealthReportOverrides,

    /// on demand validation id.
    pub on_demand_machine_validation_id: Option<uuid::Uuid>,

    pub on_demand_machine_validation_request: Option<bool>,
}

impl MachineSnapshot {
    pub fn loopback_ip(&self) -> Option<Ipv4Addr> {
        self.network_config.loopback_ip
    }

    pub fn use_admin_network(&self) -> bool {
        self.network_config.use_admin_network.unwrap_or(true)
    }

    pub fn is_maintenance_mode(&self) -> bool {
        self.maintenance_reference.is_some()
    }

    pub fn maintenance_reference(&self) -> Option<&str> {
        self.maintenance_reference.as_deref()
    }

    pub fn reprovisioning_requested(&self) -> Option<&ReprovisionRequest> {
        self.reprovisioning_requested.as_ref()
    }

    /// Returns all associated DPU Machine IDs if this is Host Machine
    pub fn associated_dpu_machine_ids(&self) -> Vec<MachineId> {
        if self.machine_id.machine_type().is_dpu() {
            return Vec::new();
        }

        self.interfaces
            .iter()
            .filter_map(|i| i.attached_dpu_machine_id.clone())
            .collect::<Vec<MachineId>>()
    }

    pub fn bmc_addr(&self) -> Option<SocketAddr> {
        self.bmc_info
            .ip
            .as_ref()
            .and_then(|ip| ip.parse().ok())
            .map(|ip| SocketAddr::new(ip, self.bmc_info.port.unwrap_or(443)))
    }

    /// If this machine is a DPU, then this returns whether the desired ManagedHost
    /// network configuration had been applied by forge-dpu-agent
    pub fn managed_host_network_config_version_synced(&self) -> bool {
        let dpu_expected_version = self.network_config.version;
        let dpu_observation = self.network_status_observation.as_ref();
        let dpu_observed_version: ConfigVersion = match dpu_observation {
            None => {
                return false;
            }
            Some(network_status) => match network_status.network_config_version {
                None => {
                    return false;
                }
                Some(version) => version,
            },
        };

        if dpu_expected_version != dpu_observed_version {
            return false;
        }

        true
    }
}

impl From<MachineSnapshot> for rpc::forge::Machine {
    fn from(machine: MachineSnapshot) -> Self {
        let health = match machine.machine_id.machine_type().is_dpu() {
            true => {
                let mut health = machine.dpu_agent_health_report.clone().unwrap_or_else(|| {
                    HealthReport::heartbeat_timeout(
                        "forge-dpu-agent".to_string(),
                        "forge-dpu-agent".to_string(),
                        "No health data was received from DPU".to_string(),
                    )
                });
                if let Some(hr) = machine.site_explorer_health_report.as_ref() {
                    health.merge(hr);
                }
                match machine.health_report_overrides.replace.as_ref() {
                    Some(over) => over.clone(),
                    None => {
                        for over in machine.health_report_overrides.merges.values() {
                            health.merge(over);
                        }
                        health
                    }
                }
            }
            false => HealthReport::empty("aggregate-health".to_string()), // Health is written by ManagedHostStateSnapshot
        };

        let associated_dpu_machine_ids: Vec<rpc::MachineId> = machine
            .associated_dpu_machine_ids()
            .iter()
            .map(|id| id.to_string().into())
            .collect();
        let associated_dpu_machine_id = associated_dpu_machine_ids.first().cloned();

        rpc::Machine {
            id: Some(machine.machine_id.to_string().into()),
            state: if machine.machine_id.machine_type().is_dpu() {
                machine.current.state.dpu_state_string(&machine.machine_id)
            } else {
                machine.current.state.to_string()
            },
            state_version: machine.current.version.version_string(),
            state_sla: Some(state_sla(&machine.current.state, &machine.current.version).into()),
            machine_type: *RpcMachineTypeWrapper::from(machine.machine_id.machine_type()) as _,
            events: machine
                .history
                .into_iter()
                .map(|event| event.into())
                .collect(),
            interfaces: machine
                .interfaces
                .into_iter()
                .map(|interface| interface.into())
                .collect(),
            discovery_info: machine
                .hardware_info
                .and_then(|hw_info| match hw_info.try_into() {
                    Ok(di) => Some(di),
                    Err(e) => {
                        tracing::warn!(
                            machine_id = %machine.machine_id,
                            error = %e,
                            "Hardware information couldn't be parsed into discovery info",
                        );
                        None
                    }
                }),
            bmc_info: Some(machine.bmc_info.into()),
            last_reboot_time: machine.last_reboot_time.map(|t| t.into()),
            last_observation_time: machine
                .network_status_observation
                .as_ref()
                .map(|obs| obs.observed_at.into()),
            dpu_agent_version: machine
                .network_status_observation
                .as_ref()
                .and_then(|obs| obs.agent_version.clone()),
            maintenance_reference: machine.maintenance_reference,
            maintenance_start_time: machine.maintenance_start_time.map(|t| t.into()),
            associated_host_machine_id: None, // Gets filled in the `ManagedHostStateSnapshot` conversion
            associated_dpu_machine_ids,
            associated_dpu_machine_id,
            inventory: Some(machine.agent_reported_inventory.clone().into()),
            last_reboot_requested_time: machine
                .last_reboot_requested
                .as_ref()
                .map(|x| x.time.into()),
            last_reboot_requested_mode: machine
                .last_reboot_requested
                .as_ref()
                .map(|x| x.mode.to_string()),
            state_reason: machine.current.outcome.map(|r| r.into()),
            health: Some(health.into()),
            firmware_autoupdate: machine.firmware_autoupdate,
            health_overrides: machine
                .health_report_overrides
                .create_iter()
                .map(|(hr, m)| HealthOverrideOrigin {
                    mode: m as i32,
                    source: hr.source,
                })
                .collect(),
            failure_details: if machine.failure_details.cause != FailureCause::NoError {
                Some(machine.failure_details.to_string())
            } else {
                None
            },
        }
    }
}

/// Represents the current state of `Machine`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentMachineState {
    pub state: ManagedHostState,
    pub version: ConfigVersion,
    /// Outcome of the last state handler iteration
    pub outcome: Option<PersistentStateHandlerOutcome>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DpuDiscoveringStates {
    pub states: HashMap<MachineId, DpuDiscoveringState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DpuInitStates {
    pub states: HashMap<MachineId, DpuInitState>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct DpuReprovisionStates {
    pub states: HashMap<MachineId, ReprovisionState>,
}

/// Possible Machine state-machine implementation
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
/// Possible ManagedHost state-machine implementation
/// Only DPU machine field in DB will contain state. Host will be empty. DPU state field will be
/// used to derive state for DPU and Host both.
pub enum ManagedHostState {
    /// Dpu was discovered by a site-explorer and is being configuring via redfish.
    DpuDiscoveringState {
        dpu_states: DpuDiscoveringStates,
    },
    /// DPU is not yet ready.
    DPUInit {
        dpu_states: DpuInitStates,
    },
    /// DPU is ready, Host is not yet Ready.
    // We don't need dpu_states as DPU's machine state is always Ready here.
    HostInit {
        machine_state: MachineState,
    },
    /// Host is Ready for instance creation.
    Ready,
    /// Host is assigned to an Instance.
    Assigned {
        instance_state: InstanceState,
    },
    /// Some cleanup is going on.
    // This is host specific state. We expect DPU to be in Ready state.
    WaitingForCleanup {
        cleanup_state: CleanupState,
    },

    /// A forced deletion process has been triggered by the admin CLI
    /// State controller will no longer manage the Machine
    ForceDeletion,

    /// A dummy state used to create DPU in beginning. State will sync to Init when host will be
    /// created.
    Created,

    /// Machine moved to failed state. Recovery will be based on FailedCause
    Failed {
        details: FailureDetails,
        machine_id: MachineId,
        #[serde(default)]
        retry_count: u32,
    },

    /// State used to indicate that DPU reprovisioning is going on.
    DPUReprovision {
        dpu_states: DpuReprovisionStates,
    },

    /// State used to indicate that host reprovisioning is going on
    HostReprovision {
        reprovision_state: HostReprovisionState,
    },

    /// State used to indicate the API is currently waiting on the
    /// machine to send attestation measurements, or waiting for
    /// measurements to match a valid/approved measurement bundle,
    /// before continuing on towards a Ready state.
    // This is host specific state. We expect DPU to be in Ready state.
    Measuring {
        measuring_state: MeasuringState,
    },

    PostAssignedMeasuring {
        measuring_state: MeasuringState,
    },
}

impl ManagedHostState {
    pub fn as_reprovision_state(&self, dpu_id: &MachineId) -> Option<&ReprovisionState> {
        match self {
            ManagedHostState::DPUReprovision { dpu_states } => dpu_states.states.get(dpu_id),
            ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision { dpu_states },
            } => dpu_states.states.get(dpu_id),
            _ => None,
        }
    }
}

// Since order is derived, Enum members must be in initial to last state sequence.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ReprovisionState {
    BmcFirmwareUpgrade {
        substate: BmcFirmwareUpgradeSubstate,
    },
    FirmwareUpgrade,
    PoweringOffHost,
    PowerDown,
    BufferTime,
    WaitingForNetworkInstall,
    WaitingForNetworkConfig,
    RebootHostBmc,
    RebootHost,
    NotUnderReprovision,
}

impl ReprovisionState {
    // This is normal case when user wants to reprovision only one DPU. In this condition, this
    // function will update state only for those DPU for which reprovision is triggered. Reset will
    // be updated as NotUnderReprovision state.
    pub fn next_state_with_all_dpus_updated(
        self,
        current_state: &ManagedHostState,
        dpu_snapshots: &[MachineSnapshot],
        dpu_ids_to_process: Vec<&MachineId>,
    ) -> Result<ManagedHostState, StateHandlerError> {
        match current_state {
            ManagedHostState::Ready => {
                let states = dpu_snapshots
                    .iter()
                    .map(|x| {
                        (
                            x.machine_id.clone(),
                            if dpu_ids_to_process.contains(&&x.machine_id) {
                                self.clone()
                            } else {
                                ReprovisionState::NotUnderReprovision
                            },
                        )
                    })
                    .collect::<HashMap<MachineId, ReprovisionState>>();

                Ok(ManagedHostState::DPUReprovision {
                    dpu_states: DpuReprovisionStates { states },
                })
            }
            ManagedHostState::DPUReprovision { dpu_states: _ } => {
                let states = dpu_snapshots
                    .iter()
                    .map(|x| {
                        (
                            x.machine_id.clone(),
                            if dpu_ids_to_process.contains(&&x.machine_id) {
                                self.clone()
                            } else {
                                ReprovisionState::NotUnderReprovision
                            },
                        )
                    })
                    .collect::<HashMap<MachineId, ReprovisionState>>();
                Ok(ManagedHostState::DPUReprovision {
                    dpu_states: DpuReprovisionStates { states },
                })
            }
            ManagedHostState::Assigned { instance_state } => match instance_state {
                InstanceState::DPUReprovision { .. }
                | InstanceState::BootingWithDiscoveryImage { .. }
                | InstanceState::Failed { .. } => {
                    let states = dpu_snapshots
                        .iter()
                        .map(|x| {
                            (
                                x.machine_id.clone(),
                                if dpu_ids_to_process.contains(&&x.machine_id) {
                                    self.clone()
                                } else {
                                    ReprovisionState::NotUnderReprovision
                                },
                            )
                        })
                        .collect::<HashMap<MachineId, ReprovisionState>>();

                    Ok(ManagedHostState::Assigned {
                        instance_state: InstanceState::DPUReprovision {
                            dpu_states: DpuReprovisionStates { states },
                        },
                    })
                }

                _ => Err(StateHandlerError::InvalidState(format!(
                    "Invalid State {:?} passed to Reprovision::Assigned::next_state_with_all_dpus.",
                    current_state
                ))),
            },
            _ => Err(StateHandlerError::InvalidState(format!(
                "Invalid State {:?} passed to Reprovision::next_state_with_all_dpus.",
                current_state
            ))),
        }
    }

    pub fn next_state(
        self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError> {
        match current_state {
            ManagedHostState::DPUReprovision { dpu_states } => {
                let mut states = dpu_states.states.clone();
                let entry = states.entry(dpu_id.clone()).or_insert(self.clone());
                *entry = self;

                Ok(ManagedHostState::DPUReprovision {
                    dpu_states: DpuReprovisionStates { states },
                })
            }

            ManagedHostState::Assigned { instance_state } => match instance_state {
                InstanceState::DPUReprovision { dpu_states } => {
                    let mut states = dpu_states.states.clone();
                    let entry = states.entry(dpu_id.clone()).or_insert(self.clone());
                    *entry = self;

                    Ok(ManagedHostState::Assigned {
                        instance_state: InstanceState::DPUReprovision {
                            dpu_states: DpuReprovisionStates { states },
                        },
                    })
                }
                InstanceState::BootingWithDiscoveryImage { retry: _ } => {
                    Ok(ManagedHostState::Assigned {
                        instance_state: InstanceState::DPUReprovision {
                            dpu_states: DpuReprovisionStates {
                                states: HashMap::from([(dpu_id.clone(), self.clone())]),
                            },
                        },
                    })
                }
                _ => Err(StateHandlerError::InvalidState(
                    "Invalid State passed to Reprovision::Assigned::next_state.".to_string(),
                )),
            },
            _ => Err(StateHandlerError::InvalidState(
                "Invalid State passed to Reprovision::next_state.".to_string(),
            )),
        }
    }

    pub fn next_bmc_updrade_step(
        &self,
        current_state: &ManagedHostStateSnapshot,
        dpu_snapshot: &MachineSnapshot,
    ) -> Result<ManagedHostState, StateHandlerError> {
        let dpu_machine_id = &dpu_snapshot.machine_id;
        match current_state.managed_state.clone() {
            ManagedHostState::DPUReprovision { dpu_states } => {
                let mut states = dpu_states.states.clone();
                states.insert(dpu_machine_id.clone(), self.clone());
                Ok(ManagedHostState::DPUReprovision {
                    dpu_states: DpuReprovisionStates { states },
                })
            }
            ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision { dpu_states },
            } => match self {
                ReprovisionState::BmcFirmwareUpgrade {
                    substate: BmcFirmwareUpgradeSubstate::Failed { failure_details },
                } => Ok(ManagedHostState::Assigned {
                    instance_state: InstanceState::Failed {
                        details: FailureDetails {
                            cause: FailureCause::Reprovisioning {
                                err: failure_details.clone(),
                            },
                            failed_at: chrono::Utc::now(),
                            source: FailureSource::StateMachine,
                        },
                        machine_id: dpu_machine_id.clone(),
                    },
                }),
                _ => {
                    let mut states = dpu_states.states.clone();
                    states.insert(dpu_machine_id.clone(), self.clone());
                    Ok(ManagedHostState::Assigned {
                        instance_state: InstanceState::DPUReprovision {
                            dpu_states: DpuReprovisionStates { states },
                        },
                    })
                }
            },
            _ => Err(StateHandlerError::InvalidState(
                "Invalid State passed to Reprovision::next_bmc_updrade_step.".to_string(),
            )),
        }
    }
}

/// MeasuringState contains states used for host attestion (or
/// measured boot).
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MeasuringState {
    /// WaitingForMeasurements is reported when the machine
    /// has reached a state where the API is now expecting
    /// measurements from the machine, which Scout sends upon
    /// receiving an Action::Measure from the API.
    WaitingForMeasurements,

    /// PendingBundle is reported when the API has received
    /// measurements from the machine, but the measurements
    /// do not match a known bundle. At this point, a matching
    /// bundle needs to be created, either via "promoting" a
    /// measurement report from a machine (through manual
    /// interaction or trusted approval automation), or by
    /// manually creating a new bundle.
    PendingBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HostReprovisionState {
    CheckingFirmware,
    WaitingForFirmwareUpgrade {
        task_id: String,
        final_version: String,
        firmware_type: FirmwareComponentType,
    },
    ResetForNewFirmware {
        final_version: String,
        firmware_type: FirmwareComponentType,
    },
    NewFirmwareReportedWait {
        final_version: String,
        firmware_type: FirmwareComponentType,
    },
    FailedFirmwareUpgrade {
        firmware_type: FirmwareComponentType,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FailureCause {
    NoError,
    NVMECleanFailed { err: String },
    Discovery { err: String },
    Reprovisioning { err: String },
    MachineValidation { err: String },
    UnhandledState { err: String },

    // Host Attestation / Measured Boot related failure causes.
    //
    // MeasurementsFailedSignatureCheck is returned when the
    // signed PCR quote fails signature verification. That is,
    // we cannot verify the PCR (Platform Configuration Register,
    // in the context of Trusted Platform Modules) values were
    // signed by the TPM. If this state is being reported, a TPM
    // event log should have been dumped by the API for viewing.
    MeasurementsFailedSignatureCheck { err: String },

    // MeasurementsRetired is returned when the measurements
    // provided by the machine match a bundle that has been
    // marked as retired, thus not allowing the machine to
    // move forward towards a Ready state.
    MeasurementsRetired { err: String },

    // MeasurementsRevoked is returned when the measurements
    // provided by the machine match a bundle that has been
    // marked as revoked, thus not allowing the machine to
    // move forward towards a Ready state.
    //
    // The difference between retired and revoked is that a
    // retired bundle can be moved out of retirement, whereas
    // a revoked bundle cannot.
    MeasurementsRevoked { err: String },

    MeasurementsCAValidationFailed { err: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum StateMachineArea {
    Default,
    HostInit,
    MainFlow,
    AssignedInstance,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum FailureSource {
    NoError,
    Scout,
    StateMachine,
    StateMachineArea(StateMachineArea),
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct FailureDetails {
    pub cause: FailureCause,
    pub failed_at: DateTime<Utc>,
    pub source: FailureSource,
}

// Since order is derived, Enum members must be in initial to last state sequence.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
#[serde(tag = "bmcfirmwareupdatesubstate", rename_all = "lowercase")]
pub enum BmcFirmwareUpgradeSubstate {
    CheckFwVersion,
    WaitForUpdateCompletion {
        firmware_type: FirmwareComponentType,
        task_id: String,
    },
    Reboot {
        count: u32,
    },
    HostPowerCycle,
    Failed {
        failure_details: String,
    },
    FwUpdateCompleted,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
#[serde(tag = "dpudiscoverystate", rename_all = "lowercase")]
pub enum DpuDiscoveringState {
    /// Dpu discovery via redfish states
    Initializing,
    Configuring,
    RebootAllDPUS,
    DisableSecureBoot {
        // this substate is optional because it was added after DisableSecureBoot was initially created (just in case we have a machine stuck in this state even though we shouldnt)
        disable_secure_boot_state: Option<DisableSecureBootState>,
        count: u32,
    },
    SetUefiHttpBoot,
    EnableRshim,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Hash, Copy, Clone, Ord, PartialOrd)]
#[serde(tag = "disablesecurebootstate", rename_all = "lowercase")]
pub enum DisableSecureBootState {
    CheckSecureBootStatus,
    DisableSecureBoot,
    RebootDPU { reboot_count: u32 },
}

impl DpuDiscoveringState {
    pub fn next_state(
        self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError> {
        match current_state {
            ManagedHostState::DpuDiscoveringState { dpu_states } => {
                let mut states = dpu_states.states.clone();
                let entry = states.entry(dpu_id.clone()).or_insert(self.clone());
                *entry = self;

                Ok(ManagedHostState::DpuDiscoveringState {
                    dpu_states: DpuDiscoveringStates { states },
                })
            }
            _ => Err(StateHandlerError::InvalidState(
                "Invalid State passed to DpuDiscoveringState::next_state.".to_string(),
            )),
        }
    }

    pub fn next_state_with_all_dpus_updated(
        self,
        current_state: &ManagedHostState,
    ) -> Result<ManagedHostState, StateHandlerError> {
        match current_state {
            ManagedHostState::DpuDiscoveringState { dpu_states } => {
                let states = dpu_states
                    .states
                    .keys()
                    .map(|x| (x.clone(), self.clone()))
                    .collect::<HashMap<MachineId, DpuDiscoveringState>>();

                Ok(ManagedHostState::DpuDiscoveringState {
                    dpu_states: DpuDiscoveringStates { states },
                })
            }
            _ => Err(StateHandlerError::InvalidState(
                "Invalid State passed to DpuDiscoveringState::next_state_all_dpu.".to_string(),
            )),
        }
    }
}

// Since order is derived, Enum members must be in initial to last state sequence.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
#[serde(tag = "dpustate", rename_all = "lowercase")]
pub enum DpuInitState {
    Init,
    WaitingForPlatformPowercycle { substate: PerformPowerOperation },
    WaitingForPlatformConfiguration,
    WaitingForNetworkConfig,
    WaitingForNetworkInstall, // Deprecated now, not used
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum PerformPowerOperation {
    Off,
    On,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum MachineState {
    Init,
    EnableIpmiOverLan,
    WaitingForPlatformConfiguration,
    UefiSetup {
        uefi_setup_info: UefiSetupInfo,
    },
    Measuring {
        measuring_state: MeasuringState,
    },
    WaitingForDiscovery,
    Discovered {
        #[serde(default)]
        skip_reboot_wait: bool,
    },
    /// Lockdown handling.
    WaitingForLockdown {
        lockdown_info: LockdownInfo,
    },
    MachineValidating {
        context: String,
        id: uuid::Uuid,
        completed: usize,
        total: usize,
        #[serde(default = "default_true")]
        is_enabled: bool,
    },
}

impl DpuInitState {
    pub fn next_state(
        self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError> {
        match current_state {
            ManagedHostState::DPUInit { dpu_states } => {
                let mut states = dpu_states.states.clone();
                let entry = states.entry(dpu_id.clone()).or_insert(self.clone());
                *entry = self;

                Ok(ManagedHostState::DPUInit {
                    dpu_states: DpuInitStates { states },
                })
            }

            _ => Err(StateHandlerError::InvalidState(
                "Invalid State passed to DpuNotReady::next_state.".to_string(),
            )),
        }
    }

    pub fn next_state_with_all_dpus_updated(
        self,
        current_state: &ManagedHostState,
    ) -> Result<ManagedHostState, StateHandlerError> {
        match current_state {
            ManagedHostState::DPUInit { dpu_states } => {
                let states = dpu_states
                    .states
                    .keys()
                    .map(|x| (x.clone(), self.clone()))
                    .collect::<HashMap<MachineId, DpuInitState>>();

                Ok(ManagedHostState::DPUInit {
                    dpu_states: DpuInitStates { states },
                })
            }
            ManagedHostState::DpuDiscoveringState { dpu_states } => {
                // All DPUs must be moved to same DPUInit state.
                let states = dpu_states
                    .states
                    .keys()
                    .map(|x| (x.clone(), DpuInitState::Init))
                    .collect::<HashMap<MachineId, DpuInitState>>();
                Ok(ManagedHostState::DPUInit {
                    dpu_states: DpuInitStates { states },
                })
            }
            _ => Err(StateHandlerError::InvalidState(
                "Invalid State passed to DpuNotReady::next_state_all_dpu.".to_string(),
            )),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct LockdownInfo {
    pub state: LockdownState,
    pub mode: LockdownMode,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct UefiSetupInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uefi_password_jid: Option<String>,
    pub uefi_setup_state: UefiSetupState,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, EnumIter)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum UefiSetupState {
    UnlockHost,
    SetUefiPassword,
    WaitForPasswordJobScheduled,
    PowercycleHost,
    WaitForPasswordJobCompletion,
    LockdownHost,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum CleanupState {
    HostCleanup,
    DisableBIOSBMCLockdown,
}

/// Substates of enabling/disabling lockdown
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")] // No tag requried - this is not nested
pub enum LockdownState {
    /// We simply wait in this state for a certain amount of time to allow the
    /// DPU to go down. Besides waiting to other checks are performed.
    TimeWaitForDPUDown,
    /// In this state we check whether the DPU restarted and is reachable again
    WaitForDPUUp,
}

/// Whether lockdown should be enabled or disabled in an operation
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")] // No tag required - this will never be nested
pub enum LockdownMode {
    Enable,
}

/// Whether lockdown should be enabled or disabled in an operation
#[derive(Debug, Default, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")] // No tag required - this will never be nested
pub struct RetryInfo {
    pub count: u64,
}

/// Possible Instance state-machine implementation, for when the machine host is assigned to a tenant
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum InstanceState {
    Init, // Instance is created but not picked by state machine yet.
    // In case of vpc_prefix based interface config, state machine should wait until network
    // segment reaches to Ready state.
    WaitingForNetworkSegmentToBeReady,
    WaitingForNetworkConfig,
    WaitingForStorageConfig,
    WaitingForRebootToReady,
    Ready,
    BootingWithDiscoveryImage {
        #[serde(default)]
        retry: RetryInfo,
    },
    SwitchToAdminNetwork,
    WaitingForNetworkReconfig,
    DPUReprovision {
        dpu_states: DpuReprovisionStates,
    },
    Failed {
        details: FailureDetails,
        machine_id: MachineId,
    },
}

/// Struct to store information if Reprovision is requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReprovisionRequest {
    pub requested_at: DateTime<Utc>,
    pub initiator: String,
    pub update_firmware: bool,
    #[serde(default)]
    pub started_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub user_approval_received: bool,
    #[serde(default)]
    pub restart_reprovision_requested_at: DateTime<Utc>,
}

/// Struct to store information if host reprovision is requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostReprovisionRequest {
    pub requested_at: DateTime<Utc>,
}

/// Should a forge-dpu-agent upgrade itself?
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeDecision {
    pub should_upgrade: bool,
    pub to_version: String,
    pub last_updated: DateTime<Utc>,
}

impl From<ReprovisionRequest> for ::rpc::forge::InstanceUpdateStatus {
    fn from(value: ReprovisionRequest) -> Self {
        ::rpc::forge::InstanceUpdateStatus {
            module: ::rpc::forge::instance_update_status::Module::Dpu as i32,
            initiator: value.initiator,
            trigger_received_at: Some(value.requested_at.into()),
            update_triggered_at: value.started_at.map(|x| x.into()),
            user_approval_received: value.user_approval_received,
        }
    }
}

impl Display for DpuDiscoveringState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for DpuInitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for MachineState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for InstanceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for CleanupState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for LockdownState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for FailureSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for FailureCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureCause::NVMECleanFailed { .. } => write!(f, "NVMECleanFailed"),
            FailureCause::NoError => write!(f, "NoError"),
            FailureCause::Discovery { .. } => write!(f, "Discovery"),
            FailureCause::Reprovisioning { .. } => write!(f, "Reprovisioning"),
            FailureCause::UnhandledState { .. } => write!(f, "UnknownState"),
            FailureCause::MeasurementsFailedSignatureCheck { .. } => {
                write!(f, "MeasurementsFailedSignatureCheck")
            }
            FailureCause::MeasurementsRetired { .. } => write!(f, "MeasurementsRetired"),
            FailureCause::MeasurementsRevoked { .. } => write!(f, "MeasurementsRevoked"),
            FailureCause::MachineValidation { .. } => write!(f, "MachineValidation"),
            FailureCause::MeasurementsCAValidationFailed { .. } => {
                write!(f, "MeasurementsCAValidationFailed")
            }
        }
    }
}

impl Display for FailureDetails {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.source, self.cause)
    }
}

impl Display for ReprovisionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for HostReprovisionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for MeasuringState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Display for ManagedHostState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ManagedHostState::DpuDiscoveringState { dpu_states } => {
                // Min state indicates the least processed DPU. The state machine is blocked
                // becasue of this.
                let dpu_lowest_state = dpu_states
                    .states
                    .values()
                    .min()
                    .map(|x| x.to_string())
                    .unwrap_or("Unknown".to_string());

                write!(f, "DPUDiscovering/{dpu_lowest_state}")
            }
            ManagedHostState::DPUInit { dpu_states } => {
                let dpu_lowest_state = dpu_states
                    .states
                    .values()
                    .min()
                    .map(|x| x.to_string())
                    .unwrap_or("Unknown".to_string());
                write!(f, "DPUInitializing/{dpu_lowest_state}")
            }
            ManagedHostState::HostInit { machine_state } => {
                write!(f, "HostInitializing/{}", machine_state)
            }
            ManagedHostState::Ready => write!(f, "Ready"),
            ManagedHostState::Assigned { instance_state, .. } => match instance_state {
                InstanceState::DPUReprovision { dpu_states } => {
                    let dpu_lowest_state = dpu_states
                        .states
                        .values()
                        .min()
                        .map(|x| x.to_string())
                        .unwrap_or("Unknown".to_string());
                    write!(f, "Assigned/Reprovision/{dpu_lowest_state}")
                }
                _ => {
                    write!(f, "Assigned/{}", instance_state)
                }
            },
            ManagedHostState::WaitingForCleanup { cleanup_state } => {
                write!(f, "WaitingForCleanup/{}", cleanup_state)
            }
            ManagedHostState::ForceDeletion => write!(f, "ForceDeletion"),
            ManagedHostState::Failed { details, .. } => {
                write!(f, "Failed/{}", details.cause)
            }
            ManagedHostState::DPUReprovision { dpu_states } => {
                let dpu_lowest_state = dpu_states
                    .states
                    .values()
                    .min()
                    .map(|x| x.to_string())
                    .unwrap_or("Unknown".to_string());
                write!(f, "Reprovisioning/{dpu_lowest_state}")
            }
            ManagedHostState::HostReprovision { reprovision_state } => {
                write!(f, "HostReprovisioning/{}", reprovision_state)
            }
            ManagedHostState::Measuring { measuring_state } => {
                write!(f, "Measuring/{}", measuring_state)
            }
            ManagedHostState::PostAssignedMeasuring { measuring_state } => {
                write!(f, "PostAssignedMeasuring/{}", measuring_state)
            }
            ManagedHostState::Created => write!(f, "Created"),
        }
    }
}

impl ManagedHostState {
    pub fn dpu_state_string(&self, dpu_id: &MachineId) -> String {
        match self {
            ManagedHostState::DpuDiscoveringState { dpu_states } => dpu_states
                .states
                .get(dpu_id)
                .map(|x| x.to_string())
                .unwrap_or("Unknown DPU".to_string()),
            ManagedHostState::DPUInit { dpu_states } => format!(
                "DPUInitializing/{}",
                dpu_states
                    .states
                    .get(dpu_id)
                    .map(|x| x.to_string())
                    .unwrap_or("Unknown DPU".to_string())
            ),
            ManagedHostState::HostInit { machine_state } => {
                format!("HostInitializing/{}", machine_state)
            }
            ManagedHostState::Ready => "Ready".to_string(),
            ManagedHostState::Assigned { instance_state } => match instance_state {
                InstanceState::DPUReprovision { dpu_states } => {
                    format!(
                        "Assigned/Reprovision/{}",
                        dpu_states
                            .states
                            .get(dpu_id)
                            .map(|x| x.to_string())
                            .unwrap_or("Unknown DPU".to_string())
                    )
                }
                _ => format!("Assigned/{}", instance_state),
            },
            ManagedHostState::WaitingForCleanup { cleanup_state } => {
                format!("WaitingForCleanup/{}", cleanup_state)
            }
            ManagedHostState::ForceDeletion => "ForceDeletion".to_string(),
            ManagedHostState::Failed { details, .. } => {
                format!("Failed/{}", details.cause)
            }
            ManagedHostState::DPUReprovision { dpu_states } => {
                format!(
                    "Reprovisioning/{}",
                    dpu_states
                        .states
                        .get(dpu_id)
                        .map(|x| x.to_string())
                        .unwrap_or("Unknown DPU".to_string())
                )
            }
            ManagedHostState::HostReprovision { reprovision_state } => {
                format!("HostReprovisioning/{}", reprovision_state)
            }
            ManagedHostState::Measuring { measuring_state } => {
                format!("Measuring/{}", measuring_state)
            }
            ManagedHostState::PostAssignedMeasuring { measuring_state } => {
                format!("PostAssignedMeasuring/{}", measuring_state)
            }
            ManagedHostState::Created => "Created".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineInterfaceSnapshot {
    pub id: MachineInterfaceId,
    pub hostname: String,
    pub is_primary: bool,
    pub mac_address: MacAddress,
    pub attached_dpu_machine_id: Option<MachineId>,
    pub domain_id: Option<DomainId>,
    pub machine_id: Option<MachineId>,
    pub segment_id: NetworkSegmentId,
    pub vendors: Vec<String>,
    pub created: DateTime<Utc>,
    pub last_dhcp: Option<DateTime<Utc>>,
    pub addresses: Vec<IpAddr>,
}

impl MachineInterfaceSnapshot {
    pub fn mock_with_mac(mac_address: MacAddress) -> Self {
        Self {
            id: MachineInterfaceId::from(uuid::Uuid::nil()),
            attached_dpu_machine_id: None,
            domain_id: None,
            machine_id: None,
            segment_id: uuid::Uuid::nil().into(),
            mac_address,
            hostname: String::new(),
            is_primary: true,
            addresses: Vec::new(),
            vendors: Vec::new(),
            created: chrono::DateTime::default(),
            last_dhcp: None,
        }
    }
}

impl From<MachineInterfaceSnapshot> for rpc::MachineInterface {
    fn from(machine_interface: MachineInterfaceSnapshot) -> rpc::MachineInterface {
        rpc::MachineInterface {
            id: Some(machine_interface.id.into()),
            attached_dpu_machine_id: machine_interface
                .attached_dpu_machine_id
                .map(|id| id.to_string().into()),
            machine_id: machine_interface.machine_id.map(|id| id.into()),
            segment_id: Some(machine_interface.segment_id.into()),
            hostname: machine_interface.hostname,
            domain_id: machine_interface.domain_id.map(|d| d.into()),
            mac_address: machine_interface.mac_address.to_string(),
            primary_interface: machine_interface.is_primary,
            address: machine_interface
                .addresses
                .iter()
                .map(|addr| addr.to_string())
                .collect(),
            vendor: machine_interface.vendors.last().cloned(),
            created: Some(machine_interface.created.into()),
            last_dhcp: machine_interface.last_dhcp.map(|t| t.into()),
            is_bmc: None,
        }
    }
}

pub struct InstanceNextStateResolver;
pub struct MachineNextStateResolver;

pub trait NextReprovisionState {
    fn next_state(
        &self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError>;

    fn next_state_with_all_dpus_updated(
        &self,
        state: &ManagedHostStateSnapshot,
        current_reprovision_state: &ReprovisionState,
    ) -> Result<ManagedHostState, StateHandlerError> {
        let dpu_ids_for_reprov =
        // EnumIter conflicts with Itertool, don't know why?
            itertools::Itertools::collect_vec(state.dpu_snapshots.iter().filter_map(|x| {
                if x.reprovision_requested.is_some() {
                    Some(&x.machine_id)
                } else {
                    None
                }
            }));

        let all_machine_ids =
            itertools::Itertools::collect_vec(state.dpu_snapshots.iter().map(|x| &x.machine_id));

        match current_reprovision_state {
            ReprovisionState::FirmwareUpgrade => ReprovisionState::PoweringOffHost
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    // Mark all DPUs in PowerDown state.
                    all_machine_ids,
                ),
            ReprovisionState::PoweringOffHost => ReprovisionState::PowerDown
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    // Mark all DPUs in PowerDown state.
                    all_machine_ids,
                ),
            ReprovisionState::PowerDown => ReprovisionState::WaitingForNetworkInstall
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    // Move only DPUs in WaitingForNetworkInstall for which reprovision is
                    // triggered.
                    dpu_ids_for_reprov,
                ),
            ReprovisionState::WaitingForNetworkInstall => ReprovisionState::BufferTime
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    all_machine_ids,
                ),
            ReprovisionState::BufferTime => ReprovisionState::WaitingForNetworkConfig
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    all_machine_ids,
                ),
            ReprovisionState::WaitingForNetworkConfig => ReprovisionState::RebootHostBmc
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    all_machine_ids,
                ),
            ReprovisionState::RebootHostBmc => ReprovisionState::RebootHost
                .next_state_with_all_dpus_updated(
                    &state.managed_state,
                    &state.dpu_snapshots,
                    all_machine_ids,
                ),
            _ => Err(StateHandlerError::InvalidState(format!(
                "Unhandled {} state for all dpu handling.",
                current_reprovision_state
            ))),
        }
    }
}

impl NextReprovisionState for MachineNextStateResolver {
    fn next_state(
        &self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError> {
        let reprovision_state = current_state
            .as_reprovision_state(dpu_id)
            .ok_or_else(|| StateHandlerError::MissingDpuFromState(dpu_id.clone()))?;

        match reprovision_state {
            ReprovisionState::RebootHost => Ok(ManagedHostState::HostInit {
                machine_state: MachineState::Discovered {
                    skip_reboot_wait: false,
                },
            }),
            _ => Err(StateHandlerError::InvalidState(format!(
                "Unhandled {} state for Non-Instance handling.",
                reprovision_state
            ))),
        }
    }
}

impl NextReprovisionState for InstanceNextStateResolver {
    fn next_state(
        &self,
        current_state: &ManagedHostState,
        dpu_id: &MachineId,
    ) -> Result<ManagedHostState, StateHandlerError> {
        let reprovision_state = current_state
            .as_reprovision_state(dpu_id)
            .ok_or_else(|| StateHandlerError::MissingDpuFromState(dpu_id.clone()))?;

        match reprovision_state {
            ReprovisionState::RebootHost => Ok(ManagedHostState::Assigned {
                instance_state: InstanceState::Ready,
            }),
            _ => Err(StateHandlerError::InvalidState(format!(
                "Unhandled {} state for Instance handling.",
                reprovision_state
            ))),
        }
    }
}

pub fn get_action_for_dpu_state(
    state: &ManagedHostState,
    dpu_machine_id: &MachineId,
) -> Result<(Action, Option<ForgeAgentControlExtraInfo>), CarbideError> {
    Ok(match state {
        ManagedHostState::DPUReprovision { .. }
        | ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision { .. },
        } => {
            let dpu_state = state
                .as_reprovision_state(dpu_machine_id)
                .ok_or_else(|| CarbideError::MissingDpu(dpu_machine_id.clone()))?;
            match dpu_state {
                ReprovisionState::BufferTime => (Action::Retry, None),
                ReprovisionState::WaitingForNetworkInstall => (Action::Discovery, None),
                _ => {
                    tracing::info!(
                        dpu_machine_id = %dpu_machine_id,
                        machine_type = "DPU",
                        %state,
                        "forge agent control",
                    );
                    (Action::Noop, None)
                }
            }
        }
        ManagedHostState::DPUInit { dpu_states } => {
            let dpu_state = dpu_states
                .states
                .get(dpu_machine_id)
                .ok_or_else(|| CarbideError::MissingDpu(dpu_machine_id.clone()))?;

            match dpu_state {
                DpuInitState::Init => (Action::Discovery, None),
                _ => {
                    tracing::info!(
                        dpu_machine_id = %dpu_machine_id,
                        machine_type = "DPU",
                        %state,
                        "forge agent control",
                    );
                    (Action::Noop, None)
                }
            }
        }
        _ => {
            // Later this might go to site admin dashboard for manual intervention
            tracing::info!(
                dpu_machine_id = %dpu_machine_id,
                machine_type = "DPU",
                %state,
                "forge agent control",
            );
            (Action::Noop, None)
        }
    })
}

pub fn all_equal<A>(states: &[A]) -> Result<bool, StateHandlerError>
where
    A: PartialEq,
{
    let Some(first) = states.first() else {
        return Err(StateHandlerError::MissingData {
            object_id: "NA".to_string(),
            missing: "DPU states.",
        });
    };

    Ok(states.iter().all(|x| x == first))
}

impl ManagedHostState {
    pub fn all_dpu_states_in_sync(&self) -> Result<bool, StateHandlerError> {
        match self {
            // Don't now why but if I use itertools::Itertools in header, EnumIter creates problem.
            ManagedHostState::DpuDiscoveringState { dpu_states } => all_equal(
                &itertools::Itertools::collect_vec(dpu_states.states.values()),
            ),
            ManagedHostState::DPUInit { dpu_states } => all_equal(
                &itertools::Itertools::collect_vec(dpu_states.states.values()),
            ),
            // TODO: multidpu: reprovision state handling.
            _ => Ok(true),
        }
    }
}

/// History of Machine states for a single Machine
#[derive(Debug, Clone)]
pub struct MachineStateHistory {
    /// The state that was entered
    pub state: String,
    // The version number associated with the state change
    pub state_version: ConfigVersion,
}

impl From<MachineStateHistory> for rpc::MachineEvent {
    fn from(value: MachineStateHistory) -> rpc::MachineEvent {
        rpc::MachineEvent {
            event: value.state,
            version: value.state_version.version_string(),
            time: Some(value.state_version.timestamp().into()),
        }
    }
}

/// Returns the SLA for the current state
pub fn state_sla(state: &ManagedHostState, state_version: &ConfigVersion) -> StateSla {
    let time_in_state = chrono::Utc::now()
        .signed_duration_since(state_version.timestamp())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));

    match state {
        ManagedHostState::DpuDiscoveringState { dpu_states } => {
            // Min state indicates the least processed DPU. The state machine is blocked
            // because of this.
            let dpu_state = dpu_states.states.values().min();
            let Some(dpu_state) = dpu_state else {
                return StateSla::no_sla();
            };

            match dpu_state {
                DpuDiscoveringState::Initializing
                | DpuDiscoveringState::Configuring
                | DpuDiscoveringState::DisableSecureBoot { .. }
                | DpuDiscoveringState::SetUefiHttpBoot
                | DpuDiscoveringState::RebootAllDPUS
                | DpuDiscoveringState::EnableRshim => StateSla::with_sla(
                    std::time::Duration::from_secs(slas::DPUDISCOVERING),
                    time_in_state,
                ),
            }
        }
        ManagedHostState::DPUInit { dpu_states } => {
            // Min state indicates the least processed DPU. The state machine is blocked
            // because of this.
            let dpu_state = dpu_states.states.values().min();
            let Some(dpu_state) = dpu_state else {
                return StateSla::no_sla();
            };

            // Init has no SLA since starting discovery requires a manual action
            match dpu_state {
                DpuInitState::Init => StateSla::no_sla(),
                _ => StateSla::with_sla(
                    std::time::Duration::from_secs(slas::DPUINIT_NOTINIT),
                    time_in_state,
                ),
            }
        }
        ManagedHostState::HostInit { machine_state } => match machine_state {
            MachineState::Init => StateSla::no_sla(),
            _ => StateSla::with_sla(
                std::time::Duration::from_secs(slas::HOST_INIT),
                time_in_state,
            ),
        },
        ManagedHostState::Ready => StateSla::no_sla(),
        ManagedHostState::Assigned { instance_state } => match instance_state {
            InstanceState::Ready => StateSla::no_sla(),
            InstanceState::BootingWithDiscoveryImage { retry } if retry.count > 0 => {
                // Since retries happen after 30min, the occurence of any retry means we exhausted the SLA
                StateSla::with_sla(std::time::Duration::ZERO, time_in_state)
            }
            _ => StateSla::with_sla(
                std::time::Duration::from_secs(slas::ASSIGNED),
                time_in_state,
            ),
        },
        ManagedHostState::WaitingForCleanup { .. } => StateSla::with_sla(
            std::time::Duration::from_secs(slas::WAITING_FOR_CLEANUP),
            time_in_state,
        ),
        ManagedHostState::Created => {
            StateSla::with_sla(std::time::Duration::from_secs(slas::CREATED), time_in_state)
        }
        ManagedHostState::ForceDeletion => StateSla::with_sla(
            std::time::Duration::from_secs(slas::FORCE_DELETION),
            time_in_state,
        ),
        ManagedHostState::Failed { .. } => {
            StateSla::with_sla(std::time::Duration::ZERO, time_in_state)
        }
        ManagedHostState::DPUReprovision { .. } => StateSla::with_sla(
            std::time::Duration::from_secs(slas::DPU_REPROVISION),
            time_in_state,
        ),
        ManagedHostState::HostReprovision { .. } => {
            // Multiple types of firmware may need to be updated, and in some cases it can take a while.
            // This SHOULD be enough based on current observed behavior, but may need to be extended.
            StateSla::with_sla(
                std::time::Duration::from_secs(slas::HOST_REPROVISION),
                time_in_state,
            )
        }
        ManagedHostState::Measuring { measuring_state } => match measuring_state {
            // The API shouldn't be waiting for measurements for long. As soon
            // as it transitions into this state, Scout should get an Action::Measure
            // action, and it should pretty quickly send measurements in (~seconds).
            MeasuringState::WaitingForMeasurements => StateSla::with_sla(
                std::time::Duration::from_secs(slas::MEASUREMENT_WAIT_FOR_MEASUREMENT),
                time_in_state,
            ),
            // If the machine is waiting for a matching bundle, this could
            // take a bit, since it means either auto-bundle generation OR
            // manual bundle generation needs to happen. In the case of new
            // turn ups, this could take hours or even days (e.g. if new gear
            // is sitting there).
            MeasuringState::PendingBundle => StateSla::no_sla(),
        },
        ManagedHostState::PostAssignedMeasuring { measuring_state } => match measuring_state {
            // The API shouldn't be waiting for measurements for long. As soon
            // as it transitions into this state, Scout should get an Action::Measure
            // action, and it should pretty quickly send measurements in (~seconds).
            MeasuringState::WaitingForMeasurements => StateSla::with_sla(
                std::time::Duration::from_secs(slas::MEASUREMENT_WAIT_FOR_MEASUREMENT),
                time_in_state,
            ),
            // If the machine is waiting for a matching bundle, this could
            // take a bit, since it means either auto-bundle generation OR
            // manual bundle generation needs to happen. In the case of new
            // turn ups, this could take hours or even days (e.g. if new gear
            // is sitting there).
            MeasuringState::PendingBundle => StateSla::no_sla(),
        },
    }
}

/// Represents the machine validation test filter
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct MachineValidationFilter {
    pub tags: Vec<String>,
    pub allowed_tests: Vec<String>,
    pub run_unverfied_tests: Option<bool>,
    pub contexts: Option<Vec<String>>,
}

impl Display for MachineValidationFilter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_json_deserialize_no_error() {
        let serialized = r#"{"cause": "noerror", "source": "noerror", "failed_at": "2023-07-31T11:26:18.261228950Z"}"#;
        let deserialized: FailureDetails = serde_json::from_str(serialized).unwrap();

        let expected_time =
            chrono::DateTime::parse_from_rfc3339("2023-07-31T11:26:18.261228950+00:00").unwrap();
        assert_eq!(FailureCause::NoError, deserialized.cause);
        assert_eq!(expected_time, deserialized.failed_at);
    }

    #[test]
    fn test_json_deserialize_nvme_error() {
        let serialized = r#"{"cause": {"nvmecleanfailed":{"err": "error1"}},  "source": "noerror","failed_at": "2023-07-31T11:26:18.261228950Z"}"#;
        let deserialized: FailureDetails = serde_json::from_str(serialized).unwrap();

        let expected_time =
            chrono::DateTime::parse_from_rfc3339("2023-07-31T11:26:18.261228950+00:00").unwrap();
        assert_eq!(
            FailureCause::NVMECleanFailed {
                err: "error1".to_string()
            },
            deserialized.cause
        );
        assert_eq!(expected_time, deserialized.failed_at);
    }

    #[test]
    fn test_json_deserialize_reprovisioning_state() {
        let serialized = r#"{"state":"dpureprovision","dpu_states":{"states":{"fm100ds7blqjsadm2uuh3qqbf1h7k8pmf47um6v9uckrg7l03po8mhqgvng":"firmwareupgrade"}}}"#;
        let deserialized: ManagedHostState = serde_json::from_str(serialized).unwrap();
        assert_eq!(
            deserialized,
            ManagedHostState::DPUReprovision {
                dpu_states: DpuReprovisionStates {
                    states: HashMap::from([(
                        MachineId::from_str(
                            "fm100ds7blqjsadm2uuh3qqbf1h7k8pmf47um6v9uckrg7l03po8mhqgvng"
                        )
                        .unwrap(),
                        ReprovisionState::FirmwareUpgrade
                    )])
                }
            }
        );

        assert_eq!(deserialized.to_string(), "Reprovisioning/FirmwareUpgrade");
    }

    #[test]
    fn test_json_deserialize_reprovisioning_state_for_instance() {
        let serialized = r#"{"state":"assigned","instance_state":{"state":"dpureprovision","dpu_states":{"states":{"fm100ds7blqjsadm2uuh3qqbf1h7k8pmf47um6v9uckrg7l03po8mhqgvng":"firmwareupgrade"}}}}"#;

        let deserialized: ManagedHostState = serde_json::from_str(serialized).unwrap();

        assert_eq!(
            deserialized,
            ManagedHostState::Assigned {
                instance_state: InstanceState::DPUReprovision {
                    dpu_states: DpuReprovisionStates {
                        states: HashMap::from([(
                            MachineId::from_str(
                                "fm100ds7blqjsadm2uuh3qqbf1h7k8pmf47um6v9uckrg7l03po8mhqgvng"
                            )
                            .unwrap(),
                            ReprovisionState::FirmwareUpgrade
                        )])
                    }
                },
            }
        );

        assert_eq!(
            deserialized.to_string(),
            "Assigned/Reprovision/FirmwareUpgrade"
        );
    }

    #[test]
    fn test_json_deserialize_bootingwithdiscoveryimage_state_for_instance() {
        let serialized =
            r#"{"state":"assigned","instance_state":{"state":"bootingwithdiscoveryimage"}}"#;
        let deserialized: ManagedHostState = serde_json::from_str(serialized).unwrap();

        assert_eq!(
            deserialized,
            ManagedHostState::Assigned {
                instance_state: InstanceState::BootingWithDiscoveryImage {
                    retry: RetryInfo { count: 0 }
                },
            }
        );
    }

    #[test]
    fn test_json_deserialize_bootingwithdiscoveryimage_state_with_retry_for_instance() {
        let serialized = r#"{"state":"assigned","instance_state":{"state":"bootingwithdiscoveryimage", "retry":{"count": 10}}}"#;
        let deserialized: ManagedHostState = serde_json::from_str(serialized).unwrap();

        assert_eq!(
            deserialized,
            ManagedHostState::Assigned {
                instance_state: InstanceState::BootingWithDiscoveryImage {
                    retry: RetryInfo { count: 10 }
                }
            }
        );
    }

    #[test]
    fn test_json_deserialize_machine_last_reboot_requested() {
        let serialized = r#"{"time":"2023-07-31T11:26:18.261228950+00:00","mode":"Reboot"}"#;
        let deserialized: MachineLastRebootRequested = serde_json::from_str(serialized).unwrap();

        assert_eq!(
            chrono::DateTime::parse_from_rfc3339("2023-07-31T11:26:18.261228950+00:00").unwrap(),
            deserialized.time,
        );
        assert!(matches!(
            deserialized.mode,
            MachineLastRebootRequestedMode::Reboot,
        ));
    }
}
