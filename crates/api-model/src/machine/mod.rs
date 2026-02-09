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
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;

use ::rpc::errors::RpcDataConversionError;
use base64::prelude::*;
use carbide_uuid::domain::DomainId;
use carbide_uuid::instance_type::InstanceTypeId;
use carbide_uuid::machine::{MachineId, MachineInterfaceId, MachineType};
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::switch::SwitchId;
use chrono::{DateTime, Duration, Utc};
use config_version::{ConfigVersion, Versioned};
use duration_str::deserialize_duration_chrono;
use health_report::HealthReport;
use json::MachineSnapshotPgJson;
use libredfish::{PowerState, SystemPowerControl};
use mac_address::MacAddress;
use rpc::forge::HealthOverrideOrigin;
use rpc::forge_agent_control_response::{Action, ForgeAgentControlExtraInfo};
use serde::{Deserialize, Serialize, Serializer};
use sqlx::postgres::PgRow;
use sqlx::{Column, FromRow, Row};
use strum_macros::EnumIter;

use self::infiniband::MachineInfinibandStatusObservation;
use self::network::{MachineNetworkStatusObservation, ManagedHostNetworkConfig};
use self::nvlink::MachineNvLinkStatusObservation;
use super::StateSla;
use super::bmc_info::BmcInfo;
use super::hardware_info::MachineInventory;
use super::instance::snapshot::InstanceSnapshot;
use super::instance::status::extension_service::InstanceExtensionServiceStatusObservation;
use super::instance::status::network::InstanceNetworkStatusObservation;
use super::metadata::Metadata;
use super::sku::SkuStatus;
use crate::controller_outcome::PersistentStateHandlerOutcome;
use crate::dpa_interface::DpaInterface;
use crate::errors::{ModelError, ModelResult};
use crate::firmware::FirmwareComponentType;
use crate::hardware_info::{HardwareInfo, MachineNvLinkInfo};
use crate::instance::config::network::DeviceLocator;
use crate::instance::snapshot::InstanceSnapshotPgJson;
use crate::machine::capabilities::MachineCapabilitiesSet;
use crate::machine::health_override::HealthReportOverrides;
use crate::machine_interface_address::InterfaceAssociationType;
use crate::network_segment::NetworkSegmentType;
use crate::power_manager::PowerOptions;

mod slas;

pub mod capabilities;
pub mod health_override;
pub mod infiniband;
pub mod json;
pub mod machine_id;
pub mod machine_search_config;
pub mod network;
pub mod nvlink;
pub mod topology;
pub mod upgrade_policy;

type DpuDeviceMappings = (HashMap<MachineId, String>, HashMap<String, Vec<MachineId>>);

pub fn get_display_ids(machines: &[Machine]) -> String {
    machines
        .iter()
        .map(|x| x.id.to_string())
        .collect::<Vec<String>>()
        .join("/")
}

fn default_true() -> bool {
    true
}

/// Represents the current state of `Machine`
#[derive(Debug, Clone)]
pub struct ManagedHostStateSnapshot {
    pub host_snapshot: Machine,
    pub dpu_snapshots: Vec<Machine>,
    pub dpa_interface_snapshots: Vec<DpaInterface>,
    /// If there is an instance provisioned on top of the machine, this holds
    /// its state
    pub instance: Option<InstanceSnapshot>,
    pub managed_state: ManagedHostState,
    /// Aggregated health. This is calculated based on the health of Hosts and DPUs
    pub aggregate_health: health_report::HealthReport,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ManagedHostStateSnapshot {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let host_snapshot: sqlx::types::Json<MachineSnapshotPgJson> =
            row.try_get("host_snapshot")?;
        let dpu_snapshots: sqlx::types::Json<Vec<Option<MachineSnapshotPgJson>>> =
            row.try_get("dpu_snapshots")?;
        // We are setting dpa_interface_snapshots to an emtpy vector here.
        // This will be filled by load_object_state later.
        let dpa_interface_snapshots: Vec<DpaInterface> = Vec::new();

        let mut instance: Option<InstanceSnapshot> =
            if let Some(column) = row.columns().iter().find(|c| c.name() == "instance") {
                let json: sqlx::types::Json<Option<InstanceSnapshotPgJson>> =
                    row.try_get(column.ordinal())?;
                json.0.map(TryInto::try_into).transpose()?
            } else {
                None
            };

        let host_snapshot: Machine = host_snapshot.0.try_into()?;

        let dpu_snapshots: Vec<Machine> = dpu_snapshots
            .0
            .into_iter()
            .flatten()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;

        // Instance network observation is fetched from dpu_snapshots.
        if let Some(instance) = &mut instance {
            instance.observations.network =
                InstanceNetworkStatusObservation::aggregate_instance_observation(&dpu_snapshots);
            instance.observations.extension_services =
                InstanceExtensionServiceStatusObservation::aggregate_instance_observation(
                    &dpu_snapshots,
                );
        }

        // TODO: consider dropping this field from ManagedHostStateSnapshot
        let managed_state = host_snapshot.state.value.clone();

        let mut result = Self {
            host_snapshot,
            dpu_snapshots,
            dpa_interface_snapshots,
            managed_state,
            instance,
            // This will need to be modified by callers, as its value depends on a
            // HardwareHealthReportsConfig being specified.
            aggregate_health: health_report::HealthReport::empty("".to_string()),
        };

        result.sort_dpu_snapshots()?;

        Ok(result)
    }
}

/// Reasons why a Machine is not allocatable
#[derive(thiserror::Error, Clone, PartialEq, Eq, Debug)]
pub enum NotAllocatableReason {
    #[error("The Machine is in a state other than `Ready`: {0:?}")]
    InvalidState(Box<ManagedHostState>),
    #[error(
        "The Machine has a pending instance creation request, that has not yet been processed by the state handler"
    )]
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

impl From<ManagedHostStateSnapshotError> for sqlx::Error {
    fn from(value: ManagedHostStateSnapshotError) -> Self {
        Self::Decode(Box::new(value))
    }
}

impl ManagedHostStateSnapshot {
    /// Returns `Ok` if the Host can be used as an instance
    ///
    /// This requires
    /// - the Machine to be in `Ready` state
    /// - the Machine has not yet been target of an instance creation request
    /// - no health alerts which classification `PreventAllocations` to be set
    /// - the machine not to be in Maintenance Mode
    pub fn is_usable_as_instance(&self, allow_unhealthy: bool) -> Result<(), NotAllocatableReason> {
        // TODO: allow other states than Ready when allow_unhealthy=true. Will require changes to state machine (see Matthias).
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

        if !allow_unhealthy
            && let Some(alert) = self.aggregate_health.find_alert_by_classification(
                &health_report::HealthAlertClassification::prevent_allocations(),
            )
        {
            return Err(NotAllocatableReason::HealthAlert(Box::new(alert.clone())));
        }

        Ok(())
    }

    /// Derives the aggregate health of the Managed Host based on individual
    /// health reports
    pub fn derive_aggregate_health(&mut self, host_health_config: HostHealthConfig) {
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

        if let Some(sku_validation_health_report) =
            self.host_snapshot.sku_validation_health_report.as_ref()
        {
            output.merge(sku_validation_health_report);
        }

        // log parser reports are only merged if available, heartbeat timeout is not applicable
        if let Some(input) = &self.host_snapshot.log_parser_health_report {
            output.merge(input);
        }

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
        match host_health_config.hardware_health_reports {
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

        // Merge DPU's alerts.  If DPU alerts should be suppressed, than remove the classification from the
        // alert so that metrics won't show a critical issue.
        let suppress_dpu_alerts = self.managed_state.suppress_dpu_alerts();
        for snapshot in self.dpu_snapshots.iter_mut() {
            let health_report = if suppress_dpu_alerts {
                let mut health_report = snapshot.dpu_agent_health_report.clone();

                if let Some(health_report) = &mut health_report {
                    for alert in &mut health_report.alerts {
                        alert.classifications.clear();
                    }
                }
                health_report
            } else {
                snapshot.dpu_agent_health_report.clone()
            };

            if let Some(network_status_observation) = snapshot.network_status_observation.as_ref()
                && let Some(health_report) = network_status_observation
                    .expired_version_health_report(
                        host_health_config.dpu_agent_version_staleness_threshold,
                        host_health_config.prevent_allocations_on_stale_dpu_agent_version,
                    )
            {
                output.merge(&health_report);
            }

            merge_or_timeout(&mut output, &health_report, "forge-dpu-agent".to_string());

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
                    .find(|dpu| dpu.id == *dpu_machine_id)?;
                let mut rpc_machine: rpc::forge::Machine = dpu_snapshot.clone().into();
                // In case the DPU does not know the associated Host - we can backfill the data here
                rpc_machine.associated_host_machine_id = Some(self.host_snapshot.id);
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

    /// Sort the DPUs by pci address and then make sure the primary DPU is the first.
    pub fn sort_dpu_snapshots(&mut self) -> Result<(), ManagedHostStateSnapshotError> {
        let mac_pci_map: HashMap<MacAddress, Option<&str>> = self
            .host_snapshot
            .hardware_info
            .iter()
            .flat_map(|hi| &hi.network_interfaces)
            .map(|interface| {
                (
                    interface.mac_address,
                    interface
                        .pci_properties
                        .as_ref()
                        .and_then(|pci| pci.slot.as_deref()),
                )
            })
            .collect();

        self.dpu_snapshots.sort_by(|lhs, rhs| {
            let Some(lhs_dpu_mac) = lhs
                .hardware_info
                .as_ref()
                .and_then(|hi| hi.dpu_info.as_ref())
                .and_then(|di| di.factory_mac_address.parse().ok())
            else {
                return Ordering::Greater;
            };

            let Some(rhs_dpu_mac) = rhs
                .hardware_info
                .as_ref()
                .and_then(|hi| hi.dpu_info.as_ref())
                .and_then(|di| di.factory_mac_address.parse().ok())
            else {
                return Ordering::Less;
            };

            let lhs_pci_slot = mac_pci_map.get(&lhs_dpu_mac).unwrap_or(&None);
            let rhs_pci_slot = mac_pci_map.get(&rhs_dpu_mac).unwrap_or(&None);

            match (lhs_pci_slot, rhs_pci_slot) {
                (Some(lhs_pci_slot), Some(rhs_pci_slot)) => lhs_pci_slot.cmp(rhs_pci_slot),
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            }
        });

        let primary_dpu_id = self
            .host_snapshot
            .interfaces
            .iter()
            .find_map(|x| {
                if x.primary_interface {
                    Some(x.attached_dpu_machine_id)
                } else {
                    None
                }
            })
            .flatten();

        if let Some(primary_dpu_id) = primary_dpu_id {
            let index = self
                .dpu_snapshots
                .iter()
                .position(|x| x.id == primary_dpu_id)
                .ok_or({
                    ManagedHostStateSnapshotError::MissingPrimaryDpu(
                        self.host_snapshot.id,
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
                self.host_snapshot.id,
            ));
        };

        Ok(())
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
            if let Some(reprovision_requested) = dpu.reprovision_requested.as_ref() {
                reprovision_request = Some(reprovision_requested.clone());
            }
        }
        let (_, dpu_id_to_device_map) = snapshot
            .host_snapshot
            .get_dpu_device_and_id_mappings()
            .map_err(|e| {
                RpcDataConversionError::InvalidValue(
                    "dpu_id_to_device_map".to_string(),
                    e.to_string(),
                )
            })?;
        let status = instance.derive_status(
            dpu_id_to_device_map,
            snapshot.managed_state.clone(),
            reprovision_request,
            snapshot
                .host_snapshot
                .infiniband_status_observation
                .as_ref(),
            snapshot.host_snapshot.nvlink_status_observation.as_ref(),
        )?;

        Ok(Some(rpc::Instance {
            id: Some(instance.id),
            machine_id: Some(instance.machine_id),
            config: Some(instance.config.try_into()?),
            status: Some(status.try_into()?),
            config_version: instance.config_version.version_string(),
            network_config_version: instance.network_config_version.version_string(),
            ib_config_version: instance.ib_config_version.version_string(),
            dpu_extension_service_version: instance
                .extension_services_config_version
                .version_string(),
            instance_type_id: instance.instance_type_id.map(|i| i.to_string()),
            metadata: Some(instance.metadata.into()),
            tpm_ek_certificate: snapshot.host_snapshot.hardware_info.and_then(|hi| {
                hi.tpm_ek_certificate
                    .map(|cert| BASE64_STANDARD.encode(cert.into_bytes()))
            }),
            nvlink_config_version: instance.nvlink_config_version.version_string(),
        }))
    }
}

/// Represents the last_reboot_requested data
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq)]
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
            SystemPowerControl::ACPowercycle => Self::Reboot,
            SystemPowerControl::PowerCycle => Self::Reboot,
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
    pub restart_verified: Option<bool>,
    pub verification_attempts: Option<i32>,
}

impl Default for MachineLastRebootRequested {
    fn default() -> Self {
        MachineLastRebootRequested {
            time: Default::default(),
            mode: MachineLastRebootRequestedMode::Reboot,
            restart_verified: None,
            verification_attempts: None,
        }
    }
}

///
/// A machine is a standalone system that performs network booting via normal DHCP processes.
///
#[derive(Debug, Clone)]
pub struct Machine {
    /// The ID of the machine, this is an internal identifier in the database that's unique for
    /// all machines managed by this instance of carbide.
    pub id: MachineId,

    /// The current state of the machine.
    pub state: Versioned<ManagedHostState>,

    /// The current network state of the machine, excluding the tenant related
    /// configuration. The latter will be tracked as part of the InstanceNetworkConfig.
    pub network_config: Versioned<ManagedHostNetworkConfig>,

    /// The most recent status forge-dpu-agent observed. Tells us if network_config has been
    /// applied yet, and other useful things.
    pub network_status_observation: Option<MachineNetworkStatusObservation>,

    /// The most recent status of infiniband interfaces.
    pub infiniband_status_observation: Option<MachineInfinibandStatusObservation>,

    // The most recent status of the nvlink GPUs.
    pub nvlink_status_observation: Option<MachineNvLinkStatusObservation>,

    /// A list of [MachineStateHistory] that this machine has experienced
    pub history: Vec<MachineStateHistory>,

    /// A list of [MachineInterfaceSnapshot]s that this machine owns
    pub interfaces: Vec<MachineInterfaceSnapshot>,

    /// The Hardware information that was discovered for this machine
    pub hardware_info: Option<HardwareInfo>,

    /// The BMC info for this machine
    pub bmc_info: BmcInfo,

    /// Last time when machine came up.
    pub last_reboot_time: Option<DateTime<Utc>>,

    /// Last time when cleanup was performed successfully.
    pub last_cleanup_time: Option<DateTime<Utc>>,

    /// Last time when discovery finished.
    pub last_discovery_time: Option<DateTime<Utc>>,

    /// Last time when scout contacted the machine.
    pub last_scout_contact_time: Option<DateTime<Utc>>,

    /// Failure cause. If failure cause is critical, machine will move into Failed state.
    pub failure_details: FailureDetails,

    /// Last time when machine reprovision requested.
    pub reprovision_requested: Option<ReprovisionRequest>,

    /// Last time when host reprovision requested
    pub host_reprovision_requested: Option<HostReprovisionRequest>,

    /// Does the forge-dpu-agent on this DPU need upgrading?
    pub dpu_agent_upgrade_requested: Option<UpgradeDecision>,

    /// Latest health report received by forge-dpu-agent
    pub dpu_agent_health_report: Option<HealthReport>,

    /// Latest health report received by hardware-health
    pub hardware_health_report: Option<HealthReport>,

    /// Latest log parser health report received from the log parser
    pub log_parser_health_report: Option<HealthReport>,

    /// Latest health report generated by validation tests
    pub machine_validation_health_report: HealthReport,

    /// Latest health report submitted by site-explorer
    pub site_explorer_health_report: Option<HealthReport>,

    /// All health report overrides
    pub health_report_overrides: HealthReportOverrides,

    // Inventory related to a DPU machine as reported by the agent there.
    // Software and versions installed on the machine.
    pub inventory: Option<MachineInventory>,

    /// Last time when machine reboot was requested.
    /// This field takes care of reboot requested from state machine only.
    pub last_reboot_requested: Option<MachineLastRebootRequested>,

    /// The result of the last attempt to change state
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,

    // Is the bios password set on the machine
    pub bios_password_set_time: Option<DateTime<Utc>>,

    /// Last host validation finished.
    pub last_machine_validation_time: Option<DateTime<Utc>>,

    /// current discovery validation id.
    pub discovery_machine_validation_id: Option<uuid::Uuid>,

    /// current cleanup validation id.
    pub cleanup_machine_validation_id: Option<uuid::Uuid>,

    /// Override to enable or disable firmware auto update
    pub firmware_autoupdate: Option<bool>,

    /// current on demand validation id.
    pub on_demand_machine_validation_id: Option<uuid::Uuid>,

    pub on_demand_machine_validation_request: Option<bool>,

    /// The InstanceType with which a machine is associated if any
    pub instance_type_id: Option<InstanceTypeId>,

    pub asn: Option<u32>,

    /// Machine metadata
    pub metadata: Metadata,

    /// Version field that tracks changes to
    /// - Metadata
    pub version: ConfigVersion,
    // Columns for these exist, but are unused in rust code
    // /// When this machine record was created
    // pub created: DateTime<Utc>,
    // /// When the machine record was last modified
    // pub updated: DateTime<Utc>,
    // /// When the machine was last deployed
    // pub deployed: Option<DateTime<Utc>>,
    pub hw_sku: Option<String>,
    pub hw_sku_status: Option<SkuStatus>,
    pub sku_validation_health_report: Option<HealthReport>,

    /// Host's power options.
    pub power_options: Option<PowerOptions>,

    /// The hardware SKU's device type
    pub hw_sku_device_type: Option<String>,

    /// If host upgrades have been completed since the last start explicit start request or actual start
    pub update_complete: bool,

    /// The NMX-M GPU info for this machine.
    pub nvlink_info: Option<MachineNvLinkInfo>,

    /// Whether the DPF is enabled for this machine
    pub dpf: Dpf,

    /// Timestamp when manual firmware upgrade was marked as completed
    /// TEMPORARY: Used for workflow where manual upgrades are required before automatic ones
    /// TODO: Remove after upgrade-through-scout is complete
    pub manual_firmware_upgrade_completed: Option<DateTime<Utc>>,
}

// Dpf status field.
#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Dpf {
    // This field is copied from expected_machines.
    pub enabled: bool,
    // If dpf is used for ingestion.
    pub used_for_ingestion: bool,
}

impl From<Machine> for ::rpc::forge::dpf_state_response::DpfState {
    fn from(value: Machine) -> Self {
        Self {
            machine_id: value.id.into(),
            enabled: value.dpf.enabled,
            used_for_ingestion: value.dpf.used_for_ingestion,
        }
    }
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for Machine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let json: serde_json::value::Value = row.try_get(0)?;
        MachineSnapshotPgJson::deserialize(json)
            .map_err(|err| sqlx::Error::Decode(err.into()))?
            .try_into()
    }
}

impl Machine {
    /// Returns whether the Machine is a DPU, based on the HardwareInfo that
    /// was available when the Machine was discovered
    pub fn is_dpu(&self) -> bool {
        self.id.machine_type().is_dpu()
    }

    pub fn bmc_vendor(&self) -> bmc_vendor::BMCVendor {
        match self.hardware_info.as_ref() {
            Some(hw) => hw.bmc_vendor(),
            None => bmc_vendor::BMCVendor::Unknown,
        }
    }

    pub fn use_admin_network(&self) -> bool {
        self.network_config.use_admin_network.unwrap_or(true)
    }

    /// Does the forge-dpu-agent on this DPU need upgrading?
    pub fn needs_agent_upgrade(&self) -> bool {
        self.dpu_agent_upgrade_requested
            .as_ref()
            .map(|d| d.should_upgrade)
            .unwrap_or(false)
    }

    /// Return the current state of the machine.
    pub fn current_state(&self) -> &ManagedHostState {
        &self.state.value
    }

    /// Return the current version of state of the machine.
    pub fn current_version(&self) -> ConfigVersion {
        self.state.version
    }

    pub fn loopback_ip(&self) -> Option<IpAddr> {
        self.network_config.loopback_ip
    }

    /// Returns all associated DPU Machine IDs if this is Host Machine
    pub fn associated_dpu_machine_ids(&self) -> Vec<MachineId> {
        if self.is_dpu() {
            return Vec::new();
        }

        self.interfaces
            .iter()
            .filter_map(|i| i.attached_dpu_machine_id)
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

    pub fn instance_network_restrictions(&self) -> rpc::forge::InstanceNetworkRestrictions {
        let inband_interfaces = self
            .interfaces
            .iter()
            .filter(|i| matches!(i.network_segment_type, Some(NetworkSegmentType::HostInband)))
            .collect::<Vec<_>>();

        // If there are no HostInband interfaces, this currently means this machine has DPUs and is
        // not restricted to being in particular network segments
        if inband_interfaces.is_empty() {
            return rpc::forge::InstanceNetworkRestrictions {
                network_segment_membership_type:
                    rpc::forge::InstanceNetworkSegmentMembershipType::TenantConfigurable as i32,
                network_segment_ids: vec![],
            };
        }

        // The machine has interfaces on HostInband segments, meaning its network segment
        // memebership is static (cannot be configured at instance allocation time.)

        // Get unique segment ID's and VPC ID's from each HostInband interface
        let inband_network_segment_ids = inband_interfaces
            .iter()
            .map(|iface| iface.segment_id)
            .collect::<HashSet<_>>();

        rpc::forge::InstanceNetworkRestrictions {
            network_segment_membership_type:
                rpc::forge::InstanceNetworkSegmentMembershipType::Static as i32,
            network_segment_ids: inband_network_segment_ids.into_iter().collect(),
        }
    }

    pub fn to_capabilities(&self) -> Option<MachineCapabilitiesSet> {
        self.hardware_info.clone().map(|info| {
            MachineCapabilitiesSet::from_hardware_info(
                info,
                self.infiniband_status_observation.as_ref(),
                self.associated_dpu_machine_ids(),
                self.interfaces.clone(),
            )
        })
    }

    pub fn get_device_locator_for_dpu_id(
        &self,
        dpu_machine_id: &MachineId,
    ) -> ModelResult<DeviceLocator> {
        let (id_to_device_map, device_to_id_map) = self.get_dpu_device_and_id_mappings()?;

        if let Some(device) = id_to_device_map.get(dpu_machine_id)
            && let Some(id_vec) = device_to_id_map.get(device)
            && let Some(instance) = id_vec.iter().position(|id| id == dpu_machine_id)
        {
            return Ok(DeviceLocator {
                device: device.clone(),
                device_instance: instance,
            });
        }
        Err(ModelError::DpuMappingError(format!(
            "No device instance found for dpu {} in machine {}",
            dpu_machine_id, self.id
        )))
    }

    pub fn get_dpu_device_and_id_mappings(&self) -> ModelResult<DpuDeviceMappings> {
        if self.is_dpu() {
            return Err(ModelError::DpuMappingError(
                "get_device_instance_and_dpu_id_mapping called on dpu".to_string(),
            ));
        }

        let hardware_info = self
            .hardware_info
            .as_ref()
            .ok_or(ModelError::DpuMappingError(format!(
                "Missing hardware information for machine {}",
                self.id
            )))?;

        let mut id_to_device_map: HashMap<MachineId, String> = HashMap::default();
        let mut device_to_id_map: HashMap<String, Vec<MachineId>> = HashMap::default();
        // in order to ensure that the primary dpu is assigned a network config, it is configured first.
        // hardware_interfaces has the primary dpu as the first interface, self.interfaces may not.
        // iterate over hardware_interfaces and match it to self.interfaces using the mac address
        for hardware_iface in &hardware_info.network_interfaces {
            if let Some(pci) = &hardware_iface.pci_properties
                && let Some(iface) = self
                    .interfaces
                    .iter()
                    .find(|i| i.mac_address == hardware_iface.mac_address)
                && let Some(dpu_machine_id) = iface.attached_dpu_machine_id
            {
                id_to_device_map.insert(dpu_machine_id, pci.device.clone());
                let id_vec = device_to_id_map.entry(pci.device.clone()).or_default();
                id_vec.push(dpu_machine_id);
            }
        }

        Ok((id_to_device_map, device_to_id_map))
    }

    /// Returns whether a Machine is marked as having updates in progress
    ///
    /// The marking is achieved by applying a special health override and health alert on the Machine
    pub fn machine_updates_in_progress(&self) -> bool {
        self.reprovision_requested.is_some()
    }
}

pub struct RpcMachineTypeWrapper(rpc::forge::MachineType);

impl From<MachineType> for RpcMachineTypeWrapper {
    fn from(value: MachineType) -> Self {
        RpcMachineTypeWrapper(match value {
            MachineType::PredictedHost | MachineType::Host => rpc::forge::MachineType::Host,
            MachineType::Dpu => rpc::forge::MachineType::Dpu,
        })
    }
}

impl Deref for RpcMachineTypeWrapper {
    type Target = rpc::forge::MachineType;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Machine> for rpc::forge::Machine {
    fn from(mut machine: Machine) -> Self {
        let health = match machine.is_dpu() {
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

        let (maintenance_reference, maintenance_start_time) = if !machine.is_dpu() {
            machine
                .health_report_overrides
                .maintenance_override()
                .map(|o| (Some(o.maintenance_reference), o.maintenance_start_time))
                .unwrap_or_default()
        } else {
            (None, None)
        };

        let associated_dpu_machine_ids = machine.associated_dpu_machine_ids();
        let associated_dpu_machine_id = associated_dpu_machine_ids.first().copied();
        let instance_network_restrictions = Some(machine.instance_network_restrictions());

        rpc::Machine {
            id: Some(machine.id),
            state: if machine.is_dpu() {
                machine.state.value.dpu_state_string(&machine.id)
            } else {
                machine.state.value.to_string()
            },
            capabilities: machine.to_capabilities().map(|mut c| {
                c.sort();
                c.into()
            }),
            instance_type_id: machine.instance_type_id.map(|i| i.to_string()),
            state_version: machine.state.version.version_string(),
            state_sla: Some(state_sla(&machine.state.value, &machine.state.version).into()),
            machine_type: *RpcMachineTypeWrapper::from(machine.id.machine_type()) as _,
            metadata: Some(machine.metadata.into()),
            version: machine.version.version_string(),
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
                            machine_id = %machine.id,
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
                .and_then(|obs| obs.agent_version),
            maintenance_reference,
            maintenance_start_time,
            associated_host_machine_id: None, // Gets filled in the `ManagedHostStateSnapshot` conversion
            associated_dpu_machine_ids,
            associated_dpu_machine_id,
            inventory: Some(machine.inventory.unwrap_or_default().into()),
            last_reboot_requested_time: machine
                .last_reboot_requested
                .as_ref()
                .map(|x| x.time.into()),
            last_reboot_requested_mode: machine.last_reboot_requested.map(|x| x.mode.to_string()),
            state_reason: machine.controller_state_outcome.map(|r| r.into()),
            health: Some(health.into()),
            firmware_autoupdate: machine.firmware_autoupdate,
            health_overrides: machine
                .health_report_overrides
                .into_iter()
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
            ib_status: Some(
                machine
                    .infiniband_status_observation
                    .take()
                    .map(|status| status.into())
                    .unwrap_or_default(),
            ),
            instance_network_restrictions,
            hw_sku: machine.hw_sku,
            hw_sku_status: machine.hw_sku_status.map(|s| s.into()),
            quarantine_state: machine
                .network_config
                .quarantine_state
                .take()
                .map(Into::into),
            hw_sku_device_type: machine.hw_sku_device_type,
            update_complete: machine.update_complete,
            nvlink_info: machine.nvlink_info.map(|info| info.into()),
            nvlink_status_observation: machine
                .nvlink_status_observation
                .map(|status| status.into()),
        }
    }
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
    /// Host validation state for machine and DPU validation
    Validation {
        validation_state: ValidationState,
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
        #[serde(default)]
        retry_count: u32,
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

    BomValidating {
        bom_validating_state: BomValidating,
    },
}
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum MachineValidatingState {
    RebootHost {
        validation_id: uuid::Uuid,
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
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "validation_type", rename_all = "lowercase")]
pub enum ValidationState {
    /// Host machine validation
    /// placeholder for DPU machine validation
    /// TODO: add DPU validation state
    /// SKU validatioon can also be moved here, so that all validation done @ one place
    MachineValidation {
        machine_validation: MachineValidatingState,
    },
}

impl std::fmt::Display for ValidationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
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

    pub fn suppress_dpu_alerts(&self) -> bool {
        matches!(
            self,
            ManagedHostState::DpuDiscoveringState { .. }
                | ManagedHostState::DPUInit { .. }
                | ManagedHostState::DPUReprovision { .. }
        )
    }

    pub fn get_host_repro_retry_count(&self) -> u32 {
        match self {
            ManagedHostState::HostReprovision { retry_count, .. } => *retry_count,
            _ => 0,
        }
    }
}

// Since order is derived, Enum members must be in initial to last state sequence.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum ReprovisionState {
    // Deprecated
    BmcFirmwareUpgrade {
        substate: BmcFirmwareUpgradeSubstate,
    },
    // Deprecated
    FirmwareUpgrade,
    DpfStates {
        substate: DpfState,
    },
    InstallDpuOs {
        substate: InstallDpuOsState,
    },
    WaitingForNetworkInstall,
    PoweringOffHost,
    PowerDown,
    // Deprecated
    BufferTime,
    VerifyFirmareVersions,
    WaitingForNetworkConfig,
    RebootHostBmc,
    RebootHost,
    NotUnderReprovision,
}

pub trait NextStateBFBSupport<A> {
    fn next_substate_based_on_bfb_support(
        enable_secure_boot: bool,
        state: &ManagedHostStateSnapshot,
        dpf_enabled_at_site: bool,
    ) -> A;
}

impl NextStateBFBSupport<DpuDiscoveringState> for DpuDiscoveringState {
    fn next_substate_based_on_bfb_support(
        enable_secure_boot: bool,
        state: &ManagedHostStateSnapshot,
        dpf_enabled_at_site: bool,
    ) -> DpuDiscoveringState {
        // DPF should be given priority over secure boot.
        // DPF does not support Secure boot.
        let is_dpf_based_provisioning_possible =
            dpf_based_dpu_provisioning_possible(state, dpf_enabled_at_site, false);

        if !is_dpf_based_provisioning_possible
            && enable_secure_boot
            && bfb_install_support(&state.dpu_snapshots)
        {
            // Move with a redfish install path
            DpuDiscoveringState::EnableSecureBoot {
                count: 0,
                enable_secure_boot_state: SetSecureBootState::CheckSecureBootStatus,
            }
        } else {
            DpuDiscoveringState::DisableSecureBoot {
                count: 0,
                disable_secure_boot_state: Some(SetSecureBootState::CheckSecureBootStatus),
            }
        }
    }
}

impl NextStateBFBSupport<ReprovisionState> for ReprovisionState {
    fn next_substate_based_on_bfb_support(
        enable_secure_boot: bool,
        state: &ManagedHostStateSnapshot,
        dpf_enabled_at_site: bool,
    ) -> ReprovisionState {
        let bfb_support = bfb_install_support(&state.dpu_snapshots);
        let is_dpf_based_provisioning_possible =
            dpf_based_dpu_provisioning_possible(state, dpf_enabled_at_site, true);
        if is_dpf_based_provisioning_possible {
            ReprovisionState::DpfStates {
                substate: DpfState::TriggerReprovisioning {
                    phase: ReprovisioningPhase::UpdateDpuStatusToError,
                },
            }
        } else if enable_secure_boot && bfb_support {
            tracing::info!("All DPUs support BFB install via Redfish");
            // Move with a redfish install path
            ReprovisionState::InstallDpuOs {
                substate: InstallDpuOsState::InstallingBFB,
            }
        } else {
            ReprovisionState::WaitingForNetworkInstall
        }
    }
}

fn bfb_install_support(dpu_snapshots: &[Machine]) -> bool {
    let bfb_install_support_ = |dpu_snapshots: &[Machine]| -> bool {
        dpu_snapshots
            .iter()
            .all(|m| m.bmc_info.supports_bfb_install())
    };

    bfb_install_support_(dpu_snapshots)
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

/// Tenant has requested network config update for the existing instance.
/// At this point, instance config, instance network config version are already increased.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkConfigUpdateState {
    WaitingForNetworkSegmentToBeReady,
    WaitingForConfigSynced,
    // State machine should identify the old resources which needs to be freed and free them.
    ReleaseOldResources,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HostReprovisionState {
    // deprecated, kept for backwards compatibility with existing database entries: FORGE-7975
    CheckingFirmware,
    // deprecated, kept for backwards compatibility with existing database entries: FORGE-7975
    CheckingFirmwareRepeat,
    CheckingFirmwareV2 {
        firmware_type: Option<FirmwareComponentType>,
        firmware_number: Option<u32>,
    },
    CheckingFirmwareRepeatV2 {
        firmware_type: Option<FirmwareComponentType>,
        firmware_number: Option<u32>,
    },
    InitialReset {
        phase: InitialResetPhase,
        last_time: DateTime<Utc>,
    },
    WaitingForManualUpgrade {
        manual_upgrade_started: DateTime<Utc>,
    },
    WaitingForScript {},
    WaitingForUpload {
        final_version: String,
        firmware_type: FirmwareComponentType,
        power_drains_needed: Option<u32>,
        firmware_number: Option<u32>,
    },
    WaitingForFirmwareUpgrade {
        task_id: String,
        final_version: String,
        firmware_type: FirmwareComponentType,
        power_drains_needed: Option<u32>,
        firmware_number: Option<u32>,
        started_waiting: Option<DateTime<Utc>>,
    },
    ResetForNewFirmware {
        final_version: String,
        firmware_type: FirmwareComponentType,
        firmware_number: Option<u32>,
        power_drains_needed: Option<u32>,
        delay_until: Option<i64>,
        last_power_drain_operation: Option<PowerDrainState>,
    },
    NewFirmwareReportedWait {
        final_version: String,
        firmware_type: FirmwareComponentType,
        firmware_number: Option<u32>,
        previous_reset_time: Option<i64>,
    },
    FailedFirmwareUpgrade {
        firmware_type: FirmwareComponentType,
        report_time: Option<DateTime<Utc>>,
        reason: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum InitialResetPhase {
    Start,
    BMCWasReset,
    WaitHostBoot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PowerDrainState {
    Off,
    Powercycle,
    On,
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
    // Wait for ERoT is not in the middle of a background copy of the new BMC image
    WaitForERoTBackgroundCopyToComplete,
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
    EnableSecureBoot {
        count: u32,
        enable_secure_boot_state: SetSecureBootState,
    },
    DisableSecureBoot {
        // this substate is optional because it was added after DisableSecureBoot was initially created (just in case we have a machine stuck in this state even though we shouldnt)
        disable_secure_boot_state: Option<SetSecureBootState>,
        count: u32,
    },
    SetUefiHttpBoot,
    EnableRshim,
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Hash, Clone, Ord, PartialOrd)]
#[serde(tag = "installdpuosstate", rename_all = "lowercase")]
pub enum InstallDpuOsState {
    InstallingBFB,
    WaitForInstallComplete { task_id: String, progress: String },
    Completed,
    InstallationError { msg: String },
}

#[derive(Debug, Deserialize, Serialize, Eq, PartialEq, Hash, Clone, Ord, PartialOrd)]
#[serde(tag = "disablesecurebootstate", rename_all = "lowercase")]
pub enum SetSecureBootState {
    CheckSecureBootStatus,
    DisableSecureBoot, // Deprecated
    SetSecureBoot,
    RebootDPU { reboot_count: u32 },
    WaitCertificateUpload { task_id: String },
}

// Since order is derived, Enum members must be in initial to last state sequence.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
#[serde(tag = "dpustate", rename_all = "lowercase")]
pub enum DpuInitState {
    InstallDpuOs { substate: InstallDpuOsState },
    DpfStates { state: DpfState },
    Init,
    WaitingForPlatformPowercycle { substate: PerformPowerOperation },
    WaitingForPlatformConfiguration,
    PollingBiosSetup,
    WaitingForNetworkConfig,
    WaitingForNetworkInstall, // Deprecated now, not used
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
#[serde(tag = "dpfstate", rename_all = "lowercase")]
pub enum DpfState {
    CreateDpuDevice,
    WaitForDpuDeviceToReady,
    DpuDeviceCreated,
    CreateDpuNode,
    DpuDeviceReady,
    TriggerReprovisioning { phase: ReprovisioningPhase }, // This is way to trigger re-provisioning of a DPU.
    UpdateNodeEffectAnnotation,
    WaitingForOsInstallToComplete,
    WaitForNetworkConfigAndRemoveAnnotation,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord)]
#[serde(tag = "reprovisioningphase", rename_all = "lowercase")]
pub enum ReprovisioningPhase {
    // Only DPUs which needs reprovisioning will be updated to error phase and deleted.
    UpdateDpuStatusToError,
    DeleteDpu,
    // Following is a sync state.
    WaitingForAllDpusUnderReprovisioningToBeDeleted,
}

pub enum WaitForNetworkConfigAndRemoveAnnotationResult {
    NetworkConfigPending(MachineId),
    ConfigSyncedAndAnnotationRemoved,
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
    PollingBiosSetup,
    SetBootOrder {
        set_boot_order_info: Option<SetBootOrderInfo>,
    },
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
    // MachineValidating has been moved to ValidationState
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

/// Substates of enabling/disabling lockdown
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, EnumIter)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum UefiSetupState {
    UnlockHost,
    SetUefiPassword,
    WaitForPasswordJobScheduled,
    PowercycleHost,
    WaitForPasswordJobCompletion,
    // Deprecated: no-op state, transitions directly to WaitingForLockdown::SetLockdown
    // Kept for backwards compatibility with hosts that may be in this state
    LockdownHost,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct SetBootOrderInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_boot_order_jid: Option<String>,
    pub set_boot_order_state: SetBootOrderState,
    /// Retry counter for SetBootOrder state machine. Defaults to 0 for backwards compatibility.
    #[serde(default)]
    pub retry_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, EnumIter)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum SetBootOrderState {
    SetBootOrder,
    WaitForSetBootOrderJobScheduled,
    RebootHost,
    WaitForSetBootOrderJobCompletion,
    CheckBootOrder,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct SecureEraseBossContext {
    pub boss_controller_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secure_erase_jid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iteration: Option<u32>,
    pub secure_erase_boss_state: SecureEraseBossState,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, EnumIter)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum SecureEraseBossState {
    UnlockHost,
    SecureEraseBoss,
    WaitForJobCompletion,
    HandleJobFailure {
        failure: String,
        power_state: PowerState,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub struct CreateBossVolumeContext {
    pub boss_controller_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub create_boss_volume_jid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iteration: Option<u32>,
    pub create_boss_volume_state: CreateBossVolumeState,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, EnumIter)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum CreateBossVolumeState {
    CreateBossVolume,
    WaitForJobScheduled,
    RebootHost,
    WaitForJobCompletion,
    HandleJobFailure {
        failure: String,
        power_state: PowerState,
    },
    LockHost,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum CleanupState {
    Init,
    // Only for Dells with BOSS drives (currently on Dell XE9860s). This will also delete the volume on the BOSS controller.
    SecureEraseBoss {
        secure_erase_boss_context: SecureEraseBossContext,
    },
    HostCleanup {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        boss_controller_id: Option<String>,
    },
    // Only for Dells with BOSS drives (currently on Dell XE9860s)
    CreateBossVolume {
        create_boss_volume_context: CreateBossVolumeContext,
    },
    // Unused
    DisableBIOSBMCLockdown,
}
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, EnumIter)]
#[serde(rename_all = "lowercase")]
pub enum LockdownState {
    SetLockdown,
    TimeWaitForDPUDown,
    WaitForDPUUp,
    PollingLockdownStatus,
}

/// Whether lockdown should be enabled or disabled in an operation
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")] // No tag required - this will never be nested
pub enum LockdownMode {
    Enable,
    Disable,
}

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
    DpaProvisioning,
    WaitingForDpaToBeReady,
    WaitingForExtensionServicesConfig,
    WaitingForRebootToReady,
    Ready,
    HostPlatformConfiguration {
        platform_config_state: HostPlatformConfigurationState,
    },
    WaitingForDpusToUp,
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
    HostReprovision {
        reprovision_state: HostReprovisionState,
    },
    NetworkConfigUpdate {
        network_config_update_state: NetworkConfigUpdateState,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum HostPlatformConfigurationState {
    PowerCycle {
        power_on: bool,
    },
    CheckHostConfig,
    UnlockHost,
    ConfigureBios,
    PollingBiosSetup,
    SetBootOrder {
        set_boot_order_info: SetBootOrderInfo,
    },
    LockHost,
}

/// Struct to store information if Reprovision is requested.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReprovisionRequest {
    pub requested_at: DateTime<Utc>,
    pub initiator: String,
    // Deprecated: Not used anymore. Now fw update is tried in every reprovision request.
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
    pub initiator: String,
    pub started_at: Option<DateTime<Utc>>,
    pub user_approval_received: bool,
    pub request_reset: Option<bool>,
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
                write!(f, "HostInitializing/{machine_state}")
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
                    write!(f, "Assigned/{instance_state}")
                }
            },
            ManagedHostState::WaitingForCleanup { cleanup_state } => {
                write!(f, "WaitingForCleanup/{cleanup_state}")
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
            ManagedHostState::HostReprovision {
                reprovision_state, ..
            } => {
                write!(f, "HostReprovisioning/{reprovision_state}")
            }
            ManagedHostState::Measuring { measuring_state } => {
                write!(f, "Measuring/{measuring_state}")
            }
            ManagedHostState::PostAssignedMeasuring { measuring_state } => {
                write!(f, "PostAssignedMeasuring/{measuring_state}")
            }
            ManagedHostState::Created => write!(f, "Created"),
            ManagedHostState::BomValidating {
                bom_validating_state,
            } => {
                write!(f, "BomValidating/{bom_validating_state:?}")
            }
            ManagedHostState::Validation { validation_state } => {
                write!(f, "{validation_state}")
            }
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
                format!("HostInitializing/{machine_state}")
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
                _ => format!("Assigned/{instance_state}"),
            },
            ManagedHostState::WaitingForCleanup { cleanup_state } => {
                format!("WaitingForCleanup/{cleanup_state}")
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
            ManagedHostState::HostReprovision {
                reprovision_state, ..
            } => {
                format!("HostReprovisioning/{reprovision_state}")
            }
            ManagedHostState::Measuring { measuring_state } => {
                format!("Measuring/{measuring_state}")
            }
            ManagedHostState::PostAssignedMeasuring { measuring_state } => {
                format!("PostAssignedMeasuring/{measuring_state}")
            }
            ManagedHostState::Created => "Created".to_string(),
            ManagedHostState::BomValidating {
                bom_validating_state,
            } => format!("BomValidating/{bom_validating_state:?}"),
            ManagedHostState::Validation { validation_state } => {
                format!("{validation_state}")
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineInterfaceSnapshot {
    pub id: MachineInterfaceId,
    pub hostname: String,
    pub primary_interface: bool,
    pub mac_address: MacAddress,
    pub attached_dpu_machine_id: Option<MachineId>,
    pub domain_id: Option<DomainId>,
    pub machine_id: Option<MachineId>,
    pub segment_id: NetworkSegmentId,
    pub vendors: Vec<String>,
    pub created: DateTime<Utc>,
    pub last_dhcp: Option<DateTime<Utc>>,
    pub addresses: Vec<IpAddr>,
    // Note: this field is denormalized, brought in from a JOIN when coming from machine_interface::find_by. It is otherwise not set.
    pub network_segment_type: Option<NetworkSegmentType>,
    pub power_shelf_id: Option<PowerShelfId>,
    pub switch_id: Option<SwitchId>,
    pub association_type: Option<InterfaceAssociationType>,
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
            primary_interface: true,
            addresses: Vec::new(),
            vendors: Vec::new(),
            created: chrono::DateTime::default(),
            last_dhcp: None,
            network_segment_type: None,
            power_shelf_id: None,
            switch_id: None,
            association_type: None,
        }
    }
}

impl From<MachineInterfaceSnapshot> for rpc::MachineInterface {
    fn from(machine_interface: MachineInterfaceSnapshot) -> rpc::MachineInterface {
        rpc::MachineInterface {
            id: Some(machine_interface.id),
            attached_dpu_machine_id: machine_interface.attached_dpu_machine_id,
            machine_id: machine_interface.machine_id,
            segment_id: Some(machine_interface.segment_id),
            hostname: machine_interface.hostname,
            domain_id: machine_interface.domain_id,
            mac_address: machine_interface.mac_address.to_string(),
            primary_interface: machine_interface.primary_interface,
            address: machine_interface
                .addresses
                .iter()
                .map(|addr| addr.to_string())
                .collect(),
            vendor: machine_interface.vendors.last().cloned(),
            created: Some(machine_interface.created.into()),
            last_dhcp: machine_interface.last_dhcp.map(|t| t.into()),
            power_shelf_id: machine_interface.power_shelf_id,
            is_bmc: None,
            switch_id: machine_interface.switch_id,
            association_type: machine_interface.association_type.map(|t| t as i32),
        }
    }
}

pub struct DpuInitNextStateResolver;
pub struct InstanceNextStateResolver;
pub struct MachineNextStateResolver;

pub fn get_action_for_dpu_state(
    state: &ManagedHostState,
    dpu_machine_id: &MachineId,
) -> ModelResult<(Action, Option<ForgeAgentControlExtraInfo>)> {
    Ok(match state {
        ManagedHostState::DPUReprovision { .. }
        | ManagedHostState::Assigned {
            instance_state: InstanceState::DPUReprovision { .. },
        } => {
            let dpu_state = state
                .as_reprovision_state(dpu_machine_id)
                .ok_or(ModelError::MissingDpu(*dpu_machine_id))?;
            match dpu_state {
                ReprovisionState::BufferTime => (Action::Retry, None),
                ReprovisionState::WaitingForNetworkInstall
                | ReprovisionState::DpfStates {
                    substate: DpfState::WaitingForOsInstallToComplete,
                } => (Action::Discovery, None),
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
                .ok_or(ModelError::MissingDpu(*dpu_machine_id))?;

            match dpu_state {
                DpuInitState::Init
                | DpuInitState::DpfStates {
                    state: DpfState::WaitingForOsInstallToComplete,
                } => (Action::Discovery, None),
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

/// History of Machine states for a single Machine
#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// History of Machine health for a single Machine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineHealthHistoryRecord {
    /// The observed health of the Machine
    pub health: health_report::HealthReport,

    /// The time when the health was observed
    pub time: DateTime<Utc>,
}

impl From<MachineHealthHistoryRecord> for rpc::forge::MachineHealthHistoryRecord {
    fn from(record: MachineHealthHistoryRecord) -> rpc::forge::MachineHealthHistoryRecord {
        rpc::forge::MachineHealthHistoryRecord {
            health: Some(record.health.into()),
            time: Some(record.time.into()),
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
                | DpuDiscoveringState::EnableSecureBoot { .. }
                | DpuDiscoveringState::DisableSecureBoot { .. }
                | DpuDiscoveringState::SetUefiHttpBoot
                | DpuDiscoveringState::RebootAllDPUS
                | DpuDiscoveringState::EnableRshim => {
                    StateSla::with_sla(slas::DPUDISCOVERING, time_in_state)
                }
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
                _ => StateSla::with_sla(slas::DPUINIT_NOTINIT, time_in_state),
            }
        }
        ManagedHostState::HostInit { machine_state } => match machine_state {
            MachineState::Init => StateSla::no_sla(),
            _ => StateSla::with_sla(slas::HOST_INIT, time_in_state),
        },
        ManagedHostState::Ready => StateSla::no_sla(),
        ManagedHostState::Assigned { instance_state } => match instance_state {
            InstanceState::Ready => StateSla::no_sla(),
            InstanceState::BootingWithDiscoveryImage { retry } if retry.count > 0 => {
                // Since retries happen after 30min, the occurence of any retry means we exhausted the SLA
                StateSla::with_sla(std::time::Duration::ZERO, time_in_state)
            }
            _ => StateSla::with_sla(slas::ASSIGNED, time_in_state),
        },
        ManagedHostState::WaitingForCleanup { .. } => {
            StateSla::with_sla(slas::WAITING_FOR_CLEANUP, time_in_state)
        }
        ManagedHostState::Created => StateSla::with_sla(slas::CREATED, time_in_state),
        ManagedHostState::ForceDeletion => StateSla::with_sla(slas::FORCE_DELETION, time_in_state),
        ManagedHostState::Failed { .. } => {
            StateSla::with_sla(std::time::Duration::ZERO, time_in_state)
        }
        ManagedHostState::DPUReprovision { .. } => {
            StateSla::with_sla(slas::DPU_REPROVISION, time_in_state)
        }
        ManagedHostState::HostReprovision { .. } => {
            // Multiple types of firmware may need to be updated, and in some cases it can take a while.
            // This SHOULD be enough based on current observed behavior, but may need to be extended.
            StateSla::with_sla(slas::HOST_REPROVISION, time_in_state)
        }
        ManagedHostState::Measuring { measuring_state } => match measuring_state {
            // The API shouldn't be waiting for measurements for long. As soon
            // as it transitions into this state, Scout should get an Action::Measure
            // action, and it should pretty quickly send measurements in (~seconds).
            MeasuringState::WaitingForMeasurements => {
                StateSla::with_sla(slas::MEASUREMENT_WAIT_FOR_MEASUREMENT, time_in_state)
            }
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
            MeasuringState::WaitingForMeasurements => {
                StateSla::with_sla(slas::MEASUREMENT_WAIT_FOR_MEASUREMENT, time_in_state)
            }
            // If the machine is waiting for a matching bundle, this could
            // take a bit, since it means either auto-bundle generation OR
            // manual bundle generation needs to happen. In the case of new
            // turn ups, this could take hours or even days (e.g. if new gear
            // is sitting there).
            MeasuringState::PendingBundle => StateSla::no_sla(),
        },
        ManagedHostState::BomValidating {
            bom_validating_state,
        } => match bom_validating_state {
            BomValidating::SkuVerificationFailed(_bom_validating_context) => StateSla::no_sla(),
            BomValidating::WaitingForSkuAssignment(_bom_validating_context) => StateSla::no_sla(),
            _ => StateSla::with_sla(slas::BOM_VALIDATION, time_in_state),
        },
        ManagedHostState::Validation { validation_state } => match validation_state {
            ValidationState::MachineValidation { machine_validation } => match machine_validation {
                MachineValidatingState::MachineValidating { .. } => {
                    StateSla::with_sla(slas::VALIDATION, time_in_state)
                }
                MachineValidatingState::RebootHost { .. } => {
                    StateSla::with_sla(slas::VALIDATION, time_in_state)
                }
            },
        },
    }
}

/// A context for passing information between states thoughout the BOM validation
/// process.
#[derive(Debug, Default, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct BomValidatingContext {
    // Machine validation works differently depending on how it is started.  In order
    // to preserve that behavior BOM validation must carry that context through
    // so that machine validation works properly.  Additionally, "None" may be
    // used to skip machine validation.  Note that "None" is not a valid
    // context for machine validation, but only services to skip it.
    pub machine_validation_context: Option<String>,
    pub reboot_retry_count: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum BomValidating {
    MatchingSku(BomValidatingContext),
    UpdatingInventory(BomValidatingContext),
    VerifyingSku(BomValidatingContext),
    SkuVerificationFailed(BomValidatingContext),
    WaitingForSkuAssignment(BomValidatingContext),
    SkuMissing(BomValidatingContext),
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

pub struct LoadSnapshotOptions {
    /// Whether to also load the Machines history
    pub include_history: bool,
    /// Whether to load instance details
    pub include_instance_data: bool,
    /// How to use hardware health for health report aggregation
    pub host_health_config: HostHealthConfig,
}

impl Default for LoadSnapshotOptions {
    fn default() -> Self {
        Self {
            include_history: false,
            include_instance_data: true,
            host_health_config: Default::default(),
        }
    }
}

impl LoadSnapshotOptions {
    pub fn with_host_health(mut self, value: HostHealthConfig) -> Self {
        self.host_health_config = value;
        self
    }
}

impl<'r> FromRow<'r, PgRow> for MachineInterfaceSnapshot {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        // Note: Make sure to use the MACHINE_INTERFACE_SNAPSHOT_QUERY when querying, or these
        // columns will not be present in the result.
        let addrs_json: sqlx::types::Json<Vec<Option<IpAddr>>> = row.try_get("addresses")?;
        let vendors_json: sqlx::types::Json<Vec<Option<String>>> = row.try_get("vendors")?;

        Ok(MachineInterfaceSnapshot {
            id: row.try_get("id")?,
            attached_dpu_machine_id: row.try_get("attached_dpu_machine_id")?,
            machine_id: row.try_get("machine_id")?,
            segment_id: row.try_get("segment_id")?,
            domain_id: row.try_get("domain_id")?,
            hostname: row.try_get("hostname")?,
            mac_address: row.try_get("mac_address")?,
            primary_interface: row.try_get("primary_interface")?,
            created: row.try_get("created")?,
            last_dhcp: row.try_get("last_dhcp")?,
            network_segment_type: row.try_get("network_segment_type")?,
            addresses: addrs_json.0.into_iter().flatten().collect(),
            vendors: vendors_json.0.into_iter().flatten().collect(),
            power_shelf_id: row.try_get("power_shelf_id")?,
            switch_id: row.try_get("switch_id")?,
            association_type: row.try_get("association_type")?,
        })
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

    #[test]
    fn test_json_deserialize_platformconfig_machine_handler() {
        // Test polling BIOS setup state
        let serialized = r#"{"state":"hostinit","machine_state":{"state":"pollingbiossetup"}}"#;
        let deserialized: ManagedHostState = serde_json::from_str(serialized).unwrap();

        assert_eq!(
            deserialized,
            ManagedHostState::HostInit {
                machine_state: MachineState::PollingBiosSetup,
            }
        );
    }

    #[test]
    fn test_json_deserialize_lockdown_states() {
        // Test Lockdown state
        let serialized = r#"{"state":"hostinit","machine_state":{"state":"waitingforlockdown","lockdown_info":{"state":"setlockdown","mode":"enable"}}}"#;
        let deserialized: ManagedHostState = serde_json::from_str(serialized).unwrap();

        assert_eq!(
            deserialized,
            ManagedHostState::HostInit {
                machine_state: MachineState::WaitingForLockdown {
                    lockdown_info: LockdownInfo {
                        state: LockdownState::SetLockdown,
                        mode: LockdownMode::Enable,
                    },
                },
            }
        );
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq)]
pub struct HostHealthConfig {
    /// Whether or not to use hardware health reports in aggregate health reports
    /// and for restricting state transitions.
    #[serde(default)]
    pub hardware_health_reports: HardwareHealthReportsConfig,
    /// How old a DPU agent's version should be before considering stale
    #[serde(
        default = "HostHealthConfig::dpu_agent_version_staleness_threshold_default",
        deserialize_with = "deserialize_duration_chrono",
        serialize_with = "as_duration"
    )]
    pub dpu_agent_version_staleness_threshold: Duration,

    /// Whether to fail health checks if a DPU agent version is stale
    #[serde(default)]
    pub prevent_allocations_on_stale_dpu_agent_version: bool,
}

/// As of now, chrono::Duration does not support Serialization, so we have to handle it manually.
fn as_duration<S>(d: &Duration, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("{}s", d.num_seconds()))
}

impl Default for HostHealthConfig {
    fn default() -> Self {
        HostHealthConfig {
            hardware_health_reports: HardwareHealthReportsConfig::default(),
            dpu_agent_version_staleness_threshold:
                Self::dpu_agent_version_staleness_threshold_default(),
            prevent_allocations_on_stale_dpu_agent_version: false,
        }
    }
}

impl HostHealthConfig {
    pub fn dpu_agent_version_staleness_threshold_default() -> Duration {
        Duration::days(1)
    }
}

#[derive(Clone, Copy, Default, Debug, Serialize, Deserialize, PartialEq)]
pub enum HardwareHealthReportsConfig {
    #[default]
    Disabled,
    /// Include successes and alerts but remove their classifications
    MonitorOnly,
    /// Include successes, alerts, and classifications.
    Enabled,
}

pub fn dpf_based_dpu_provisioning_possible(
    state: &ManagedHostStateSnapshot,
    dpf_enabled_at_site: bool,
    reprovisioing_case: bool,
) -> bool {
    // DPF is disabled at site.
    if !dpf_enabled_at_site {
        return false;
    }

    // DPF should be enabled for host.
    if !state.host_snapshot.dpf.enabled {
        tracing::info!(
            "DPF based DPU provisioning is not possible because DPF is not enabled for the host {}.",
            state.host_snapshot.id
        );
        return false;
    }

    // if it is reprovisioing case, initial ingestion should be done with dpf to continue
    // reprovision.
    if reprovisioing_case && !state.host_snapshot.dpf.used_for_ingestion {
        tracing::info!(
            "DPF based DPU reprovisioning is not possible because initial ingestion is not done with DPF - host {}.",
            state.host_snapshot.id
        );
        return false;
    }

    // All DPUs should not be Bluefield 2.
    if state.dpu_snapshots.iter().any(|dpu| {
        dpu.hardware_info
            .as_ref()
            .and_then(|hardware_info| hardware_info.dpu_info.as_ref())
            .map(|dpu_data| crate::site_explorer::is_bf2_dpu(&dpu_data.part_number))
            .unwrap_or(false)
    }) {
        tracing::info!(
            "DPF based DPU provisioning is not possible because some DPUs are Bluefield 2 in {}.",
            state.host_snapshot.id
        );
        return false;
    }

    // All DPUs support BFB install via Redfish.
    if !state
        .dpu_snapshots
        .iter()
        .all(|dpu| dpu.bmc_info.supports_bfb_install())
    {
        tracing::info!(
            "DPF based DPU provisioning is not possible because some DPUs do not support BFB install via Redfish."
        );
        return false;
    }

    true
}
