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
use std::collections::HashMap;
use std::fmt::Display;

use carbide_uuid::rack::RackId;
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use rpc::Timestamp;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::StateSla;
use crate::controller_outcome::PersistentStateHandlerOutcome;
use crate::machine::health_override::HealthReportOverrides;
use crate::metadata::Metadata;

#[derive(Debug, Clone)]
pub struct Rack {
    pub id: RackId,
    pub config: RackConfig,
    pub controller_state: Versioned<RackState>,
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,
    pub firmware_upgrade_job: Option<FirmwareUpgradeJob>,
    pub health_report_overrides: HealthReportOverrides,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub metadata: Metadata,
    pub version: ConfigVersion,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FirmwareUpgradeJob {
    pub job_id: Option<String>,
    pub status: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub machines: Vec<FirmwareUpgradeDeviceStatus>,
    #[serde(default)]
    pub switches: Vec<FirmwareUpgradeDeviceStatus>,
    #[serde(default)]
    pub power_shelves: Vec<FirmwareUpgradeDeviceStatus>,
}

impl FirmwareUpgradeJob {
    pub fn all_devices(&self) -> impl Iterator<Item = &FirmwareUpgradeDeviceStatus> {
        self.machines
            .iter()
            .chain(self.switches.iter())
            .chain(self.power_shelves.iter())
    }

    pub fn all_devices_mut(&mut self) -> impl Iterator<Item = &mut FirmwareUpgradeDeviceStatus> {
        self.machines
            .iter_mut()
            .chain(self.switches.iter_mut())
            .chain(self.power_shelves.iter_mut())
    }
}

/// Per-device input passed to RMS when starting a firmware upgrade.
/// TODO to be replaced with RMS protobuf message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareUpgradeDeviceInfo {
    pub mac: String,
    pub bmc_ip: String,
    pub bmc_username: String,
    pub bmc_password: String,
    pub os_ip: Option<String>,
    pub os_username: Option<String>,
    pub os_password: Option<String>,
}

/// Per-device status tracked inside `FirmwareUpgradeJob`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirmwareUpgradeDeviceStatus {
    pub mac: String,
    pub bmc_ip: String,
    pub status: String,
}

/// Per-device firmware upgrade status set by the rack state machine during a
/// rack-level firmware upgrade. Used on both machines and switches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RackFirmwareUpgradeStatus {
    pub task_id: String,
    pub status: RackFirmwareUpgradeState,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
}

impl RackFirmwareUpgradeStatus {
    /// Returns true if the firmware upgrade is still in progress
    /// (i.e. `ended_at` has not been set yet).
    pub fn is_in_progress(&self) -> bool {
        self.ended_at.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RackFirmwareUpgradeState {
    Started,
    InProgress,
    Completed,
    Failed { cause: String },
}

impl From<Rack> for rpc::forge::Rack {
    fn from(value: Rack) -> Self {
        let health = derive_rack_aggregate_health(&value.health_report_overrides);
        let health_overrides = value
            .health_report_overrides
            .clone()
            .into_iter()
            .map(|(hr, m)| rpc::forge::HealthOverrideOrigin {
                mode: m as i32,
                source: hr.source,
            })
            .collect();

        rpc::forge::Rack {
            id: Some(value.id),
            rack_state: value.controller_state.value.to_string(),
            expected_compute_trays: vec![],
            expected_power_shelves: vec![],
            expected_nvlink_switches: vec![],
            compute_trays: vec![],
            power_shelves: vec![],
            switches: vec![],
            created: Some(Timestamp::from(value.created)),
            updated: Some(Timestamp::from(value.updated)),
            deleted: value.deleted.map(Timestamp::from),
            health: Some(health.into()),
            health_overrides,
            metadata: Some(value.metadata.into()),
            version: value.version.version_string(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RackSearchFilter {}

impl From<rpc::forge::RackSearchFilter> for RackSearchFilter {
    fn from(_filter: rpc::forge::RackSearchFilter) -> Self {
        RackSearchFilter {}
    }
}

fn derive_rack_aggregate_health(overrides: &HealthReportOverrides) -> health_report::HealthReport {
    if let Some(replace) = &overrides.replace {
        return replace.clone();
    }
    let mut output = health_report::HealthReport::empty("rack-aggregate-health".to_string());
    for report in overrides.merges.values() {
        output.merge(report);
    }
    output.observed_at = Some(chrono::Utc::now());
    output
}

impl<'r> FromRow<'r, PgRow> for Rack {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let config: sqlx::types::Json<RackConfig> = row.try_get("config")?;
        let controller_state: sqlx::types::Json<RackState> = row.try_get("controller_state")?;
        let controller_state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome").ok();
        let health_report_overrides: HealthReportOverrides = row
            .try_get::<sqlx::types::Json<HealthReportOverrides>, _>("health_report_overrides")
            .map(|j| j.0)
            .unwrap_or_default();
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("labels")?;
        let metadata = Metadata {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            labels: labels.0,
        };
        let firmware_upgrade_job: Option<FirmwareUpgradeJob> = row
            .try_get::<Option<sqlx::types::Json<FirmwareUpgradeJob>>, _>("firmware_upgrade_job")
            .ok()
            .flatten()
            .map(|j| j.0);
        Ok(Rack {
            id: row.try_get("id")?,
            config: config.0,
            controller_state: Versioned {
                value: controller_state.0,
                version: row.try_get("controller_state_version")?,
            },
            controller_state_outcome: controller_state_outcome.map(|o| o.0),
            firmware_upgrade_job,
            health_report_overrides,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
            metadata,
            version: row.try_get("version")?,
        })
    }
}

// ============================================================================
// RACK STATES
// ============================================================================

/// State of a Rack as tracked by the controller.
///
/// The rack progresses through discovery and maintenance phases, then enters
/// validation where partitions (groups of nodes) are validated by an external
/// service (RVS).
///
/// ## State Flow
///
/// ```text
/// Created -> Discovering -> Maintenance -> Validating -> Ready
///                ^               |              |          |  |
///                |               v              v          |  |
///                |            Error <------  Error         |  |
///                |                                         |  |
///                +--- topology_changed --------------------+  |
///                                                             |
///           Maintenance <--- reprovision_requested -----------+
/// ```
///
/// ### Maintenance Sub-states
///
/// ```text
/// FirmwareUpgrade -> ConfigureNmxCluster -> Completed -> Validating(Pending)
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RackState {
    /// Rack has been created in Carbide.
    /// Created when ExpectedMachine/Switch/PS references this rack.
    #[default]
    #[serde(alias = "expected", alias = "unknown")]
    Created,

    /// Discovery in progress - waiting for all expected devices to appear
    /// and reach ManagedHostState::Ready.
    Discovering,

    /// Rack is in the validation phase. The sub-state tracks progress from
    /// waiting for RVS through partition-level pass/fail to a final verdict.
    ///
    /// The active RVS run ID is stored inside each non-`Pending` substate of
    /// `rack_validation`. It is set on the `Pending -> InProgress` transition
    /// when Carbide first observes an `rv.run-id` label on a rack machine.
    #[serde(alias = "validation")]
    Validating {
        #[serde(alias = "rack_validation")]
        validating_state: RackValidationState,
    },

    /// Rack is fully validated and ready for production workloads.
    Ready,

    /// Rack is undergoing maintenance (firmware upgrade, power sequencing, etc.).
    /// Maintenance happens after discovery and before validation.
    Maintenance {
        #[serde(alias = "rack_maintenance")]
        maintenance_state: RackMaintenanceState,
    },

    /// There is error in the Rack; Rack can not be used if it's in error.
    Error { cause: String },

    /// Rack is in the process of deleting.
    Deleting,
}

/// Sub-states of rack maintenance.
///
/// The rack enters maintenance after discovery (all devices found, all machines
/// ready) and exits into `Validation(Pending)` once maintenance is complete,
/// at which point the validation flow takes over.
///
/// ## Sub-state Flow
///
/// ```text
/// FirmwareUpgrade -> ConfigureNmxCluster -> Completed -> Validation(Pending)
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RackMaintenanceState {
    FirmwareUpgrade {
        rack_firmware_upgrade: FirmwareUpgradeState,
    },
    ConfigureNmxCluster,
    PowerSequence {
        rack_power: RackPowerState,
    },
    Completed,
}

impl Display for RackMaintenanceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RackMaintenanceState::FirmwareUpgrade {
                rack_firmware_upgrade,
            } => {
                write!(f, "FirmwareUpgrade({})", rack_firmware_upgrade)
            }
            RackMaintenanceState::ConfigureNmxCluster => write!(f, "ConfigureNmxCluster"),
            RackMaintenanceState::PowerSequence { rack_power } => {
                write!(f, "PowerSequence({})", rack_power)
            }
            RackMaintenanceState::Completed => write!(f, "Completed"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FirmwareUpgradeState {
    Start,
    WaitForComplete,
}

impl Display for FirmwareUpgradeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirmwareUpgradeState::Start => write!(f, "Start"),
            FirmwareUpgradeState::WaitForComplete => write!(f, "WaitForComplete"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RackPowerState {
    PoweringOn,
    PoweringOff,
    PowerReset,
}

impl Display for RackPowerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RackPowerState::PoweringOn => write!(f, "PoweringOn"),
            RackPowerState::PoweringOff => write!(f, "PoweringOff"),
            RackPowerState::PowerReset => write!(f, "PowerReset"),
        }
    }
}

/// Sub-states of rack validation.
///
/// The rack enters validation after maintenance completes (starting in
/// `Pending`). RVS drives transitions by writing instance metadata labels
/// that BMMC polls and aggregates into partition-level summaries.
///
/// All non-`Pending` substates carry the `run_id` of the active RVS run.
/// The run ID is set when the first `rv.run-id` label is observed on a
/// rack machine (the `Pending -> InProgress` transition); all subsequent
/// substates inherit it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RackValidationState {
    /// All nodes discovered and all machines have reached
    /// ManagedHostState::Ready. Waiting for RVS to begin partition
    /// validation.
    ///
    /// TODO[#416]: The responsibility of gating production instance allocation
    /// should live in the node/tray-level state machine, not the rack SM.
    /// The proposed mechanism is to force health overrides for each
    /// node that transitioning into READY state, essentially make
    /// nodes "unhealthy". This way no instance can be allocated
    /// for the tenant. RVS, however, will be able to force the
    /// instance via supplying "allow_unhealthy" flag while creating
    /// instances.
    Pending,

    /// At least one partition has started validation, but none have
    /// completed (neither passed nor failed yet).
    InProgress { run_id: String },

    /// At least one partition has passed validation, and no partitions
    /// have failed. Waiting for remaining partitions to complete.
    Partial { run_id: String },

    /// At least one partition has failed validation.
    /// Can recover to Partial if failed partitions are re-validated.
    FailedPartial { run_id: String },

    /// All partitions have passed validation successfully.
    /// Rack is ready to transition to the Ready state.
    Validated { run_id: String },

    /// All partitions have failed validation.
    /// Requires intervention before the rack can be used.
    Failed { run_id: String },
}

impl RackValidationState {
    /// Returns the active RVS run ID, or `None` for the `Pending` substate.
    pub fn run_id(&self) -> Option<&str> {
        match self {
            RackValidationState::InProgress { run_id }
            | RackValidationState::Partial { run_id }
            | RackValidationState::FailedPartial { run_id }
            | RackValidationState::Validated { run_id }
            | RackValidationState::Failed { run_id } => Some(run_id),
            RackValidationState::Pending => None,
        }
    }
}

impl Display for RackValidationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RackValidationState::Pending => write!(f, "Pending"),
            RackValidationState::InProgress { .. } => write!(f, "InProgress"),
            RackValidationState::Partial { .. } => write!(f, "Partial"),
            RackValidationState::FailedPartial { .. } => write!(f, "FailedPartial"),
            RackValidationState::Validated { .. } => write!(f, "Validated"),
            RackValidationState::Failed { .. } => write!(f, "Failed"),
        }
    }
}

impl Display for RackState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RackState::Created => write!(f, "Created"),
            RackState::Discovering => write!(f, "Discovering"),
            RackState::Validating { validating_state } => {
                write!(f, "Validating({})", validating_state)
            }
            RackState::Ready => write!(f, "Ready"),
            RackState::Maintenance { maintenance_state } => {
                write!(f, "Maintenance({})", maintenance_state)
            }
            RackState::Error { cause } => write!(f, "Error({})", cause),
            RackState::Deleting => write!(f, "Deleting"),
        }
    }
}

/// Machine metadata labels set by RVS to communicate validation state.
pub enum MachineRvLabels {
    /// Partition ID grouping nodes into validation partitions.
    PartitionId,
    /// Run correlation ID -- used to filter stale labels from prior runs.
    RunId,
    /// Per-node validation status.
    State,
    /// Failure description (only when status is `fail`).
    FailDesc,
}

impl MachineRvLabels {
    pub fn as_str(&self) -> &'static str {
        match self {
            MachineRvLabels::PartitionId => "rv.part-id",
            MachineRvLabels::RunId => "rv.run-id",
            MachineRvLabels::State => "rv.st",
            MachineRvLabels::FailDesc => "rv.fail-desc",
        }
    }
}

// ============================================================================
// RACK CONFIG & HISTORY
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RackStateHistory {
    /// The state that was entered
    pub state: String,
    /// The version number associated with the state change
    pub state_version: ConfigVersion,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RackConfig {
    /// rack_type is the name of the rack type (e.g. "NVL72") that maps to
    /// a RackCapabilitiesSet in the config file. The capabilities are looked
    /// up at runtime so config changes apply retroactively to all racks.
    #[serde(default)]
    pub rack_type: Option<String>,

    /// When set, the Ready state handler will transition back to Maintenance
    /// to re-provision the rack to a new version.
    #[serde(default)]
    pub reprovision_requested: bool,

    /// When set, the Ready state handler will transition back to Discovering
    /// because a tray was replaced (rack topology change).
    #[serde(default)]
    pub topology_changed: bool,
}

// ============================================================================
// SLA & CONVERSIONS
// ============================================================================

pub fn state_sla(state: &RackState, state_version: &ConfigVersion) -> StateSla {
    let _time_in_state = chrono::Utc::now()
        .signed_duration_since(state_version.timestamp())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));

    // TODO[#416]: Define SLAs for validation and maintenance states
    match state {
        RackState::Created => StateSla::no_sla(),
        RackState::Discovering => StateSla::no_sla(),
        RackState::Validating { .. } => StateSla::no_sla(),
        RackState::Ready => StateSla::no_sla(),
        RackState::Maintenance { .. } => StateSla::no_sla(),
        RackState::Error { .. } => StateSla::no_sla(),
        RackState::Deleting => StateSla::no_sla(),
    }
}

impl From<RackStateHistory> for rpc::forge::RackStateHistoryRecord {
    fn from(value: RackStateHistory) -> rpc::forge::RackStateHistoryRecord {
        rpc::forge::RackStateHistoryRecord {
            state: value.state,
            version: value.state_version.version_string(),
            time: Some(value.state_version.timestamp().into()),
        }
    }
}
