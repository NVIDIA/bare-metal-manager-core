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
use std::fmt::Display;

use carbide_uuid::machine::MachineId;
use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::rack::RackId;
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use mac_address::MacAddress;
use rpc::Timestamp;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::StateSla;
use crate::controller_outcome::PersistentStateHandlerOutcome;
use crate::machine::health_override::HealthReportOverrides;

#[derive(Debug, Clone)]
pub struct Rack {
    pub id: RackId,
    pub config: RackConfig,
    pub controller_state: Versioned<RackState>,
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,
    pub health_report_overrides: HealthReportOverrides,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
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
            expected_compute_trays: value
                .config
                .expected_compute_trays
                .iter()
                .map(|x| x.to_string())
                .collect(),
            expected_power_shelves: value
                .config
                .expected_power_shelves
                .iter()
                .map(|x| x.to_string())
                .collect(),
            expected_nvlink_switches: value
                .config
                .expected_switches
                .iter()
                .map(|x| x.to_string())
                .collect(),
            compute_trays: value.config.compute_trays,
            power_shelves: value.config.power_shelves,
            created: Some(Timestamp::from(value.created)),
            updated: Some(Timestamp::from(value.updated)),
            deleted: value.deleted.map(Timestamp::from),
            health: Some(health.into()),
            health_overrides,
        }
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
        Ok(Rack {
            id: row.try_get("id")?,
            config: config.0,
            controller_state: Versioned {
                value: controller_state.0,
                version: row.try_get("controller_state_version")?,
            },
            controller_state_outcome: controller_state_outcome.map(|o| o.0),
            health_report_overrides,
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
        })
    }
}

// ============================================================================
// RACK STATES
// ============================================================================

/// Overall state of the rack lifecycle.
///
/// The rack progresses through discovery and maintenance phases, then enters
/// validation where partitions (groups of nodes) are validated by an external
/// service (RVS).
///
/// ## Simplified State Flow
///
/// Most important transitions are shown below.
///
/// ```text
/// Expected -> Discovering -> Maintenance -> Validation
///                                                |
///                                                v
///                           Validation(Failed) <---> Validation(Validated)
///                                                         |
///                                                         v
///                                                       Ready
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum RackState {
    /// Default DB column value. The rack SM does not transition out of this
    /// state on its own -- the transition to `Expected` is forced by
    /// `db::rack::create()`, which explicitly writes `{"state":"expected"}`
    /// when a rack is first created via the ExpectedMachine/Switch/PS APIs.
    ///
    /// This variant exists solely to deserialize rows that were inserted with
    /// the column default (`{"state":"unknown"}`). Under normal operation no
    /// rack should remain in this state.
    #[default]
    Unknown,

    /// Rack is expected - waiting for machines to be discovered.
    /// Created when ExpectedMachine/Switch/PS references this rack.
    Expected,

    /// Discovery in progress - waiting for all expected devices to appear
    /// and reach ManagedHostState::Ready.
    Discovering,

    /// Rack is in the validation phase. The sub-state tracks progress from
    /// waiting for RVS through partition-level pass/fail to a final verdict.
    Validation {
        rack_validation: RackValidationState,
    },

    /// Rack is fully validated and ready for production workloads.
    Ready,

    /// Rack is undergoing maintenance (firmware upgrade, power sequencing, etc.).
    /// Maintenance happens after discovery and before validation.
    Maintenance {
        rack_maintenance: RackMaintenanceState,
    },

    /// Rack encountered an unrecoverable error.
    Error { cause: String },

    /// Rack is being deleted.
    Deleting,
}

/// Sub-states of rack maintenance.
///
/// The rack enters maintenance after discovery (all devices found, all machines
/// ready) and exits into `Validation(Pending)` once maintenance is complete,
/// at which point the validation flow takes over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RackMaintenanceState {
    FirmwareUpgrade {
        rack_firmware_upgrade: RackFirmwareUpgradeState,
    },
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
            RackMaintenanceState::PowerSequence { rack_power } => {
                write!(f, "PowerSequence({})", rack_power)
            }
            RackMaintenanceState::Completed => write!(f, "Completed"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RackFirmwareUpgradeState {
    Compute,
    Switch,
    PowerShelf,
    All,
}

impl Display for RackFirmwareUpgradeState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RackFirmwareUpgradeState::Compute => write!(f, "Compute"),
            RackFirmwareUpgradeState::Switch => write!(f, "Switch"),
            RackFirmwareUpgradeState::PowerShelf => write!(f, "PowerShelf"),
            RackFirmwareUpgradeState::All => write!(f, "All"),
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
    InProgress,

    /// At least one partition has passed validation, and no partitions
    /// have failed. Waiting for remaining partitions to complete.
    Partial,

    /// At least one partition has failed validation.
    /// Can recover to Partial if failed partitions are re-validated.
    FailedPartial,

    /// All partitions have passed validation successfully.
    /// Rack is ready to transition to the Ready state.
    Validated,

    /// All partitions have failed validation.
    /// Requires intervention before the rack can be used.
    Failed,
}

impl Display for RackValidationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RackValidationState::Pending => write!(f, "Pending"),
            RackValidationState::InProgress => write!(f, "InProgress"),
            RackValidationState::Partial => write!(f, "Partial"),
            RackValidationState::FailedPartial => write!(f, "FailedPartial"),
            RackValidationState::Validated => write!(f, "Validated"),
            RackValidationState::Failed => write!(f, "Failed"),
        }
    }
}

impl Display for RackState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RackState::Unknown => write!(f, "Unknown"),
            RackState::Expected => write!(f, "Expected"),
            RackState::Discovering => write!(f, "Discovering"),
            RackState::Validation { rack_validation } => {
                write!(f, "Validation({})", rack_validation)
            }
            RackState::Ready => write!(f, "Ready"),
            RackState::Maintenance { rack_maintenance } => {
                write!(f, "Maintenance({})", rack_maintenance)
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
    /// Run correlation ID -- must match rack's validation_run_id.
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
    pub compute_trays: Vec<MachineId>,
    pub power_shelves: Vec<PowerShelfId>,

    /// expected_compute_trays contains the BMC MAC addresses of every
    /// expected compute tray in the rack.
    pub expected_compute_trays: Vec<MacAddress>,
    /// expected_switches contains the BMC MAC addresses of every expected
    /// switch in the rack. The NVOS management MAC address is stored
    /// separately in the expected switch's metadata labels, and validated
    /// separately as part of the switch state controller.
    #[serde(default)]
    pub expected_switches: Vec<MacAddress>,
    /// expected_power_shelves contains the BMC MAC addresses of every
    /// expected power shelf in the rack.
    pub expected_power_shelves: Vec<MacAddress>,

    /// rack_type is the name of the rack type (e.g. "NVL72") that maps to
    /// a RackCapabilitiesSet in the config file. The capabilities are looked
    /// up at runtime so config changes apply retroactively to all racks.
    #[serde(default)]
    pub rack_type: Option<String>,

    /// Active validation run ID. Set when entering Validation(Pending),
    /// used to filter stale machine labels from previous runs.
    #[serde(default)]
    pub validation_run_id: Option<String>,
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
        RackState::Unknown => StateSla::no_sla(),
        RackState::Expected => StateSla::no_sla(),
        RackState::Discovering => StateSla::no_sla(),
        RackState::Validation { .. } => StateSla::no_sla(),
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
