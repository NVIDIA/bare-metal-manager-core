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

use carbide_uuid::rack::RackId;
use carbide_uuid::switch::SwitchId;
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::StateSla;
use crate::controller_outcome::PersistentStateHandlerOutcome;
use crate::health::HealthReportSources;
use crate::metadata::Metadata;

pub mod slas;
pub mod switch_id;

#[derive(Debug, Clone)]
pub struct NewSwitch {
    pub id: SwitchId,
    pub config: SwitchConfig,
    pub bmc_mac_address: Option<MacAddress>,
    pub metadata: Option<Metadata>,
    pub rack_id: Option<RackId>,
    pub slot_number: Option<i32>,
    pub tray_index: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwitchConfig {
    pub name: String,
    pub enable_nmxc: bool,
    pub fabric_manager_config: Option<FabricManagerConfig>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FabricManagerConfig {
    pub config_map: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwitchStatus {
    pub switch_name: String,
    pub power_state: String,   // "on", "off", "standby"
    pub health_status: String, // "ok", "warning", "critical"
}

fn default_continue_after_firmware_upgrade() -> bool {
    true
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "lowercase")]
#[allow(clippy::enum_variant_names)]
pub enum SwitchMaintenanceOperation {
    /// Power on the switch.
    PowerOn,
    /// Power off the switch.
    PowerOff,
    /// Reset the switch (restart / AC power cycle).
    Reset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchMaintenanceRequest {
    pub requested_at: DateTime<Utc>,
    pub initiator: String,
    pub operation: SwitchMaintenanceOperation,
}

/// Set by an external entity to request switch reprovisioning. When the switch is in Ready state,
/// the state controller checks this flag and transitions to ReProvisioning::Start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchReprovisionRequest {
    pub requested_at: DateTime<Utc>,
    pub initiator: String,
    /// Continue through rack-managed post-firmware phases such as NVOS/NMXC.
    #[serde(default = "default_continue_after_firmware_upgrade")]
    pub continue_after_firmware_upgrade: bool,
}

pub use crate::rack::{
    RackFirmwareUpgradeState, RackFirmwareUpgradeStatus, SwitchNvosUpdateState,
    SwitchNvosUpdateStatus,
};

/// Controller state value for a switch in [`SwitchControllerState::Ready`].
pub const SWITCH_CONTROLLER_STATE_READY: &str = "ready";

/// `addition_info` value reported by Fabric Manager when the NMX-C control plane is configured.
pub const CONTROL_PLANE_STATE_CONFIGURED: &str = "CONTROL_PLANE_STATE_CONFIGURED";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FabricManagerState {
    Ok,
    NotOk,
    Unknown,
}

impl FabricManagerState {
    /// JSON representation stored in the `fabric_manager_status` column.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::NotOk => "not_ok",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricManagerStatus {
    pub fabric_manager_state: FabricManagerState,
    pub addition_info: Option<String>,
    pub reason: Option<String>,
    pub error_message: Option<String>,
}

impl FabricManagerStatus {
    pub fn is_control_plane_configured(&self) -> bool {
        self.fabric_manager_state == FabricManagerState::Ok
            && self.addition_info.as_deref() == Some(CONTROL_PLANE_STATE_CONFIGURED)
    }

    pub fn display_status(&self) -> &'static str {
        if self.is_control_plane_configured() {
            "running"
        } else {
            "not_running"
        }
    }
}

#[derive(Debug, Clone)]
pub struct Switch {
    pub id: SwitchId,

    pub config: SwitchConfig,
    pub status: Option<SwitchStatus>,

    pub deleted: Option<DateTime<Utc>>,

    pub bmc_mac_address: Option<MacAddress>,

    pub controller_state: Versioned<SwitchControllerState>,

    /// The result of the last attempt to change state
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,

    /// When set, the state controller (in Ready or Error) transitions to Maintenance.
    pub switch_maintenance_requested: Option<SwitchMaintenanceRequest>,

    /// When set, the state controller (in Ready) transitions to ReProvisioning::Start.
    pub switch_reprovisioning_requested: Option<SwitchReprovisionRequest>,

    /// Firmware upgrade status during ReProvisioning, set by the rack state machine.
    pub firmware_upgrade_status: Option<RackFirmwareUpgradeStatus>,

    /// NVOS update status set by the rack state machine.
    pub nvos_update_status: Option<SwitchNvosUpdateStatus>,

    /// FabricManager / NMX-C status set by the rack state machine.
    pub fabric_manager_status: Option<FabricManagerStatus>,

    /// The rack that this switch is associated with.
    pub rack_id: Option<RackId>,
    // Columns for these exist, but are unused in rust code
    // pub created: DateTime<Utc>,
    // pub updated: DateTime<Utc>,
    pub metadata: Metadata,
    pub version: ConfigVersion,
    pub is_primary: bool,
    pub slot_number: Option<i32>,
    pub tray_index: Option<i32>,
    pub health_reports: HealthReportSources,
}

impl<'r> FromRow<'r, PgRow> for Switch {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state: sqlx::types::Json<SwitchControllerState> =
            row.try_get("controller_state")?;
        let config: sqlx::types::Json<SwitchConfig> = row.try_get("config")?;
        let status: Option<sqlx::types::Json<SwitchStatus>> = row.try_get("status").ok();
        let controller_state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome").ok();
        let switch_maintenance_requested: Option<sqlx::types::Json<SwitchMaintenanceRequest>> =
            row.try_get("switch_maintenance_requested").ok();
        let switch_reprovisioning_requested: Option<sqlx::types::Json<SwitchReprovisionRequest>> =
            row.try_get("switch_reprovisioning_requested").ok();
        let firmware_upgrade_status: Option<sqlx::types::Json<RackFirmwareUpgradeStatus>> =
            row.try_get("firmware_upgrade_status").ok();
        let nvos_update_status: Option<sqlx::types::Json<SwitchNvosUpdateStatus>> =
            row.try_get("nvos_update_status").ok();
        let fabric_manager_status: Option<sqlx::types::Json<FabricManagerStatus>> =
            row.try_get("fabric_manager_status").ok().flatten();

        let health_reports: HealthReportSources = row
            .try_get::<sqlx::types::Json<HealthReportSources>, _>("health_reports")
            .map(|j| j.0)
            .unwrap_or_default();
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("labels")?;
        let metadata = Metadata {
            name: row.try_get("name")?,
            description: row.try_get("description")?,
            labels: labels.0,
        };
        Ok(Switch {
            id: row.try_get("id")?,
            config: config.0,
            status: status.map(|s| s.0),
            deleted: row.try_get("deleted")?,
            bmc_mac_address: row.try_get("bmc_mac_address").ok().flatten(),
            controller_state: Versioned {
                value: controller_state.0,
                version: row.try_get("controller_state_version")?,
            },
            controller_state_outcome: controller_state_outcome.map(|o| o.0),
            switch_maintenance_requested: switch_maintenance_requested.map(|j| j.0),
            switch_reprovisioning_requested: switch_reprovisioning_requested.map(|j| j.0),
            firmware_upgrade_status: firmware_upgrade_status.map(|j| j.0),
            nvos_update_status: nvos_update_status.map(|j| j.0),
            fabric_manager_status: fabric_manager_status.map(|j| j.0),
            metadata,
            version: row.try_get("version")?,
            is_primary: row.try_get("is_primary").unwrap_or(false),
            rack_id: row.try_get("rack_id").ok().flatten(),
            slot_number: row.try_get("slot_number").ok().flatten(),
            tray_index: row.try_get("tray_index").ok().flatten(),
            health_reports,
        })
    }
}

pub fn derive_switch_aggregate_health(
    sources: &HealthReportSources,
) -> health_report::HealthReport {
    if let Some(replace) = &sources.replace {
        return replace.clone();
    }
    let mut output = health_report::HealthReport::empty("switch-aggregate-health".to_string());
    for report in sources.merges.values() {
        output.merge(report);
    }
    output.observed_at = Some(chrono::Utc::now());
    output
}

/// Sub-state for SwitchControllerState::Initializing
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum InitializingState {
    WaitForOsMachineInterface,
}

/// Sub-state for SwitchControllerState::Configuring
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfiguringState {
    RotateOsPassword,
}

/// Sub-state for SwitchControllerState::Validating
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValidatingState {
    ValidationComplete,
}

/// Sub-state for SwitchControllerState::BomValidating
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum BomValidatingState {
    /// BOM validation is complete; handler transitions to Ready.
    BomValidationComplete,
}

/// Sub-state for SwitchControllerState::ReProvisioning
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::enum_variant_names)]
pub enum ReProvisioningState {
    /// Rack-level firmware upgrade in progress; the rack state machine manages the
    /// upgrade and clears `switch_reprovisioning_requested` when done.
    WaitingForRackFirmwareUpgrade,
    /// Rack-level NVOS upgrade in progress.
    WaitingForNVOSUpgrade,
    /// Rack-level NMX-C configuration in progress.
    WaitingForNMXCConfigure,
}

/// State of a Switch as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum SwitchControllerState {
    /// The Switch has been created in Carbide.
    Created,
    /// The Switch is initializing.
    Initializing {
        initializing_state: InitializingState,
    },
    /// The Switch is configuring.
    Configuring { config_state: ConfiguringState },
    /// The Switch is validating.
    Validating { validating_state: ValidatingState },
    /// The Switch is validating the BOM.
    BomValidating {
        bom_validating_state: BomValidatingState,
    },
    /// The Switch is ready for use.
    Ready,

    /// The Switch is executing an operator-requested power operation.
    Maintenance {
        operation: SwitchMaintenanceOperation,
    },

    // ReProvisioning
    ReProvisioning {
        reprovisioning_state: ReProvisioningState,
    },
    /// There is error in Switch; Switch can not be used if it's in error.
    Error { cause: String },
    /// The Switch is in the process of deleting.
    Deleting,
}

/// Returns the SLA for the current state
pub fn state_sla(state: &SwitchControllerState, state_version: &ConfigVersion) -> StateSla {
    let time_in_state = chrono::Utc::now()
        .signed_duration_since(state_version.timestamp())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));

    match state {
        SwitchControllerState::Created => StateSla::with_sla(
            std::time::Duration::from_secs(slas::INITIALIZING),
            time_in_state,
        ),
        SwitchControllerState::Initializing { .. } => StateSla::with_sla(
            std::time::Duration::from_secs(slas::INITIALIZING),
            time_in_state,
        ),
        SwitchControllerState::Configuring { .. } => StateSla::with_sla(
            std::time::Duration::from_secs(slas::CONFIGURING),
            time_in_state,
        ),
        SwitchControllerState::Validating { .. } => StateSla::with_sla(
            std::time::Duration::from_secs(slas::VALIDATING),
            time_in_state,
        ),
        SwitchControllerState::BomValidating { .. } => StateSla::with_sla(
            std::time::Duration::from_secs(slas::CONFIGURING),
            time_in_state,
        ),
        SwitchControllerState::Ready => StateSla::no_sla(),
        SwitchControllerState::Maintenance { .. } => StateSla::with_sla(
            std::time::Duration::from_secs(slas::MAINTENANCE),
            time_in_state,
        ),
        SwitchControllerState::ReProvisioning { .. } => StateSla::with_sla(
            std::time::Duration::from_secs(slas::CONFIGURING),
            time_in_state,
        ),
        SwitchControllerState::Error { .. } => StateSla::no_sla(),
        SwitchControllerState::Deleting => StateSla::with_sla(
            std::time::Duration::from_secs(slas::DELETING),
            time_in_state,
        ),
    }
}

impl Switch {
    pub fn is_marked_as_deleted(&self) -> bool {
        self.deleted.is_some()
    }
}

#[derive(Clone, Debug, Default)]
pub struct SwitchSearchFilter {
    pub rack_id: Option<RackId>,
    pub deleted: crate::DeletedFilter,
    pub controller_state: Option<String>,
    pub bmc_mac: Option<MacAddress>,
    pub nvos_mac: Option<MacAddress>,
    pub only_with_health_alert: Option<String>,
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{scenarios, value_scenarios};

    use super::*;

    /// Build a `FabricManagerStatus` with only the two fields `display_status`
    /// inspects; the rest are irrelevant to its logic.
    fn fm_status(state: FabricManagerState, addition_info: Option<&str>) -> FabricManagerStatus {
        FabricManagerStatus {
            fabric_manager_state: state,
            addition_info: addition_info.map(str::to_string),
            reason: None,
            error_message: None,
        }
    }

    #[test]
    fn controller_state_serializes_to_expected_json() {
        scenarios!(
            run = |state| serde_json::to_string(&state).map_err(drop);
            "created" {
                SwitchControllerState::Created => Yields(r#"{"state":"created"}"#.to_string()),
            }

            "initializing" {
                SwitchControllerState::Initializing {
                    initializing_state: InitializingState::WaitForOsMachineInterface,
                } => Yields(
                    r#"{"state":"initializing","initializing_state":"WaitForOsMachineInterface"}"#
                        .to_string(),
                ),
            }

            "configuring" {
                SwitchControllerState::Configuring {
                    config_state: ConfiguringState::RotateOsPassword,
                } => Yields(
                    r#"{"state":"configuring","config_state":"RotateOsPassword"}"#.to_string(),
                ),
            }

            "validating" {
                SwitchControllerState::Validating {
                    validating_state: ValidatingState::ValidationComplete,
                } => Yields(
                    r#"{"state":"validating","validating_state":"ValidationComplete"}"#
                        .to_string(),
                ),
            }

            "bomvalidating" {
                SwitchControllerState::BomValidating {
                    bom_validating_state: BomValidatingState::BomValidationComplete,
                } => Yields(
                    r#"{"state":"bomvalidating","bom_validating_state":"BomValidationComplete"}"#
                        .to_string(),
                ),
            }

            "ready" {
                SwitchControllerState::Ready => Yields(r#"{"state":"ready"}"#.to_string()),
            }

            "maintenance: power on" {
                SwitchControllerState::Maintenance {
                    operation: SwitchMaintenanceOperation::PowerOn,
                } => Yields(
                    r#"{"state":"maintenance","operation":{"operation":"poweron"}}"#.to_string(),
                ),
            }

            "maintenance: power off" {
                SwitchControllerState::Maintenance {
                    operation: SwitchMaintenanceOperation::PowerOff,
                } => Yields(
                    r#"{"state":"maintenance","operation":{"operation":"poweroff"}}"#
                        .to_string(),
                ),
            }

            "maintenance: reset" {
                SwitchControllerState::Maintenance {
                    operation: SwitchMaintenanceOperation::Reset,
                } => Yields(
                    r#"{"state":"maintenance","operation":{"operation":"reset"}}"#.to_string(),
                ),
            }

            "reprovisioning: firmware upgrade" {
                SwitchControllerState::ReProvisioning {
                    reprovisioning_state:
                        ReProvisioningState::WaitingForRackFirmwareUpgrade,
                } => Yields(
                    r#"{"state":"reprovisioning","reprovisioning_state":"WaitingForRackFirmwareUpgrade"}"#
                        .to_string(),
                ),
            }

            "reprovisioning: nvos upgrade" {
                SwitchControllerState::ReProvisioning {
                    reprovisioning_state: ReProvisioningState::WaitingForNVOSUpgrade,
                } => Yields(
                    r#"{"state":"reprovisioning","reprovisioning_state":"WaitingForNVOSUpgrade"}"#
                        .to_string(),
                ),
            }

            "reprovisioning: nmxc configure" {
                SwitchControllerState::ReProvisioning {
                    reprovisioning_state: ReProvisioningState::WaitingForNMXCConfigure,
                } => Yields(
                    r#"{"state":"reprovisioning","reprovisioning_state":"WaitingForNMXCConfigure"}"#
                        .to_string(),
                ),
            }

            "error carries its cause" {
                SwitchControllerState::Error {
                    cause: "cause goes here".to_string(),
                } => Yields(
                    r#"{"state":"error","cause":"cause goes here"}"#.to_string(),
                ),
            }

            "deleting" {
                SwitchControllerState::Deleting => Yields(r#"{"state":"deleting"}"#.to_string()),
            }
        );
    }

    #[test]
    fn controller_state_deserializes_from_json() {
        scenarios!(
            run = |json| serde_json::from_str::<SwitchControllerState>(json).map_err(drop);
            "created" {
                r#"{"state":"created"}"# => Yields(SwitchControllerState::Created),
            }

            "initializing" {
                r#"{"state":"initializing","initializing_state":"WaitForOsMachineInterface"}"# => Yields(SwitchControllerState::Initializing {
                    initializing_state: InitializingState::WaitForOsMachineInterface,
                }),
            }

            "configuring" {
                r#"{"state":"configuring","config_state":"RotateOsPassword"}"# => Yields(SwitchControllerState::Configuring {
                    config_state: ConfiguringState::RotateOsPassword,
                }),
            }

            "validating" {
                r#"{"state":"validating","validating_state":"ValidationComplete"}"# => Yields(SwitchControllerState::Validating {
                    validating_state: ValidatingState::ValidationComplete,
                }),
            }

            "bomvalidating" {
                r#"{"state":"bomvalidating","bom_validating_state":"BomValidationComplete"}"# => Yields(SwitchControllerState::BomValidating {
                    bom_validating_state: BomValidatingState::BomValidationComplete,
                }),
            }

            "ready" {
                r#"{"state":"ready"}"# => Yields(SwitchControllerState::Ready),
            }

            "legacy ready with stray ready_state still deserializes to Ready" {
                r#"{"state":"ready","ready_state":"poweroff"}"# => Yields(SwitchControllerState::Ready),
            }

            "maintenance: reset" {
                r#"{"state":"maintenance","operation":{"operation":"reset"}}"# => Yields(SwitchControllerState::Maintenance {
                    operation: SwitchMaintenanceOperation::Reset,
                }),
            }

            "error" {
                r#"{"state":"error","cause":"boom"}"# => Yields(SwitchControllerState::Error {
                    cause: "boom".to_string(),
                }),
            }

            "deleting" {
                r#"{"state":"deleting"}"# => Yields(SwitchControllerState::Deleting),
            }

            "unknown state tag is rejected" {
                r#"{"state":"frobnicating"}"# => Fails,
            }

            "missing state tag is rejected" {
                r#"{"cause":"boom"}"# => Fails,
            }

            "error without its cause is rejected" {
                r#"{"state":"error"}"# => Fails,
            }

            "not even json" {
                "not json" => Fails,
            }
        );
    }

    #[test]
    fn maintenance_operation_serializes_lowercase() {
        scenarios!(
            run = |op| serde_json::to_string(&op).map_err(drop);
            "power on" {
                SwitchMaintenanceOperation::PowerOn => Yields(r#"{"operation":"poweron"}"#.to_string()),
            }

            "power off" {
                SwitchMaintenanceOperation::PowerOff => Yields(r#"{"operation":"poweroff"}"#.to_string()),
            }

            "reset" {
                SwitchMaintenanceOperation::Reset => Yields(r#"{"operation":"reset"}"#.to_string()),
            }
        );
    }

    #[test]
    fn maintenance_operation_deserializes() {
        scenarios!(
            run = |json| serde_json::from_str::<SwitchMaintenanceOperation>(json).map_err(drop);
            "power on" {
                r#"{"operation":"poweron"}"# => Yields(SwitchMaintenanceOperation::PowerOn),
            }

            "power off" {
                r#"{"operation":"poweroff"}"# => Yields(SwitchMaintenanceOperation::PowerOff),
            }

            "reset" {
                r#"{"operation":"reset"}"# => Yields(SwitchMaintenanceOperation::Reset),
            }

            "uppercase tag is rejected" {
                r#"{"operation":"PowerOn"}"# => Fails,
            }

            "unknown operation is rejected" {
                r#"{"operation":"explode"}"# => Fails,
            }
        );
    }

    #[test]
    fn fabric_manager_state_serializes_snake_case() {
        scenarios!(
            run = |state| serde_json::to_string(&state).map_err(drop);
            "ok" {
                FabricManagerState::Ok => Yields(r#""ok""#.to_string()),
            }

            "not ok renders snake_case" {
                FabricManagerState::NotOk => Yields(r#""not_ok""#.to_string()),
            }

            "unknown" {
                FabricManagerState::Unknown => Yields(r#""unknown""#.to_string()),
            }
        );
    }

    #[test]
    fn fabric_manager_state_deserializes() {
        scenarios!(
            run = |json| serde_json::from_str::<FabricManagerState>(json).map_err(drop);
            "ok" {
                r#""ok""# => Yields(FabricManagerState::Ok),
            }

            "not_ok" {
                r#""not_ok""# => Yields(FabricManagerState::NotOk),
            }

            "unknown" {
                r#""unknown""# => Yields(FabricManagerState::Unknown),
            }

            "camelCase NotOk is rejected" {
                r#""NotOk""# => Fails,
            }

            "unrecognized state is rejected" {
                r#""degraded""# => Fails,
            }
        );
    }

    #[test]
    fn display_status_is_running_only_when_ok_and_configured() {
        value_scenarios!(
            run = |status| status.display_status();
            "ok + CONFIGURED is running" {
                fm_status(
                    FabricManagerState::Ok,
                    Some("CONTROL_PLANE_STATE_CONFIGURED"),
                ) => "running",
            }

            "ok but no addition_info is not running" {
                fm_status(FabricManagerState::Ok, None) => "not_running",
            }

            "ok but different addition_info is not running" {
                fm_status(
                    FabricManagerState::Ok,
                    Some("CONTROL_PLANE_STATE_INITIALIZING"),
                ) => "not_running",
            }

            "ok but empty addition_info is not running" {
                fm_status(FabricManagerState::Ok, Some("")) => "not_running",
            }

            "not_ok even when configured is not running" {
                fm_status(
                    FabricManagerState::NotOk,
                    Some("CONTROL_PLANE_STATE_CONFIGURED"),
                ) => "not_running",
            }

            "unknown even when configured is not running" {
                fm_status(
                    FabricManagerState::Unknown,
                    Some("CONTROL_PLANE_STATE_CONFIGURED"),
                ) => "not_running",
            }

            "not_ok with no info is not running" {
                fm_status(FabricManagerState::NotOk, None) => "not_running",
            }
        );
    }

    #[test]
    fn reprovision_request_defaults_continue_after_firmware_upgrade_to_true() {
        scenarios!(
            run = |json| {
                serde_json::from_str::<SwitchReprovisionRequest>(json)
                    .map(|r| r.continue_after_firmware_upgrade)
                    .map_err(drop)
            };
            "omitted flag defaults to true" {
                r#"{"requested_at":"2026-01-01T00:00:00Z","initiator":"op"}"# => Yields(true),
            }

            "explicit false is honored" {
                r#"{"requested_at":"2026-01-01T00:00:00Z","initiator":"op","continue_after_firmware_upgrade":false}"# => Yields(false),
            }

            "explicit true is honored" {
                r#"{"requested_at":"2026-01-01T00:00:00Z","initiator":"op","continue_after_firmware_upgrade":true}"# => Yields(true),
            }
        );
    }
}
