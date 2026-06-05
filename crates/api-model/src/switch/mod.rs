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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FabricManagerState {
    Ok,
    NotOk,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricManagerStatus {
    pub fabric_manager_state: FabricManagerState,
    pub addition_info: Option<String>,
    pub reason: Option<String>,
    pub error_message: Option<String>,
}

impl FabricManagerStatus {
    pub fn display_status(&self) -> &'static str {
        if self.fabric_manager_state == FabricManagerState::Ok
            && self.addition_info.as_deref() == Some("CONTROL_PLANE_STATE_CONFIGURED")
        {
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
    use super::*;

    #[test]
    fn serialize_controller_state() {
        let state = SwitchControllerState::Created;
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"created\"}");
        assert_eq!(
            serde_json::from_str::<SwitchControllerState>(&serialized).unwrap(),
            state
        );
        let state = SwitchControllerState::Initializing {
            initializing_state: InitializingState::WaitForOsMachineInterface,
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serialized,
            "{\"state\":\"initializing\",\"initializing_state\":\"WaitForOsMachineInterface\"}"
        );
        assert_eq!(
            serde_json::from_str::<SwitchControllerState>(&serialized).unwrap(),
            state
        );
        let state = SwitchControllerState::Configuring {
            config_state: ConfiguringState::RotateOsPassword,
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serialized,
            "{\"state\":\"configuring\",\"config_state\":\"RotateOsPassword\"}"
        );
        assert_eq!(
            serde_json::from_str::<SwitchControllerState>(&serialized).unwrap(),
            state
        );
        let state = SwitchControllerState::Ready;
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"ready\"}");
        assert_eq!(
            serde_json::from_str::<SwitchControllerState>(&serialized).unwrap(),
            state
        );
        let state = SwitchControllerState::Error {
            cause: "cause goes here".to_string(),
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, r#"{"state":"error","cause":"cause goes here"}"#);
        assert_eq!(
            serde_json::from_str::<SwitchControllerState>(&serialized).unwrap(),
            state
        );
        let state = SwitchControllerState::Deleting;
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"deleting\"}");
        assert_eq!(
            serde_json::from_str::<SwitchControllerState>(&serialized).unwrap(),
            state
        );
    }
}
