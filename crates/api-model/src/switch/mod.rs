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

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
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

impl TryFrom<rpc::SwitchCreationRequest> for NewSwitch {
    type Error = RpcDataConversionError;
    fn try_from(value: rpc::SwitchCreationRequest) -> Result<Self, Self::Error> {
        let conf = match value.config {
            Some(c) => c,
            None => {
                return Err(RpcDataConversionError::InvalidArgument(
                    "Switch configuration is empty".to_string(),
                ));
            }
        };

        let switch_uuid: Option<uuid::Uuid> = value
            .id
            .as_ref()
            .map(|rpc_uuid| {
                rpc_uuid
                    .try_into()
                    .map_err(|_| RpcDataConversionError::InvalidSwitchId(rpc_uuid.to_string()))
            })
            .transpose()?;

        let id = match switch_uuid {
            Some(v) => SwitchId::from(v),
            None => uuid::Uuid::new_v4().into(),
        };

        let config = SwitchConfig::try_from(conf)?;

        Ok(NewSwitch {
            id,
            config,
            bmc_mac_address: None,
            metadata: None,
            rack_id: None,
            slot_number: value.placement_in_rack.as_ref().and_then(|p| p.slot_number),
            tray_index: value.placement_in_rack.as_ref().and_then(|p| p.tray_index),
        })
    }
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

/// Set by an external entity to request switch reprovisioning. When the switch is in Ready state,
/// the state controller checks this flag and transitions to ReProvisioning::Start.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwitchReprovisionRequest {
    pub requested_at: DateTime<Utc>,
    pub initiator: String,
}

pub use crate::rack::{RackFirmwareUpgradeState, RackFirmwareUpgradeStatus};

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

    /// The rack that this switch is associated with.
    pub rack_id: Option<RackId>,
    // Columns for these exist, but are unused in rust code
    // pub created: DateTime<Utc>,
    // pub updated: DateTime<Utc>,
    pub metadata: Metadata,
    pub version: ConfigVersion,
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

        // DB column is still named "health_report_overrides" for backward compatibility.
        let health_reports: HealthReportSources = row
            .try_get::<sqlx::types::Json<HealthReportSources>, _>("health_report_overrides")
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
            metadata,
            version: row.try_get("version")?,
            rack_id: row.try_get("rack_id").ok().flatten(),
            slot_number: row.try_get("slot_number").ok().flatten(),
            tray_index: row.try_get("tray_index").ok().flatten(),
            health_reports,
        })
    }
}

impl TryFrom<rpc::SwitchConfig> for SwitchConfig {
    type Error = RpcDataConversionError;

    fn try_from(conf: rpc::SwitchConfig) -> Result<Self, Self::Error> {
        Ok(SwitchConfig {
            name: conf.name,
            enable_nmxc: conf.enable_nmxc,
            fabric_manager_config: Some(FabricManagerConfig {
                config_map: conf.fabric_manager_config.unwrap_or_default().config_map,
            }),
        })
    }
}

fn derive_switch_aggregate_health(sources: &HealthReportSources) -> health_report::HealthReport {
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

impl TryFrom<Switch> for rpc::Switch {
    type Error = RpcDataConversionError;

    fn try_from(src: Switch) -> Result<Self, Self::Error> {
        let state_reason = src.controller_state_outcome.map(|r| r.into());
        let sla = state_sla(&src.controller_state.value, &src.controller_state.version).into();
        let controller_state = serde_json::to_string(&src.controller_state.value).unwrap();
        let status = Some(match src.status {
            Some(s) => rpc::SwitchStatus {
                state_reason,
                state_sla: Some(sla),
                switch_name: Some(s.switch_name),
                power_state: Some(s.power_state),
                health_status: Some(s.health_status),
                controller_state: Some(controller_state.clone()),
            },
            None => rpc::SwitchStatus {
                state_reason,
                state_sla: Some(sla),
                switch_name: None,
                power_state: None,
                health_status: None,
                controller_state: Some(controller_state.clone()),
            },
        });

        let placement_in_rack = Some(rpc::PlacementInRack {
            slot_number: src.slot_number,
            tray_index: src.tray_index,
        });
        let config = rpc::SwitchConfig {
            name: src.config.name,
            fabric_manager_config: Some(rpc::FabricManagerConfig {
                config_map: src
                    .config
                    .fabric_manager_config
                    .unwrap_or_default()
                    .config_map,
            }),
            enable_nmxc: src.config.enable_nmxc,
        };

        let health = derive_switch_aggregate_health(&src.health_reports);
        let health_sources = src
            .health_reports
            .clone()
            .into_iter()
            .map(|(hr, m)| rpc::HealthSourceOrigin {
                mode: m as i32,
                source: hr.source,
            })
            .collect();
        let deleted = if src.deleted.is_some() {
            Some(src.deleted.unwrap().into())
        } else {
            None
        };
        let state_version = src.controller_state.version.to_string();
        Ok(rpc::Switch {
            id: Some(src.id),
            config: Some(config),
            status,
            deleted,
            controller_state,
            bmc_info: None,
            state_version,
            metadata: Some(src.metadata.into()),
            version: src.version.version_string(),
            rack_id: src.rack_id,
            placement_in_rack,
            health: Some(health.into()),
            health_sources,
        })
    }
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
pub enum ReProvisioningState {
    /// Rack-level firmware upgrade in progress; the rack state machine manages the
    /// upgrade and clears `switch_reprovisioning_requested` when done.
    WaitingForRackFirmwareUpgrade,
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
}

impl From<rpc::SwitchSearchFilter> for SwitchSearchFilter {
    fn from(filter: rpc::SwitchSearchFilter) -> Self {
        SwitchSearchFilter {
            rack_id: filter.rack_id,
            deleted: crate::DeletedFilter::from(filter.deleted),
            controller_state: filter.controller_state,
            bmc_mac: filter.bmc_mac.and_then(|m| m.parse::<MacAddress>().ok()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller_outcome::PersistentStateHandlerOutcome;

    #[test]
    fn try_from_switch_populates_state_reason() {
        let switch = Switch {
            id: SwitchId::from(uuid::Uuid::new_v4()),
            config: SwitchConfig {
                name: "test-switch".to_string(),
                enable_nmxc: false,
                fabric_manager_config: None,
            },
            status: Some(SwitchStatus {
                switch_name: "test-switch".to_string(),
                power_state: "on".to_string(),
                health_status: "ok".to_string(),
            }),
            deleted: None,
            bmc_mac_address: None,
            controller_state: Versioned::new(
                SwitchControllerState::Ready,
                config_version::ConfigVersion::initial(),
            ),
            controller_state_outcome: Some(PersistentStateHandlerOutcome::Transition {
                source_ref: None,
            }),
            switch_reprovisioning_requested: None,
            firmware_upgrade_status: None,
            metadata: Metadata::default(),
            version: ConfigVersion::initial(),
            rack_id: None,
            slot_number: Some(1),
            tray_index: Some(2),
            health_reports: Default::default(),
        };

        let rpc_switch: rpc::Switch = switch.try_into().unwrap();
        let status = rpc_switch.status.expect("status should be Some");
        assert!(
            status.state_reason.is_some(),
            "state_reason should be populated from controller_state_outcome"
        );
        assert!(status.state_sla.is_some(), "state_sla should be populated");
        assert_eq!(status.power_state, Some("on".to_string()));
        assert_eq!(status.health_status, Some("ok".to_string()));
    }

    #[test]
    fn try_from_switch_without_status_still_has_state_reason() {
        let switch = Switch {
            id: SwitchId::from(uuid::Uuid::new_v4()),
            config: SwitchConfig {
                name: "test-switch".to_string(),
                enable_nmxc: false,
                fabric_manager_config: None,
            },
            status: None,
            deleted: None,
            bmc_mac_address: None,
            controller_state: Versioned::new(
                SwitchControllerState::Created,
                config_version::ConfigVersion::initial(),
            ),
            controller_state_outcome: Some(PersistentStateHandlerOutcome::Wait {
                reason: "waiting for something".to_string(),
                source_ref: None,
            }),
            switch_reprovisioning_requested: None,
            firmware_upgrade_status: None,
            metadata: Metadata::default(),
            version: ConfigVersion::initial(),
            rack_id: None,
            slot_number: None,
            tray_index: None,
            health_reports: Default::default(),
        };

        let rpc_switch: rpc::Switch = switch.try_into().unwrap();
        let status = rpc_switch
            .status
            .expect("status should be Some even when switch.status is None");
        assert!(
            status.state_reason.is_some(),
            "state_reason should be populated even without switch status"
        );
        assert_eq!(status.power_state, None);
        assert_eq!(status.health_status, None);
    }

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
