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

use carbide_uuid::power_shelf::PowerShelfId;
use carbide_uuid::rack::RackId;
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

pub mod power_shelf_id;
pub mod slas;

#[derive(Debug, Clone)]
pub struct NewPowerShelf {
    pub id: PowerShelfId,
    pub config: PowerShelfConfig,
    pub bmc_mac_address: Option<MacAddress>,
    pub metadata: Option<Metadata>,
    pub rack_id: Option<RackId>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PowerShelfConfig {
    pub name: String,
    pub capacity: Option<u32>, // Power capacity in watts
    pub voltage: Option<u32>,  // Voltage in volts
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PowerShelfStatus {
    pub shelf_name: String,
    pub power_state: String,   // "on", "off", "standby"
    pub health_status: String, // "ok", "warning", "critical"
}

#[derive(Debug, Clone)]
pub struct PowerShelf {
    pub id: PowerShelfId,

    pub config: PowerShelfConfig,
    pub status: Option<PowerShelfStatus>,

    pub deleted: Option<DateTime<Utc>>,

    pub controller_state: Versioned<PowerShelfControllerState>,

    /// The result of the last attempt to change state
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,

    pub bmc_mac_address: Option<MacAddress>,

    /// The rack that this power shelf is associated with.
    pub rack_id: Option<RackId>,

    pub power_shelf_maintenance_requested: Option<PowerShelfMaintenanceRequest>,

    // Columns for these exist, but are unused in rust code
    // pub created: DateTime<Utc>,
    // pub updated: DateTime<Utc>,
    pub metadata: Metadata,
    pub version: ConfigVersion,
    pub health_reports: HealthReportSources,
}

impl<'r> FromRow<'r, PgRow> for PowerShelf {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state: sqlx::types::Json<PowerShelfControllerState> =
            row.try_get("controller_state")?;
        let config: sqlx::types::Json<PowerShelfConfig> = row.try_get("config")?;
        let status: Option<sqlx::types::Json<PowerShelfStatus>> = row.try_get("status").ok();
        let controller_state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome").ok();
        let power_shelf_maintenance_requested: Option<
            sqlx::types::Json<PowerShelfMaintenanceRequest>,
        > = row.try_get("power_shelf_maintenance_requested").ok();

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
        Ok(PowerShelf {
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
            metadata,
            version: row.try_get("version")?,
            rack_id: row.try_get("rack_id").ok().flatten(),
            power_shelf_maintenance_requested: power_shelf_maintenance_requested.map(|r| r.0),
            health_reports,
        })
    }
}

pub fn derive_power_shelf_aggregate_health(
    sources: &HealthReportSources,
) -> health_report::HealthReport {
    if let Some(replace) = &sources.replace {
        return replace.clone();
    }
    let mut output = health_report::HealthReport::empty("power-shelf-aggregate-health".to_string());
    for report in sources.merges.values() {
        output.merge(report);
    }
    output.observed_at = Some(chrono::Utc::now());
    output
}

impl PowerShelf {
    pub fn is_marked_as_deleted(&self) -> bool {
        self.deleted.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "lowercase")]
#[allow(clippy::enum_variant_names)]
pub enum PowerShelfMaintenanceOperation {
    /// Power on the PowerShelf.
    PowerOn,
    /// Power off the PowerShelf.
    PowerOff,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerShelfMaintenanceRequest {
    pub requested_at: DateTime<Utc>,
    pub initiator: String,
    pub operation: PowerShelfMaintenanceOperation,
}

/// State of a PowerShelf as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum PowerShelfControllerState {
    /// The PowerShelf is created in Carbide, waiting for initialization.
    Initializing,
    /// The PowerShelf is fetching data.
    FetchingData,
    /// The PowerShelf is configuring.
    Configuring,
    /// The PowerShelf is ready for use.
    Ready,

    Maintenance {
        operation: PowerShelfMaintenanceOperation,
    },
    /// There is error in PowerShelf; PowerShelf can not be used if it's in error.
    Error { cause: String },
    /// The PowerShelf is in the process of deleting.
    Deleting,
}

/// Returns the SLA for the current state
pub fn state_sla(state: &PowerShelfControllerState, state_version: &ConfigVersion) -> StateSla {
    let time_in_state = chrono::Utc::now()
        .signed_duration_since(state_version.timestamp())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));

    match state {
        PowerShelfControllerState::Initializing => StateSla::with_sla(
            std::time::Duration::from_secs(slas::INITIALIZING),
            time_in_state,
        ),
        PowerShelfControllerState::FetchingData => StateSla::with_sla(
            std::time::Duration::from_secs(slas::FETCHING_DATA),
            time_in_state,
        ),
        PowerShelfControllerState::Configuring => StateSla::with_sla(
            std::time::Duration::from_secs(slas::CONFIGURING),
            time_in_state,
        ),
        PowerShelfControllerState::Ready => StateSla::no_sla(),
        PowerShelfControllerState::Maintenance { .. } => StateSla::with_sla(
            std::time::Duration::from_secs(slas::MAINTENANCE),
            time_in_state,
        ),
        PowerShelfControllerState::Error { .. } => StateSla::no_sla(),
        PowerShelfControllerState::Deleting => StateSla::with_sla(
            std::time::Duration::from_secs(slas::DELETING),
            time_in_state,
        ),
    }
}

#[derive(Clone, Debug, Default)]
pub struct PowerShelfSearchFilter {
    pub rack_id: Option<RackId>,
    pub deleted: crate::DeletedFilter,
    pub controller_state: Option<String>,
    pub bmc_mac: Option<MacAddress>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_controller_state() {
        let state = PowerShelfControllerState::Initializing {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"initializing\"}");
        assert_eq!(
            serde_json::from_str::<PowerShelfControllerState>(&serialized).unwrap(),
            state
        );
        let state = PowerShelfControllerState::FetchingData {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"fetchingdata\"}");
        assert_eq!(
            serde_json::from_str::<PowerShelfControllerState>(&serialized).unwrap(),
            state
        );
        let state = PowerShelfControllerState::Configuring {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"configuring\"}");
        assert_eq!(
            serde_json::from_str::<PowerShelfControllerState>(&serialized).unwrap(),
            state
        );
        let state = PowerShelfControllerState::Ready {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"ready\"}");
        assert_eq!(
            serde_json::from_str::<PowerShelfControllerState>(&serialized).unwrap(),
            state
        );
        let state = PowerShelfControllerState::Error {
            cause: "cause goes here".to_string(),
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, r#"{"state":"error","cause":"cause goes here"}"#);
        assert_eq!(
            serde_json::from_str::<PowerShelfControllerState>(&serialized).unwrap(),
            state
        );
        let state = PowerShelfControllerState::Deleting {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"deleting\"}");
        assert_eq!(
            serde_json::from_str::<PowerShelfControllerState>(&serialized).unwrap(),
            state
        );
        let state = PowerShelfControllerState::Maintenance {
            operation: PowerShelfMaintenanceOperation::PowerOn,
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serialized,
            r#"{"state":"maintenance","operation":{"operation":"poweron"}}"#
        );
        assert_eq!(
            serde_json::from_str::<PowerShelfControllerState>(&serialized).unwrap(),
            state
        );
        let state = PowerShelfControllerState::Maintenance {
            operation: PowerShelfMaintenanceOperation::PowerOff,
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serialized,
            r#"{"state":"maintenance","operation":{"operation":"poweroff"}}"#
        );
        assert_eq!(
            serde_json::from_str::<PowerShelfControllerState>(&serialized).unwrap(),
            state
        );
    }

    #[test]
    fn serialize_maintenance_operation_round_trip() {
        for operation in [
            PowerShelfMaintenanceOperation::PowerOn,
            PowerShelfMaintenanceOperation::PowerOff,
        ] {
            let serialized = serde_json::to_string(&operation).unwrap();
            let parsed: PowerShelfMaintenanceOperation = serde_json::from_str(&serialized).unwrap();
            assert_eq!(parsed, operation);
        }
    }

    #[test]
    fn serialize_maintenance_operation_lowercase_tags() {
        assert_eq!(
            serde_json::to_string(&PowerShelfMaintenanceOperation::PowerOn).unwrap(),
            r#"{"operation":"poweron"}"#
        );
        assert_eq!(
            serde_json::to_string(&PowerShelfMaintenanceOperation::PowerOff).unwrap(),
            r#"{"operation":"poweroff"}"#
        );
    }

    #[test]
    fn serialize_maintenance_request_round_trip() {
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-13T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        for operation in [
            PowerShelfMaintenanceOperation::PowerOn,
            PowerShelfMaintenanceOperation::PowerOff,
        ] {
            let request = PowerShelfMaintenanceRequest {
                requested_at: now,
                initiator: "operator (TICKET-1)".to_string(),
                operation,
            };
            let serialized = serde_json::to_string(&request).unwrap();
            let parsed: PowerShelfMaintenanceRequest = serde_json::from_str(&serialized).unwrap();
            assert_eq!(parsed, request);
        }
    }

    #[test]
    fn maintenance_state_distinguishes_on_and_off() {
        let on = PowerShelfControllerState::Maintenance {
            operation: PowerShelfMaintenanceOperation::PowerOn,
        };
        let off = PowerShelfControllerState::Maintenance {
            operation: PowerShelfMaintenanceOperation::PowerOff,
        };
        assert_ne!(on, off);
    }
}
