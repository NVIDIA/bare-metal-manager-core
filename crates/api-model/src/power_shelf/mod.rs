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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};

    use super::*;

    #[test]
    fn serialize_controller_state() {
        // Each controller-state variant serializes to its tagged JSON and round-trips
        // back to the same value. The op yields (serialized, deserialized) so both the
        // exact JSON string and the round-trip equality are asserted per row.
        check_cases(
            [
                Case {
                    scenario: "initializing",
                    input: PowerShelfControllerState::Initializing {},
                    expect: Yields((
                        "{\"state\":\"initializing\"}".to_string(),
                        PowerShelfControllerState::Initializing {},
                    )),
                },
                Case {
                    scenario: "fetching data",
                    input: PowerShelfControllerState::FetchingData {},
                    expect: Yields((
                        "{\"state\":\"fetchingdata\"}".to_string(),
                        PowerShelfControllerState::FetchingData {},
                    )),
                },
                Case {
                    scenario: "configuring",
                    input: PowerShelfControllerState::Configuring {},
                    expect: Yields((
                        "{\"state\":\"configuring\"}".to_string(),
                        PowerShelfControllerState::Configuring {},
                    )),
                },
                Case {
                    scenario: "ready",
                    input: PowerShelfControllerState::Ready {},
                    expect: Yields((
                        "{\"state\":\"ready\"}".to_string(),
                        PowerShelfControllerState::Ready {},
                    )),
                },
                Case {
                    scenario: "error with cause",
                    input: PowerShelfControllerState::Error {
                        cause: "cause goes here".to_string(),
                    },
                    expect: Yields((
                        r#"{"state":"error","cause":"cause goes here"}"#.to_string(),
                        PowerShelfControllerState::Error {
                            cause: "cause goes here".to_string(),
                        },
                    )),
                },
                Case {
                    scenario: "deleting",
                    input: PowerShelfControllerState::Deleting {},
                    expect: Yields((
                        "{\"state\":\"deleting\"}".to_string(),
                        PowerShelfControllerState::Deleting {},
                    )),
                },
                Case {
                    scenario: "maintenance power-on",
                    input: PowerShelfControllerState::Maintenance {
                        operation: PowerShelfMaintenanceOperation::PowerOn,
                    },
                    expect: Yields((
                        r#"{"state":"maintenance","operation":{"operation":"poweron"}}"#
                            .to_string(),
                        PowerShelfControllerState::Maintenance {
                            operation: PowerShelfMaintenanceOperation::PowerOn,
                        },
                    )),
                },
                Case {
                    scenario: "maintenance power-off",
                    input: PowerShelfControllerState::Maintenance {
                        operation: PowerShelfMaintenanceOperation::PowerOff,
                    },
                    expect: Yields((
                        r#"{"state":"maintenance","operation":{"operation":"poweroff"}}"#
                            .to_string(),
                        PowerShelfControllerState::Maintenance {
                            operation: PowerShelfMaintenanceOperation::PowerOff,
                        },
                    )),
                },
            ],
            // Serialize the state, then deserialize the produced JSON back.
            |state: PowerShelfControllerState| {
                let serialized = serde_json::to_string(&state).map_err(drop)?;
                let parsed =
                    serde_json::from_str::<PowerShelfControllerState>(&serialized).map_err(drop)?;
                Ok::<_, ()>((serialized, parsed))
            },
        );
    }

    #[test]
    fn serialize_maintenance_operation() {
        // Each maintenance operation serializes to its lowercase-tagged JSON and
        // round-trips back. The op yields (serialized, deserialized), folding the
        // exact-tag and round-trip assertions into one table.
        check_cases(
            [
                Case {
                    scenario: "power on",
                    input: PowerShelfMaintenanceOperation::PowerOn,
                    expect: Yields((
                        r#"{"operation":"poweron"}"#.to_string(),
                        PowerShelfMaintenanceOperation::PowerOn,
                    )),
                },
                Case {
                    scenario: "power off",
                    input: PowerShelfMaintenanceOperation::PowerOff,
                    expect: Yields((
                        r#"{"operation":"poweroff"}"#.to_string(),
                        PowerShelfMaintenanceOperation::PowerOff,
                    )),
                },
            ],
            |operation: PowerShelfMaintenanceOperation| {
                let serialized = serde_json::to_string(&operation).map_err(drop)?;
                let parsed = serde_json::from_str::<PowerShelfMaintenanceOperation>(&serialized)
                    .map_err(drop)?;
                Ok::<_, ()>((serialized, parsed))
            },
        );
    }

    #[test]
    fn serialize_maintenance_request_round_trip() {
        // A maintenance request round-trips through JSON for each operation. Only the
        // operation varies; the timestamp and initiator are fixed across rows.
        let now = chrono::DateTime::parse_from_rfc3339("2026-05-13T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let request = |operation| PowerShelfMaintenanceRequest {
            requested_at: now,
            initiator: "operator (TICKET-1)".to_string(),
            operation,
        };
        check_cases(
            [
                Case {
                    scenario: "power on",
                    input: PowerShelfMaintenanceOperation::PowerOn,
                    expect: Yields(request(PowerShelfMaintenanceOperation::PowerOn)),
                },
                Case {
                    scenario: "power off",
                    input: PowerShelfMaintenanceOperation::PowerOff,
                    expect: Yields(request(PowerShelfMaintenanceOperation::PowerOff)),
                },
            ],
            |operation| {
                let serialized = serde_json::to_string(&request(operation)).map_err(drop)?;
                serde_json::from_str::<PowerShelfMaintenanceRequest>(&serialized).map_err(drop)
            },
        );
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

    #[test]
    fn controller_state_deserializes_from_tagged_json() {
        // Each tagged-JSON form parses back to its variant; malformed or unknown
        // tags are rejected. The op yields the parsed variant so both the accepted
        // shapes and the rejected ones are pinned in one table.
        check_cases(
            [
                Case {
                    scenario: "initializing tag",
                    input: r#"{"state":"initializing"}"#,
                    expect: Yields(PowerShelfControllerState::Initializing),
                },
                Case {
                    scenario: "fetchingdata tag",
                    input: r#"{"state":"fetchingdata"}"#,
                    expect: Yields(PowerShelfControllerState::FetchingData),
                },
                Case {
                    scenario: "configuring tag",
                    input: r#"{"state":"configuring"}"#,
                    expect: Yields(PowerShelfControllerState::Configuring),
                },
                Case {
                    scenario: "ready tag",
                    input: r#"{"state":"ready"}"#,
                    expect: Yields(PowerShelfControllerState::Ready),
                },
                Case {
                    scenario: "deleting tag",
                    input: r#"{"state":"deleting"}"#,
                    expect: Yields(PowerShelfControllerState::Deleting),
                },
                Case {
                    scenario: "error with cause",
                    input: r#"{"state":"error","cause":"boom"}"#,
                    expect: Yields(PowerShelfControllerState::Error {
                        cause: "boom".to_string(),
                    }),
                },
                Case {
                    scenario: "error with empty cause",
                    input: r#"{"state":"error","cause":""}"#,
                    expect: Yields(PowerShelfControllerState::Error {
                        cause: String::new(),
                    }),
                },
                Case {
                    scenario: "maintenance power-on",
                    input: r#"{"state":"maintenance","operation":{"operation":"poweron"}}"#,
                    expect: Yields(PowerShelfControllerState::Maintenance {
                        operation: PowerShelfMaintenanceOperation::PowerOn,
                    }),
                },
                Case {
                    scenario: "maintenance power-off",
                    input: r#"{"state":"maintenance","operation":{"operation":"poweroff"}}"#,
                    expect: Yields(PowerShelfControllerState::Maintenance {
                        operation: PowerShelfMaintenanceOperation::PowerOff,
                    }),
                },
                Case {
                    scenario: "unknown tag is rejected",
                    input: r#"{"state":"running"}"#,
                    expect: Fails,
                },
                Case {
                    scenario: "wrong-case tag is rejected",
                    input: r#"{"state":"Initializing"}"#,
                    expect: Fails,
                },
                Case {
                    scenario: "error without cause is rejected",
                    input: r#"{"state":"error"}"#,
                    expect: Fails,
                },
                Case {
                    scenario: "maintenance without operation is rejected",
                    input: r#"{"state":"maintenance"}"#,
                    expect: Fails,
                },
                Case {
                    scenario: "missing state tag is rejected",
                    input: r#"{}"#,
                    expect: Fails,
                },
                Case {
                    scenario: "not an object is rejected",
                    input: r#""initializing""#,
                    expect: Fails,
                },
                Case {
                    scenario: "malformed json is rejected",
                    input: r#"{"state":"#,
                    expect: Fails,
                },
            ],
            |json: &str| serde_json::from_str::<PowerShelfControllerState>(json).map_err(drop),
        );
    }

    #[test]
    fn maintenance_operation_deserializes_from_tagged_json() {
        // The lowercase operation tags parse back to their variants; unknown or
        // wrong-case tags are rejected.
        check_cases(
            [
                Case {
                    scenario: "poweron tag",
                    input: r#"{"operation":"poweron"}"#,
                    expect: Yields(PowerShelfMaintenanceOperation::PowerOn),
                },
                Case {
                    scenario: "poweroff tag",
                    input: r#"{"operation":"poweroff"}"#,
                    expect: Yields(PowerShelfMaintenanceOperation::PowerOff),
                },
                Case {
                    scenario: "unknown operation is rejected",
                    input: r#"{"operation":"reset"}"#,
                    expect: Fails,
                },
                Case {
                    scenario: "wrong-case operation is rejected",
                    input: r#"{"operation":"PowerOn"}"#,
                    expect: Fails,
                },
                Case {
                    scenario: "missing operation tag is rejected",
                    input: r#"{}"#,
                    expect: Fails,
                },
            ],
            |json: &str| serde_json::from_str::<PowerShelfMaintenanceOperation>(json).map_err(drop),
        );
    }

    #[test]
    fn config_round_trips_through_json() {
        // PowerShelfConfig round-trips for present/absent optionals, empty names, and
        // numeric boundaries. The op yields the value parsed back from its own JSON.
        check_cases(
            [
                Case {
                    scenario: "all fields present",
                    input: PowerShelfConfig {
                        name: "shelf-1".to_string(),
                        capacity: Some(5000),
                        voltage: Some(48),
                    },
                    expect: Yields(PowerShelfConfig {
                        name: "shelf-1".to_string(),
                        capacity: Some(5000),
                        voltage: Some(48),
                    }),
                },
                Case {
                    scenario: "optionals absent",
                    input: PowerShelfConfig {
                        name: "shelf-2".to_string(),
                        capacity: None,
                        voltage: None,
                    },
                    expect: Yields(PowerShelfConfig {
                        name: "shelf-2".to_string(),
                        capacity: None,
                        voltage: None,
                    }),
                },
                Case {
                    scenario: "empty name and zero values",
                    input: PowerShelfConfig {
                        name: String::new(),
                        capacity: Some(0),
                        voltage: Some(0),
                    },
                    expect: Yields(PowerShelfConfig {
                        name: String::new(),
                        capacity: Some(0),
                        voltage: Some(0),
                    }),
                },
                Case {
                    scenario: "u32 maxima",
                    input: PowerShelfConfig {
                        name: "max".to_string(),
                        capacity: Some(u32::MAX),
                        voltage: Some(u32::MAX),
                    },
                    expect: Yields(PowerShelfConfig {
                        name: "max".to_string(),
                        capacity: Some(u32::MAX),
                        voltage: Some(u32::MAX),
                    }),
                },
            ],
            |config: PowerShelfConfig| {
                let serialized = serde_json::to_string(&config).map_err(drop)?;
                serde_json::from_str::<PowerShelfConfig>(&serialized).map_err(drop)
            },
        );
    }

    #[test]
    fn status_round_trips_through_json() {
        // PowerShelfStatus round-trips across each power/health string the field is
        // documented to hold, plus empty strings.
        check_cases(
            [
                Case {
                    scenario: "on / ok",
                    input: PowerShelfStatus {
                        shelf_name: "psu-a".to_string(),
                        power_state: "on".to_string(),
                        health_status: "ok".to_string(),
                    },
                    expect: Yields(PowerShelfStatus {
                        shelf_name: "psu-a".to_string(),
                        power_state: "on".to_string(),
                        health_status: "ok".to_string(),
                    }),
                },
                Case {
                    scenario: "off / warning",
                    input: PowerShelfStatus {
                        shelf_name: "psu-b".to_string(),
                        power_state: "off".to_string(),
                        health_status: "warning".to_string(),
                    },
                    expect: Yields(PowerShelfStatus {
                        shelf_name: "psu-b".to_string(),
                        power_state: "off".to_string(),
                        health_status: "warning".to_string(),
                    }),
                },
                Case {
                    scenario: "standby / critical",
                    input: PowerShelfStatus {
                        shelf_name: "psu-c".to_string(),
                        power_state: "standby".to_string(),
                        health_status: "critical".to_string(),
                    },
                    expect: Yields(PowerShelfStatus {
                        shelf_name: "psu-c".to_string(),
                        power_state: "standby".to_string(),
                        health_status: "critical".to_string(),
                    }),
                },
                Case {
                    scenario: "empty strings",
                    input: PowerShelfStatus {
                        shelf_name: String::new(),
                        power_state: String::new(),
                        health_status: String::new(),
                    },
                    expect: Yields(PowerShelfStatus {
                        shelf_name: String::new(),
                        power_state: String::new(),
                        health_status: String::new(),
                    }),
                },
            ],
            |status: PowerShelfStatus| {
                let serialized = serde_json::to_string(&status).map_err(drop)?;
                serde_json::from_str::<PowerShelfStatus>(&serialized).map_err(drop)
            },
        );
    }

    #[test]
    fn state_sla_reports_whether_an_sla_applies() {
        // `state_sla` selects an SLA bucket per controller state. Driven from an
        // epoch-old `ConfigVersion` (via `invalid()`), the time-in-state is far past
        // any finite SLA, so each SLA-bearing state reports its exact SLA duration and
        // an `above_sla` of true, while the no-SLA states report `None`/false. The op
        // yields `(sla, time_in_state_above_sla)`.
        let stale = ConfigVersion::invalid();
        let secs = |s: u64| Some(std::time::Duration::from_secs(s));
        check_values(
            [
                Check {
                    scenario: "initializing has an SLA and is overdue",
                    input: PowerShelfControllerState::Initializing,
                    expect: (secs(slas::INITIALIZING), true),
                },
                Check {
                    scenario: "fetching-data has an SLA and is overdue",
                    input: PowerShelfControllerState::FetchingData,
                    expect: (secs(slas::FETCHING_DATA), true),
                },
                Check {
                    scenario: "configuring has an SLA and is overdue",
                    input: PowerShelfControllerState::Configuring,
                    expect: (secs(slas::CONFIGURING), true),
                },
                Check {
                    scenario: "deleting has an SLA and is overdue",
                    input: PowerShelfControllerState::Deleting,
                    expect: (secs(slas::DELETING), true),
                },
                Check {
                    scenario: "maintenance power-on has the maintenance SLA",
                    input: PowerShelfControllerState::Maintenance {
                        operation: PowerShelfMaintenanceOperation::PowerOn,
                    },
                    expect: (secs(slas::MAINTENANCE), true),
                },
                Check {
                    scenario: "maintenance power-off has the maintenance SLA",
                    input: PowerShelfControllerState::Maintenance {
                        operation: PowerShelfMaintenanceOperation::PowerOff,
                    },
                    expect: (secs(slas::MAINTENANCE), true),
                },
                Check {
                    scenario: "ready carries no SLA",
                    input: PowerShelfControllerState::Ready,
                    expect: (None, false),
                },
                Check {
                    scenario: "error carries no SLA",
                    input: PowerShelfControllerState::Error {
                        cause: "boom".to_string(),
                    },
                    expect: (None, false),
                },
            ],
            |state: PowerShelfControllerState| {
                let result = state_sla(&state, &stale);
                (result.sla, result.time_in_state_above_sla)
            },
        );
    }

    #[test]
    fn aggregate_health_prefers_the_replace_source() {
        // When a `replace` source is set, `derive_power_shelf_aggregate_health` returns
        // it verbatim (its `observed_at` untouched), short-circuiting the merge path.
        // The op yields the derived report's source name.
        let with_replace = |source: &str| HealthReportSources {
            replace: Some(health_report::HealthReport::empty(source.to_string())),
            ..Default::default()
        };
        check_cases(
            [
                Case {
                    scenario: "replace source wins",
                    input: with_replace("override.sre"),
                    expect: Yields("override.sre".to_string()),
                },
                Case {
                    scenario: "no replace falls back to the aggregate name",
                    input: HealthReportSources::default(),
                    expect: Yields("power-shelf-aggregate-health".to_string()),
                },
            ],
            |sources: HealthReportSources| {
                Ok::<_, ()>(derive_power_shelf_aggregate_health(&sources).source)
            },
        );
    }
}
