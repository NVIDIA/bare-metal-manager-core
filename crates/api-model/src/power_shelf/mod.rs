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
use ::rpc::forge::{self as rpc, LifecycleStatus};
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
    pub metadata: Option<Metadata>,
    pub rack_id: Option<RackId>,
}

impl TryFrom<rpc::PowerShelfCreationRequest> for NewPowerShelf {
    type Error = RpcDataConversionError;
    fn try_from(value: rpc::PowerShelfCreationRequest) -> Result<Self, Self::Error> {
        let conf = match value.config {
            Some(c) => c,
            None => {
                return Err(RpcDataConversionError::InvalidArgument(
                    "PowerShelf configuration is empty".to_string(),
                ));
            }
        };

        let id = value.id.unwrap_or_else(|| uuid::Uuid::new_v4().into());

        let config = PowerShelfConfig::try_from(conf)?;

        Ok(NewPowerShelf {
            id,
            config,
            metadata: None,
            rack_id: None,
        })
    }
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

    /// The rack that this power shelf is associated with.
    pub rack_id: Option<RackId>,

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
            controller_state: Versioned {
                value: controller_state.0,
                version: row.try_get("controller_state_version")?,
            },
            controller_state_outcome: controller_state_outcome.map(|o| o.0),
            metadata,
            version: row.try_get("version")?,
            rack_id: row.try_get("rack_id").ok().flatten(),
            health_reports,
        })
    }
}

impl TryFrom<rpc::PowerShelfConfig> for PowerShelfConfig {
    type Error = RpcDataConversionError;

    fn try_from(conf: rpc::PowerShelfConfig) -> Result<Self, Self::Error> {
        Ok(PowerShelfConfig {
            name: conf.name,
            capacity: conf.capacity.map(|c| c as u32),
            voltage: conf.voltage.map(|v| v as u32),
        })
    }
}

fn derive_power_shelf_aggregate_health(
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

impl TryFrom<PowerShelf> for rpc::PowerShelf {
    type Error = RpcDataConversionError;

    fn try_from(src: PowerShelf) -> Result<Self, Self::Error> {
        let health = derive_power_shelf_aggregate_health(&src.health_reports);
        let health_sources = src
            .health_reports
            .iter()
            .map(|(hr, m)| rpc::HealthSourceOrigin {
                mode: m as i32,
                source: hr.source.clone(),
            })
            .collect();

        let lifecycle = LifecycleStatus {
            state: serde_json::to_string(&src.controller_state.value).unwrap_or_default(),
            version: src.controller_state.version.version_string(),
            state_reason: src.controller_state_outcome.map(Into::into),
            sla: Some(rpc::StateSla {
                sla: None, // TODO: Calculate SLA properly
                time_in_state_above_sla: false,
            }),
        };
        let controller_state = lifecycle.state.clone();

        let status = Some(match src.status {
            Some(s) => rpc::PowerShelfStatus {
                state_reason: None, // TODO: implement state_reason
                state_sla: Some(rpc::StateSla {
                    sla: None,
                    time_in_state_above_sla: false,
                }),
                shelf_name: Some(s.shelf_name),
                power_state: Some(s.power_state),
                health_status: Some(s.health_status),
                controller_state: Some(controller_state.clone()),
                health: Some(health.into()),
                health_sources,
                lifecycle: Some(lifecycle),
            },
            None => rpc::PowerShelfStatus {
                state_reason: None,
                state_sla: Some(rpc::StateSla {
                    sla: None,
                    time_in_state_above_sla: false,
                }),
                shelf_name: None,
                power_state: None,
                health_status: None,
                controller_state: Some(controller_state.clone()),
                health: Some(health.into()),
                health_sources,
                lifecycle: Some(lifecycle),
            },
        });

        let config = rpc::PowerShelfConfig {
            name: src.config.name,
            capacity: src.config.capacity.map(|c| c as i32),
            voltage: src.config.voltage.map(|v| v as i32),
        };

        let deleted = if src.deleted.is_some() {
            Some(src.deleted.unwrap().into())
        } else {
            None
        };
        let state_version = src.controller_state.version.to_string();
        Ok(rpc::PowerShelf {
            id: Some(src.id),
            config: Some(config),
            status,
            deleted,
            controller_state,
            metadata: Some(src.metadata.into()),
            version: src.version.version_string(),
            bmc_info: None,
            state_version,
            rack_id: src.rack_id,
        })
    }
}

impl PowerShelf {
    pub fn is_marked_as_deleted(&self) -> bool {
        self.deleted.is_some()
    }
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

impl From<rpc::PowerShelfSearchFilter> for PowerShelfSearchFilter {
    fn from(filter: rpc::PowerShelfSearchFilter) -> Self {
        PowerShelfSearchFilter {
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
    }
}
