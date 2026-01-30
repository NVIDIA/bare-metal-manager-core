/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::errors::RpcDataConversionError;
use ::rpc::forge as rpc;
use carbide_uuid::power_shelf::PowerShelfId;
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::StateSla;
use crate::controller_outcome::PersistentStateHandlerOutcome;

pub mod power_shelf_id;
pub mod slas;

#[derive(Debug, Clone)]
pub struct NewPowerShelf {
    pub id: PowerShelfId,
    pub config: PowerShelfConfig,
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

        Ok(NewPowerShelf {
            id,
            config: PowerShelfConfig::try_from(conf)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PowerShelfConfig {
    pub name: String,
    pub capacity: Option<u32>,    // Power capacity in watts
    pub voltage: Option<u32>,     // Voltage in volts
    pub location: Option<String>, // Physical location
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
    // Columns for these exist, but are unused in rust code
    // pub created: DateTime<Utc>,
    // pub updated: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for PowerShelf {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state: sqlx::types::Json<PowerShelfControllerState> =
            row.try_get("controller_state")?;
        let config: sqlx::types::Json<PowerShelfConfig> = row.try_get("config")?;
        let status: Option<sqlx::types::Json<PowerShelfStatus>> = row.try_get("status").ok();
        let controller_state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome").ok();

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
            location: conf.location,
        })
    }
}

impl TryFrom<PowerShelf> for rpc::PowerShelf {
    type Error = RpcDataConversionError;

    fn try_from(src: PowerShelf) -> Result<Self, Self::Error> {
        let status = src.status.map(|s| rpc::PowerShelfStatus {
            state_reason: None, // TODO: implement state_reason
            state_sla: Some(rpc::StateSla {
                sla: None,
                time_in_state_above_sla: false,
            }),
            shelf_name: Some(s.shelf_name),
            power_state: Some(s.power_state),
            health_status: Some(s.health_status),
        });

        let config = rpc::PowerShelfConfig {
            name: src.config.name,
            capacity: src.config.capacity.map(|c| c as i32),
            voltage: src.config.voltage.map(|v| v as i32),
            location: src.config.location,
        };

        let deleted = if src.deleted.is_some() {
            Some(src.deleted.unwrap().into())
        } else {
            None
        };
        let controller_state = serde_json::to_string(&src.controller_state.value).unwrap();
        Ok(rpc::PowerShelf {
            id: Some(src.id),
            config: Some(config),
            status,
            deleted,
            controller_state,
        })
    }
}

impl PowerShelf {
    #[allow(dead_code)]
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

/// History of Power Shelf states for a single Power Shelf
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowerShelfStateHistoryRecord {
    /// The state that was entered
    pub state: String,
    // The version number associated with the state change
    pub state_version: ConfigVersion,
}

impl From<PowerShelfStateHistoryRecord> for rpc::PowerShelfStateHistoryRecord {
    fn from(value: PowerShelfStateHistoryRecord) -> rpc::PowerShelfStateHistoryRecord {
        rpc::PowerShelfStateHistoryRecord {
            state: value.state,
            version: value.state_version.version_string(),
            time: Some(value.state_version.timestamp().into()),
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
