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
use carbide_uuid::switch::SwitchId;
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::StateSla;
use crate::controller_outcome::PersistentStateHandlerOutcome;

pub mod slas;
pub mod switch_id;

#[derive(Debug, Clone)]
pub struct NewSwitch {
    pub id: SwitchId,
    pub config: SwitchConfig,
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

        Ok(NewSwitch {
            id,
            config: SwitchConfig::try_from(conf)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SwitchConfig {
    pub name: String,
    pub enable_nmxc: bool,
    pub fabric_manager_config: Option<FabricManagerConfig>,
    pub location: Option<String>, // Physical location
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

#[derive(Debug, Clone)]
pub struct Switch {
    pub id: SwitchId,

    pub config: SwitchConfig,
    pub status: Option<SwitchStatus>,

    pub deleted: Option<DateTime<Utc>>,

    pub controller_state: Versioned<SwitchControllerState>,

    /// The result of the last attempt to change state
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,
    // Columns for these exist, but are unused in rust code
    // pub created: DateTime<Utc>,
    // pub updated: DateTime<Utc>,
}

impl<'r> FromRow<'r, PgRow> for Switch {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state: sqlx::types::Json<SwitchControllerState> =
            row.try_get("controller_state")?;
        let config: sqlx::types::Json<SwitchConfig> = row.try_get("config")?;
        let status: Option<sqlx::types::Json<SwitchStatus>> = row.try_get("status").ok();
        let controller_state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome").ok();

        Ok(Switch {
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

impl TryFrom<rpc::SwitchConfig> for SwitchConfig {
    type Error = RpcDataConversionError;

    fn try_from(conf: rpc::SwitchConfig) -> Result<Self, Self::Error> {
        Ok(SwitchConfig {
            name: conf.name,
            enable_nmxc: conf.enable_nmxc,
            fabric_manager_config: Some(FabricManagerConfig {
                config_map: conf.fabric_manager_config.unwrap_or_default().config_map,
            }),
            location: conf.location,
        })
    }
}

impl TryFrom<Switch> for rpc::Switch {
    type Error = RpcDataConversionError;

    fn try_from(src: Switch) -> Result<Self, Self::Error> {
        let status = src.status.map(|s| rpc::SwitchStatus {
            state_reason: None, // TODO: implement state_reason
            state_sla: Some(rpc::StateSla {
                sla: None,
                time_in_state_above_sla: false,
            }),
            switch_name: Some(s.switch_name),
            power_state: Some(s.power_state),
            health_status: Some(s.health_status),
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
            location: src.config.location,
        };

        let deleted = if src.deleted.is_some() {
            Some(src.deleted.unwrap().into())
        } else {
            None
        };
        let controller_state = serde_json::to_string(&src.controller_state.value).unwrap();
        Ok(rpc::Switch {
            id: Some(src.id),
            config: Some(config),
            status,
            deleted,
            controller_state,
            bmc_info: None,
        })
    }
}

/// State of a Switch as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum SwitchControllerState {
    /// The Switch is created in Carbide, waiting for initialization.
    Initializing,
    /// The Switch is fetching data.
    FetchingData,
    /// The Switch is configuring.
    Configuring,
    /// The Switch is ready for use.
    Ready,
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
        SwitchControllerState::Initializing => StateSla::with_sla(
            std::time::Duration::from_secs(slas::INITIALIZING),
            time_in_state,
        ),
        SwitchControllerState::FetchingData => StateSla::with_sla(
            std::time::Duration::from_secs(slas::FETCHING_DATA),
            time_in_state,
        ),
        SwitchControllerState::Configuring => StateSla::with_sla(
            std::time::Duration::from_secs(slas::CONFIGURING),
            time_in_state,
        ),
        SwitchControllerState::Ready => StateSla::no_sla(),
        SwitchControllerState::Error { .. } => StateSla::no_sla(),
        SwitchControllerState::Deleting => StateSla::with_sla(
            std::time::Duration::from_secs(slas::DELETING),
            time_in_state,
        ),
    }
}

/// History of Switch states for a single Switch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwitchStateHistoryRecord {
    /// The state that was entered
    pub state: String,
    // The version number associated with the state change
    pub state_version: ConfigVersion,
}

impl From<SwitchStateHistoryRecord> for rpc::SwitchStateHistoryRecord {
    fn from(value: SwitchStateHistoryRecord) -> rpc::SwitchStateHistoryRecord {
        rpc::SwitchStateHistoryRecord {
            state: value.state,
            version: value.state_version.version_string(),
            time: Some(value.state_version.timestamp().into()),
        }
    }
}

impl Switch {
    #[allow(dead_code)]
    pub fn is_marked_as_deleted(&self) -> bool {
        self.deleted.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_controller_state() {
        let state = SwitchControllerState::Initializing {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"initializing\"}");
        assert_eq!(
            serde_json::from_str::<SwitchControllerState>(&serialized).unwrap(),
            state
        );
        let state = SwitchControllerState::FetchingData {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"fetchingdata\"}");
        assert_eq!(
            serde_json::from_str::<SwitchControllerState>(&serialized).unwrap(),
            state
        );
        let state = SwitchControllerState::Configuring {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"configuring\"}");
        assert_eq!(
            serde_json::from_str::<SwitchControllerState>(&serialized).unwrap(),
            state
        );
        let state = SwitchControllerState::Ready {};
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
        let state = SwitchControllerState::Deleting {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"deleting\"}");
        assert_eq!(
            serde_json::from_str::<SwitchControllerState>(&serialized).unwrap(),
            state
        );
    }
}
