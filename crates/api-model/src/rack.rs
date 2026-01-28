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

#[derive(Debug, Clone)]
pub struct Rack {
    pub id: RackId,
    pub config: RackConfig,
    pub controller_state: Versioned<RackState>,
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
}

impl From<Rack> for rpc::forge::Rack {
    fn from(value: Rack) -> Self {
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
            expected_nvlink_switches: vec![],
            compute_trays: value.config.compute_trays,
            power_shelves: value.config.power_shelves,
            created: Some(Timestamp::from(value.created)),
            updated: Some(Timestamp::from(value.updated)),
            deleted: value.deleted.map(Timestamp::from),
        }
    }
}

impl<'r> FromRow<'r, PgRow> for Rack {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let config: sqlx::types::Json<RackConfig> = row.try_get("config")?;
        let controller_state: sqlx::types::Json<RackState> = row.try_get("controller_state")?;
        let controller_state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome").ok();
        Ok(Rack {
            id: row.try_get("id")?,
            config: config.0,
            controller_state: Versioned {
                value: controller_state.0,
                version: row.try_get("controller_state_version")?,
            },
            controller_state_outcome: controller_state_outcome.map(|o| o.0),
            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
/// Overall state of the rack. When the rack identifier is supplied in ExpectedMachine/Switch/PS,
/// the rack is expected. Once any one of the devices is found, the rack state moves to discovering
/// till all expected devices with the given rack id are found. The discovered devices are put into
/// rack level holding substates while the rack state controller acts on them via rack manager calls.
/// once the maintenance is completed, they are restored to their prior device specific state.
pub enum RackState {
    // initial state when added via Expected[Machine/Switch/PS]
    Expected,

    // when any of the trays show up
    Discovering,

    // once devices are discovered, put some/all in maintenance and do firmware upgrades
    Maintenance {
        rack_maintenance: RackMaintenanceState,
    },

    // rack is ready
    Ready {
        rack_ready: RackReadyState,
    },

    // todo: error enum for recovery actions
    Error {
        cause: String,
    },
    Deleting,
    // default state
    Unknown,
}

impl Display for RackState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RackReadyState {
    Partial,
    Full,
}

impl Display for RackReadyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RackMaintenanceState {
    FirmwareUpgrade {
        rack_firmware_upgrade: RackFirmwareUpgradeState,
    },
    PowerSequence {
        rack_power: RackPowerState,
    },
    RackValidation {
        rack_validation: RackValidationState,
    },
    Completed,
}

impl Display for RackMaintenanceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
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
        std::fmt::Debug::fmt(self, f)
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
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RackValidationState {
    Compute,
    Switch,
    Power,
    Nvlink,
    Topology,
}

impl Display for RackValidationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RackStateHistory {
    /// The state that was entered
    pub state: String,
    // The version number associated with the state change
    pub state_version: ConfigVersion,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RackConfig {
    pub compute_trays: Vec<MachineId>,
    // todo: put in nvlink switch ids here when that code lands
    // pub nvlink_switches: Vec<NvlinkSwitchId>
    pub power_shelves: Vec<PowerShelfId>,

    // store bmc mac address of every tray in the rack
    pub expected_compute_trays: Vec<MacAddress>,
    // todo: nvlink switches
    // pub expected_nvlink_switches: Vec<MacAddress>,
    pub expected_power_shelves: Vec<MacAddress>,
}

pub fn state_sla(state: &RackState, state_version: &ConfigVersion) -> StateSla {
    let _time_in_state = chrono::Utc::now()
        .signed_duration_since(state_version.timestamp())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));

    match state {
        RackState::Expected => StateSla::no_sla(),
        RackState::Discovering => StateSla::no_sla(),
        RackState::Maintenance { .. } => StateSla::no_sla(),
        RackState::Ready { .. } => StateSla::no_sla(),
        RackState::Error { .. } => StateSla::no_sla(),
        RackState::Deleting => StateSla::no_sla(),
        RackState::Unknown => StateSla::no_sla(),
    }
}

impl From<RackStateHistory> for rpc::forge::RackEvent {
    fn from(value: RackStateHistory) -> rpc::forge::RackEvent {
        rpc::forge::RackEvent {
            event: value.state,
            version: value.state_version.version_string(),
            time: Some(value.state_version.timestamp().into()),
        }
    }
}
