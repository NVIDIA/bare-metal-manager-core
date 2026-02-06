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

use std::convert::TryFrom;
use std::fmt::Display;
use std::net::IpAddr;
use std::str::FromStr;

use carbide_uuid::dpa_interface::DpaInterfaceId;
use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use itertools::Itertools;
use mac_address::MacAddress;
use rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::StateSla;
use crate::controller_outcome::PersistentStateHandlerOutcome;

mod slas;

/// State of a dpa interface as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum DpaInterfaceControllerState {
    /// Initial state
    Provisioning,
    /// The dpa interface is ready. It has been configured with a zero VNI
    Ready,
    /// Unlock the card
    Unlocking,
    /// Apply mlx profile
    ApplyProfile,
    /// Lock the card
    Locking,
    /// The VNI associated with the DPA interface is being set
    WaitingForSetVNI,
    /// The Dpa Interface has been configured with a non-zero VNI
    Assigned,
    /// The VNI associated with the DPA interface is being reset
    WaitingForResetVNI,
}

impl Display for DpaInterfaceControllerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpaInterfaceNetworkConfig {
    pub use_admin_network: Option<bool>,
    pub quarantine_state: Option<DpaInterfaceQuarantineState>,
}

impl Display for DpaInterfaceNetworkConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl Default for DpaInterfaceNetworkConfig {
    fn default() -> Self {
        DpaInterfaceNetworkConfig {
            use_admin_network: Some(true),
            quarantine_state: None,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpaInterfaceQuarantineState {
    pub reason: Option<String>,
    pub mode: DpaInterfaceQuarantineMode,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum DpaInterfaceQuarantineMode {
    BlockAllTraffic,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpaInterfaceNetworkStatusObservation {
    pub observed_at: DateTime<Utc>,
    pub network_config_version: Option<ConfigVersion>,
}

impl Display for DpaInterfaceNetworkStatusObservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum DpaLockMode {
    Unlocked,
    Locked,
}

impl TryFrom<i32> for DpaLockMode {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DpaLockMode::Locked),
            2 => Ok(DpaLockMode::Unlocked),
            _ => Err("Invalid value for DpaLockMode"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct CardState {
    pub lockmode: Option<DpaLockMode>,
    pub profile: Option<String>,
    pub profile_synced: Option<bool>,
}

impl Display for CardState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// Returns the SLA for the current state
/// We can be in the Provisioning, Ready and Assigned states
/// for a long time.
pub fn state_sla(state: &DpaInterfaceControllerState, state_version: &ConfigVersion) -> StateSla {
    let time_in_state = chrono::Utc::now()
        .signed_duration_since(state_version.timestamp())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));
    match state {
        DpaInterfaceControllerState::Provisioning => StateSla::no_sla(),
        DpaInterfaceControllerState::Ready => StateSla::no_sla(),
        DpaInterfaceControllerState::Locking => StateSla::with_sla(slas::LOCKING, time_in_state),
        DpaInterfaceControllerState::ApplyProfile => {
            StateSla::with_sla(slas::APPLY_PROFILE, time_in_state)
        }
        DpaInterfaceControllerState::Unlocking => {
            StateSla::with_sla(slas::UNLOCKING, time_in_state)
        }
        DpaInterfaceControllerState::WaitingForSetVNI => {
            StateSla::with_sla(slas::WAITINGFORSETVNI, time_in_state)
        }
        DpaInterfaceControllerState::Assigned => StateSla::no_sla(),
        DpaInterfaceControllerState::WaitingForResetVNI => {
            StateSla::with_sla(slas::WAITINGFORRESETVNI, time_in_state)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_controller_state() {
        let state = DpaInterfaceControllerState::Provisioning {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"provisioning\"}");
        assert_eq!(
            serde_json::from_str::<DpaInterfaceControllerState>(&serialized).unwrap(),
            state
        );

        let state = DpaInterfaceControllerState::Ready {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"ready\"}");
        assert_eq!(
            serde_json::from_str::<DpaInterfaceControllerState>(&serialized).unwrap(),
            state
        );
    }
}

#[derive(Clone, Debug)]
pub struct DpaInterface {
    pub id: DpaInterfaceId,
    pub machine_id: MachineId,

    pub mac_address: MacAddress,
    pub pci_name: String,

    pub underlay_ip: Option<IpAddr>,
    pub overlay_ip: Option<IpAddr>,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,

    pub controller_state: Versioned<DpaInterfaceControllerState>,

    // Last time we issued a heartbeat command to the DPA
    pub last_hb_time: DateTime<Utc>,

    /// The result of the last attempt to change state
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,

    pub network_config: Versioned<DpaInterfaceNetworkConfig>,
    pub network_status_observation: Option<DpaInterfaceNetworkStatusObservation>,

    pub card_state: Option<CardState>,

    pub history: Vec<DpaInterfaceStateHistoryRecord>,
}

#[derive(Clone, Debug)]
pub struct NewDpaInterface {
    pub machine_id: MachineId,
    pub mac_address: MacAddress,
    pub device_type: String,
    pub pci_name: String,
}

impl TryFrom<rpc::forge::DpaInterfaceCreationRequest> for NewDpaInterface {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::DpaInterfaceCreationRequest) -> Result<Self, Self::Error> {
        let machine_id = value
            .machine_id
            .ok_or(RpcDataConversionError::MissingArgument("id"))?;
        let mac_address = MacAddress::from_str(&value.mac_addr)
            .map_err(|_| RpcDataConversionError::InvalidMacAddress(value.mac_addr.to_string()))?;
        Ok(NewDpaInterface {
            machine_id,
            mac_address,
            device_type: value.device_type,
            pci_name: value.pci_name,
        })
    }
}

impl DpaInterface {
    pub fn use_admin_network(&self) -> bool {
        self.network_config.use_admin_network.unwrap_or(true)
    }

    pub fn get_machine_id(&self) -> MachineId {
        self.machine_id
    }

    pub fn managed_host_network_config_version_synced(&self) -> bool {
        let dpa_expected_version = self.network_config.version;
        let dpa_observation = self.network_status_observation.as_ref();

        if self.use_admin_network()
            && self.controller_state.value == DpaInterfaceControllerState::Provisioning
        {
            return true;
        }

        let dpa_observed_version: ConfigVersion = match dpa_observation {
            Some(network_status) => match network_status.network_config_version {
                Some(version) => version,
                None => return false,
            },
            None => return false,
        };

        dpa_expected_version == dpa_observed_version
    }

    pub fn is_ready(&self) -> bool {
        self.controller_state.value == DpaInterfaceControllerState::Ready
    }
}

impl<'r> FromRow<'r, PgRow> for DpaInterface {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let json: serde_json::value::Value = row.try_get(0)?;
        DpaInterfaceSnapshotPgJson::deserialize(json)
            .map_err(|err| sqlx::Error::Decode(err.into()))?
            .try_into()
    }
}

impl From<DpaInterface> for rpc::forge::DpaInterface {
    fn from(src: DpaInterface) -> Self {
        let (controller_state, controller_state_version) = src.controller_state.take();
        let (network_config, network_config_version) = src.network_config.take();

        let outcome = match src.controller_state_outcome {
            Some(psho) => psho.to_string(),
            None => "None".to_string(),
        };

        let network_status_observation = match src.network_status_observation {
            Some(nso) => nso.to_string(),
            None => "None".to_string(),
        };

        let cstate = match src.card_state {
            Some(cs) => cs.to_string(),
            None => "None".to_string(),
        };

        let underlay = match src.underlay_ip {
            Some(ip) => ip.to_string(),
            None => String::new(),
        };

        let overlay = match src.overlay_ip {
            Some(ip) => ip.to_string(),
            None => String::new(),
        };

        let history: Vec<rpc::forge::DpaInterfaceStateHistoryRecord> = src
            .history
            .into_iter()
            .sorted_by(
                |s1: &crate::dpa_interface::DpaInterfaceStateHistoryRecord,
                 s2: &crate::dpa_interface::DpaInterfaceStateHistoryRecord| {
                    Ord::cmp(&s1.state_version.timestamp(), &s2.state_version.timestamp())
                },
            )
            .map(Into::into)
            .collect();

        rpc::forge::DpaInterface {
            id: Some(src.id),
            created: Some(src.created.into()),
            updated: Some(src.updated.into()),
            deleted: src.deleted.map(|t| t.into()),
            last_hb_time: Some(src.last_hb_time.into()),
            mac_addr: src.mac_address.to_string(),
            machine_id: Some(src.machine_id),
            controller_state: controller_state.to_string(),
            controller_state_version: controller_state_version.to_string(),
            network_config: network_config.to_string(),
            network_config_version: network_config_version.to_string(),
            controller_state_outcome: outcome,
            network_status_observation,
            history,
            card_state: cstate,
            pci_name: src.pci_name,
            underlay_ip: underlay,
            overlay_ip: overlay,
        }
    }
}

/// A record of a past state of a DpaInterface
///
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DpaInterfaceStateHistoryRecord {
    /// The UUID of the dpa interface that experienced the state change
    interface_id: DpaInterfaceId,

    /// The state that was entered
    pub state: String,
    pub state_version: ConfigVersion,

    /// The timestamp of the state change
    timestamp: DateTime<Utc>,
}

impl From<DpaInterfaceStateHistoryRecord> for rpc::forge::DpaInterfaceStateHistoryRecord {
    fn from(value: DpaInterfaceStateHistoryRecord) -> Self {
        rpc::forge::DpaInterfaceStateHistoryRecord {
            state: value.state,
            version: value.state_version.version_string(),
            time: Some(value.timestamp.into()),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct DpaInterfaceSnapshotPgJson {
    pub id: DpaInterfaceId,
    pub machine_id: MachineId,
    pub mac_address: MacAddress,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub last_hb_time: DateTime<Utc>,
    pub controller_state: DpaInterfaceControllerState,
    pub controller_state_version: String,
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,
    pub network_config: DpaInterfaceNetworkConfig,
    pub network_config_version: String,
    pub network_status_observation: Option<DpaInterfaceNetworkStatusObservation>,
    pub card_state: Option<CardState>,
    pub pci_name: String,
    pub underlay_ip: Option<IpAddr>,
    pub overlay_ip: Option<IpAddr>,
    #[serde(default)]
    pub history: Vec<DpaInterfaceStateHistoryRecord>,
}

impl TryFrom<DpaInterfaceSnapshotPgJson> for DpaInterface {
    type Error = sqlx::Error;

    fn try_from(value: DpaInterfaceSnapshotPgJson) -> sqlx::Result<Self> {
        Ok(Self {
            id: value.id,
            machine_id: value.machine_id,
            mac_address: value.mac_address,
            created: value.created,
            updated: value.updated,
            deleted: value.deleted,
            last_hb_time: value.last_hb_time,
            controller_state: Versioned {
                value: value.controller_state,
                version: value.controller_state_version.parse().map_err(|e| {
                    sqlx::error::Error::ColumnDecode {
                        index: "controller_state_version".to_string(),
                        source: Box::new(e),
                    }
                })?,
            },
            controller_state_outcome: value.controller_state_outcome,
            network_config: Versioned {
                value: value.network_config,
                version: value.network_config_version.parse().map_err(|e| {
                    sqlx::error::Error::ColumnDecode {
                        index: "network_config_version".to_string(),
                        source: Box::new(e),
                    }
                })?,
            },
            network_status_observation: value.network_status_observation,
            card_state: value.card_state,
            history: value.history,
            pci_name: value.pci_name,
            underlay_ip: value.underlay_ip,
            overlay_ip: value.overlay_ip,
        })
    }
}
