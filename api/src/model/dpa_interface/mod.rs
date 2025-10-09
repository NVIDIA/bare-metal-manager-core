/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::fmt::Display;
use std::str::FromStr;

use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use forge_uuid::dpa_interface::DpaInterfaceId;
use forge_uuid::machine::MachineId;
use itertools::Itertools;
use mac_address::MacAddress;
use rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::model::StateSla;
use crate::model::controller_outcome::PersistentStateHandlerOutcome;

mod slas;

/// State of a dpa interface as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum DpaInterfaceControllerState {
    /// Initial state
    Provisioning,
    /// The dpa interface is ready. It has been configured with a zero VNI
    Ready,
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

/// Returns the SLA for the current state
pub fn state_sla(state: &DpaInterfaceControllerState, state_version: &ConfigVersion) -> StateSla {
    let time_in_state = chrono::Utc::now()
        .signed_duration_since(state_version.timestamp())
        .to_std()
        .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));
    match state {
        DpaInterfaceControllerState::Provisioning => StateSla::with_sla(
            std::time::Duration::from_secs(slas::PROVISIONING),
            time_in_state,
        ),
        DpaInterfaceControllerState::Ready => StateSla::no_sla(),
        DpaInterfaceControllerState::WaitingForSetVNI => StateSla::with_sla(
            std::time::Duration::from_secs(slas::WAITINGFORSETVNI),
            time_in_state,
        ),
        DpaInterfaceControllerState::Assigned => StateSla::no_sla(),
        DpaInterfaceControllerState::WaitingForResetVNI => StateSla::with_sla(
            std::time::Duration::from_secs(slas::WAITINGFORRESETVNI),
            time_in_state,
        ),
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

    pub history: Vec<DpaInterfaceStateHistory>,
}

#[derive(Clone, Debug)]
pub struct NewDpaInterface {
    pub machine_id: MachineId,
    pub mac_address: MacAddress,
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
        })
    }
}

impl DpaInterface {
    pub fn use_admin_network(&self) -> bool {
        self.network_config.use_admin_network.unwrap_or(true)
    }

    pub fn managed_host_network_config_version_synced(&self) -> bool {
        let dpa_expected_version = self.network_config.version;
        let dpa_observation = self.network_status_observation.as_ref();

        let dpa_observed_version: ConfigVersion = match dpa_observation {
            Some(network_status) => match network_status.network_config_version {
                Some(version) => version,
                None => return false,
            },
            None => return false,
        };

        dpa_expected_version == dpa_observed_version
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

        let history: Vec<rpc::forge::DpaInterfaceStateHistory> = src
            .history
            .into_iter()
            .sorted_by(
                |s1: &crate::model::dpa_interface::DpaInterfaceStateHistory,
                 s2: &crate::model::dpa_interface::DpaInterfaceStateHistory| {
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
        }
    }
}

/// A record of a past state of a DpaInterface
///
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct DpaInterfaceStateHistory {
    /// The UUID of the dpa interface that experienced the state change
    interface_id: DpaInterfaceId,

    /// The state that was entered
    pub state: String,
    pub state_version: ConfigVersion,

    /// The timestamp of the state change
    timestamp: DateTime<Utc>,
}

impl From<DpaInterfaceStateHistory> for rpc::forge::DpaInterfaceStateHistory {
    fn from(value: DpaInterfaceStateHistory) -> Self {
        rpc::forge::DpaInterfaceStateHistory {
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
    #[serde(default)]
    pub history: Vec<DpaInterfaceStateHistory>,
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
            history: value.history,
        })
    }
}
