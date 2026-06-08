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

use carbide_libmlx_model::device::info::MlxDeviceInfo;
use carbide_libmlx_model::firmware::result::FirmwareFlashReport;
use carbide_uuid::dpa_interface::DpaInterfaceId;
use carbide_uuid::machine::MachineId;
use carbide_uuid::spx::NULL_SPX_PARTITION_ID;
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};

use crate::StateSla;
use crate::controller_outcome::PersistentStateHandlerOutcome;
use crate::instance::snapshot::InstanceSnapshot;
use crate::machine::spx::MachineSpxStatusObservation;
use crate::state_history::StateHistoryRecord;

mod slas;

/// Interface type for the DPA interface
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "dpa_interface_type")]
pub enum DpaInterfaceType {
    Svpc,
    Astra,
}

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
    /// Apply firmware to the SuperNIC, in which we will send down
    /// a FirmwareFlasherProfile matching the device P/N + PSID,
    /// with the target version. We may also send down a "None"
    /// profile, which is effectively a noop; scout will report
    /// back saying it successfully applied nothing.
    ///
    /// The API can also choose to just skip to the ApplyProfile
    /// state in the case of there being None to send to scout,
    /// but scout is expected to successfully reply "Ok" if it
    /// gets a None.
    ApplyFirmware,
    /// Apply mlx profile
    ApplyProfile,
    /// Lock the card
    Locking,
    /// The Dpa Interface has been configured with a non-zero VNI
    Assigned,
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

    #[serde(default)]
    // firmware_report contains the latest FirmwareFlashReport as
    // fed back from scout after receiving a FirmwareFlashProfile
    // to apply as part of the ApplyFirmware state + OpCode
    // workflow. This report will let us know if the firmware
    // flash occurred, as well as a number of optional bits
    // of feedback (e.g. if a reset was configured, did it happen,
    // if a version verification was configured, did it happen,
    // etc). This is useful for metrics, verification, and general
    // transparency via logging or other mechanisms.
    pub firmware_report: Option<FirmwareFlashReport>,
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
        DpaInterfaceControllerState::ApplyFirmware => {
            StateSla::with_sla(slas::APPLY_FIRMWARE, time_in_state)
        }
        DpaInterfaceControllerState::ApplyProfile => {
            StateSla::with_sla(slas::APPLY_PROFILE, time_in_state)
        }
        DpaInterfaceControllerState::Unlocking => {
            StateSla::with_sla(slas::UNLOCKING, time_in_state)
        }
        DpaInterfaceControllerState::Assigned => StateSla::no_sla(),
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

    pub card_state: Option<CardState>,

    // device_info and its corresponding timestamp are used to
    // keep track of the latest MlxDeviceInfo received by scout
    // for the target Mellanox device. This contains information
    // like the part number, PSID, firmware version(s), MAC address,
    // etc. We store the received timestamp alongside it to detect
    // if we're acting on potentially stale MlxDeviceInfo data.
    pub device_info: Option<MlxDeviceInfo>,
    pub device_info_ts: Option<DateTime<Utc>>,

    // mlxconfig_profile is the name of an MlxConfigProfile from
    // the mlx-config-profiles config map. When set, this profile
    // will be applied to the device during the ApplyProfile state.
    // When None, ApplyProfile will simply perform an mlxconfig
    // reset and not apply any subsequent defaults, ensuring the
    // card is back to stock before the next tenancy.
    pub mlxconfig_profile: Option<String>,

    pub history: Vec<StateHistoryRecord>,

    pub device_description: Option<String>,

    pub interface_type: DpaInterfaceType,
}

#[derive(Clone, Debug)]
pub struct NewDpaInterface {
    pub machine_id: MachineId,
    pub mac_address: MacAddress,
    pub device_type: String,
    pub pci_name: String,
    pub device_description: Option<String>,
    pub interface_type: DpaInterfaceType,
}

impl NewDpaInterface {
    /// from_device_info builds a NewDpaInterface instance for a given
    /// MachineId from a given MlxDeviceInfo, since it contains everything
    /// we use as input for an interface.
    ///
    /// Right now the only reason this would fail is if base_mac was unset,
    /// at which point we'll just return None, meaning the caller knows that
    /// the base_mac was unset. Since the mac_address is the latter half of
    /// what is effectively a (machine_id, mac_address) compound primary key,
    /// it's kind of important to have.
    pub fn from_device_info(
        machine_id: MachineId,
        base_mac: Option<MacAddress>,
        device_type: String,
        pci_name: String,
        device_description: Option<String>,
        interface_type: DpaInterfaceType,
    ) -> Option<Self> {
        Some(Self {
            machine_id,
            mac_address: base_mac?,
            device_type,
            pci_name,
            device_description,
            interface_type,
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

    // If the DPA machine is an instance, the config version sent to the card will
    // the spx_config_version of the instance.
    // If the DPA machine is a managed host, the config version sent to the card will
    // be the network_config.version of the DPA interface.
    pub fn managed_host_network_config_version_synced(
        &self,
        instance: &Option<InstanceSnapshot>,
        spx_status_observation: &Option<MachineSpxStatusObservation>,
    ) -> bool {
        let mut dpa_expected_version = self.network_config.version;

        // If we haven't yet seen any observations, we are not synced
        let Some(spx_status_observation) = spx_status_observation else {
            tracing::info!(
                "DPA interface {dpa_id} is not synced because no SPX status observation is available",
                dpa_id = self.id
            );
            return false;
        };

        // If there is an instance, and the instance has SPX attachments,
        // and one of the attachments matches our mac address and has a non-zero partition ID,
        // then the DPA expected version should be the instance's SPX config version.
        if let Some(instance) = instance
            && instance
                .config
                .spxconfig
                .spx_attachments
                .iter()
                .any(|attachment| {
                    attachment.mac_address.as_deref().unwrap_or_default()
                        == self.mac_address.to_string()
                        && attachment.spx_partition_id != NULL_SPX_PARTITION_ID
                })
        {
            dpa_expected_version = instance.spx_config_version;
        }

        for obs in spx_status_observation.spx_attachments.iter() {
            if obs.mac_address == self.mac_address
                && let Some(config_version) = obs.config_version
            {
                if config_version != dpa_expected_version {
                    tracing::info!(
                        "DPA interface {dpa_id} is not synced version mismatch: {config_version} != {dpa_expected_version}",
                        dpa_id = self.id,
                        config_version = config_version,
                        dpa_expected_version = dpa_expected_version
                    );
                    return false;
                }
                return true;
            }
        }

        tracing::info!(
            "DPA interface {dpa_id} is not synced verrsion mismatch: {dpa_expected_version}",
            dpa_id = self.id,
            dpa_expected_version = dpa_expected_version
        );

        false
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
    pub card_state: Option<CardState>,
    pub pci_name: String,
    pub underlay_ip: Option<IpAddr>,
    pub overlay_ip: Option<IpAddr>,
    #[serde(default, alias = "device_info_report")]
    pub device_info: Option<MlxDeviceInfo>,
    #[serde(default, alias = "device_info_report_ts")]
    pub device_info_ts: Option<DateTime<Utc>>,
    #[serde(default)]
    pub mlxconfig_profile: Option<String>,
    #[serde(default)]
    pub history: Vec<StateHistoryRecord>,
    #[serde(default)]
    pub device_description: Option<String>,
    pub interface_type: DpaInterfaceType,
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
            card_state: value.card_state,
            device_info: value.device_info,
            device_info_ts: value.device_info_ts,
            mlxconfig_profile: value.mlxconfig_profile,
            history: value.history,
            pci_name: value.pci_name,
            underlay_ip: value.underlay_ip,
            overlay_ip: value.overlay_ip,
            device_description: value.device_description,
            interface_type: value.interface_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    #[test]
    fn from_device_info_extracts_fields() {
        let machine_id =
            MachineId::from_str("fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30")
                .unwrap();

        let base_mac = MacAddress::from_str("00:11:22:33:44:55").unwrap();
        let device_type = "BlueField3".to_string();
        let pci_name = "01:00.0".to_string();
        let device_description = Some("SuperNIC".to_string());
        let interface_type = DpaInterfaceType::Svpc;

        let new_intf = NewDpaInterface::from_device_info(
            machine_id,
            Some(base_mac),
            device_type,
            pci_name,
            device_description,
            interface_type,
        )
        .unwrap();
        assert_eq!(new_intf.machine_id, machine_id);
        assert_eq!(
            new_intf.mac_address,
            MacAddress::from_str("00:11:22:33:44:55").unwrap()
        );
        assert_eq!(new_intf.device_type, "BlueField3");
        assert_eq!(new_intf.pci_name, "01:00.0");
    }

    #[test]
    fn from_device_info_returns_none_without_base_mac() {
        let machine_id =
            MachineId::from_str("fm100htes3rn1npvbtm5qd57dkilaag7ljugl1llmm7rfuq1ov50i0rpl30")
                .unwrap();
        let base_mac = None;
        let device_type = "BlueField3".to_string();
        let pci_name = "01:00.0".to_string();
        let device_description = None;
        let interface_type = DpaInterfaceType::Svpc;

        assert!(
            NewDpaInterface::from_device_info(
                machine_id,
                base_mac,
                device_type,
                pci_name,
                device_description,
                interface_type
            )
            .is_none()
        );
    }

    #[test]
    fn serialize_controller_state() {
        // Make sure the Provisioning state serializes to/from "provisioning".
        let state = DpaInterfaceControllerState::Provisioning {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"provisioning\"}");
        assert_eq!(
            serde_json::from_str::<DpaInterfaceControllerState>(&serialized).unwrap(),
            state
        );

        // Make sure the Ready state serializes to/from "ready".
        let state = DpaInterfaceControllerState::Ready {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"ready\"}");
        assert_eq!(
            serde_json::from_str::<DpaInterfaceControllerState>(&serialized).unwrap(),
            state
        );

        // Make sure the ApplyFirmware state serializes to/from "applyfirmware".
        let state = DpaInterfaceControllerState::ApplyFirmware;
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"applyfirmware\"}");
        assert_eq!(
            serde_json::from_str::<DpaInterfaceControllerState>(&serialized).unwrap(),
            state
        );
    }
}
