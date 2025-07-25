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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The infiniband status that was last reported by the networking subsystem
/// Stored in a Postgres JSON field
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineInfinibandStatusObservation {
    /// Observed status for each configured interface
    #[serde(default)]
    pub ib_interfaces: Vec<MachineIbInterfaceStatusObservation>,

    /// When this status was observed
    pub observed_at: DateTime<Utc>,
}

/// The infiniband interface status that was last reported by the infiniband subsystem
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineIbInterfaceStatusObservation {
    /// The GUID whose status has been monitored
    pub guid: String,
    /// The ocal Identifier observed from UFM. This is set to 0xffff if no status
    /// could be retrieved or if the port is not reported as Active.
    pub lid: u16,
    /// The ID of the fabric on which the GUID has been observed
    /// This is empty if the GUID hasn't been observed on any fabric
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fabric_id: String,
}

impl From<MachineInfinibandStatusObservation> for rpc::forge::InfinibandStatusObservation {
    fn from(
        ib_status: MachineInfinibandStatusObservation,
    ) -> rpc::forge::InfinibandStatusObservation {
        rpc::forge::InfinibandStatusObservation {
            ib_interfaces: ib_status
                .ib_interfaces
                .into_iter()
                .map(|interface| interface.into())
                .collect(),
            observed_at: Some(ib_status.observed_at.into()),
        }
    }
}

impl From<MachineIbInterfaceStatusObservation> for rpc::forge::MachineIbInterface {
    fn from(
        machine_ib_interface: MachineIbInterfaceStatusObservation,
    ) -> rpc::forge::MachineIbInterface {
        rpc::forge::MachineIbInterface {
            pf_guid: None,
            guid: Some(machine_ib_interface.guid),
            lid: Some(machine_ib_interface.lid as u32),
            fabric_id: match machine_ib_interface.fabric_id.is_empty() {
                true => None,
                false => Some(machine_ib_interface.fabric_id),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_legacy_ib_status_observation() {
        let obs1 = r#"{"observed_at": "2024-12-18T23:17:57.919166804Z", "ib_interfaces": []}"#;
        let _deserialized: MachineInfinibandStatusObservation = serde_json::from_str(obs1).unwrap();

        let obs2 = r#"{"observed_at": "2025-06-06T19:47:16.597282585Z", "ib_interfaces": [{"lid": 65535, "guid": "1070fd0300bd7574"}, {"lid": 65535, "guid": "1070fd0300bd7575"}]}"#;
        let _deserialized: MachineInfinibandStatusObservation = serde_json::from_str(obs2).unwrap();
    }
}
