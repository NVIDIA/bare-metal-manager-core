/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

/// State of a network segment as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum NetworkSegmentControllerState {
    Provisioning,
    /// The network segment is ready. Instances can be created
    Ready,
    /// The network segment is in the process of being deleted.
    Deleting {
        deletion_state: NetworkSegmentDeletionState,
    },
}

/// Possible states during deletion of a network segment
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum NetworkSegmentDeletionState {
    /// The segment is waiting until all IPs that had been allocated on the segment
    /// have been released - plus an additional grace period to avoid any race
    /// conditions.
    DrainAllocatedIps {
        /// Denotes the time at which the network segment will be deleted,
        /// assuming no IPs are detected to be in use until then.
        delete_at: DateTime<Utc>,
    },
    /// In this state we release the VNI and VLAN ID allocations and delete the segment from the
    /// database. This is the final state.
    DBDelete,
}

// How we specifiy a network segment in the config file
#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct NetworkDefinition {
    #[serde(rename = "type")]
    pub segment_type: NetworkDefinitionSegmentType,
    /// CIDR notation
    pub prefix: String,
    /// Usually the first IP in the prefix range
    pub gateway: String,
    /// Typically 9000 for admin network, 1500 for underlay
    pub mtu: i32,
    /// How many addresses to skip before allocating
    pub reserve_first: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDefinitionSegmentType {
    Admin,
    Underlay,
    // Tenant networks are created via the API, not the config file
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_controller_state() {
        let state = NetworkSegmentControllerState::Provisioning {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"provisioning\"}");
        assert_eq!(
            serde_json::from_str::<NetworkSegmentControllerState>(&serialized).unwrap(),
            state
        );

        let state = NetworkSegmentControllerState::Ready {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"ready\"}");
        assert_eq!(
            serde_json::from_str::<NetworkSegmentControllerState>(&serialized).unwrap(),
            state
        );

        let deletion_time: DateTime<Utc> = "2022-12-13T04:41:38Z".parse().unwrap();
        let state = NetworkSegmentControllerState::Deleting {
            deletion_state: NetworkSegmentDeletionState::DrainAllocatedIps {
                delete_at: deletion_time,
            },
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"deleting\",\"deletion_state\":{\"state\":\"drainallocatedips\",\"delete_at\":\"2022-12-13T04:41:38Z\"}}");
        assert_eq!(
            serde_json::from_str::<NetworkSegmentControllerState>(&serialized).unwrap(),
            state
        );
    }
}
