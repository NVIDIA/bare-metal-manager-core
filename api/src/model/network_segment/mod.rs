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
    /// The network segment is in provisioning state until all prefixes have
    /// been created on VPC.
    Provisioning,
    /// The network segment is ready. Instances can be created
    Ready,
    /// The network segment is in the process of deleting.
    /// This includes waiting for a grace period, and then deleting the associated
    /// ResourceGroup CRDs.
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
    /// In this state we delete ResourceGroups on VPC
    /// Once all resourcegroups have been deleted, the prefixes and networksegment
    /// can be deleted. Therefore this is the final state.
    DeleteVPCResourceGroups,
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
