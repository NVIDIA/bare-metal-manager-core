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

use serde::{Deserialize, Serialize};

use crate::db::ib_partition::IBPartition;
use crate::ib::types::{IBNetwork, IBNETWORK_DEFAULT_INDEX0, IBNETWORK_DEFAULT_MEMBERSHIP};

pub const IB_DEFAULT_MTU: i32 = 2048;
pub const IB_MTU_ENV: &str = "IB_DEFAULT_MTU";
pub const IB_DEFAULT_RATE_LIMIT: i32 = 100;
pub const IB_RATE_LIMIT_ENV: &str = "IB_DEFAULT_RATE_LIMIT";
pub const IB_DEFAULT_SERVICE_LEVEL: i32 = 0;
pub const IB_SERVICE_LEVEL_ENV: &str = "IB_DEFAULT_SERVICE_LEVEL";

/// State of a IB subnet as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum IBPartitionControllerState {
    /// The IB subnet is created in Carbide, waiting for provisioning in IB Fabric.
    Provisioning,
    /// The IB subnet is ready for IB ports.
    Ready,
    /// There is error in IB subnet; IB ports can not be added into IB subnet if it's error.
    Error { cause: String },
    /// The IB subnet is in the process of deleting.
    Deleting,
}

impl From<&IBPartition> for IBNetwork {
    fn from(ib: &IBPartition) -> IBNetwork {
        Self {
            name: ib.config.name.clone(),
            pkey: ib.config.pkey.unwrap_or(0) as i32,
            enable_sharp: false,
            mtu: ib.config.mtu as u16,
            ipoib: true,
            service_level: ib.config.service_level as u8,
            membership: IBNETWORK_DEFAULT_MEMBERSHIP,
            index0: IBNETWORK_DEFAULT_INDEX0,
            rate_limit: ib.config.rate_limit as f64,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_controller_state() {
        let state = IBPartitionControllerState::Provisioning {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"provisioning\"}");
        assert_eq!(
            serde_json::from_str::<IBPartitionControllerState>(&serialized).unwrap(),
            state
        );
        let state = IBPartitionControllerState::Ready {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"ready\"}");
        assert_eq!(
            serde_json::from_str::<IBPartitionControllerState>(&serialized).unwrap(),
            state
        );
        let state = IBPartitionControllerState::Error {
            cause: "cause goes here".to_string(),
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, r#"{"state":"error","cause":"cause goes here"}"#);
        assert_eq!(
            serde_json::from_str::<IBPartitionControllerState>(&serialized).unwrap(),
            state
        );
        let state = IBPartitionControllerState::Deleting {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"deleting\"}");
        assert_eq!(
            serde_json::from_str::<IBPartitionControllerState>(&serialized).unwrap(),
            state
        );
    }
}
