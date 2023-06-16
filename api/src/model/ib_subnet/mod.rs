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

pub const IB_DEFAULT_MTU: i32 = 2048;
pub const IB_MTU_ENV: &str = "IB_DEFAULT_MTU";
pub const IB_DEFAULT_RATE_LIMIT: i32 = 100;
pub const IB_RATE_LIMIT_ENV: &str = "IB_DEFAULT_RATE_LIMIT";
pub const IB_DEFAULT_SERVICE_LEVEL: i32 = 0;
pub const IB_SERVICE_LEVEL_ENV: &str = "IB_DEFAULT_SERVICE_LEVEL";

/// State of a IB subnet as tracked by the controller
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum IBSubnetControllerState {
    /// The IB subnet is created in Carbide, waiting for provisioning in IB Fabric.
    Provisioning,
    /// The IB subnet is ready for IB ports.
    Ready,
    /// There is error in IB subnet; IB ports can not be added into IB subnet if it's error.
    Error,
    /// The IB subnet is in the process of deleting.
    Deleting,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_controller_state() {
        let state = IBSubnetControllerState::Provisioning {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"provisioning\"}");
        assert_eq!(
            serde_json::from_str::<IBSubnetControllerState>(&serialized).unwrap(),
            state
        );
        let state = IBSubnetControllerState::Ready {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"ready\"}");
        assert_eq!(
            serde_json::from_str::<IBSubnetControllerState>(&serialized).unwrap(),
            state
        );
        let state = IBSubnetControllerState::Error {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"error\"}");
        assert_eq!(
            serde_json::from_str::<IBSubnetControllerState>(&serialized).unwrap(),
            state
        );
        let state = IBSubnetControllerState::Deleting {};
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, "{\"state\":\"deleting\"}");
        assert_eq!(
            serde_json::from_str::<IBSubnetControllerState>(&serialized).unwrap(),
            state
        );
    }
}
