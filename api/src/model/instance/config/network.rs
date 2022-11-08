/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use uuid::Uuid;

/// Uniquely identifies an interface on the instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum InterfaceFunctionId {
    #[serde(rename = "physical")]
    PhysicalFunctionId {
        // This might later on also contain the DPU ID
    },
    #[serde(rename = "virtual")]
    VirtualFunctionId {
        /// Uniquely identifies the VF on a DPU
        ///
        /// The first VF assigned to a host must use ID 1.
        /// All other IDs need to be consecutively assigned.
        id: u8,
        // This might later on also contain the DPU ID
    },
}

/// Desired network configuration for an instance
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceNetworkConfig {
    /// Configures how instance network interfaces are set up
    pub interfaces: Vec<InstanceInterfaceConfig>,
    // TODO: Security group
}

impl InstanceNetworkConfig {
    /// Returns a network configuration for a single physical interface
    pub fn for_segment_id(network_segment_id: Uuid) -> Self {
        Self {
            interfaces: vec![InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::PhysicalFunctionId {},
                network_segment_id,
            }],
        }
    }
}

/// The configuration that a customer desires for an instances network interface
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceInterfaceConfig {
    /// Uniquely identifies the interface on the instance
    pub function_id: InterfaceFunctionId,
    /// The network segment this interface is attached to
    pub network_segment_id: Uuid,
    // TODO: Security group
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialize_function_id() {
        let function_id = InterfaceFunctionId::PhysicalFunctionId {};
        let serialized = serde_json::to_string(&function_id).unwrap();
        assert_eq!(serialized, "{\"type\":\"physical\"}");
        assert_eq!(
            serde_json::from_str::<InterfaceFunctionId>(&serialized).unwrap(),
            function_id
        );

        let function_id = InterfaceFunctionId::VirtualFunctionId { id: 24 };
        let serialized = serde_json::to_string(&function_id).unwrap();
        assert_eq!(serialized, "{\"type\":\"virtual\",\"id\":24}");
        assert_eq!(
            serde_json::from_str::<InterfaceFunctionId>(&serialized).unwrap(),
            function_id
        );
    }

    #[test]
    fn serialize_interface_config() {
        let function_id = InterfaceFunctionId::PhysicalFunctionId {};
        let network_segment_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");
        let interface = InstanceInterfaceConfig {
            function_id,
            network_segment_id,
        };

        let serialized = serde_json::to_string(&interface).unwrap();
        assert_eq!(serialized, "{\"function_id\":{\"type\":\"physical\"},\"network_segment_id\":\"91609f10-c91d-470d-a260-6293ea0c1200\"}");
        assert_eq!(
            serde_json::from_str::<InstanceInterfaceConfig>(&serialized).unwrap(),
            interface
        );
    }
}
