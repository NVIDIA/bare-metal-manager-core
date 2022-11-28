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

use crate::model::{ConfigValidationError, RpcDataConversionError};

// Specifies whether a network interface is physical network function (PF)
// or a virtual network function
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterfaceFunctionType {
    PhysicalFunction = 0,
    VirtualFunction = 1,
}

impl TryFrom<rpc::InterfaceFunctionType> for InterfaceFunctionType {
    type Error = RpcDataConversionError;

    fn try_from(function_type: rpc::InterfaceFunctionType) -> Result<Self, Self::Error> {
        Ok(match function_type {
            rpc::InterfaceFunctionType::PhysicalFunction => InterfaceFunctionType::PhysicalFunction,
            rpc::InterfaceFunctionType::VirtualFunction => InterfaceFunctionType::VirtualFunction,
        })
    }
}

impl From<InterfaceFunctionType> for rpc::InterfaceFunctionType {
    fn from(function_type: InterfaceFunctionType) -> rpc::InterfaceFunctionType {
        match function_type {
            InterfaceFunctionType::PhysicalFunction => rpc::InterfaceFunctionType::PhysicalFunction,
            InterfaceFunctionType::VirtualFunction => rpc::InterfaceFunctionType::VirtualFunction,
        }
    }
}

/// Uniquely identifies an interface on the instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
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

impl InterfaceFunctionId {
    // Returns String that will be used to represent FunctionId in kubernetes.
    pub fn kube_representation(&self) -> String {
        match self {
            InterfaceFunctionId::PhysicalFunctionId {} => "pf".to_string(),
            InterfaceFunctionId::VirtualFunctionId { id } => format!("vf-{}", id),
        }
    }

    /// Returns whether ID refers to a physical or virtual function
    pub fn function_type(&self) -> InterfaceFunctionType {
        match self {
            InterfaceFunctionId::PhysicalFunctionId { .. } => {
                InterfaceFunctionType::PhysicalFunction
            }
            InterfaceFunctionId::VirtualFunctionId { .. } => InterfaceFunctionType::VirtualFunction,
        }
    }

    /// Tries to convert a numeric identifier that represents a virtual function
    /// into a `InterfaceFunctionId::VirtualFunctionId`.
    /// This will return an error if the ID is not in the valid range.
    pub fn try_virtual_from(id: usize) -> Result<InterfaceFunctionId, InvalidVirtualFunctionId> {
        if !(INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX).contains(&id) {
            return Err(InvalidVirtualFunctionId());
        }

        Ok(InterfaceFunctionId::VirtualFunctionId { id: id as u8 })
    }
}

/// An ID is not a valid virtual function ID due to being out of bounds
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct InvalidVirtualFunctionId();

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

    /// Validates the network configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_interface_function_ids(&self.interfaces, |iface| iface.function_id.clone())
            .map_err(ConfigValidationError::InvalidValue)?;

        Ok(())
    }
}

/// Validates that any container which has elements that have InterfaceFunctionIds
/// assigned assigned is using unique and valid FunctionIds.
pub fn validate_interface_function_ids<T, F: Fn(&T) -> InterfaceFunctionId>(
    container: &Vec<T>,
    get_function_id: F,
) -> Result<(), String> {
    if container.is_empty() {
        return Err("InstanceNetworkConfig.interfaces is empty".to_string());
    }

    // We need 1 physical interface, virtual interfaces must start at VFID 1,
    // and IDs must not be duplicated
    let mut used_ids = [false; 32];
    for (idx, iface) in container.iter().enumerate() {
        let id = match get_function_id(iface) {
            InterfaceFunctionId::PhysicalFunctionId {} => 0,
            InterfaceFunctionId::VirtualFunctionId { id } => {
                let id = id as usize;
                if !(INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX).contains(&id) {
                    return Err(format!(
                        "Invalid interface function ID {} for network interface at index {}",
                        id, idx
                    ));
                }
                id
            }
        };

        if used_ids[id] {
            return Err(format!(
                "Interface function ID {} for network interface at index {} is already used",
                id, idx
            ));
        }
        used_ids[id] = true;

        // Note: We can't validate the network segment ID here
    }

    // Check that there IDs are consecutively assigned and the physical
    // function exists
    for (id, is_used) in used_ids.iter().enumerate().take(container.len()) {
        if !is_used {
            if id == 0 {
                return Err("Missing Physical Function".to_string());
            }

            return Err(format!("Missing Virtual function with ID {}", id,));
        }
    }

    Ok(())
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

/// Minimum valid value (inclusive) for a virtual function ID
pub const INTERFACE_VFID_MIN: usize = 1;
/// Maximum valid value (inclusive) for a virtual function ID
pub const INTERFACE_VFID_MAX: usize = 16;

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

    /// Creats a valid instance network configuration using the maximum
    /// amount of interface
    fn create_valid_network_config() -> InstanceNetworkConfig {
        let base_segment_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c0000");

        let interfaces: Vec<InstanceInterfaceConfig> = (0..=INTERFACE_VFID_MAX)
            .map(|idx| {
                let function_id = if idx == 0 {
                    InterfaceFunctionId::PhysicalFunctionId {}
                } else {
                    InterfaceFunctionId::VirtualFunctionId { id: idx as u8 }
                };

                let network_segment_id = Uuid::from_u128(base_segment_id.as_u128() + idx as u128);
                InstanceInterfaceConfig {
                    function_id,
                    network_segment_id,
                }
            })
            .collect();

        InstanceNetworkConfig { interfaces }
    }

    #[test]
    fn validate_network_config() {
        create_valid_network_config().validate().unwrap();

        // Duplicate virtual function
        let mut config = create_valid_network_config();
        config.interfaces[2].function_id = InterfaceFunctionId::VirtualFunctionId { id: 1 };
        assert!(config.validate().is_err());

        // Out of bounds virtual function
        let mut config = create_valid_network_config();
        config.interfaces[2].function_id = InterfaceFunctionId::VirtualFunctionId { id: 17 };
        assert!(config.validate().is_err());

        // No physical function
        let mut config = create_valid_network_config();
        config.interfaces.swap_remove(0);
        assert!(config.validate().is_err());

        // Missing virtual functions (except the last)
        for idx in 1..INTERFACE_VFID_MAX {
            let mut config = create_valid_network_config();
            config.interfaces.swap_remove(idx);
            assert!(config.validate().is_err());
        }

        // The last virtual function is ok to be missing
        let mut config = create_valid_network_config();
        config.interfaces.swap_remove(INTERFACE_VFID_MAX);
        config.validate().unwrap();
    }
}
