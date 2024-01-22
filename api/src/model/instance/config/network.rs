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

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::model::{ConfigValidationError, RpcDataConversionError};

// Specifies whether a network interface is physical network function (PF)
// or a virtual network function
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InterfaceFunctionType {
    Physical = 0,
    Virtual = 1,
}

impl TryFrom<rpc::InterfaceFunctionType> for InterfaceFunctionType {
    type Error = RpcDataConversionError;

    fn try_from(function_type: rpc::InterfaceFunctionType) -> Result<Self, Self::Error> {
        Ok(match function_type {
            rpc::InterfaceFunctionType::Physical => InterfaceFunctionType::Physical,
            rpc::InterfaceFunctionType::Virtual => InterfaceFunctionType::Virtual,
        })
    }
}

impl From<InterfaceFunctionType> for rpc::InterfaceFunctionType {
    fn from(function_type: InterfaceFunctionType) -> rpc::InterfaceFunctionType {
        match function_type {
            InterfaceFunctionType::Physical => rpc::InterfaceFunctionType::Physical,
            InterfaceFunctionType::Virtual => rpc::InterfaceFunctionType::Virtual,
        }
    }
}

/// Uniquely identifies an interface on the instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash)]
#[serde(tag = "type")]
pub enum InterfaceFunctionId {
    #[serde(rename = "physical")]
    Physical {
        // This might later on also contain the DPU ID
    },
    #[serde(rename = "virtual")]
    Virtual {
        /// Uniquely identifies the VF on a DPU
        ///
        /// The first VF assigned to a host must use ID 1.
        /// All other IDs need to be consecutively assigned.
        id: u8,
        // This might later on also contain the DPU ID
    },
}

impl InterfaceFunctionId {
    /// Returns an iterator that yields all valid InterfaceFunctionIds
    ///
    /// The first returned item is the `Physical`.
    /// Then the list of `Virtual`s will follow
    pub fn iter_all() -> impl Iterator<Item = InterfaceFunctionId> {
        debug_assert!(INTERFACE_VFID_MAX <= i32::MAX as usize);

        (-1..=INTERFACE_VFID_MAX as i32).map(|idx| {
            if idx == -1 {
                InterfaceFunctionId::Physical {}
            } else {
                InterfaceFunctionId::Virtual { id: idx as u8 }
            }
        })
    }

    /// Returns whether ID refers to a physical or virtual function
    pub fn function_type(&self) -> InterfaceFunctionType {
        match self {
            InterfaceFunctionId::Physical { .. } => InterfaceFunctionType::Physical,
            InterfaceFunctionId::Virtual { .. } => InterfaceFunctionType::Virtual,
        }
    }

    /// Tries to convert a numeric identifier that represents a virtual function
    /// into a `InterfaceFunctionId::Virtual`.
    /// This will return an error if the ID is not in the valid range.
    pub fn try_virtual_from(id: usize) -> Result<InterfaceFunctionId, InvalidVirtualFunctionId> {
        if !(INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX).contains(&id) {
            return Err(InvalidVirtualFunctionId());
        }

        Ok(InterfaceFunctionId::Virtual { id: id as u8 })
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
                function_id: InterfaceFunctionId::Physical {},
                network_segment_id,
                ip_addrs: HashMap::default(),
            }],
        }
    }

    /// Validates the network configuration
    pub fn validate(&self) -> Result<(), ConfigValidationError> {
        validate_interface_function_ids(&self.interfaces, |iface| iface.function_id.clone())
            .map_err(ConfigValidationError::InvalidValue)?;

        // Note: We can't fully validate the network segment IDs here
        // We validate that the ID is not duplicated, but not whether it actually exists
        // or belongs to the tenant. This validation is currently happening in the
        // cloud API, and when we try to allocate IPs.
        // Multiple interfaces currently can't reference the same segment ID due to
        // how DHCP works. It would be ambiguous during a DHCP request which
        // interface it references, since the interface is resolved by the CircuitId
        // and thereby by the network segment ID
        let mut used_segment_ids = HashSet::new();
        for iface in self.interfaces.iter() {
            if !used_segment_ids.insert(&iface.network_segment_id) {
                return Err(ConfigValidationError::InvalidValue(format!(
                    "Multiple network interfaces use the same network segment {}",
                    iface.network_segment_id
                )));
            }
        }

        Ok(())
    }
}

impl TryFrom<rpc::InstanceNetworkConfig> for InstanceNetworkConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: rpc::InstanceNetworkConfig) -> Result<Self, Self::Error> {
        // try_from for interfaces:
        let mut assigned_vfs: u8 = 0;
        let mut interfaces = Vec::with_capacity(config.interfaces.len());
        for iface in config.interfaces.into_iter() {
            let rpc_iface_type = rpc::InterfaceFunctionType::try_from(iface.function_type)
                .map_err(|_| {
                    RpcDataConversionError::InvalidInterfaceFunctionType(iface.function_type)
                })?;
            let iface_type = InterfaceFunctionType::try_from(rpc_iface_type).map_err(|_| {
                RpcDataConversionError::InvalidInterfaceFunctionType(iface.function_type)
            })?;

            let function_id = match iface_type {
                InterfaceFunctionType::Physical => InterfaceFunctionId::Physical {},
                InterfaceFunctionType::Virtual => {
                    // Note that this might overflow if the RPC call delivers more than
                    // 256 VFs. However that's ok - the `InstanceNetworkConfig.validate()`
                    // call will declare those configs as invalid later on anyway.
                    // We mainly don't want to crash here.
                    let id = InterfaceFunctionId::Virtual { id: assigned_vfs };
                    assigned_vfs = assigned_vfs.saturating_add(1);
                    id
                }
            };

            let network_segment_id =
                iface
                    .network_segment_id
                    .ok_or(RpcDataConversionError::MissingArgument(
                        "InstanceInterfaceConfig::network_segment_id",
                    ))?;
            let network_segment_id = uuid::Uuid::try_from(network_segment_id).map_err(|_| {
                RpcDataConversionError::InvalidUuid("InstanceInterfaceConfig::network_segment_id")
            })?;

            interfaces.push(InstanceInterfaceConfig {
                function_id,
                network_segment_id,
                ip_addrs: HashMap::default(),
            });
        }

        Ok(Self { interfaces })
    }
}

impl TryFrom<InstanceNetworkConfig> for rpc::InstanceNetworkConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: InstanceNetworkConfig) -> Result<rpc::InstanceNetworkConfig, Self::Error> {
        let mut interfaces = Vec::with_capacity(config.interfaces.len());
        for iface in config.interfaces.into_iter() {
            let function_type = iface.function_id.function_type();

            interfaces.push(rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::from(function_type) as i32,
                network_segment_id: Some(iface.network_segment_id.into()),
            });
        }

        Ok(rpc::InstanceNetworkConfig { interfaces })
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
    let mut used_pf = false;
    let mut used_vfids = [false; 32];
    for (idx, iface) in container.iter().enumerate() {
        match get_function_id(iface) {
            InterfaceFunctionId::Physical {} => {
                if used_pf {
                    return Err(format!(
                        "Physical function ID for network interface at index {} is already used",
                        idx
                    ));
                }
                used_pf = true;
            }
            InterfaceFunctionId::Virtual { id } => {
                let id = id as usize;
                if !(INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX).contains(&id) {
                    return Err(format!(
                        "Invalid interface virtual function ID {} for network interface at index {}",
                        id, idx
                    ));
                }
                if used_vfids[id] {
                    return Err(format!(
                        "Virtual function ID {} for network interface at index {} is already used",
                        id, idx
                    ));
                }
                used_vfids[id] = true;
            }
        }

        // Note: We can't validate the network segment ID here
    }

    // Check that there IDs are consecutively assigned and the physical
    // function exists
    if !used_pf {
        return Err("Missing Physical Function".to_string());
    }
    for (id, is_used) in used_vfids.iter().enumerate().take(container.len() - 1) {
        if !is_used {
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
    /// The IP address we allocated for each network prefix for this interface
    /// This is not populated if we have not allocated IP addresses yet.
    pub ip_addrs: HashMap<uuid::Uuid, IpAddr>,
    // TODO: Security group
}

/// Minimum valid value (inclusive) for a virtual function ID
pub const INTERFACE_VFID_MIN: usize = 0;
/// Maximum valid value (inclusive) for a virtual function ID
pub const INTERFACE_VFID_MAX: usize = 15;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterate_function_ids() {
        let func_ids: Vec<InterfaceFunctionId> = InterfaceFunctionId::iter_all().collect();
        assert_eq!(func_ids.len(), 2 + INTERFACE_VFID_MAX - INTERFACE_VFID_MIN);

        assert_eq!(func_ids[0], InterfaceFunctionId::Physical {});
        for (i, func_id) in func_ids[1..].iter().enumerate() {
            assert_eq!(
                *func_id,
                InterfaceFunctionId::Virtual {
                    id: (INTERFACE_VFID_MIN + i) as u8
                }
            );
        }
    }

    #[test]
    fn serialize_function_id() {
        let function_id = InterfaceFunctionId::Physical {};
        let serialized = serde_json::to_string(&function_id).unwrap();
        assert_eq!(serialized, "{\"type\":\"physical\"}");
        assert_eq!(
            serde_json::from_str::<InterfaceFunctionId>(&serialized).unwrap(),
            function_id
        );

        let function_id = InterfaceFunctionId::Virtual { id: 24 };
        let serialized = serde_json::to_string(&function_id).unwrap();
        assert_eq!(serialized, "{\"type\":\"virtual\",\"id\":24}");
        assert_eq!(
            serde_json::from_str::<InterfaceFunctionId>(&serialized).unwrap(),
            function_id
        );
    }

    #[test]
    fn serialize_interface_config() {
        let function_id = InterfaceFunctionId::Physical {};
        let network_segment_id = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200");
        let network_prefix_1 = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1201");
        let mut ip_addrs = HashMap::new();
        ip_addrs.insert(network_prefix_1, "192.168.1.2".parse().unwrap());

        // Test plain serialization without inserting ip addresses. The
        let interface = InstanceInterfaceConfig {
            function_id,
            network_segment_id,
            ip_addrs,
        };
        let serialized = serde_json::to_string(&interface).unwrap();
        assert_eq!(serialized, "{\"function_id\":{\"type\":\"physical\"},\"network_segment_id\":\"91609f10-c91d-470d-a260-6293ea0c1200\",\"ip_addrs\":{\"91609f10-c91d-470d-a260-6293ea0c1201\":\"192.168.1.2\"}}");

        assert_eq!(
            serde_json::from_str::<InstanceInterfaceConfig>(&serialized).unwrap(),
            interface
        );
    }

    /// Creates a valid instance network configuration using the maximum
    /// amount of interface
    const BASE_SEGMENT_ID: uuid::Uuid = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c0000");
    fn offset_segment_id(offset: usize) -> uuid::Uuid {
        Uuid::from_u128(BASE_SEGMENT_ID.as_u128() + offset as u128)
    }

    fn create_valid_network_config() -> InstanceNetworkConfig {
        let interfaces: Vec<InstanceInterfaceConfig> = InterfaceFunctionId::iter_all()
            .enumerate()
            .map(|(idx, function_id)| {
                let network_segment_id = offset_segment_id(idx);
                InstanceInterfaceConfig {
                    function_id,
                    network_segment_id,
                    ip_addrs: HashMap::default(),
                }
            })
            .collect();

        InstanceNetworkConfig { interfaces }
    }

    #[test]
    fn assign_ids_from_rpc_config_pf_only() {
        let config = rpc::InstanceNetworkConfig {
            interfaces: vec![rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as _,
                network_segment_id: Some(BASE_SEGMENT_ID.into()),
            }],
        };

        let netconfig: InstanceNetworkConfig = config.try_into().unwrap();
        assert_eq!(
            netconfig.interfaces,
            &[InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::Physical {},
                network_segment_id: BASE_SEGMENT_ID,
                ip_addrs: HashMap::new(),
            }]
        );
    }

    #[test]
    fn assign_ids_from_rpc_config_pf_and_vf() {
        let mut interfaces = vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as _,
            network_segment_id: Some(BASE_SEGMENT_ID.into()),
        }];
        for vfid in INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX {
            interfaces.push(rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as _,
                network_segment_id: Some(offset_segment_id(vfid + 1).into()),
            });
        }

        let config = rpc::InstanceNetworkConfig { interfaces };

        let netconfig: InstanceNetworkConfig = config.try_into().unwrap();
        let mut expected_interfaces = vec![InstanceInterfaceConfig {
            function_id: InterfaceFunctionId::Physical {},
            network_segment_id: BASE_SEGMENT_ID,
            ip_addrs: HashMap::new(),
        }];

        for vfid in INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX {
            expected_interfaces.push(InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::Virtual { id: vfid as u8 },
                network_segment_id: offset_segment_id(vfid + 1),
                ip_addrs: HashMap::new(),
            });
        }
        assert_eq!(netconfig.interfaces, &expected_interfaces[..]);
    }

    #[test]
    fn validate_network_config() {
        create_valid_network_config().validate().unwrap();

        // Duplicate virtual function
        let mut config = create_valid_network_config();
        config.interfaces[2].function_id = InterfaceFunctionId::Virtual { id: 0 };
        assert!(config.validate().is_err());

        // Out of bounds virtual function
        let mut config = create_valid_network_config();
        config.interfaces[2].function_id = InterfaceFunctionId::Virtual { id: 16 };
        assert!(config.validate().is_err());

        // No physical function
        let mut config = create_valid_network_config();
        config.interfaces.swap_remove(0);
        assert!(config.validate().is_err());

        // Missing virtual functions (except the last)
        for idx in 1..=INTERFACE_VFID_MAX {
            let mut config = create_valid_network_config();
            config.interfaces.swap_remove(idx);
            assert!(config.validate().is_err());
        }

        // The last virtual function is ok to be missing
        let mut config = create_valid_network_config();
        config.interfaces.swap_remove(INTERFACE_VFID_MAX + 1);
        config.validate().unwrap();

        // Duplicate network segment
        const DUPLICATE_SEGMENT_ID: uuid::Uuid =
            uuid::uuid!("91609f10-c91d-470d-a260-1234560c0000");
        let mut config = create_valid_network_config();
        config.interfaces[0].network_segment_id = DUPLICATE_SEGMENT_ID;
        config.interfaces[1].network_segment_id = DUPLICATE_SEGMENT_ID;
        assert!(config.validate().is_err());
    }
}
