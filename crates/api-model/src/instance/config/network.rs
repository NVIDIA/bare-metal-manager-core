/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::net::IpAddr;

use ::rpc::errors::RpcDataConversionError;
use carbide_uuid::machine::MachineId;
use carbide_uuid::network::{NetworkPrefixId, NetworkSegmentId};
use carbide_uuid::vpc::VpcPrefixId;
use ipnetwork::IpNetwork;
use itertools::Itertools;
use mac_address::MacAddress;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::ConfigValidationError;

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
    pub fn try_virtual_from(id: u8) -> Result<InterfaceFunctionId, InvalidVirtualFunctionId> {
        if !(INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX).contains(&id) {
            return Err(InvalidVirtualFunctionId());
        }

        Ok(InterfaceFunctionId::Virtual { id })
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
}

/// Struct to store instance network config updated request with current config.
/// Current config is kept here to release these resources once instance moves to the new network
/// resources.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceNetworkConfigUpdate {
    // Current configuration which will be deallocated.
    // If any interface is present in requested config with same network details and function id,
    // that should be removed from the old config and must not be deallocated.
    pub old_config: InstanceNetworkConfig,

    // New requested config.
    pub new_config: InstanceNetworkConfig,
}

impl InstanceNetworkConfig {
    /// Returns a network configuration for a single physical interface
    pub fn for_segment_ids(
        network_segment_ids: &[NetworkSegmentId],
        device_locators: &[DeviceLocator],
    ) -> Self {
        if device_locators.is_empty() {
            Self {
                interfaces: vec![InstanceInterfaceConfig {
                    function_id: InterfaceFunctionId::Physical {},
                    network_segment_id: network_segment_ids.first().copied(),
                    network_details: Some(NetworkDetails::NetworkSegment(
                        network_segment_ids.first().copied().unwrap(),
                    )),
                    ip_addrs: HashMap::default(),
                    interface_prefixes: HashMap::default(),
                    network_segment_gateways: HashMap::default(),
                    host_inband_mac_address: None,
                    device_locator: None,
                    internal_uuid: uuid::Uuid::nil(),
                }],
            }
        } else {
            Self {
                interfaces: device_locators
                    .iter()
                    .enumerate()
                    .map(|(dl_index, dl)| InstanceInterfaceConfig {
                        function_id: InterfaceFunctionId::Physical {},
                        network_segment_id: network_segment_ids.get(dl_index).copied(),
                        network_details: Some(NetworkDetails::NetworkSegment(
                            network_segment_ids[dl_index],
                        )),
                        ip_addrs: HashMap::default(),
                        interface_prefixes: HashMap::default(),
                        network_segment_gateways: HashMap::default(),
                        host_inband_mac_address: None,
                        device_locator: Some(dl.clone()),
                        internal_uuid: uuid::Uuid::nil(),
                    })
                    .collect(),
            }
        }
    }

    /// Returns a network configuration for a single physical interface
    pub fn for_vpc_prefix_id(
        vpc_prefix_id: VpcPrefixId,
        _dpu_machine_id: Option<MachineId>,
    ) -> Self {
        Self {
            interfaces: vec![InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::Physical {},
                network_segment_id: None,
                network_details: Some(NetworkDetails::VpcPrefixId(vpc_prefix_id)),
                ip_addrs: HashMap::default(),
                interface_prefixes: HashMap::default(),
                network_segment_gateways: HashMap::default(),
                host_inband_mac_address: None,
                device_locator: None,
                internal_uuid: uuid::Uuid::nil(),
            }],
        }
    }

    /// Validates the network configuration
    pub fn validate(&self, allow_instance_vf: bool) -> Result<(), ConfigValidationError> {
        if !allow_instance_vf
            && self
                .interfaces
                .iter()
                .any(|i| matches!(i.function_id, InterfaceFunctionId::Virtual { .. }))
        {
            return Err(ConfigValidationError::InvalidValue(
                "Virtual functions are disabled by site configuration".to_string(),
            ));
        }

        validate_interface_function_ids(
            &self.interfaces,
            |iface| &iface.function_id,
            |iface| iface.device_locator.as_ref(),
        )
        .map_err(ConfigValidationError::InvalidValue)?;

        // Note: We can't fully validate the network segment IDs here
        // We validate that the ID is not duplicated, but not whether it actually exists
        // or belongs to the tenant. This validation is currently happening in the
        // cloud API, and when we try to allocate IPs.
        //
        // Multiple interfaces currently can't reference the same segment ID due to
        // how DHCP works. It would be ambiguous during a DHCP request which
        // interface it references, since the interface is resolved by the CircuitId
        // and thereby by the network segment ID
        let mut used_segment_ids = HashSet::new();
        for iface in self.interfaces.iter() {
            let Some(network_segment_id) = &iface.network_segment_id else {
                return Err(ConfigValidationError::MissingSegment(
                    iface.function_id.clone(),
                ));
            };

            if !used_segment_ids.insert(network_segment_id) {
                return Err(ConfigValidationError::InvalidValue(format!(
                    "Multiple network interfaces use the same network segment {network_segment_id}"
                )));
            }

            // Verify the list of network prefix IDs between the interface
            // IP addresses and interface prefix allocations match. There
            // should be a 1:1 correlation, as in, for network prefix ID XYZ,
            // there should be an entry in `ip_addrs` and `instance_prefixes`.
            //
            // TODO(chet): Only do this if there are actual prefixes set for
            // this interface. If there aren't, its because this is an old
            // instance which existed prior to introducing instance_prefixes.
            // Once all instances are configured with prefixes, then there's
            // no need for an empty check.
            if iface.interface_prefixes.keys().len() > 0
                && iface
                    .ip_addrs
                    .keys()
                    .collect::<std::collections::HashSet<_>>()
                    != iface
                        .interface_prefixes
                        .keys()
                        .collect::<std::collections::HashSet<_>>()
            {
                return Err(ConfigValidationError::NetworkPrefixAllocationMismatch);
            }
        }

        Ok(())
    }

    pub fn verify_update_allowed_to(
        &self,
        _new_config: &Self,
    ) -> Result<(), ConfigValidationError> {
        Ok(())
    }

    pub fn is_network_config_update_requested(&self, new_config: &Self) -> bool {
        // Remove all service-generated properties before validating the config
        let mut current = self.clone();
        let mut new_config = new_config.clone();
        for iface in &mut current.interfaces {
            iface.ip_addrs.clear();
            iface.interface_prefixes.clear();
            iface.network_segment_gateways.clear();
            iface.host_inband_mac_address = None;
            iface.internal_uuid = uuid::Uuid::nil();

            // It is possible that cloud sends network_segment_id with network_details as well.
            if iface.network_details.is_some() {
                iface.network_segment_id = None;
            }
        }

        for iface in &mut new_config.interfaces {
            // It is possible that cloud sends network_segment_id with network_details as well.
            if iface.network_details.is_some() {
                iface.network_segment_id = None;
            }
            iface.internal_uuid = uuid::Uuid::nil();
        }

        current != new_config
    }

    // This function copies exiting resources which are unchanged in new network config.
    // This usually represents the case of adding/deleting a VF.
    // This function also returns the copied resources so that state machine can filter out used
    // resources and release other resources.
    // The algorithm should remain same for copying and filtering to keep things consistent.
    pub fn copy_existing_resources<'a>(
        &mut self,
        current_config: &'a Self,
    ) -> Vec<&'a InstanceInterfaceConfig> {
        let mut common_function_ids = Vec::new();

        // Virtual function id does not change during the instance life cycle.
        // If a VF is deleted, cloud won't send that id to carbide.
        // e.g. VF configured 0,1,2,3; tenant deletes vf id 2. In this case cloud will forward new
        // config only with vf id as 0,1,3.
        for interface in &mut self.interfaces {
            let existing_interface = current_config.interfaces.iter().find(|x| {
                let is_network_same = if interface.network_details.is_some() {
                    x.network_details == interface.network_details
                } else if interface.network_segment_id.is_some() {
                    x.network_segment_id == interface.network_segment_id
                } else {
                    false
                };

                if is_network_same {
                    // Exactly same interface id and device locator must be used.
                    interface.function_id == x.function_id
                        && interface.device_locator == x.device_locator
                } else {
                    false
                }
            });

            if let Some(existing_interface) = existing_interface {
                // Copy all allocated resources
                // TODO: Zero DPU changes.
                interface.ip_addrs = existing_interface.ip_addrs.clone();
                interface.interface_prefixes = existing_interface.interface_prefixes.clone();
                interface.network_segment_gateways =
                    existing_interface.network_segment_gateways.clone();
                if interface.network_details.is_some() {
                    interface.network_segment_id = existing_interface.network_segment_id;
                }
                common_function_ids.push(existing_interface);
            }
        }

        common_function_ids
    }

    /// Returns true if all interfaces on this instance are equivalent to the host's in-band
    /// interface, meaning they belong to a network segment of type
    /// [`NetworkSegmentType::HostInband`]. This is in contrast to DPU-based interfaces where the
    /// instance sees an overlay network.
    pub fn is_host_inband(&self) -> bool {
        self.interfaces.iter().all(|i| i.is_host_inband())
    }
}

#[derive(PartialEq)]
enum VFAllocationType {
    // Only physical interface is defined. No virtual function is defined.
    None,
    // Cloud is sending valid virtual function id.
    Cloud,
    // Cloud is sending None for virtual function id. This bis possible in older versions.
    Carbide,
}

type DeviceVFIdsMap =
    HashMap<(Option<String>, u32), Vec<(rpc::InterfaceFunctionType, Option<u32>)>>;

fn validate_virtual_function_ids_and_get_allocation_method(
    interfaces: &[rpc::InstanceInterfaceConfig],
) -> Result<VFAllocationType, RpcDataConversionError> {
    let mut device_vf_ids: DeviceVFIdsMap = HashMap::new();

    // Create grouping based on device and device_instance.
    interfaces.iter().for_each(|x| {
        device_vf_ids
            .entry((x.device.clone(), x.device_instance))
            .or_default()
            .push((x.function_type(), x.virtual_function_id))
    });

    let all_vf_ids = device_vf_ids
        .values()
        .flatten()
        .filter(|x| x.0 == rpc::InterfaceFunctionType::Virtual)
        .collect_vec();

    if all_vf_ids.is_empty() {
        // Only Physical interfaces are mentioned.
        return Ok(VFAllocationType::None);
    }

    if all_vf_ids.iter().all(|x| x.1.is_none()) {
        // Virtual function ids are not yet implemented at cloud.
        return Ok(VFAllocationType::Carbide);
    }

    if all_vf_ids.iter().any(|x| x.1.is_none()) {
        // At least one None and one valid virtual_function_id is given. Mix of both is not allowed.
        return Err(RpcDataConversionError::InvalidValue(
            "Mix of VF".to_string(),
            "Mix of valid virtual_function_id and None is found.".to_string(),
        ));
    }

    for vf_info in device_vf_ids.values() {
        let vf_ids = vf_info
            .iter()
            .filter_map(|(ft, vf_id)| {
                if let rpc::InterfaceFunctionType::Virtual = ft {
                    Some(*vf_id)
                } else {
                    None
                }
            })
            .flatten()
            .collect_vec();

        if vf_ids.is_empty() {
            // Only physical interfaces are provided.
            // Nothing to validate for this device and device_instance.
            continue;
        }

        // Check for duplicate VF ids.
        let vf_ids_set = vf_ids.iter().collect::<HashSet<&u32>>();
        if vf_ids.len() != vf_ids_set.len() {
            return Err(RpcDataConversionError::InvalidValue(
                "Duplicate VFs".to_string(),
                "Duplicate VF IDs detected.".to_string(),
            ));
        }
    }

    // All device and device_instance's VF IDs are validated.
    Ok(VFAllocationType::Cloud)
}

impl TryFrom<rpc::InstanceNetworkConfig> for InstanceNetworkConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: rpc::InstanceNetworkConfig) -> Result<Self, Self::Error> {
        // try_from for interfaces:
        let mut assigned_vfs_map: HashMap<(Option<String>, u32), u8> = HashMap::default();
        let mut interfaces = Vec::with_capacity(config.interfaces.len());
        // Either all virtual ids for VF are None, or all should have some valid values.
        // virtual_function_id can not be repeated.

        let allocation_type =
            validate_virtual_function_ids_and_get_allocation_method(&config.interfaces)?;
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
                    InterfaceFunctionId::Virtual {
                        id: if allocation_type == VFAllocationType::Carbide {
                            let assigned_vfs = assigned_vfs_map
                                .entry((iface.device.clone(), iface.device_instance))
                                .or_insert(0);
                            let id = *assigned_vfs;
                            *assigned_vfs = assigned_vfs.saturating_add(1);
                            id
                        } else {
                            // Already validated.
                            iface.virtual_function_id.unwrap_or_default() as u8
                        },
                    }
                }
            };

            // If network_details is present, that gets precedence and we'll pull the network_segment_id from that
            // if it's a NetworkSegment.
            let (network_details, network_segment_id) = if let Some(x) = iface.network_details {
                let nd: NetworkDetails = x.try_into()?;
                let ns_id = match nd {
                    NetworkDetails::NetworkSegment(network_segment_id) => Some(network_segment_id),
                    NetworkDetails::VpcPrefixId(_uuid) => None,
                };

                (Some(nd), ns_id)
            } else {
                // If network_details wasn't set, then the caller is required to
                // send network_segment_id.
                // This is old model. Let's use network segment id as such.
                // TODO: This should be removed in future.
                let ns_id =
                    iface
                        .network_segment_id
                        .ok_or(RpcDataConversionError::MissingArgument(
                            "InstanceInterfaceConfig::network_segment_id",
                        ))?;

                // And then we'll populate network_details from that as well.
                (Some(NetworkDetails::NetworkSegment(ns_id)), Some(ns_id))
            };

            let device_locator = iface.device.map(|device| DeviceLocator {
                device,
                device_instance: iface.device_instance as usize,
            });

            interfaces.push(InstanceInterfaceConfig {
                function_id,
                network_segment_id,
                network_details,
                ip_addrs: HashMap::default(),
                interface_prefixes: HashMap::default(),
                network_segment_gateways: HashMap::new(),
                host_inband_mac_address: None,
                device_locator,
                internal_uuid: uuid::Uuid::new_v4(),
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

            // Update network segment id based on network details.
            let network_details: Option<rpc::forge::instance_interface_config::NetworkDetails> =
                iface.network_details.map(|x| x.into());
            let network_segment_id = iface.network_segment_id;

            let (device, device_instance) = match iface.device_locator {
                Some(dl) => (Some(dl.device), dl.device_instance as u32),
                None => (None, 0),
            };

            let virtual_function_id = match iface.function_id {
                InterfaceFunctionId::Physical {} => None,
                InterfaceFunctionId::Virtual { id } => Some(id as u32),
            };

            interfaces.push(rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::from(function_type) as i32,
                network_segment_id,
                network_details,
                device,
                device_instance,
                virtual_function_id,
            });
        }

        Ok(rpc::InstanceNetworkConfig { interfaces })
    }
}

/// Validates that any container which has elements that have InterfaceFunctionIds
/// assigned assigned is using unique and valid FunctionIds.
pub fn validate_interface_function_ids<
    T,
    F: Fn(&T) -> &InterfaceFunctionId,
    G: Fn(&T) -> Option<&DeviceLocator>,
>(
    container: &[T],
    get_function_id: F,
    get_device_locator: G,
) -> Result<(), String> {
    if container.is_empty() {
        // Empty interfaces can be filled via host's host_inband interfaces later. If it's still
        // empty then, we throw an error later.
        return Ok(());
    }

    // We need 1 physical interface, virtual interfaces must start at VFID 0,
    // and IDs must not be duplicated
    let mut used_functions: HashMap<Option<&DeviceLocator>, Vec<i32>> = HashMap::new();

    for (idx, iface) in container.iter().enumerate() {
        let function_id = get_function_id(iface);
        let device_locator = get_device_locator(iface);

        if let InterfaceFunctionId::Virtual { id } = function_id
            && !(INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX).contains(id)
        {
            return Err(format!(
                "Invalid interface virtual function ID {id} for network interface at index {idx}"
            ));
        }

        let func_id = match function_id {
            InterfaceFunctionId::Physical {} => -1,
            InterfaceFunctionId::Virtual { id } => (*id) as i32,
        };

        used_functions
            .entry(device_locator)
            .or_default()
            .push(func_id);

        // Note: We can't validate the network segment ID here
    }

    // Now there can be a gap in virtual id. We can only validate that if physical id is given or
    // not.
    for (device_locator, fids) in &mut used_functions {
        fids.sort();
        if let Some(pf) = fids.first() {
            if *pf != -1 {
                return Err(format!(
                    "Missing Physical Function for device {}",
                    device_locator.cloned().unwrap_or_default(),
                ));
            }
        } else {
            return Err(format!(
                "No Function is given for device {}",
                device_locator.cloned().unwrap_or_default(),
            ));
        };

        let fids_hash: HashSet<i32> = HashSet::from_iter(fids.iter().copied());
        if fids.len() != fids_hash.len() {
            // Duplicate function ids are present.
            return Err(format!(
                "Duplicate fucntion ids are present for device {}: {:?}",
                device_locator.cloned().unwrap_or_default(),
                fids
            ));
        }
    }

    Ok(())
}

/// Enum to keep either network segment id or vpc_prefix id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDetails {
    NetworkSegment(NetworkSegmentId),
    VpcPrefixId(VpcPrefixId),
}

impl From<NetworkDetails> for rpc::forge::instance_interface_config::NetworkDetails {
    fn from(value: NetworkDetails) -> Self {
        match value {
            NetworkDetails::NetworkSegment(network_segment_id) => {
                rpc::forge::instance_interface_config::NetworkDetails::SegmentId(network_segment_id)
            }
            NetworkDetails::VpcPrefixId(uuid) => {
                rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(uuid)
            }
        }
    }
}

impl TryFrom<rpc::forge::instance_interface_config::NetworkDetails> for NetworkDetails {
    fn try_from(
        value: rpc::forge::instance_interface_config::NetworkDetails,
    ) -> Result<Self, Self::Error> {
        Ok(match value {
            rpc::forge::instance_interface_config::NetworkDetails::SegmentId(ns_id) => {
                NetworkDetails::NetworkSegment(ns_id)
            }
            rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(vpc_prefix_id) => {
                NetworkDetails::VpcPrefixId(vpc_prefix_id)
            }
        })
    }

    type Error = RpcDataConversionError;
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Default)]
pub struct DeviceLocator {
    pub device: String,
    pub device_instance: usize,
}
impl Display for DeviceLocator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.device, self.device_instance)
    }
}

/// The configuration that a customer desires for an instances network interface
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceInterfaceConfig {
    /// Uniquely identifies the interface on the instance
    pub function_id: InterfaceFunctionId,
    /// Tenant can provide vpc_prefix_id instead of network segment id.
    /// In case of vpc_prefix_id, carbide should allocate a new network segment and use it for
    /// further IP allocation.
    pub network_details: Option<NetworkDetails>,
    /// The network segment this interface is attached to.
    /// In case vpc_prefix_id is provided, a new segment has to be created and assign here.
    pub network_segment_id: Option<NetworkSegmentId>,
    /// The IP address we allocated for each network prefix for this interface
    /// This is not populated if we have not allocated IP addresses yet.
    #[serde(
        default,
        deserialize_with = "deserialize_network_prefix_id_ipaddr_map",
        serialize_with = "serialize_network_prefix_id_ipaddr_map"
    )]
    pub ip_addrs: HashMap<NetworkPrefixId, IpAddr>,
    /// The interface-specific prefix allocation we carved out from each
    /// network prefix for this interface (e.g. in FNN we might carve out
    /// a /30 for an interface, whereas in ETV we just allocate a /32).
    ///
    /// There should be a 1:1 correlation between this and the `ip_addrs`,
    /// as in, for each network prefix ID entry in the `ip_addrs` map, there
    /// should be a corresponding `inteface_prefixes` entry here (even if it's
    /// just a /32 for derived from the ip_addr).
    ///
    /// TODO(chet): Allow a default value to be set here for backwards
    /// compatibility, since InstanceInterfaceConfigs for existing instances
    /// won't have this information stored.
    #[serde(
        default,
        deserialize_with = "deserialize_network_prefix_id_ipnetwork_map",
        serialize_with = "serialize_network_prefix_id_ipnetwork_map"
    )]
    pub interface_prefixes: HashMap<NetworkPrefixId, IpNetwork>,

    /// The gateway (with prefix) for each network segment
    #[serde(
        default,
        deserialize_with = "deserialize_network_prefix_id_ipnetwork_map",
        serialize_with = "serialize_network_prefix_id_ipnetwork_map"
    )]
    pub network_segment_gateways: HashMap<NetworkPrefixId, IpNetwork>,

    /// The MAC address of the NIC, if this is zero-DPU instance with host inband networking. For
    /// zero-DPU instances, the instance interface is just the host's network interface, so we can
    /// assign the host's MAC here. This is opposed to instances with DPUs, where we do not know the
    /// MAC address that the instance will see until we start getting status observations from the
    /// forge agent.
    pub host_inband_mac_address: Option<MacAddress>,

    /// The DPU device this interface corresponds to.  The device/instance pair will be mapped to a specific DPU
    pub device_locator: Option<DeviceLocator>,

    /// An internal ID used to associate an interface status with the interface config
    pub internal_uuid: uuid::Uuid,
}

impl InstanceInterfaceConfig {
    /// Returns true if this instance interface is equivalent to the host's in-band interface,
    /// meaning it belong to a network segment of type [`NetworkSegmentType::HostInband`]. This is
    /// in contrast to DPU-based interfaces where the instance sees an overlay network.
    ///
    /// Currently this is true if self.host_inband_mac_address is set to some value.
    pub fn is_host_inband(&self) -> bool {
        self.host_inband_mac_address.is_some()
    }
}

/// Minimum valid value (inclusive) for a virtual function ID
pub const INTERFACE_VFID_MIN: u8 = 0;
/// Maximum valid value (inclusive) for a virtual function ID
pub const INTERFACE_VFID_MAX: u8 = 15;

pub fn deserialize_network_prefix_id_ipaddr_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<NetworkPrefixId, IpAddr>, D::Error>
where
    D: Deserializer<'de>,
{
    let uuid_map = <HashMap<uuid::Uuid, IpAddr>>::deserialize(deserializer)?;
    Ok(uuid_map
        .into_iter()
        .map(|(uuid, ipaddr)| (NetworkPrefixId::from(uuid), ipaddr))
        .collect())
}

pub fn deserialize_network_prefix_id_ipnetwork_map<'de, D>(
    deserializer: D,
) -> Result<HashMap<NetworkPrefixId, IpNetwork>, D::Error>
where
    D: Deserializer<'de>,
{
    let uuid_map = <HashMap<uuid::Uuid, IpNetwork>>::deserialize(deserializer)?;
    Ok(uuid_map
        .into_iter()
        .map(|(uuid, ipnetwork)| (NetworkPrefixId::from(uuid), ipnetwork))
        .collect())
}

pub fn serialize_network_prefix_id_ipaddr_map<S>(
    map: &HashMap<NetworkPrefixId, IpAddr>,
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut out_map = s.serialize_map(Some(map.len()))?;
    for (k, v) in map {
        let uuid: uuid::Uuid = (*k).into();
        out_map.serialize_entry(&uuid, v)?
    }
    out_map.end()
}

pub fn serialize_network_prefix_id_ipnetwork_map<S>(
    map: &HashMap<NetworkPrefixId, IpNetwork>,
    s: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut out_map = s.serialize_map(Some(map.len()))?;
    for (k, v) in map {
        let uuid: uuid::Uuid = (*k).into();
        out_map.serialize_entry(&uuid, v)?
    }
    out_map.end()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iterate_function_ids() {
        let func_ids: Vec<InterfaceFunctionId> = InterfaceFunctionId::iter_all().collect();
        assert_eq!(
            func_ids.len(),
            2 + INTERFACE_VFID_MAX as usize - INTERFACE_VFID_MIN as usize
        );

        assert_eq!(func_ids[0], InterfaceFunctionId::Physical {});
        for (i, func_id) in func_ids[1..].iter().enumerate() {
            assert_eq!(
                *func_id,
                InterfaceFunctionId::Virtual {
                    id: (INTERFACE_VFID_MIN + i as u8)
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
        let network_segment_id: NetworkSegmentId =
            uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let network_prefix_1 =
            NetworkPrefixId::from(uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1201"));
        let ip_addrs = HashMap::from([(network_prefix_1, "192.168.1.2".parse().unwrap())]);
        let interface_prefixes =
            HashMap::from([(network_prefix_1, "192.168.1.2/32".parse().unwrap())]);
        let network_segment_gateways = HashMap::default();
        let internal_uuid = uuid::uuid!("37c3dc65-9aef-4439-b7ca-d532a0a41d7f");

        let interface = InstanceInterfaceConfig {
            function_id,
            network_segment_id: Some(network_segment_id),
            ip_addrs,
            interface_prefixes,
            network_segment_gateways,
            host_inband_mac_address: None,
            network_details: None,
            device_locator: None,
            internal_uuid,
        };
        let serialized = serde_json::to_string(&interface).unwrap();
        assert_eq!(
            serialized,
            r#"{"function_id":{"type":"physical"},"network_details":null,"network_segment_id":"91609f10-c91d-470d-a260-6293ea0c1200","ip_addrs":{"91609f10-c91d-470d-a260-6293ea0c1201":"192.168.1.2"},"interface_prefixes":{"91609f10-c91d-470d-a260-6293ea0c1201":"192.168.1.2/32"},"network_segment_gateways":{},"host_inband_mac_address":null,"device_locator":null,"internal_uuid":"37c3dc65-9aef-4439-b7ca-d532a0a41d7f"}"#
        );

        assert_eq!(
            serde_json::from_str::<InstanceInterfaceConfig>(&serialized).unwrap(),
            interface
        );
    }

    /// Creates a valid instance network configuration using the maximum
    /// amount of interface
    const BASE_SEGMENT_ID: uuid::Uuid = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c0000");
    fn offset_segment_id(offset: u8) -> NetworkSegmentId {
        uuid::Uuid::from_u128(BASE_SEGMENT_ID.as_u128() + offset as u128).into()
    }

    fn create_valid_network_config() -> InstanceNetworkConfig {
        let interfaces: Vec<InstanceInterfaceConfig> = InterfaceFunctionId::iter_all()
            .enumerate()
            .map(|(idx, function_id)| {
                let network_segment_id = offset_segment_id(idx as u8);
                InstanceInterfaceConfig {
                    function_id,
                    network_segment_id: Some(network_segment_id),
                    ip_addrs: HashMap::default(),
                    interface_prefixes: HashMap::default(),
                    network_segment_gateways: HashMap::default(),
                    host_inband_mac_address: None,
                    network_details: None,
                    device_locator: None,
                    internal_uuid: uuid::Uuid::new_v4(),
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
                network_segment_id: Some(NetworkSegmentId::from(BASE_SEGMENT_ID)),
                network_details: None,
                device: None,
                device_instance: 0u32,
                virtual_function_id: None,
            }],
        };

        let netconfig: InstanceNetworkConfig = config.try_into().unwrap();
        assert_eq!(
            netconfig.interfaces,
            &[InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::Physical {},
                network_segment_id: Some(BASE_SEGMENT_ID.into()),
                ip_addrs: HashMap::new(),
                interface_prefixes: HashMap::new(),
                network_segment_gateways: HashMap::new(),
                host_inband_mac_address: None,
                network_details: Some(NetworkDetails::NetworkSegment(BASE_SEGMENT_ID.into()),),
                device_locator: None,
                internal_uuid: netconfig.interfaces.first().unwrap().internal_uuid,
            }]
        );
    }

    #[test]
    fn assign_ids_from_rpc_config_pf_and_vf() {
        let mut interfaces = vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as _,
            network_segment_id: Some(BASE_SEGMENT_ID.into()),
            network_details: None,
            device: None,
            device_instance: 0u32,
            virtual_function_id: None,
        }];
        for vfid in INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX {
            interfaces.push(rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as _,
                network_segment_id: Some(offset_segment_id(vfid + 1)),
                network_details: None,
                device: None,
                device_instance: 0u32,
                virtual_function_id: None,
            });
        }

        let config = rpc::InstanceNetworkConfig { interfaces };
        let netconfig: InstanceNetworkConfig = config.try_into().unwrap();
        let mut netconf_interfaces_iter = netconfig.interfaces.iter();

        let mut expected_interfaces = vec![InstanceInterfaceConfig {
            function_id: InterfaceFunctionId::Physical {},
            network_segment_id: Some(BASE_SEGMENT_ID.into()),
            ip_addrs: HashMap::new(),
            interface_prefixes: HashMap::new(),
            network_segment_gateways: HashMap::new(),
            host_inband_mac_address: None,
            network_details: Some(NetworkDetails::NetworkSegment(BASE_SEGMENT_ID.into())),
            device_locator: None,
            internal_uuid: netconf_interfaces_iter.next().unwrap().internal_uuid,
        }];

        for vfid in INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX {
            let segment_id = offset_segment_id(vfid + 1);
            expected_interfaces.push(InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::Virtual { id: vfid },
                network_segment_id: Some(segment_id),
                ip_addrs: HashMap::new(),
                interface_prefixes: HashMap::new(),
                network_segment_gateways: HashMap::new(),
                host_inband_mac_address: None,
                network_details: Some(NetworkDetails::NetworkSegment(segment_id)),
                device_locator: None,
                internal_uuid: netconf_interfaces_iter.next().unwrap().internal_uuid,
            });
        }
        assert_eq!(netconfig.interfaces, &expected_interfaces[..]);
    }

    #[test]
    fn validate_network_config() {
        let config = create_valid_network_config();
        config.validate(true).unwrap();

        // Same config with virtual function, but virtual functions are disabled
        assert!(config.validate(false).is_err());

        // Duplicate virtual function
        let mut config = create_valid_network_config();
        config.interfaces[2].function_id = InterfaceFunctionId::Virtual { id: 0 };
        assert!(config.validate(true).is_err());

        // Out of bounds virtual function
        let mut config = create_valid_network_config();
        config.interfaces[2].function_id = InterfaceFunctionId::Virtual { id: 16 };
        assert!(config.validate(true).is_err());

        // No physical function
        let mut config = create_valid_network_config();
        config.interfaces.swap_remove(0);
        assert!(config.validate(true).is_err());

        // Missing virtual function id in between is now a valid scenario.
        // The last virtual function is ok to be missing
        let mut config = create_valid_network_config();
        config
            .interfaces
            .swap_remove(INTERFACE_VFID_MAX as usize + 1);
        config.validate(true).unwrap();

        // Duplicate network segment
        const DUPLICATE_SEGMENT_ID: uuid::Uuid =
            uuid::uuid!("91609f10-c91d-470d-a260-1234560c0000");
        let mut config = create_valid_network_config();
        config.interfaces[0].network_segment_id = Some(DUPLICATE_SEGMENT_ID.into());
        config.interfaces[1].network_segment_id = Some(DUPLICATE_SEGMENT_ID.into());
        assert!(config.validate(true).is_err());
    }

    fn get_rpc_instance_network_config() -> Vec<rpc::InstanceInterfaceConfig> {
        vec![
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                virtual_function_id: None,
                network_details: Some(
                    rpc::forge::instance_interface_config::NetworkDetails::SegmentId(
                        offset_segment_id(0),
                    ),
                ),
                device: None,
                device_instance: 0u32,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: None,
                virtual_function_id: Some(0),
                network_details: Some(
                    rpc::forge::instance_interface_config::NetworkDetails::SegmentId(
                        offset_segment_id(1),
                    ),
                ),
                device: None,
                device_instance: 0u32,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: None,
                virtual_function_id: Some(1),
                network_details: Some(
                    rpc::forge::instance_interface_config::NetworkDetails::SegmentId(
                        offset_segment_id(2),
                    ),
                ),
                device: None,
                device_instance: 0u32,
            },
            rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as i32,
                network_segment_id: None,
                virtual_function_id: Some(2),
                network_details: Some(
                    rpc::forge::instance_interface_config::NetworkDetails::SegmentId(
                        offset_segment_id(3),
                    ),
                ),
                device: None,
                device_instance: 0u32,
            },
        ]
    }

    #[test]
    fn test_validate_virtual_function_ids() {
        let interfaces = get_rpc_instance_network_config();

        let network_config = rpc::InstanceNetworkConfig { interfaces };
        let network_config: InstanceNetworkConfig = network_config.try_into().unwrap();

        let vf_ids = network_config.interfaces.iter().filter_map(|x| {
            if let InterfaceFunctionId::Virtual { id } = x.function_id {
                Some(id)
            } else {
                None
            }
        });

        let vf_ids = vf_ids.sorted().collect_vec();

        // All VF ids should be present after converting.
        let expected = vec![0, 1, 2];
        assert_eq!(expected, vf_ids);
    }

    #[test]
    fn test_validate_virtual_function_ids_missing_1() {
        let mut interfaces = get_rpc_instance_network_config();
        interfaces.remove(2);

        let network_config = rpc::InstanceNetworkConfig { interfaces };
        let network_config: InstanceNetworkConfig = network_config.try_into().unwrap();

        let vf_ids = network_config.interfaces.iter().filter_map(|x| {
            if let InterfaceFunctionId::Virtual { id } = x.function_id {
                Some(id)
            } else {
                None
            }
        });

        let vf_ids = vf_ids.sorted().collect_vec();

        // Since vf_id: 1 is removed, it should not be present in the parsed config.
        let expected = vec![0, 2];
        assert_eq!(expected, vf_ids);
    }

    #[test]
    fn test_validate_virtual_function_ids_only_physical() {
        let mut interfaces = get_rpc_instance_network_config();
        interfaces = vec![interfaces[0].clone()];

        let network_config = rpc::InstanceNetworkConfig { interfaces };
        let network_config: InstanceNetworkConfig = network_config.try_into().unwrap();

        let vf_ids = network_config
            .interfaces
            .iter()
            .filter_map(|x| {
                if let InterfaceFunctionId::Virtual { id } = x.function_id {
                    Some(id)
                } else {
                    None
                }
            })
            .collect_vec();

        assert!(vf_ids.is_empty());
    }

    #[test]
    fn test_validate_virtual_function_ids_duplicate() {
        let mut interfaces = get_rpc_instance_network_config();
        interfaces[2].virtual_function_id = Some(0);

        let network_config = rpc::InstanceNetworkConfig { interfaces };
        let network_config: Result<InstanceNetworkConfig, RpcDataConversionError> =
            network_config.try_into();

        assert!(network_config.is_err());
    }

    #[test]
    fn test_validate_virtual_function_ids_mix() {
        let mut interfaces = get_rpc_instance_network_config();
        interfaces[2].virtual_function_id = None;

        let network_config = rpc::InstanceNetworkConfig { interfaces };
        let network_config: Result<InstanceNetworkConfig, RpcDataConversionError> =
            network_config.try_into();

        assert!(network_config.is_err());
    }
}
