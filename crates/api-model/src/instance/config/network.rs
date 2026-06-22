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

use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use std::net::IpAddr;

use carbide_uuid::machine::MachineId;
use carbide_uuid::network::{NetworkPrefixId, NetworkSegmentId};
use carbide_uuid::vpc::VpcPrefixId;
use ipnetwork::IpNetwork;
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
    /// Configures how instance network interfaces are set up.
    /// Mutually exclusive with `auto`: when `auto` is true, this
    /// MUST be empty, When `auto` is false, this lists the explicit
    /// interface configuration the caller wants applied.
    pub interfaces: Vec<InstanceInterfaceConfig>,

    /// When true, NICO (or potentially some pluggable SDN backend) will
    /// auto-resolve the instance's network interfaces from the host's
    /// HostInband network segments. Only valid for instances on zero-DPU
    /// hosts (well, no DPU, *or* DPU in NIC mode).
    ///
    /// It is also important to note that on the wire (request AND response),
    /// `auto: true` only travels with `interfaces: []`, but internally some
    /// other things are happening.
    ///
    /// On allocation/update, NICo resolves the empty interfaces: [] into
    /// one entry per HostInband segment on the host, then stores the
    /// fully-resolved config internally (allowing storage, status, IP
    /// bookkeeping, config diffs, etc to all operate on real interfaces).
    ///
    /// Then, at the model <-> RPC boundary, the resolved interfaces are
    /// stripped off to `[]`, so callers reading the instance config back
    /// simply see what they originally sent (`auto: true` with no interfaces).
    ///
    /// The resolved per-interface details (IP, MAC, gateway, prefix) appear in
    /// `Instance.status.network.interfaces` like usual.
    #[serde(default)]
    pub auto: bool,
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
                    requested_ip_addr: None,
                    ipv6_interface_config: None,
                    routing_profile: None,
                    interface_prefixes: HashMap::default(),
                    network_segment_gateways: HashMap::default(),
                    host_inband_mac_address: None,
                    device_locator: None,
                    internal_uuid: uuid::Uuid::nil(),
                }],
                auto: false,
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
                        requested_ip_addr: None,
                        ipv6_interface_config: None,
                        routing_profile: None,
                        interface_prefixes: HashMap::default(),
                        network_segment_gateways: HashMap::default(),
                        host_inband_mac_address: None,
                        device_locator: Some(dl.clone()),
                        internal_uuid: uuid::Uuid::nil(),
                    })
                    .collect(),
                auto: false,
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
                requested_ip_addr: None,
                ipv6_interface_config: None,
                routing_profile: None,
                interface_prefixes: HashMap::default(),
                network_segment_gateways: HashMap::default(),
                host_inband_mac_address: None,
                device_locator: None,
                internal_uuid: uuid::Uuid::nil(),
            }],
            auto: false,
        }
    }

    /// Returns this config as it should appear on the wire: for `auto`
    /// configs, the resolved interfaces are stripped so external callers see
    /// just their request (`{ auto: true, interfaces: [] }`). The fully-
    /// resolved interfaces still drive `InstanceNetworkStatus` population
    /// from the internal model. For non-auto configs, returns `self`
    /// unchanged.
    ///
    /// This exists to keep the input config from the user represented
    /// back to them as they sent it, and mask any internal interface
    /// resolution that happened as a result of `auto`.
    pub fn into_external_view(self) -> Self {
        if self.auto {
            Self {
                interfaces: vec![],
                auto: true,
            }
        } else {
            self
        }
    }

    /// Returns the DPU machine IDs used by the instance network configuration.
    pub fn get_used_dpus(
        &self,
        device_to_id_map: &HashMap<String, Vec<MachineId>>,
        primary_dpu_machine_id: Option<MachineId>,
    ) -> Vec<MachineId> {
        let device_locators: Vec<&DeviceLocator> = self
            .interfaces
            .iter()
            .filter_map(|i| i.device_locator.as_ref())
            .collect();

        let legacy_physical_interface_count = self
            .interfaces
            .iter()
            .filter(|iface| {
                iface.function_id == InterfaceFunctionId::Physical {}
                    && iface.device_locator.is_none()
            })
            .count();

        let use_primary_dpu_only = legacy_physical_interface_count > 0
            || device_locators.is_empty()
            || device_to_id_map.is_empty();

        if use_primary_dpu_only {
            return primary_dpu_machine_id.into_iter().collect();
        }

        let used_dpus: Vec<MachineId> = device_locators
            .iter()
            .filter_map(|device_locator| {
                device_to_id_map
                    .get(&device_locator.device)
                    .and_then(|dpu_ids| dpu_ids.get(device_locator.device_instance))
                    .copied()
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();

        if used_dpus.is_empty() {
            return device_to_id_map
                .values()
                .flatten()
                .copied()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
        }

        used_dpus
    }

    /// Validates the network configuration.
    ///
    /// Note: this is also called on POST-resolution configs (i.e. after
    /// `add_inband_interfaces_to_config` has expanded an `auto` request into
    /// underlying interfaces), so it must not reject the combination
    /// `auto: true` + non-empty interfaces here. The "auto must arrive with
    /// empty interfaces" rule is enforced in RPC <-> model conversion, which
    /// only runs on user input.
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
                    // TODO:  && x.requested_ip_addr == interface.requested_ip_addr
                    // There's originally a gap here where it wasn't possible to change
                    // IPs without switching to a different prefix.  It's technically
                    // possible to test requested_ip_addr so that explicit IP changes
                    // could trigger the update, even for the same VPC prefix, but it appears
                    // to trigger postgres table constraints.  For now, the existing implementation
                    // gap is being maintained, and both will need to be resolved together.
                    x.network_details == interface.network_details
                        && x.ipv6_interface_config == interface.ipv6_interface_config
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
                interface.requested_ip_addr = existing_interface.requested_ip_addr;
                interface.ipv6_interface_config = existing_interface.ipv6_interface_config.clone();
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

/// IPv6 dual-stack configuration for an instance interface.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ipv6InterfaceConfig {
    pub vpc_prefix_id: VpcPrefixId,
    pub requested_ip_addr: Option<std::net::Ipv6Addr>,
}

/// Routing-profile options that can be narrowed for an instance interface.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceInterfaceRoutingProfile {
    /// Prefixes this interface is allowed to announce as anycast routes.
    #[serde(default)]
    pub allowed_anycast_prefixes: Vec<IpNetwork>,
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

    /// IP address allocation that was explicitly requested by a caller from the VPC prefix of the interface.
    pub requested_ip_addr: Option<IpAddr>,

    /// Optional IPv6 dual-stack configuration. When set alongside a
    /// VpcPrefixId in network_details, both prefixes are allocated to a single segment.
    #[serde(rename = "ipv6")]
    pub ipv6_interface_config: Option<Ipv6InterfaceConfig>,

    /// Optional routing-profile settings that narrow the owning VPC profile for this interface.
    #[serde(default)]
    pub routing_profile: Option<InstanceInterfaceRoutingProfile>,

    /// The interface-specific prefix allocation we carved out from each
    /// network prefix for this interface (e.g. in FNN we might carve out
    /// a /31 for an interface, whereas in ETV we just allocate a /32).
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
    use carbide_test_support::Outcome::*;
    use carbide_test_support::scenarios;

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

    // Serde JSON round-trip for each InterfaceFunctionId variant: each row
    // asserts the exact serialized form, and the closure confirms the value
    // round-trips back equal before yielding that string.
    #[test]
    fn serialize_function_id() {
        scenarios!(
            // Serialize, confirm it round-trips back equal, then yield the JSON.
            // serde_json::Error is not PartialEq, so collapse failures to ().
            run = |function_id| {
                let serialized = serde_json::to_string(&function_id).map_err(|_| ())?;
                let round_tripped =
                    serde_json::from_str::<InterfaceFunctionId>(&serialized).map_err(|_| ())?;
                assert_eq!(round_tripped, function_id);
                Ok::<_, ()>(serialized)
            };
            "physical" {
                InterfaceFunctionId::Physical {} => Yields(r#"{"type":"physical"}"#.to_string()),
            }

            "virtual" {
                InterfaceFunctionId::Virtual { id: 24 } => Yields(r#"{"type":"virtual","id":24}"#.to_string()),
            }
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
        let requested_ip_addr = Some("192.168.1.2".parse().unwrap());
        let interface_prefixes =
            HashMap::from([(network_prefix_1, "192.168.1.2/32".parse().unwrap())]);
        let network_segment_gateways = HashMap::default();
        let internal_uuid = uuid::uuid!("37c3dc65-9aef-4439-b7ca-d532a0a41d7f");

        let interface = InstanceInterfaceConfig {
            function_id,
            network_segment_id: Some(network_segment_id),
            ip_addrs,
            requested_ip_addr,
            ipv6_interface_config: None,
            routing_profile: None,
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
            r#"{"function_id":{"type":"physical"},"network_details":null,"network_segment_id":"91609f10-c91d-470d-a260-6293ea0c1200","ip_addrs":{"91609f10-c91d-470d-a260-6293ea0c1201":"192.168.1.2"},"requested_ip_addr":"192.168.1.2","ipv6":null,"routing_profile":null,"interface_prefixes":{"91609f10-c91d-470d-a260-6293ea0c1201":"192.168.1.2/32"},"network_segment_gateways":{},"host_inband_mac_address":null,"device_locator":null,"internal_uuid":"37c3dc65-9aef-4439-b7ca-d532a0a41d7f"}"#
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
                    requested_ip_addr: None,
                    ipv6_interface_config: None,
                    routing_profile: None,
                    interface_prefixes: HashMap::default(),
                    network_segment_gateways: HashMap::default(),
                    host_inband_mac_address: None,
                    network_details: None,
                    device_locator: None,
                    internal_uuid: uuid::Uuid::new_v4(),
                }
            })
            .collect();

        InstanceNetworkConfig {
            interfaces,
            auto: false,
        }
    }

    // InstanceNetworkConfig::validate over a base valid config mutated per row.
    // Input is (config, allow_instance_vf). ConfigValidationError is not
    // PartialEq, so rejections assert only that validation errs (Fails); the
    // exact error value is not part of the contract here.
    #[test]
    fn validate_network_config() {
        const DUPLICATE_SEGMENT_ID: uuid::Uuid =
            uuid::uuid!("91609f10-c91d-470d-a260-1234560c0000");

        let valid = create_valid_network_config();

        let virtual_functions_disabled = create_valid_network_config();

        let mut duplicate_virtual_function = create_valid_network_config();
        duplicate_virtual_function.interfaces[2].function_id =
            InterfaceFunctionId::Virtual { id: 0 };

        let mut out_of_bounds_virtual_function = create_valid_network_config();
        out_of_bounds_virtual_function.interfaces[2].function_id =
            InterfaceFunctionId::Virtual { id: 16 };

        let mut no_physical_function = create_valid_network_config();
        no_physical_function.interfaces.swap_remove(0);

        let mut missing_middle_virtual_function = create_valid_network_config();
        missing_middle_virtual_function
            .interfaces
            .swap_remove(INTERFACE_VFID_MAX as usize + 1);

        let mut duplicate_network_segment = create_valid_network_config();
        duplicate_network_segment.interfaces[0].network_segment_id =
            Some(DUPLICATE_SEGMENT_ID.into());
        duplicate_network_segment.interfaces[1].network_segment_id =
            Some(DUPLICATE_SEGMENT_ID.into());

        scenarios!(
            run = |(config, allow_instance_vf)| config.validate(allow_instance_vf).map_err(drop);
            "valid config with virtual functions allowed" {
                (valid, true) => Yields(()),
            }

            "virtual functions disabled by site configuration" {
                (virtual_functions_disabled, false) => Fails,
            }

            "duplicate virtual function id" {
                (duplicate_virtual_function, true) => Fails,
            }

            "out of bounds virtual function id" {
                (out_of_bounds_virtual_function, true) => Fails,
            }

            "no physical function" {
                (no_physical_function, true) => Fails,
            }

            "missing middle virtual function id is allowed" {
                (missing_middle_virtual_function, true) => Yields(()),
            }

            "duplicate network segment" {
                (duplicate_network_segment, true) => Fails,
            }
        );
    }
}
