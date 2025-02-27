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
    str::FromStr,
};

use crate::db::instance_address::InstanceAddress;
use crate::db::network_segment::{NetworkSegment, NetworkSegmentType};
use crate::errors::{CarbideError, CarbideResult};
use crate::model::machine::Machine;
use crate::{db::network_prefix::NetworkPrefixId, model::ConfigValidationError};
use ::rpc::errors::RpcDataConversionError;
use forge_uuid::instance::InstanceId;
use forge_uuid::network::NetworkSegmentId;
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeMap};

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
    #[cfg(test)]
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
}

impl InstanceNetworkConfig {
    /// Returns a network configuration for a single physical interface
    #[cfg(test)]
    pub fn for_segment_id(network_segment_id: NetworkSegmentId) -> Self {
        Self {
            interfaces: vec![InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::Physical {},
                network_segment_id: Some(network_segment_id),
                network_details: Some(NetworkDetails::NetworkSegment(network_segment_id)),
                ip_addrs: HashMap::default(),
                interface_prefixes: HashMap::default(),
                network_segment_gateways: HashMap::default(),
                host_inband_mac_address: None,
            }],
        }
    }

    /// Returns a network configuration for a single physical interface
    #[cfg(test)]
    pub fn for_vpc_prefix_id(vpc_prefix_id: uuid::Uuid) -> Self {
        Self {
            interfaces: vec![InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::Physical {},
                network_segment_id: None,
                network_details: Some(NetworkDetails::VpcPrefixId(vpc_prefix_id)),
                ip_addrs: HashMap::default(),
                interface_prefixes: HashMap::default(),
                network_segment_gateways: HashMap::default(),
                host_inband_mac_address: None,
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
                    "Multiple network interfaces use the same network segment {}",
                    network_segment_id
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

    pub fn verify_update_allowed_to(&self, new_config: &Self) -> Result<(), ConfigValidationError> {
        // Remove all service-generated properties before validating the config
        let mut current = self.clone();
        for iface in &mut current.interfaces {
            iface.ip_addrs.clear();
            iface.interface_prefixes.clear();
            iface.network_segment_gateways.clear();
        }

        if current != *new_config {
            return Err(ConfigValidationError::ConfigCanNotBeModified(
                "network".to_string(),
            ));
        }

        Ok(())
    }

    /// Returns true if all interfaces on this instance are equivalent to the host's in-band
    /// interface, meaning they belong to a network segment of type
    /// [`NetworkSegmentType::HostInband`]. This is in contrast to DPU-based interfaces where the
    /// instance sees an overlay network.
    pub fn is_host_inband(&self) -> bool {
        self.interfaces.iter().all(|i| i.is_host_inband())
    }

    /// Allocate IP's for this network config, filling the InstanceInterfaceConfigs with the newly
    /// allocated IP's.
    pub async fn with_allocated_ips(
        self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        instance_id: InstanceId,
        machine: &Machine,
    ) -> CarbideResult<InstanceNetworkConfig> {
        InstanceAddress::allocate(txn, instance_id, self, machine).await
    }

    /// Find any host_inband segments on the given machine, and replicate them into this instance
    /// network config. This is because allocation requests do not need to explicitly enumerate
    /// a host's in-band (non-dpu) network segments: they cannot be configured through carbide.
    pub async fn with_inband_interfaces_from_machine(
        mut self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        machine_id: &forge_uuid::machine::MachineId,
    ) -> CarbideResult<InstanceNetworkConfig> {
        let host_inband_segment_ids = NetworkSegment::find_ids_by_machine_id(
            txn,
            machine_id,
            Some(NetworkSegmentType::HostInband),
        )
        .await
        .map_err(CarbideError::from)?;

        for host_inband_segment_id in host_inband_segment_ids {
            // Only add it to the instance config if there isn't already an interface in this segment
            if !self
                .interfaces
                .iter()
                .any(|i| i.network_segment_id == Some(host_inband_segment_id))
            {
                self.interfaces.push(InstanceInterfaceConfig {
                    function_id: InterfaceFunctionId::Physical {},
                    network_segment_id: Some(host_inband_segment_id),
                    network_details: None,
                    ip_addrs: Default::default(),
                    interface_prefixes: Default::default(),
                    network_segment_gateways: Default::default(),
                    host_inband_mac_address: None,
                })
            }
        }

        Ok(self)
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

            let network_details: Option<NetworkDetails> = if let Some(x) = iface.network_details {
                Some(x.try_into()?)
            } else {
                None
            };

            // If we have network_details available, use it to get network_segment id.
            let network_segment_id = match &network_details {
                Some(network_details) => match network_details {
                    NetworkDetails::NetworkSegment(network_segment_id) => Some(*network_segment_id),
                    NetworkDetails::VpcPrefixId(_uuid) => None,
                },
                None => {
                    // This is old model. Let's use network segment id as such.
                    // TODO: This should be removed in future.
                    let ns_id = NetworkSegmentId::try_from(iface.network_segment_id.ok_or(
                        RpcDataConversionError::MissingArgument(
                            "InstanceInterfaceConfig::network_segment_id",
                        ),
                    )?)?;
                    Some(ns_id)
                }
            };

            interfaces.push(InstanceInterfaceConfig {
                function_id,
                network_segment_id,
                network_details,
                ip_addrs: HashMap::default(),
                interface_prefixes: HashMap::default(),
                network_segment_gateways: HashMap::new(),
                host_inband_mac_address: None,
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
            let network_segment_id: Option<rpc::Uuid> = iface.network_segment_id.map(|x| x.into());

            interfaces.push(rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::from(function_type) as i32,
                network_segment_id,
                network_details,
            });
        }

        Ok(rpc::InstanceNetworkConfig { interfaces })
    }
}

/// Validates that any container which has elements that have InterfaceFunctionIds
/// assigned assigned is using unique and valid FunctionIds.
pub fn validate_interface_function_ids<T, F: Fn(&T) -> InterfaceFunctionId>(
    container: &[T],
    get_function_id: F,
) -> Result<(), String> {
    if container.is_empty() {
        // Empty interfaces can be filled via host's host_inband interfaces later. If it's still
        // empty then, we throw an error later.
        return Ok(());
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

/// Enum to keep either network segment id or vpc_prefix id.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkDetails {
    NetworkSegment(NetworkSegmentId),
    VpcPrefixId(uuid::Uuid),
}

impl From<NetworkDetails> for rpc::forge::instance_interface_config::NetworkDetails {
    fn from(value: NetworkDetails) -> Self {
        match value {
            NetworkDetails::NetworkSegment(network_segment_id) => {
                rpc::forge::instance_interface_config::NetworkDetails::SegmentId(
                    network_segment_id.0.into(),
                )
            }
            NetworkDetails::VpcPrefixId(uuid) => {
                rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(uuid.into())
            }
        }
    }
}

impl TryFrom<rpc::forge::instance_interface_config::NetworkDetails> for NetworkDetails {
    fn try_from(
        value: rpc::forge::instance_interface_config::NetworkDetails,
    ) -> Result<Self, Self::Error> {
        Ok(match value {
            rpc::forge::instance_interface_config::NetworkDetails::SegmentId(uuid) => {
                let ns_id = NetworkSegmentId::try_from(uuid)?;
                NetworkDetails::NetworkSegment(ns_id)
            }
            rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(uuid) => {
                let vpc_prefix_id = uuid::Uuid::from_str(&uuid.value).map_err(|_| {
                    RpcDataConversionError::InvalidUuid("VpcPrefixId", uuid.to_string())
                })?;
                NetworkDetails::VpcPrefixId(vpc_prefix_id)
            }
        })
    }

    type Error = RpcDataConversionError;
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
    // TODO: Security group
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
pub const INTERFACE_VFID_MIN: usize = 0;
/// Maximum valid value (inclusive) for a virtual function ID
pub const INTERFACE_VFID_MAX: usize = 15;

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
        let uuid: uuid::Uuid = k.into();
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
        let network_segment_id: NetworkSegmentId =
            uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let network_prefix_1 =
            NetworkPrefixId::from(uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1201"));
        let ip_addrs = HashMap::from([(network_prefix_1, "192.168.1.2".parse().unwrap())]);
        let interface_prefixes =
            HashMap::from([(network_prefix_1, "192.168.1.2/32".parse().unwrap())]);
        let network_segment_gateways = HashMap::default();

        let interface = InstanceInterfaceConfig {
            function_id,
            network_segment_id: Some(network_segment_id),
            ip_addrs,
            interface_prefixes,
            network_segment_gateways,
            host_inband_mac_address: None,
            network_details: None,
        };
        let serialized = serde_json::to_string(&interface).unwrap();
        assert_eq!(
            serialized,
            "{\"function_id\":{\"type\":\"physical\"},\"network_details\":null,\"network_segment_id\":\"91609f10-c91d-470d-a260-6293ea0c1200\",\"ip_addrs\":{\"91609f10-c91d-470d-a260-6293ea0c1201\":\"192.168.1.2\"},\"interface_prefixes\":{\"91609f10-c91d-470d-a260-6293ea0c1201\":\"192.168.1.2/32\"},\"network_segment_gateways\":{},\"host_inband_mac_address\":null}"
        );

        assert_eq!(
            serde_json::from_str::<InstanceInterfaceConfig>(&serialized).unwrap(),
            interface
        );
    }

    /// Creates a valid instance network configuration using the maximum
    /// amount of interface
    const BASE_SEGMENT_ID: uuid::Uuid = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c0000");
    fn offset_segment_id(offset: usize) -> NetworkSegmentId {
        uuid::Uuid::from_u128(BASE_SEGMENT_ID.as_u128() + offset as u128).into()
    }

    fn create_valid_network_config() -> InstanceNetworkConfig {
        let interfaces: Vec<InstanceInterfaceConfig> = InterfaceFunctionId::iter_all()
            .enumerate()
            .map(|(idx, function_id)| {
                let network_segment_id = offset_segment_id(idx);
                InstanceInterfaceConfig {
                    function_id,
                    network_segment_id: Some(network_segment_id),
                    ip_addrs: HashMap::default(),
                    interface_prefixes: HashMap::default(),
                    network_segment_gateways: HashMap::default(),
                    host_inband_mac_address: None,
                    network_details: None,
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
                network_segment_id: Some(NetworkSegmentId::from(BASE_SEGMENT_ID).into()),
                network_details: None,
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
                network_details: None
            }]
        );
    }

    #[test]
    fn assign_ids_from_rpc_config_pf_and_vf() {
        let mut interfaces = vec![rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as _,
            network_segment_id: Some(BASE_SEGMENT_ID.into()),
            network_details: None,
        }];
        for vfid in INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX {
            interfaces.push(rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as _,
                network_segment_id: Some(offset_segment_id(vfid + 1).into()),
                network_details: None,
            });
        }

        let config = rpc::InstanceNetworkConfig { interfaces };

        let netconfig: InstanceNetworkConfig = config.try_into().unwrap();
        let mut expected_interfaces = vec![InstanceInterfaceConfig {
            function_id: InterfaceFunctionId::Physical {},
            network_segment_id: Some(BASE_SEGMENT_ID.into()),
            ip_addrs: HashMap::new(),
            interface_prefixes: HashMap::new(),
            network_segment_gateways: HashMap::new(),
            host_inband_mac_address: None,
            network_details: None,
        }];

        for vfid in INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX {
            expected_interfaces.push(InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::Virtual { id: vfid as u8 },
                network_segment_id: Some(offset_segment_id(vfid + 1)),
                ip_addrs: HashMap::new(),
                interface_prefixes: HashMap::new(),
                network_segment_gateways: HashMap::new(),
                host_inband_mac_address: None,
                network_details: None,
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
        config.interfaces[0].network_segment_id = Some(DUPLICATE_SEGMENT_ID.into());
        config.interfaces[1].network_segment_id = Some(DUPLICATE_SEGMENT_ID.into());
        assert!(config.validate().is_err());
    }
}
