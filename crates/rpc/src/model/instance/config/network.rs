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
use std::net::IpAddr;

use itertools::Itertools;
use model::instance::config::network::{
    DeviceLocator, InstanceInterfaceConfig, InstanceInterfaceRoutingProfile, InstanceNetworkConfig,
    InterfaceFunctionId, InterfaceFunctionType, Ipv6InterfaceConfig, NetworkDetails,
};

use crate as rpc;
use crate::errors::RpcDataConversionError;

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
        let auto = config.auto;

        if auto && !config.interfaces.is_empty() {
            return Err(RpcDataConversionError::InvalidArgument(
                "InstanceNetworkConfig.auto cannot be combined with explicit interfaces"
                    .to_string(),
            ));
        }

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

            if iface.ip_address.is_some()
                && matches!(network_details, Some(NetworkDetails::NetworkSegment(..)))
            {
                return Err(RpcDataConversionError::InvalidArgument(
                    "explicit IP requests are only supported for VPC prefixes".to_string(),
                ));
            };

            // ipv6_interface_config is only valid alongside a VPC prefix -- it makes no
            // sense with a NetworkSegment (segment already has its own prefixes) or
            // without any network_details at all. Check before parsing.
            if iface.ipv6_interface_config.is_some()
                && !matches!(network_details, Some(NetworkDetails::VpcPrefixId(_)))
            {
                return Err(RpcDataConversionError::InvalidArgument(
                    "ipv6 requires vpc_prefix_id to be set".to_string(),
                ));
            };

            // Prevent setting an IPv6 address in ip_address when ipv6_interface_config
            // is also set -- that would mean two IPv6 configs for the same interface,
            // and DHCP can't hand out two IPs of the same family on one interface.
            if let Some(ref ip_str) = iface.ip_address
                && iface.ipv6_interface_config.is_some()
                && ip_str.parse::<std::net::Ipv6Addr>().is_ok()
            {
                return Err(RpcDataConversionError::InvalidArgument(
                    "ip_address cannot be IPv6 when ipv6_interface_config is also set -- use ipv6_interface_config.ip_address for the IPv6 address".to_string(),
                ));
            }

            let ipv6_interface_config = iface
                .ipv6_interface_config
                .map(
                    |v6| -> Result<Ipv6InterfaceConfig, RpcDataConversionError> {
                        let vpc_prefix_id =
                            v6.vpc_prefix_id
                                .ok_or(RpcDataConversionError::MissingArgument(
                                    "InstanceInterfaceIpv6Config::vpc_prefix_id",
                                ))?;
                        let requested_ip_addr = v6
                            .ip_address
                            .map(|s| {
                                s.parse::<std::net::Ipv6Addr>().map_err(|_| {
                                    RpcDataConversionError::InvalidIpAddress(format!(
                                        "IPv6 address expected, got: {s}"
                                    ))
                                })
                            })
                            .transpose()?;
                        Ok(Ipv6InterfaceConfig {
                            vpc_prefix_id,
                            requested_ip_addr,
                        })
                    },
                )
                .transpose()?;

            let device_locator = iface.device.map(|device| DeviceLocator {
                device,
                device_instance: iface.device_instance as usize,
            });

            let routing_profile = iface
                .routing_profile
                .map(
                    |profile| -> Result<InstanceInterfaceRoutingProfile, RpcDataConversionError> {
                        let allowed_anycast_prefixes = profile
                            .allowed_anycast_prefixes
                            .into_iter()
                            .map(|entry| entry.prefix.parse())
                            .collect::<Result<Vec<_>, _>>()?;

                        Ok(InstanceInterfaceRoutingProfile {
                            allowed_anycast_prefixes,
                        })
                    },
                )
                .transpose()?;

            interfaces.push(InstanceInterfaceConfig {
                function_id,
                network_segment_id,
                network_details,
                ip_addrs: HashMap::default(),
                requested_ip_addr: iface
                    .ip_address
                    .map(|i| i.parse::<IpAddr>())
                    .transpose()
                    .map_err(|e| RpcDataConversionError::InvalidIpAddress(e.to_string()))?,
                ipv6_interface_config,
                routing_profile,
                interface_prefixes: HashMap::default(),
                network_segment_gateways: HashMap::new(),
                host_inband_mac_address: None,
                device_locator,
                internal_uuid: uuid::Uuid::new_v4(),
            });
        }

        Ok(Self { interfaces, auto })
    }
}

impl TryFrom<InstanceNetworkConfig> for rpc::InstanceNetworkConfig {
    type Error = RpcDataConversionError;

    fn try_from(config: InstanceNetworkConfig) -> Result<rpc::InstanceNetworkConfig, Self::Error> {
        // This is where we prep the interface for "external" viewing,
        // stripping resolved interfaces in the case of an auto config,
        // but leaving them untouched otherwise.
        let config = config.into_external_view();
        let auto = config.auto;
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
                ip_address: iface.requested_ip_addr.map(|i| i.to_string()),
                ipv6_interface_config: iface.ipv6_interface_config.map(|v6| {
                    rpc::forge::InstanceInterfaceIpv6Config {
                        vpc_prefix_id: Some(v6.vpc_prefix_id),
                        ip_address: v6.requested_ip_addr.map(|i| i.to_string()),
                    }
                }),
                routing_profile: iface.routing_profile.map(|profile| {
                    rpc::forge::InstanceInterfaceRoutingProfile {
                        allowed_anycast_prefixes: profile
                            .allowed_anycast_prefixes
                            .into_iter()
                            .map(|prefix| rpc::forge::PrefixFilterPolicyEntry {
                                prefix: prefix.to_string(),
                            })
                            .collect(),
                    }
                }),
            });
        }

        Ok(rpc::InstanceNetworkConfig { interfaces, auto })
    }
}

impl From<&InstanceInterfaceRoutingProfile> for rpc::forge::FlatInterfaceRoutingProfile {
    fn from(profile: &InstanceInterfaceRoutingProfile) -> Self {
        Self {
            allowed_anycast_prefixes: profile
                .allowed_anycast_prefixes
                .iter()
                .map(|prefix| rpc::forge::PrefixFilterPolicyEntry {
                    prefix: prefix.to_string(),
                })
                .collect(),
        }
    }
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
    type Error = RpcDataConversionError;

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
}

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{scenarios, value_scenarios};
    use carbide_uuid::network::NetworkSegmentId;
    use carbide_uuid::vpc::VpcPrefixId;
    use model::instance::config::network::{INTERFACE_VFID_MAX, INTERFACE_VFID_MIN};

    use super::*;

    /// Creates a valid instance network configuration using the maximum
    /// amount of interface
    const BASE_SEGMENT_ID: uuid::Uuid = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c0000");
    fn offset_segment_id(offset: u8) -> NetworkSegmentId {
        uuid::Uuid::from_u128(BASE_SEGMENT_ID.as_u128() + offset as u128).into()
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
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
            }],
            auto: false,
        };

        let netconfig: InstanceNetworkConfig = config.try_into().unwrap();
        assert_eq!(
            netconfig.interfaces,
            &[InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::Physical {},
                network_segment_id: Some(BASE_SEGMENT_ID.into()),
                ip_addrs: HashMap::new(),
                requested_ip_addr: None,
                ipv6_interface_config: None,
                routing_profile: None,
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
            ip_address: None,
            ipv6_interface_config: None,
            routing_profile: None,
        }];
        for vfid in INTERFACE_VFID_MIN..=INTERFACE_VFID_MAX {
            interfaces.push(rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual as _,
                network_segment_id: Some(offset_segment_id(vfid + 1)),
                network_details: None,
                device: None,
                device_instance: 0u32,
                virtual_function_id: None,
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
            });
        }

        let config = rpc::InstanceNetworkConfig {
            interfaces,
            auto: false,
        };
        let netconfig: InstanceNetworkConfig = config.try_into().unwrap();
        let mut netconf_interfaces_iter = netconfig.interfaces.iter();

        let mut expected_interfaces = vec![InstanceInterfaceConfig {
            function_id: InterfaceFunctionId::Physical {},
            network_segment_id: Some(BASE_SEGMENT_ID.into()),
            ip_addrs: HashMap::new(),
            requested_ip_addr: None,
            ipv6_interface_config: None,
            routing_profile: None,
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
                requested_ip_addr: None,
                ipv6_interface_config: None,
                routing_profile: None,
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
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
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
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
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
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
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
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
            },
        ]
    }

    // Converting an rpc config validates virtual-function ids and assigns them.
    // Each row starts from `get_rpc_instance_network_config()`, optionally mutated,
    // and the op converts then projects the sorted VF ids out of the model (or
    // fails when the VF ids are invalid). The error type isn't pinned here -- a
    // duplicate or a mix of None/valid just `Fails`.
    #[test]
    fn test_validate_virtual_function_ids() {
        let all = get_rpc_instance_network_config();

        let only_physical = vec![all[0].clone()];

        let mut missing_1 = get_rpc_instance_network_config();
        missing_1.remove(2);

        let mut duplicate = get_rpc_instance_network_config();
        duplicate[2].virtual_function_id = Some(0);

        let mut mix = get_rpc_instance_network_config();
        mix[2].virtual_function_id = None;

        scenarios!(
            run = |interfaces| {
                let network_config = rpc::InstanceNetworkConfig {
                    interfaces,
                    auto: false,
                };
                let network_config =
                    InstanceNetworkConfig::try_from(network_config).map_err(drop)?;
                let vf_ids = network_config
                    .interfaces
                    .iter()
                    .filter_map(|x| match x.function_id {
                        InterfaceFunctionId::Virtual { id } => Some(id),
                        InterfaceFunctionId::Physical {} => None,
                    })
                    .sorted()
                    .collect_vec();
                Ok::<_, ()>(vf_ids)
            };
            "all VF ids present after converting" {
                all => Yields(vec![0, 1, 2]),
            }

            "removed vf_id 1 is absent from the parsed config" {
                missing_1 => Yields(vec![0, 2]),
            }

            "only a physical interface yields no VF ids" {
                only_physical => Yields(vec![]),
            }

            "duplicate VF id is rejected" {
                duplicate => Fails,
            }

            "mix of None and valid VF ids is rejected" {
                mix => Fails,
            }
        );
    }

    #[test]
    fn test_network_details_serde_backward_compat_single() {
        // Old JSON format: single VPC prefix.
        let uuid = uuid::Uuid::new_v4();
        let json = format!(r#"{{"VpcPrefixId":"{}"}}"#, uuid);
        let nd: NetworkDetails = serde_json::from_str(&json).unwrap();
        assert_eq!(nd, NetworkDetails::VpcPrefixId(VpcPrefixId::from(uuid)));

        // Round-trip
        let serialized = serde_json::to_string(&nd).unwrap();
        let nd2: NetworkDetails = serde_json::from_str(&serialized).unwrap();
        assert_eq!(nd, nd2);
    }

    #[test]
    fn test_network_details_rpc_roundtrip_single() {
        let id = VpcPrefixId::new();
        let model_nd = NetworkDetails::VpcPrefixId(id);

        // Model -> RPC
        let rpc_nd: rpc::forge::instance_interface_config::NetworkDetails = model_nd.clone().into();
        assert!(matches!(
            rpc_nd,
            rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(_)
        ));

        // RPC -> Model
        let roundtripped: NetworkDetails = rpc_nd.try_into().unwrap();
        assert_eq!(roundtripped, model_nd);
    }

    #[test]
    fn test_dual_stack_rpc_roundtrip() {
        // Verify that ipv6 survives a model → rpc → model round-trip.
        let v4_id = VpcPrefixId::new();
        let v6_id = VpcPrefixId::new();

        let model_config = InstanceNetworkConfig {
            interfaces: vec![InstanceInterfaceConfig {
                function_id: InterfaceFunctionId::Physical {},
                network_segment_id: None,
                network_details: Some(NetworkDetails::VpcPrefixId(v4_id)),
                ip_addrs: HashMap::default(),
                requested_ip_addr: None,
                ipv6_interface_config: Some(Ipv6InterfaceConfig {
                    vpc_prefix_id: v6_id,
                    requested_ip_addr: Some("2001:db8::1".parse().unwrap()),
                }),
                routing_profile: None,
                interface_prefixes: HashMap::default(),
                network_segment_gateways: HashMap::default(),
                host_inband_mac_address: None,
                device_locator: None,
                internal_uuid: uuid::Uuid::new_v4(),
            }],
            auto: false,
        };

        // Model -> RPC
        let rpc_config: rpc::InstanceNetworkConfig = model_config.try_into().unwrap();
        let rpc_iface = &rpc_config.interfaces[0];
        assert!(matches!(
            rpc_iface.network_details,
            Some(rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(_))
        ));
        assert_eq!(
            rpc_iface
                .ipv6_interface_config
                .as_ref()
                .and_then(|v6| v6.vpc_prefix_id),
            Some(v6_id)
        );
        assert_eq!(
            rpc_iface
                .ipv6_interface_config
                .as_ref()
                .and_then(|v6| v6.ip_address.clone()),
            Some("2001:db8::1".to_string())
        );

        // RPC -> Model
        let roundtripped: InstanceNetworkConfig = rpc_config.try_into().unwrap();
        let v6 = roundtripped.interfaces[0]
            .ipv6_interface_config
            .as_ref()
            .unwrap();
        assert_eq!(v6.vpc_prefix_id, v6_id);
        assert_eq!(v6.requested_ip_addr, Some("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_interface_routing_profile_rpc_roundtrip() {
        let segment_id = NetworkSegmentId::new();
        let anycast_prefix = "192.0.2.0/24";

        // Convert a wire interface profile into the internal model.
        let rpc_config = rpc::InstanceNetworkConfig {
            interfaces: vec![rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some(segment_id),
                network_details: Some(
                    rpc::forge::instance_interface_config::NetworkDetails::SegmentId(segment_id),
                ),
                device: None,
                device_instance: 0,
                virtual_function_id: None,
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: Some(rpc::forge::InstanceInterfaceRoutingProfile {
                    allowed_anycast_prefixes: vec![rpc::forge::PrefixFilterPolicyEntry {
                        prefix: anycast_prefix.to_string(),
                    }],
                }),
            }],
            auto: false,
        };

        let model: InstanceNetworkConfig = rpc_config.try_into().unwrap();
        assert_eq!(
            model.interfaces[0]
                .routing_profile
                .as_ref()
                .unwrap()
                .allowed_anycast_prefixes,
            vec![anycast_prefix.parse::<ipnetwork::IpNetwork>().unwrap()]
        );

        // Convert the model back to the wire shape and verify the prefix is preserved.
        let rpc_config: rpc::InstanceNetworkConfig = model.try_into().unwrap();
        assert_eq!(
            rpc_config.interfaces[0]
                .routing_profile
                .as_ref()
                .unwrap()
                .allowed_anycast_prefixes[0]
                .prefix,
            anycast_prefix
        );
    }

    #[test]
    fn test_interface_routing_profile_rejects_invalid_prefix() {
        let segment_id = NetworkSegmentId::new();

        // Invalid anycast prefixes should be rejected at the RPC boundary.
        let rpc_config = rpc::InstanceNetworkConfig {
            interfaces: vec![rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some(segment_id),
                network_details: Some(
                    rpc::forge::instance_interface_config::NetworkDetails::SegmentId(segment_id),
                ),
                device: None,
                device_instance: 0,
                virtual_function_id: None,
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: Some(rpc::forge::InstanceInterfaceRoutingProfile {
                    allowed_anycast_prefixes: vec![rpc::forge::PrefixFilterPolicyEntry {
                        prefix: "not-a-prefix".to_string(),
                    }],
                }),
            }],
            auto: false,
        };

        let result: Result<InstanceNetworkConfig, _> = rpc_config.try_into();
        assert!(matches!(
            result,
            Err(RpcDataConversionError::NetworkParseError(_))
        ));
    }

    // ipv6_interface_config alongside ip_address / network_details is gated at the
    // RPC boundary: each row builds one interface config and the op asserts only
    // whether the conversion succeeds (`true`) or is rejected (`false`).
    #[test]
    fn test_ipv6_interface_config_acceptance() {
        let v6_id = VpcPrefixId::new();
        let v4_id = VpcPrefixId::new();

        // ipv6 without vpc_prefix_id (network_details is a segment) should be rejected.
        let ipv6_without_vpc_prefix = rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: Some(NetworkSegmentId::new()),
            network_details: Some(
                rpc::forge::instance_interface_config::NetworkDetails::SegmentId(
                    NetworkSegmentId::new(),
                ),
            ),
            device: None,
            device_instance: 0,
            virtual_function_id: None,
            ip_address: None,
            ipv6_interface_config: Some(rpc::forge::InstanceInterfaceIpv6Config {
                vpc_prefix_id: Some(v6_id),
                ip_address: None,
            }),
            routing_profile: None,
        };

        // An IPv6 ip_address AND ipv6_interface_config together should be rejected.
        let v6_ip_with_ipv6_config = rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: None,
            network_details: Some(
                rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(v4_id),
            ),
            device: None,
            device_instance: 0,
            virtual_function_id: None,
            ip_address: Some("2001:db8::1".to_string()),
            ipv6_interface_config: Some(rpc::forge::InstanceInterfaceIpv6Config {
                vpc_prefix_id: Some(v6_id),
                ip_address: None,
            }),
            routing_profile: None,
        };

        // An IPv4 ip_address AND ipv6_interface_config is fine (dual-stack).
        let v4_ip_with_ipv6_config = rpc::InstanceInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical as i32,
            network_segment_id: None,
            network_details: Some(
                rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(v4_id),
            ),
            device: None,
            device_instance: 0,
            virtual_function_id: None,
            ip_address: Some("10.0.0.1".to_string()),
            ipv6_interface_config: Some(rpc::forge::InstanceInterfaceIpv6Config {
                vpc_prefix_id: Some(v6_id),
                ip_address: None,
            }),
            routing_profile: None,
        };

        value_scenarios!(
            run = |iface| {
                let rpc_config = rpc::InstanceNetworkConfig {
                    interfaces: vec![iface],
                    auto: false,
                };
                InstanceNetworkConfig::try_from(rpc_config).is_ok()
            };
            "ipv6 without vpc_prefix_id is rejected" {
                ipv6_without_vpc_prefix => false,
            }

            "ipv6 ip_address with ipv6_interface_config is rejected" {
                v6_ip_with_ipv6_config => false,
            }

            "ipv4 ip_address with ipv6_interface_config is allowed" {
                v4_ip_with_ipv6_config => true,
            }
        );
    }

    #[test]
    fn test_v6_only_uses_primary_field() {
        // v6-only allocation: just put the v6 prefix in the primary vpc_prefix_id field.
        let v6_id = VpcPrefixId::new();
        let rpc_config = rpc::InstanceNetworkConfig {
            interfaces: vec![rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: None,
                network_details: Some(
                    rpc::forge::instance_interface_config::NetworkDetails::VpcPrefixId(v6_id),
                ),
                device: None,
                device_instance: 0,
                virtual_function_id: None,
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
            }],
            auto: false,
        };
        let model: InstanceNetworkConfig = rpc_config.try_into().unwrap();
        assert_eq!(
            model.interfaces[0].network_details,
            Some(NetworkDetails::VpcPrefixId(v6_id))
        );
        assert_eq!(model.interfaces[0].ipv6_interface_config, None);
    }

    #[test]
    fn test_auto_rejects_explicit_interfaces() {
        // `auto: true` and populated interfaces are mutually exclusive,
        // so this should error.
        let rpc_config = rpc::InstanceNetworkConfig {
            interfaces: vec![rpc::InstanceInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical as i32,
                network_segment_id: Some(NetworkSegmentId::new()),
                network_details: None,
                device: None,
                device_instance: 0,
                virtual_function_id: None,
                ip_address: None,
                ipv6_interface_config: None,
                routing_profile: None,
            }],
            auto: true,
        };
        let result: Result<InstanceNetworkConfig, _> = rpc_config.try_into();
        let err = result.expect_err("auto + non-empty interfaces should be rejected");
        let msg = format!("{err}");
        assert!(
            msg.contains("auto"),
            "error should mention auto, got: {msg}"
        );
    }

    #[test]
    fn test_auto_allows_empty_interfaces() {
        // Verify "auto" requests work.
        let rpc_config = rpc::InstanceNetworkConfig {
            interfaces: vec![],
            auto: true,
        };
        let model: InstanceNetworkConfig = rpc_config
            .try_into()
            .expect("auto + empty should round-trip");
        assert!(model.auto);
        assert!(model.interfaces.is_empty());
    }
}
