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

use std::collections::HashMap;
use std::convert::Into;
use std::net::IpAddr;

use ::rpc::errors::RpcDataConversionError;
use carbide_uuid::machine::MachineId;
use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use ipnetwork::IpNetwork;
use itertools::Itertools;
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

use crate::SerializableMacAddress;
use crate::instance::config::network::{
    InstanceInterfaceConfig, InstanceNetworkConfig, InterfaceFunctionId,
};
use crate::instance::status::SyncState;
use crate::machine::Machine;
use crate::network_security_group::NetworkSecurityGroupStatusObservation;

/// Status of the networking subsystem of an instance
///
/// The status report is only valid against one particular version of
/// [InstanceInterfaceConfig](crate::model::instance::config::network::InstanceInterfaceConfig). It can not be interpreted without it, since
/// e.g. the amount and configuration of network interfaces can change between
/// configs.
///
/// Since the user can change the configuration at any point in time for an instance,
/// we can not directly store this status in the database - it might not match
/// the newest config anymore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceNetworkStatus {
    /// Status for each configured interface
    ///
    /// Each entry in this status array maps to its corresponding entry in the
    /// Config section. E.g. `instance.status.network.interface_status[1]`
    /// would map to `instance.config.network.interface_configs[1]`.
    pub interfaces: Vec<InstanceInterfaceStatus>,

    /// Whether all desired network changes that the user has applied have taken effect
    /// This includes:
    /// - Whether `InstanceNetworkConfig` is of exactly the same version as the
    ///   version the user desires.
    /// - Whether the version of each security policy that is either directly referenced
    ///   as part of an `InstanceInterfaceConfig` or indirectly referenced via the
    ///   the security policies that are applied to the VPC or NetworkSegment
    ///   is exactly the same version as the version the user desires.
    ///
    /// Note for the implementation: We need to monitor all these config versions
    /// on the feedback path from DPU to carbide in order to know whether the
    /// changes have indeed taken effect.
    /// TODO: Do we also want to show all applied versions here, or just track them
    /// internally? Probably not helpful for tenants at all - but it could be helpful
    /// for the Forge operating team to debug settings that to do do not go in-sync
    /// without having to attach to the database.
    pub configs_synced: SyncState,
}

impl TryFrom<InstanceNetworkStatus> for rpc::InstanceNetworkStatus {
    type Error = RpcDataConversionError;

    fn try_from(status: InstanceNetworkStatus) -> Result<Self, Self::Error> {
        let mut interfaces = Vec::with_capacity(status.interfaces.len());
        for iface in status.interfaces {
            interfaces.push(rpc::InstanceInterfaceStatus::try_from(iface)?);
        }
        Ok(rpc::InstanceNetworkStatus {
            interfaces,
            configs_synced: rpc::SyncState::try_from(status.configs_synced)? as i32,
        })
    }
}

impl InstanceNetworkStatus {
    /// Derives an Instances network status from the users desired config
    /// and status that we observed from the networking subsystem.
    ///
    /// This mechanism guarantees that the status we return to the user always
    /// matches the latest `Config` set by the user. We can not directly
    /// forwarding the last observed status without taking `Config` into account,
    /// because the observation might have been related to a different config,
    /// and the interfaces therefore won't match.
    pub fn from_config_and_observations(
        dpu_id_to_device_map: HashMap<String, Vec<MachineId>>,
        config: Versioned<&InstanceNetworkConfig>,
        observations: &HashMap<MachineId, InstanceNetworkStatusObservation>,
        is_network_config_request_pending: bool,
    ) -> Self {
        if is_network_config_request_pending {
            return Self::unsynchronized_for_config(&config);
        }

        if observations
            .iter()
            .any(|obs| obs.1.config_version != config.version)
        {
            return Self::unsynchronized_for_config(&config);
        }

        // Observations without interfaces are from unused DPUs.  filter them out
        let observations: HashMap<&MachineId, &InstanceNetworkStatusObservation> = observations
            .iter()
            .filter(|obs| !obs.1.interfaces.is_empty())
            .collect();

        if observations.is_empty() {
            if config.is_host_inband() {
                return Self::synchronized_from_host_interfaces(config.value.interfaces.clone());
            } else {
                return Self::unsynchronized_for_config(&config);
            }
        }

        let mut configs_synced = SyncState::Synced;
        let mut missing_dpus = Vec::default();
        let mut interfaces = Vec::default();
        for config_iface in &config.interfaces {
            let device_locator = config_iface.device_locator.as_ref();

            let dpu_machine_id = device_locator.and_then(|dl| {
                dpu_id_to_device_map
                    .get(&dl.device)
                    .and_then(|id_vec| id_vec.get(dl.device_instance))
            });
            match dpu_machine_id {
                Some(dpu_machine_id) => match observations.get(dpu_machine_id) {
                    Some(dpu_obs) => {
                        let obs_iface = dpu_obs
                            .interfaces
                            .iter()
                            .find(|obs_iface| obs_iface.function_id == config_iface.function_id);

                        match obs_iface {
                            Some(obs_iface) => {
                                interfaces.push(InstanceInterfaceStatus {
                                    function_id: config_iface.function_id.clone(),
                                    mac_address: obs_iface.mac_address.map(Into::into),
                                    addresses: obs_iface.addresses.clone(),
                                    prefixes: obs_iface.prefixes.clone(),
                                    gateways: obs_iface.gateways.clone(),
                                    device: config_iface
                                        .device_locator
                                        .as_ref()
                                        .map(|dl| dl.device.clone()),
                                    device_instance: config_iface
                                        .device_locator
                                        .as_ref()
                                        .map(|dl| dl.device_instance)
                                        .unwrap_or_default(),
                                });
                            }
                            None => {
                                tracing::error!(
                                    dpu_machine_id = ?dpu_machine_id, function_id = ?config_iface.function_id, ?config, ?observations,
                                    "Could not find matching status for interface",
                                );

                                // TODO: Might also be worthwhile to return an error?
                                // On the other hand the error is also visible via returning no IPs - and at least we don't break
                                // all other interfaces this way
                                // UPDATE:  added pending status.
                                interfaces.push(InstanceInterfaceStatus {
                                    function_id: config_iface.function_id.clone(),
                                    mac_address: None,
                                    addresses: Vec::new(),
                                    prefixes: Vec::new(),
                                    gateways: Vec::new(),
                                    device: config_iface
                                        .device_locator
                                        .as_ref()
                                        .map(|dl| dl.device.clone()),
                                    device_instance: config_iface
                                        .device_locator
                                        .as_ref()
                                        .map(|dl| dl.device_instance)
                                        .unwrap_or_default(),
                                });
                                configs_synced = SyncState::Pending;
                            }
                        }
                    }
                    None => {
                        interfaces.push(InstanceInterfaceStatus {
                            function_id: config_iface.function_id.clone(),
                            mac_address: None,
                            addresses: Vec::new(),
                            prefixes: Vec::new(),
                            gateways: Vec::new(),
                            device: config_iface
                                .device_locator
                                .as_ref()
                                .map(|dl| dl.device.clone()),
                            device_instance: config_iface
                                .device_locator
                                .as_ref()
                                .map(|dl| dl.device_instance)
                                .unwrap_or_default(),
                        });
                        missing_dpus.push(dpu_machine_id);
                        configs_synced = SyncState::Pending;
                    }
                },
                None => {
                    if config
                        .interfaces
                        .iter()
                        .filter(|iface| iface.function_id == InterfaceFunctionId::Physical {})
                        .count()
                        > 1
                    {
                        tracing::error!(
                            "Found multiple physical interfaces when no device specified: {:?}",
                            config
                        );
                        return Self::unsynchronized_for_config(&config);
                    }

                    if observations.is_empty() {
                        return Self::unsynchronized_for_config(&config);
                    }

                    if let Some((_id, dpu_obs)) = observations.iter().next() {
                        let intf_obs = dpu_obs
                            .interfaces
                            .iter()
                            .find(|iface| iface.function_id == config_iface.function_id);
                        match intf_obs {
                            Some(intf_obs) => {
                                interfaces.push(InstanceInterfaceStatus {
                                    function_id: config_iface.function_id.clone(),
                                    mac_address: intf_obs.mac_address.map(Into::into),
                                    addresses: intf_obs.addresses.clone(),
                                    prefixes: intf_obs.prefixes.clone(),
                                    gateways: intf_obs.gateways.clone(),
                                    device: config_iface
                                        .device_locator
                                        .as_ref()
                                        .map(|dl| dl.device.clone()),
                                    device_instance: config_iface
                                        .device_locator
                                        .as_ref()
                                        .map(|dl| dl.device_instance)
                                        .unwrap_or_default(),
                                });
                            }
                            None => {
                                tracing::error!(
                                    function_id = ?config_iface.function_id, ?config, ?observations,
                                    "Could not find matching status for interface for legacy config",
                                );

                                // TODO: Might also be worthwhile to return an error?
                                // On the other hand the error is also visible via returning no IPs - and at least we don't break
                                // all other interfaces this way
                                interfaces.push(InstanceInterfaceStatus {
                                    function_id: config_iface.function_id.clone(),
                                    mac_address: None,
                                    addresses: Vec::new(),
                                    prefixes: Vec::new(),
                                    gateways: Vec::new(),
                                    device: config_iface
                                        .device_locator
                                        .as_ref()
                                        .map(|dl| dl.device.clone()),
                                    device_instance: config_iface
                                        .device_locator
                                        .as_ref()
                                        .map(|dl| dl.device_instance)
                                        .unwrap_or_default(),
                                });
                            }
                        }
                    }
                }
            }
        }

        if !missing_dpus.is_empty() {
            tracing::info!(
                "Missing observations for DPUs: {}",
                missing_dpus.into_iter().join(",")
            );
        }

        Self {
            interfaces,
            configs_synced,
        }
    }

    /// Creates a `InstanceNetworkStatus` report for cases there the configuration
    /// has not been synchronized.
    ///
    /// This status report will contain an interface for each requested interface,
    /// but all interfaces will have no addresses assigned to them.
    fn unsynchronized_for_config(config: &InstanceNetworkConfig) -> Self {
        Self {
            interfaces: config
                .interfaces
                .iter()
                .map(|iface| InstanceInterfaceStatus {
                    function_id: iface.function_id.clone(),
                    mac_address: None,
                    addresses: Vec::new(),
                    prefixes: Vec::new(),
                    gateways: Vec::new(),
                    device: iface.device_locator.as_ref().map(|dl| dl.device.clone()),
                    device_instance: iface
                        .device_locator
                        .as_ref()
                        .map(|dl| dl.device_instance)
                        .unwrap_or_default(),
                })
                .collect(),
            configs_synced: SyncState::Pending,
        }
    }

    /// Creates an `InstanceNetworkStatus` report for cases where all interfaces on the instance are
    /// host-inband (and we do not expect any observations.)
    fn synchronized_from_host_interfaces(interfaces: Vec<InstanceInterfaceConfig>) -> Self {
        Self {
            interfaces: interfaces
                .into_iter()
                .map(InstanceInterfaceStatus::from_host_inband_interface)
                .collect(),
            configs_synced: SyncState::Synced,
        }
    }
}

/// The actual status of a single network interface of an instance
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstanceInterfaceStatus {
    /// The function ID that is assigned to this interface
    pub function_id: InterfaceFunctionId,

    /// The MAC address which has been assigned to this interface
    /// The list will be empty if interface configuration hasn't been completed
    /// and therefore the address is unknown.
    pub mac_address: Option<MacAddress>,

    /// The list of IP addresses that had been assigned to this interface,
    /// based on the requested subnet.
    /// The list will be empty if interface configuration hasn't been completed
    pub addresses: Vec<IpAddr>,

    // The list of IP prefixes that have been assigned to this interface
    // out of the requested subnet (where the prefix allocated to the interface
    // may be a /30 in the case of FNN, or just a /32 in the case of ETV).
    //
    // This is similar to `gateways`, in that there is one `prefix` for each
    // address in `addresses`.
    ///
    /// The list will be empty if interface configuration hasn't been completed
    pub prefixes: Vec<IpNetwork>,

    /// The list of gateways, in CIDR notation, one for each address in `addresses`.
    pub gateways: Vec<IpNetwork>,

    pub device: Option<String>,
    pub device_instance: usize,
}

impl InstanceInterfaceStatus {
    /// Create a "synthetic" InstanceInterfaceStatus using an InstanceInterfaceConfig as a seed.
    /// Host-inband interfaces do not get real network status observations, so we construct status
    /// ourselves from the host interface's config.
    pub fn from_host_inband_interface(mut value: InstanceInterfaceConfig) -> Self {
        let (prefix_ids, addresses): (Vec<_>, Vec<_>) = value.ip_addrs.into_iter().unzip();

        // For each NetworkPrefixId we saw in ip_addrs, get that entry from the
        // network_segment_gateways map. Collecting them into an Option<Vec<IpNetwork>> returns None
        // if any of them were not found.
        let gateways = prefix_ids
            .iter()
            .map(|id| if let Some(gw) = value.network_segment_gateways.remove(id) {
                Some(gw)
            } else {
                tracing::warn!("Missing gateway in InstanceInterfaceConfig for network prefix {id}, gateways field will be empty.");
                None
            })
            .collect::<Option<Vec<_>>>()
            .unwrap_or_default();

        // Build a map of prefixes by taking the gateway field (which already is an IpNetwork e.g.
        // 10.1.2.1/24) and building an IpNetwork from the gateway's prefix (e.g. 10.1.2.0/24)
        let prefixes = gateways
            .iter()
            // Unwrap safety: This only fails if the prefix length passed to IpNetwork::new() is
            // invalid, which can't happen because we're getting it from another (valid)
            // IpNetwork.
            .map(|gw| IpNetwork::new(gw.network(), gw.prefix()).unwrap())
            .collect();

        Self {
            function_id: value.function_id,
            mac_address: value.host_inband_mac_address,
            addresses,
            prefixes,
            gateways,
            device: None,
            device_instance: 0,
        }
    }
}

impl TryFrom<InstanceInterfaceStatus> for rpc::InstanceInterfaceStatus {
    type Error = RpcDataConversionError;

    fn try_from(status: InstanceInterfaceStatus) -> Result<Self, Self::Error> {
        Ok(rpc::InstanceInterfaceStatus {
            virtual_function_id: match status.function_id {
                InterfaceFunctionId::Physical {} => None,
                InterfaceFunctionId::Virtual { id } => Some(id as u32),
            },
            mac_address: status.mac_address.map(|mac| mac.to_string()),
            addresses: status
                .addresses
                .into_iter()
                .map(|ip| ip.to_string())
                .collect(),
            prefixes: status
                .prefixes
                .into_iter()
                .map(|ip_network| ip_network.to_string())
                .collect(),
            gateways: status
                .gateways
                .into_iter()
                .map(|ip| ip.to_string())
                .collect(),
            device: status.device,
            device_instance: status.device_instance as u32,
        })
    }
}

/// The network status that was last reported by the networking subsystem
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceNetworkStatusObservation {
    /// The version of the config that is applied on the networking subsystem
    /// Only if the version is equivalent to the latest desired version we
    /// can actually interpret the results. If the version is outdated, then the
    /// list of interfaces might actually relate to a different interfaces than
    /// the ones that are currently required by the networking config.
    pub config_version: ConfigVersion,

    /// Observed status of the instance config version
    #[serde(default)]
    pub instance_config_version: Option<ConfigVersion>,

    /// Observed status for each configured interface
    #[serde(default)]
    pub interfaces: Vec<InstanceInterfaceStatusObservation>,

    /// When this status was observed
    pub observed_at: DateTime<Utc>,
}

impl InstanceNetworkStatusObservation {
    pub fn any_observed_version_changed(&self, other: &Self) -> bool {
        self.config_version != other.config_version
            || self.instance_config_version != other.instance_config_version
    }

    pub fn aggregate_instance_observation(
        dpu_snapshots: &[Machine],
    ) -> HashMap<MachineId, InstanceNetworkStatusObservation> {
        let mut observation_map = HashMap::default();

        for dpu_snapshot in dpu_snapshots {
            if let Some(obs) = dpu_snapshot
                .network_status_observation
                .as_ref()
                .and_then(|x| x.instance_network_observation.as_ref())
                .map(|m| InstanceNetworkStatusObservation {
                    config_version: m.config_version,
                    instance_config_version: m.instance_config_version,
                    interfaces: m.interfaces.clone(),
                    observed_at: m.observed_at,
                })
            {
                observation_map.insert(dpu_snapshot.id, obs);
            }
        }

        observation_map
    }
}

/// The actual status of a single network interface of an instance
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceInterfaceStatusObservation {
    /// The function ID that is assigned to this interface
    pub function_id: InterfaceFunctionId,

    /// The MAC address which has been assigned to this interface
    /// The list will be empty if interface configuration hasn't been completed
    /// and therefore the address is unknown.
    #[serde(default)]
    pub mac_address: Option<SerializableMacAddress>,

    /// The list of IP addresses that had been assigned to this interface,
    /// based on the requested subnet.
    /// The list will be empty if interface configuration hasn't been completed
    #[serde(default)]
    pub addresses: Vec<IpAddr>,

    // The list of IP prefixes that have been assigned to this interface
    // out of the requested subnet (where the prefix allocated to the interface
    // may be a /30 in the case of FNN, or just a /32 in the case of ETV).
    //
    // This is similar to `gateways`, in that there is one `prefix` for each
    // address in `addresses`.
    ///
    /// The list will be empty if interface configuration hasn't been completed
    #[serde(default)]
    pub prefixes: Vec<IpNetwork>,

    /// The list of gateways, in CIDR notation, one for each address in `addresses`.
    #[serde(default)]
    pub gateways: Vec<IpNetwork>,

    /// The details of the network security that has
    /// actually been applied to the interface.
    pub network_security_group: Option<NetworkSecurityGroupStatusObservation>,

    /// An ID used to associated the interface status with the interface config.
    #[serde(default)]
    pub internal_uuid: Option<uuid::Uuid>,
}

impl TryFrom<rpc::InstanceInterfaceStatusObservation> for InstanceInterfaceStatusObservation {
    type Error = RpcDataConversionError;

    fn try_from(observation: rpc::InstanceInterfaceStatusObservation) -> Result<Self, Self::Error> {
        let function_id = match observation.function_type() {
            rpc::forge::InterfaceFunctionType::Physical => InterfaceFunctionId::Physical {},
            rpc::forge::InterfaceFunctionType::Virtual => {
                InterfaceFunctionId::try_virtual_from(observation.virtual_function_id() as u8)
                    .map_err(|_| {
                        RpcDataConversionError::InvalidVirtualFunctionId(
                            observation.virtual_function_id() as usize,
                        )
                    })?
            }
        };

        let addresses = observation
            .addresses
            .iter()
            .map(|addr| {
                addr.parse::<IpAddr>()
                    .map_err(|_| RpcDataConversionError::InvalidIpAddress(addr.clone()))
            })
            .try_collect()?;

        let internal_uuid = if let Some(internal_uuid) = &observation.internal_uuid {
            Some(internal_uuid.try_into().map_err(|_| {
                RpcDataConversionError::InvalidUuid("internal_uuid", internal_uuid.to_string())
            })?)
        } else {
            None
        };

        Ok(Self {
            function_id,
            addresses,
            prefixes: observation
                .prefixes
                .iter()
                .map(|ip_network| {
                    IpNetwork::try_from(ip_network.as_str())
                        .map_err(|_| Self::Error::InvalidCidr(ip_network.to_string()))
                })
                .collect::<Result<Vec<IpNetwork>, Self::Error>>()?,
            gateways: observation
                .gateways
                .iter()
                .map(|gw| {
                    IpNetwork::try_from(gw.as_str())
                        .map_err(|_| Self::Error::InvalidCidr(gw.to_string()))
                })
                .collect::<Result<Vec<IpNetwork>, Self::Error>>()?,
            mac_address: observation
                .mac_address
                .map(|addr| {
                    addr.parse::<MacAddress>()
                        .map_err(|_| RpcDataConversionError::InvalidMacAddress(addr))
                })
                .transpose()?
                .map(Into::into),
            network_security_group: observation
                .network_security_group
                .map(|nsgo| nsgo.try_into())
                .transpose()?,
            internal_uuid,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fmt::Write;
    use std::str::FromStr;

    use carbide_uuid::network::{NetworkPrefixId, NetworkSegmentId};

    use super::*;
    use crate::instance::config::network::InstanceInterfaceConfig;

    #[test]
    fn deserialize_old_network_status_observation() {
        let timestamp: DateTime<Utc> = Utc::now();
        let serialized_timestamp = format!("{timestamp:?}");
        let version = ConfigVersion::initial();

        let observation = InstanceNetworkStatusObservation {
            instance_config_version: None,
            config_version: version,
            interfaces: Vec::new(),
            observed_at: timestamp,
        };

        // Let's make sure the one without the instance_config_version
        // doesn't cause an issue.
        let serialized = format!(
            "{{\"config_version\":\"{version}\",\"interfaces\":[],\"observed_at\":\"{serialized_timestamp}\"}}"
        );

        assert_eq!(
            serde_json::from_str::<InstanceNetworkStatusObservation>(&serialized).unwrap(),
            observation
        );
    }

    #[test]
    fn serialize_network_status_observation() {
        let timestamp: DateTime<Utc> = Utc::now();
        let serialized_timestamp = format!("{timestamp:?}");
        let version = ConfigVersion::initial();
        let instance_version = version;

        let mut observation = InstanceNetworkStatusObservation {
            instance_config_version: Some(instance_version),
            config_version: version,
            interfaces: Vec::new(),
            observed_at: timestamp,
        };
        let serialized = serde_json::to_string(&observation).unwrap();
        assert_eq!(
            serialized,
            format!(
                r#"{{"config_version":"{}","instance_config_version":"{}","interfaces":[],"observed_at":"{}"}}"#,
                instance_version.version_string(),
                version.version_string(),
                serialized_timestamp
            )
        );
        assert_eq!(
            serde_json::from_str::<InstanceNetworkStatusObservation>(&serialized).unwrap(),
            observation
        );

        observation
            .interfaces
            .push(InstanceInterfaceStatusObservation {
                function_id: InterfaceFunctionId::Physical {},
                mac_address: None,
                addresses: Vec::new(),
                prefixes: Vec::new(),
                gateways: Vec::new(),
                network_security_group: None,
                internal_uuid: None,
            });
        observation
            .interfaces
            .push(InstanceInterfaceStatusObservation {
                function_id: InterfaceFunctionId::Virtual { id: 1 },
                mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 6]).into()),
                addresses: vec!["127.1.2.3".parse().unwrap()],
                prefixes: vec!["127.1.2.3/32".parse().unwrap()],
                gateways: vec!["127.1.2.1".parse().unwrap()],
                network_security_group: Some(NetworkSecurityGroupStatusObservation {
                    id: "c7c056c8-daa5-11ef-b221-c76a97b6c2ec".parse().unwrap(),
                    source: rpc::forge::NetworkSecurityGroupSource::NsgSourceInstance
                        .try_into()
                        .unwrap(),
                    version: "V1-T1".parse().unwrap(),
                }),
                internal_uuid: None,
            });
        let serialized = serde_json::to_string(&observation).unwrap();
        let mut expected = format!(
            r#"{{"config_version":"{}","instance_config_version":"{}","interfaces":["#,
            instance_version.version_string(),
            version.version_string()
        );
        write!(
            &mut expected,
            r#"{{"function_id":{{"type":"physical"}},"mac_address":null,"addresses":[],"prefixes":[],"gateways":[],"network_security_group":null,"internal_uuid":null}},"#
        )
        .unwrap();
        write!(&mut expected, r#"{{"function_id":{{"type":"virtual","id":1}},"mac_address":"01:02:03:04:05:06","addresses":["127.1.2.3"],"prefixes":["127.1.2.3/32"],"gateways":["127.1.2.1/32"],"network_security_group":{{"id":"c7c056c8-daa5-11ef-b221-c76a97b6c2ec","version":"V1-T1","source":"INSTANCE"}},"internal_uuid":null}}"#).unwrap();
        write!(
            &mut expected,
            r#"],"observed_at":"{serialized_timestamp}"}}"#
        )
        .unwrap();
        assert_eq!(serialized, expected);
        assert_eq!(
            serde_json::from_str::<InstanceNetworkStatusObservation>(&serialized).unwrap(),
            observation
        );
    }

    fn network_config() -> InstanceNetworkConfig {
        let base_uuid: NetworkSegmentId =
            uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let prefix_uuid: NetworkPrefixId =
            uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1400").into();

        InstanceNetworkConfig {
            interfaces: vec![
                InstanceInterfaceConfig {
                    function_id: InterfaceFunctionId::Physical {},
                    network_segment_id: Some(base_uuid),
                    ip_addrs: HashMap::from([(prefix_uuid, "127.0.0.1".parse().unwrap())]),
                    interface_prefixes: HashMap::from([(
                        prefix_uuid,
                        "127.0.0.1/32".parse().unwrap(),
                    )]),
                    network_segment_gateways: HashMap::from([(
                        prefix_uuid,
                        "127.0.0.1/32".parse().unwrap(),
                    )]),
                    host_inband_mac_address: None,
                    network_details: None,
                    device_locator: None,
                    internal_uuid: uuid::Uuid::new_v4(),
                },
                InstanceInterfaceConfig {
                    function_id: InterfaceFunctionId::Virtual { id: 1 },
                    network_segment_id: Some(base_uuid.offset(1)),
                    ip_addrs: HashMap::from([(
                        prefix_uuid.offset(1),
                        "127.0.0.2".parse().unwrap(),
                    )]),
                    interface_prefixes: HashMap::from([(
                        prefix_uuid.offset(1),
                        "127.0.0.2/32".parse().unwrap(),
                    )]),
                    network_segment_gateways: HashMap::from([(
                        prefix_uuid.offset(1),
                        "127.0.0.2/32".parse().unwrap(),
                    )]),
                    host_inband_mac_address: None,
                    network_details: None,
                    device_locator: None,
                    internal_uuid: uuid::Uuid::new_v4(),
                },
                InstanceInterfaceConfig {
                    function_id: InterfaceFunctionId::Virtual { id: 2 },
                    network_segment_id: Some(base_uuid.offset(2)),
                    ip_addrs: HashMap::from([(
                        prefix_uuid.offset(2),
                        "127.0.0.3".parse().unwrap(),
                    )]),
                    interface_prefixes: HashMap::from([(
                        prefix_uuid.offset(2),
                        "127.0.0.3/32".parse().unwrap(),
                    )]),
                    network_segment_gateways: HashMap::from([(
                        prefix_uuid.offset(2),
                        "127.0.0.3/32".parse().unwrap(),
                    )]),
                    host_inband_mac_address: None,
                    network_details: None,
                    device_locator: None,
                    internal_uuid: uuid::Uuid::new_v4(),
                },
            ],
        }
    }

    fn host_inband_network_config() -> InstanceNetworkConfig {
        let base_uuid: NetworkSegmentId =
            uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let prefix_uuid: NetworkPrefixId =
            uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1400").into();
        let internal_uuid1 = uuid::Uuid::new_v4();
        let internal_uuid2 = uuid::Uuid::new_v4();
        let internal_uuid3 = uuid::Uuid::new_v4();

        InstanceNetworkConfig {
            interfaces: vec![
                InstanceInterfaceConfig {
                    function_id: InterfaceFunctionId::Physical {},
                    network_segment_id: Some(base_uuid),
                    ip_addrs: HashMap::from([(prefix_uuid, "127.0.1.2".parse().unwrap())]),
                    interface_prefixes: HashMap::from([(
                        prefix_uuid,
                        "127.0.1.0/24".parse().unwrap(),
                    )]),
                    network_segment_gateways: HashMap::from([(
                        prefix_uuid,
                        "127.0.1.1/24".parse().unwrap(),
                    )]),
                    host_inband_mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 6])),
                    network_details: None,
                    device_locator: None,
                    internal_uuid: internal_uuid1,
                },
                InstanceInterfaceConfig {
                    function_id: InterfaceFunctionId::Virtual { id: 1 },
                    network_segment_id: Some(base_uuid.offset(1)),
                    ip_addrs: HashMap::from([(
                        prefix_uuid.offset(1),
                        "127.0.2.2".parse().unwrap(),
                    )]),
                    interface_prefixes: HashMap::from([(
                        prefix_uuid.offset(1),
                        "127.0.2.0/24".parse().unwrap(),
                    )]),
                    network_segment_gateways: HashMap::from([(
                        prefix_uuid.offset(1),
                        "127.0.2.1/24".parse().unwrap(),
                    )]),
                    host_inband_mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 16])),
                    network_details: None,
                    device_locator: None,
                    internal_uuid: internal_uuid2,
                },
                InstanceInterfaceConfig {
                    function_id: InterfaceFunctionId::Virtual { id: 2 },
                    network_segment_id: Some(base_uuid.offset(2)),
                    ip_addrs: HashMap::from([(
                        prefix_uuid.offset(2),
                        "127.0.3.2".parse().unwrap(),
                    )]),
                    interface_prefixes: HashMap::from([(
                        prefix_uuid.offset(2),
                        "127.0.3.0/24".parse().unwrap(),
                    )]),
                    network_segment_gateways: HashMap::from([(
                        prefix_uuid.offset(2),
                        "127.0.3.1/24".parse().unwrap(),
                    )]),
                    host_inband_mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 26])),
                    network_details: None,
                    device_locator: None,
                    internal_uuid: internal_uuid3,
                },
            ],
        }
    }

    const DPU_ID1: &str = "fm100dsvstfujf6mis0gpsoi81tadmllicv7rqo4s7gc16gi0t2478672vg";

    fn observations_for_config(
        config: &InstanceNetworkConfig,
        config_version: ConfigVersion,
    ) -> HashMap<MachineId, InstanceNetworkStatusObservation> {
        let mut observations = HashMap::default();

        // put the interfaces in a different order so the status are not sequential
        let interfaces = vec![
            &config.interfaces[2],
            &config.interfaces[0],
            &config.interfaces[1],
        ];
        let mut obs = Vec::default();

        for iface in interfaces {
            let mac_address = iface.host_inband_mac_address.map(|mac| mac.into());
            let addresses = iface.ip_addrs.values().copied().collect();
            let prefixes = iface.interface_prefixes.values().copied().collect();
            let gateways = iface.network_segment_gateways.values().copied().collect();

            obs.push(InstanceInterfaceStatusObservation {
                function_id: iface.function_id.clone(),
                mac_address,
                addresses,
                prefixes,
                gateways,
                network_security_group: Some(NetworkSecurityGroupStatusObservation {
                    id: "c7c056c8-daa5-11ef-b221-c76a97b6c2ec".parse().unwrap(),
                    source: rpc::forge::NetworkSecurityGroupSource::NsgSourceInstance
                        .try_into()
                        .unwrap(),
                    version: "V1-T1".parse().unwrap(),
                }),
                internal_uuid: Some(iface.internal_uuid),
            });
        }
        observations.insert(
            MachineId::from_str(DPU_ID1).unwrap(),
            InstanceNetworkStatusObservation {
                instance_config_version: None, // Reported by rpc::DpuNetworkStatus not rpc::InstanceNetworkStatusObservation
                config_version,
                observed_at: Utc::now(),
                interfaces: obs,
            },
        );
        observations
    }

    fn unsynced_status() -> InstanceNetworkStatus {
        InstanceNetworkStatus {
            interfaces: vec![
                InstanceInterfaceStatus {
                    function_id: InterfaceFunctionId::Physical {},
                    mac_address: None,
                    addresses: Vec::new(),
                    prefixes: Vec::new(),
                    gateways: Vec::new(),
                    device: None,
                    device_instance: 0,
                },
                InstanceInterfaceStatus {
                    function_id: InterfaceFunctionId::Virtual { id: 1 },
                    mac_address: None,
                    addresses: Vec::new(),
                    prefixes: Vec::new(),
                    gateways: Vec::new(),
                    device: None,
                    device_instance: 0,
                },
                InstanceInterfaceStatus {
                    function_id: InterfaceFunctionId::Virtual { id: 2 },
                    mac_address: None,
                    addresses: Vec::new(),
                    prefixes: Vec::new(),
                    gateways: Vec::new(),
                    device: None,
                    device_instance: 0,
                },
            ],
            configs_synced: SyncState::Pending,
        }
    }

    fn expected_status(config: &InstanceNetworkConfig) -> InstanceNetworkStatus {
        let mut interface_status = Vec::default();

        let mut iface_iter = config.interfaces.iter();
        let iface = iface_iter.next().unwrap();

        interface_status.push(InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::Physical {},
            mac_address: iface.host_inband_mac_address,
            addresses: iface.ip_addrs.values().copied().collect(),
            prefixes: iface.interface_prefixes.values().copied().collect(),
            gateways: iface.network_segment_gateways.values().copied().collect(),
            device: iface.device_locator.as_ref().map(|dl| dl.device.clone()),
            device_instance: iface
                .device_locator
                .as_ref()
                .map(|dl| dl.device_instance)
                .unwrap_or_default(),
        });
        let iface = iface_iter.next().unwrap();

        interface_status.push(InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::Virtual { id: 1 },
            mac_address: iface.host_inband_mac_address,
            addresses: iface.ip_addrs.values().copied().collect(),
            prefixes: iface.interface_prefixes.values().copied().collect(),
            gateways: iface.network_segment_gateways.values().copied().collect(),
            device: iface.device_locator.as_ref().map(|dl| dl.device.clone()),
            device_instance: iface
                .device_locator
                .as_ref()
                .map(|dl| dl.device_instance)
                .unwrap_or_default(),
        });

        let iface = iface_iter.next().unwrap();

        interface_status.push(InstanceInterfaceStatus {
            function_id: InterfaceFunctionId::Virtual { id: 2 },
            mac_address: iface.host_inband_mac_address,
            addresses: iface.ip_addrs.values().copied().collect(),
            prefixes: iface.interface_prefixes.values().copied().collect(),
            gateways: iface.network_segment_gateways.values().copied().collect(),
            device: iface.device_locator.as_ref().map(|dl| dl.device.clone()),
            device_instance: iface
                .device_locator
                .as_ref()
                .map(|dl| dl.device_instance)
                .unwrap_or_default(),
        });

        InstanceNetworkStatus {
            interfaces: interface_status,
            configs_synced: SyncState::Synced,
        }
    }

    fn expected_host_inband_status() -> InstanceNetworkStatus {
        InstanceNetworkStatus {
            interfaces: vec![
                InstanceInterfaceStatus {
                    function_id: InterfaceFunctionId::Physical {},
                    mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 6])),
                    addresses: vec!["127.0.1.2".parse().unwrap()],
                    prefixes: vec!["127.0.1.0/24".parse().unwrap()],
                    gateways: vec!["127.0.1.1/24".parse().unwrap()],
                    device: None,
                    device_instance: 0,
                },
                InstanceInterfaceStatus {
                    function_id: InterfaceFunctionId::Virtual { id: 1 },
                    mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 16])),
                    addresses: vec!["127.0.2.2".parse().unwrap()],
                    prefixes: vec!["127.0.2.0/24".parse().unwrap()],
                    gateways: vec!["127.0.2.1/24".parse().unwrap()],
                    device: None,
                    device_instance: 0,
                },
                InstanceInterfaceStatus {
                    function_id: InterfaceFunctionId::Virtual { id: 2 },
                    mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 26])),
                    addresses: vec!["127.0.3.2".parse().unwrap()],
                    prefixes: vec!["127.0.3.0/24".parse().unwrap()],
                    gateways: vec!["127.0.3.1/24".parse().unwrap()],
                    device: None,
                    device_instance: 0,
                },
            ],
            configs_synced: SyncState::Synced,
        }
    }

    #[test]
    fn network_status_without_observations() {
        let config = network_config();
        let version = ConfigVersion::initial();

        let status = InstanceNetworkStatus::from_config_and_observations(
            HashMap::default(),
            Versioned::new(&config, version),
            &HashMap::default(),
            false,
        );
        assert_eq!(status, unsynced_status())
    }

    #[test]
    fn network_status_with_correct_version_observation() {
        let config = network_config();
        let version = ConfigVersion::initial();
        let observations = observations_for_config(&config, version);

        let status = InstanceNetworkStatus::from_config_and_observations(
            HashMap::default(),
            Versioned::new(&config, version),
            &observations,
            false,
        );
        assert_eq!(status, expected_status(&config))
    }

    #[test]
    fn network_status_with_update_going_on() {
        let config = network_config();
        let version = ConfigVersion::initial();
        let observations = observations_for_config(&config, version);

        let status = InstanceNetworkStatus::from_config_and_observations(
            HashMap::default(),
            Versioned::new(&config, version),
            &observations,
            true,
        );
        assert_eq!(status, unsynced_status())
    }

    #[test]
    fn network_status_with_mismatched_version_observation() {
        let config = network_config();
        let version = ConfigVersion::initial();
        let observations = observations_for_config(&config, version);

        let status = InstanceNetworkStatus::from_config_and_observations(
            HashMap::default(),
            Versioned::new(&config, version.increment()),
            &observations,
            false,
        );
        assert_eq!(status, unsynced_status())
    }

    #[test]
    fn network_status_host_inband_interface_config() {
        let config = host_inband_network_config();
        let version = ConfigVersion::initial();
        let status = InstanceNetworkStatus::from_config_and_observations(
            HashMap::default(),
            Versioned::new(&config, version.increment()),
            // No observations
            &HashMap::default(),
            false,
        );
        assert_eq!(status, expected_host_inband_status())
    }
}
