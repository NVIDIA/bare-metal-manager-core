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

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use config_version::{ConfigVersion, Versioned};
use mac_address::MacAddress;
use serde::{Deserialize, Serialize};

use crate::model::{
    instance::{
        config::network::{
            validate_interface_function_ids, InstanceNetworkConfig, InterfaceFunctionId,
        },
        status::SyncState,
    },
    RpcDataConversionError, SerializableMacAddress, StatusValidationError,
};

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
    /// Each entry in this status array maps to it's corresponding entry in the
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
    pub fn from_config_and_observation(
        config: Versioned<&InstanceNetworkConfig>,
        observations: Option<&InstanceNetworkStatusObservation>,
    ) -> Self {
        let observations = match observations {
            Some(observations) => observations,
            None => return Self::unsynchronized_for_config(&config),
        };

        if observations.config_version != config.version {
            return Self::unsynchronized_for_config(&config);
        }

        let interfaces = config
            .interfaces
            .iter()
            .map(|config| {
                // TODO: This isn't super efficient. We could do it better if there would be a guarantee
                // that interfaces in the observation are in the same order as in the config.
                // But it isn't obvious at the moment whether we can achieve this while
                // not mixing up order for users.
                let observation = observations
                    .interfaces
                    .iter()
                    .find(|iface| iface.function_id == config.function_id);
                match observation {
                    Some(observation) => InstanceInterfaceStatus {
                        function_id: config.function_id.clone(),
                        mac_address: observation.mac_address.map(Into::into),
                        addresses: observation.addresses.clone(),
                    },
                    None => {
                        tracing::error!(
                            function_id = ?config.function_id, ?config, ?observation,
                            "Could not find matching status for interface",
                        );

                        // TODO: Might also be worthwhile to return an error?
                        // On the other hand the error is also visible via returning no IPs - and at least we don't break
                        // all other interfaces this way
                        InstanceInterfaceStatus {
                            function_id: config.function_id.clone(),
                            mac_address: None,
                            addresses: Vec::new(),
                        }
                    }
                }
            })
            .collect();

        Self {
            interfaces,
            configs_synced: SyncState::Synced,
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
                })
                .collect(),
            configs_synced: SyncState::Pending,
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

    /// Observed status for each configured interface
    #[serde(default)]
    pub interfaces: Vec<InstanceInterfaceStatusObservation>,

    /// When this status was observed
    pub observed_at: DateTime<Utc>,
}

impl InstanceNetworkStatusObservation {
    /// Validates that a report about an observed network status has a valid
    /// format
    pub fn validate(&self) -> Result<(), StatusValidationError> {
        validate_interface_function_ids(&self.interfaces, |iface| iface.function_id.clone())
            .map_err(StatusValidationError::InvalidValue)?;

        Ok(())
    }
}

impl TryFrom<rpc::InstanceNetworkStatusObservation> for InstanceNetworkStatusObservation {
    type Error = RpcDataConversionError;

    fn try_from(observation: rpc::InstanceNetworkStatusObservation) -> Result<Self, Self::Error> {
        let mut interfaces = Vec::with_capacity(observation.interfaces.len());
        for iface in observation.interfaces {
            interfaces.push(InstanceInterfaceStatusObservation::try_from(iface)?);
        }

        let observed_at = match observation.observed_at {
            Some(timestamp) => {
                let system_time = std::time::SystemTime::try_from(timestamp.clone())
                    .map_err(|_| RpcDataConversionError::InvalidTimestamp(timestamp.to_string()))?;
                DateTime::from(system_time)
            }
            None => Utc::now(),
        };

        Ok(Self {
            config_version: observation.config_version.parse().map_err(|_| {
                RpcDataConversionError::InvalidConfigVersion(observation.config_version)
            })?,
            interfaces,
            observed_at,
        })
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
}

impl TryFrom<rpc::InstanceInterfaceStatusObservation> for InstanceInterfaceStatusObservation {
    type Error = RpcDataConversionError;

    fn try_from(observation: rpc::InstanceInterfaceStatusObservation) -> Result<Self, Self::Error> {
        let function_id = match observation.function_type() {
            rpc::forge::InterfaceFunctionType::Physical => InterfaceFunctionId::Physical {},
            rpc::forge::InterfaceFunctionType::Virtual => {
                InterfaceFunctionId::try_virtual_from(observation.virtual_function_id() as usize)
                    .map_err(|_| {
                        RpcDataConversionError::InvalidVirtualFunctionId(
                            observation.virtual_function_id() as usize,
                        )
                    })?
            }
        };

        let mut addresses = Vec::with_capacity(observation.addresses.len());
        for address in observation.addresses {
            addresses.push(
                address
                    .parse::<IpAddr>()
                    .map_err(|_| RpcDataConversionError::InvalidIpAddress(address))?,
            );
        }

        Ok(Self {
            function_id,
            addresses,
            mac_address: observation
                .mac_address
                .map(|addr| {
                    addr.parse::<MacAddress>()
                        .map_err(|_| RpcDataConversionError::InvalidMacAddress(addr))
                })
                .transpose()?
                .map(Into::into),
        })
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fmt::Write};

    use super::*;
    use crate::db::network_segment::NetworkSegmentId;
    use crate::model::instance::config::network::InstanceInterfaceConfig;

    #[test]
    fn serialize_network_status_observation() {
        let timestamp: DateTime<Utc> = Utc::now();
        let serialized_timestamp = format!("{:?}", timestamp);
        let version = ConfigVersion::initial();

        let mut observation = InstanceNetworkStatusObservation {
            config_version: version,
            interfaces: Vec::new(),
            observed_at: timestamp,
        };
        let serialized = serde_json::to_string(&observation).unwrap();
        assert_eq!(
            serialized,
            format!(
                "{{\"config_version\":\"{}\",\"interfaces\":[],\"observed_at\":\"{}\"}}",
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
            });
        observation
            .interfaces
            .push(InstanceInterfaceStatusObservation {
                function_id: InterfaceFunctionId::Virtual { id: 1 },
                mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 6]).into()),
                addresses: vec!["127.1.2.3".parse().unwrap()],
            });
        let serialized = serde_json::to_string(&observation).unwrap();
        let mut expected = format!(
            "{{\"config_version\":\"{}\",\"interfaces\":[",
            version.version_string()
        );
        write!(
            &mut expected,
            "{{\"function_id\":{{\"type\":\"physical\"}},\"mac_address\":null,\"addresses\":[]}},"
        )
        .unwrap();
        write!(&mut expected, "{{\"function_id\":{{\"type\":\"virtual\",\"id\":1}},\"mac_address\":\"01:02:03:04:05:06\",\"addresses\":[\"127.1.2.3\"]}}").unwrap();
        write!(
            &mut expected,
            "],\"observed_at\":\"{}\"}}",
            serialized_timestamp
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
        let prefix_uuid = uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1400");

        InstanceNetworkConfig {
            interfaces: vec![
                InstanceInterfaceConfig {
                    function_id: InterfaceFunctionId::Physical {},
                    network_segment_id: base_uuid,
                    ip_addrs: HashMap::from([(prefix_uuid, "127.0.0.1".parse().unwrap())]),
                },
                InstanceInterfaceConfig {
                    function_id: InterfaceFunctionId::Virtual { id: 1 },
                    network_segment_id: uuid::Uuid::from_u128(base_uuid.0.as_u128() + 1).into(),
                    ip_addrs: HashMap::from([(
                        uuid::Uuid::from_u128(prefix_uuid.as_u128() + 1),
                        "127.0.0.2".parse().unwrap(),
                    )]),
                },
                InstanceInterfaceConfig {
                    function_id: InterfaceFunctionId::Virtual { id: 2 },
                    network_segment_id: uuid::Uuid::from_u128(base_uuid.0.as_u128() + 2).into(),
                    ip_addrs: HashMap::from([(
                        uuid::Uuid::from_u128(prefix_uuid.as_u128() + 2),
                        "127.0.0.3".parse().unwrap(),
                    )]),
                },
            ],
        }
    }

    fn observation_for_config(config_version: ConfigVersion) -> InstanceNetworkStatusObservation {
        // Note that the interfaces are reordered to make sure we actually can
        // look up the matching status
        InstanceNetworkStatusObservation {
            config_version,
            observed_at: Utc::now(),
            interfaces: vec![
                InstanceInterfaceStatusObservation {
                    function_id: InterfaceFunctionId::Virtual { id: 2 },
                    mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 26]).into()),
                    addresses: vec!["127.0.0.3".parse().unwrap()],
                },
                InstanceInterfaceStatusObservation {
                    function_id: InterfaceFunctionId::Physical {},
                    mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 6]).into()),
                    addresses: vec!["127.0.0.1".parse().unwrap()],
                },
                InstanceInterfaceStatusObservation {
                    function_id: InterfaceFunctionId::Virtual { id: 1 },
                    mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 16]).into()),
                    addresses: vec!["127.0.0.2".parse().unwrap()],
                },
            ],
        }
    }

    fn unsynced_status() -> InstanceNetworkStatus {
        InstanceNetworkStatus {
            interfaces: vec![
                InstanceInterfaceStatus {
                    function_id: InterfaceFunctionId::Physical {},
                    mac_address: None,
                    addresses: Vec::new(),
                },
                InstanceInterfaceStatus {
                    function_id: InterfaceFunctionId::Virtual { id: 1 },
                    mac_address: None,
                    addresses: Vec::new(),
                },
                InstanceInterfaceStatus {
                    function_id: InterfaceFunctionId::Virtual { id: 2 },
                    mac_address: None,
                    addresses: Vec::new(),
                },
            ],
            configs_synced: SyncState::Pending,
        }
    }

    fn expected_status() -> InstanceNetworkStatus {
        InstanceNetworkStatus {
            interfaces: vec![
                InstanceInterfaceStatus {
                    function_id: InterfaceFunctionId::Physical {},
                    mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 6])),
                    addresses: vec!["127.0.0.1".parse().unwrap()],
                },
                InstanceInterfaceStatus {
                    function_id: InterfaceFunctionId::Virtual { id: 1 },
                    mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 16])),
                    addresses: vec!["127.0.0.2".parse().unwrap()],
                },
                InstanceInterfaceStatus {
                    function_id: InterfaceFunctionId::Virtual { id: 2 },
                    mac_address: Some(MacAddress::new([1, 2, 3, 4, 5, 26])),
                    addresses: vec!["127.0.0.3".parse().unwrap()],
                },
            ],
            configs_synced: SyncState::Synced,
        }
    }

    #[test]
    fn network_status_without_observations() {
        let config = network_config();
        let version = ConfigVersion::initial();

        let status = InstanceNetworkStatus::from_config_and_observation(
            Versioned::new(&config, version),
            None,
        );
        assert_eq!(status, unsynced_status())
    }

    #[test]
    fn network_status_with_correct_version_observation() {
        let config = network_config();
        let version = ConfigVersion::initial();
        let observation = observation_for_config(version);

        let status = InstanceNetworkStatus::from_config_and_observation(
            Versioned::new(&config, version),
            Some(&observation),
        );
        assert_eq!(status, expected_status())
    }

    #[test]
    fn network_status_with_mismatched_version_observation() {
        let config = network_config();
        let version = ConfigVersion::initial();
        let observation = observation_for_config(version);

        let status = InstanceNetworkStatus::from_config_and_observation(
            Versioned::new(&config, version.increment()),
            Some(&observation),
        );
        assert_eq!(status, unsynced_status())
    }
}
