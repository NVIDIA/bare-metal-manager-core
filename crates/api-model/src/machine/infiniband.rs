/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashSet;
use std::fmt::Write;

use carbide_uuid::infiniband::IBPartitionId;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::ib_partition::PartitionKey;
use crate::instance::config::infiniband::InstanceInfinibandConfig;

/// The infiniband status that was last reported by the networking subsystem
/// Stored in a Postgres JSON field
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineInfinibandStatusObservation {
    /// Observed status for each configured interface
    #[serde(default)]
    pub ib_interfaces: Vec<MachineIbInterfaceStatusObservation>,

    /// When this status was observed
    pub observed_at: DateTime<Utc>,
}

/// The infiniband interface status that was last reported by the infiniband subsystem
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineIbInterfaceStatusObservation {
    /// The GUID whose status has been monitored
    pub guid: String,
    /// The ocal Identifier observed from UFM. This is set to 0xffff if no status
    /// could be retrieved or if the port is not reported as Active.
    pub lid: u16,
    /// The ID of the fabric on which the GUID has been observed
    /// This is empty if the GUID hasn't been observed on any fabric
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub fabric_id: String,
    /// Partition keys currently associated with the interface at UFM
    /// None means the associated pkeys could not be determined
    pub associated_pkeys: Option<HashSet<PartitionKey>>,
    /// Partition IDs currently associated with the interface at UFM
    /// None means the associated pkeys could not be determined.
    /// The amount of IDs can be different than the amount of `associated_pkeys`
    /// in case a pkey that is associated with the port does not map to any
    /// partition ID.
    pub associated_partition_ids: Option<HashSet<IBPartitionId>>,
}

impl From<MachineInfinibandStatusObservation> for rpc::forge::InfinibandStatusObservation {
    fn from(
        ib_status: MachineInfinibandStatusObservation,
    ) -> rpc::forge::InfinibandStatusObservation {
        rpc::forge::InfinibandStatusObservation {
            ib_interfaces: ib_status
                .ib_interfaces
                .into_iter()
                .map(|interface| interface.into())
                .collect(),
            observed_at: Some(ib_status.observed_at.into()),
        }
    }
}

impl From<MachineIbInterfaceStatusObservation> for rpc::forge::MachineIbInterface {
    fn from(
        machine_ib_interface: MachineIbInterfaceStatusObservation,
    ) -> rpc::forge::MachineIbInterface {
        rpc::forge::MachineIbInterface {
            pf_guid: None,
            guid: Some(machine_ib_interface.guid),
            lid: Some(machine_ib_interface.lid as u32),
            fabric_id: match machine_ib_interface.fabric_id.is_empty() {
                true => None,
                false => Some(machine_ib_interface.fabric_id),
            },
            associated_pkeys: machine_ib_interface.associated_pkeys.map(|pkeys| {
                rpc::common::StringList {
                    items: pkeys.into_iter().map(|key| key.to_string()).collect(),
                }
            }),
            associated_partition_ids: machine_ib_interface.associated_partition_ids.map(|ids| {
                rpc::common::StringList {
                    items: ids.into_iter().map(|id| id.into()).collect(),
                }
            }),
        }
    }
}

/// The reason why the IB config is not synced
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IbConfigNotSyncedReason {
    /// Port states could not be observed
    PortStateUnobservable { guids: Vec<String>, details: String },
    /// Configuration mismatch between expected and actual
    ConfigurationMismatch { details: String },
    /// Missing observation data entirely
    MissingObservation { reason: String },
}

impl std::fmt::Display for IbConfigNotSyncedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PortStateUnobservable { details, .. } => {
                write!(f, "Port state unobservable: {}", details)
            }
            Self::ConfigurationMismatch { details } => {
                write!(f, "Configuration mismatch: {}", details)
            }
            Self::MissingObservation { reason } => {
                write!(f, "Missing observation: {}", reason)
            }
        }
    }
}

/// Returns whether the desired InfiniBand config for a Machine has been applied
pub fn ib_config_synced(
    observation: Option<&MachineInfinibandStatusObservation>,
    config: Option<&InstanceInfinibandConfig>,
    use_tenant_network: bool,
) -> Result<(), IbConfigNotSyncedReason> {
    let Some(config) = config.as_ref() else {
        // If no IB config is requested, we always treat the config as applied
        // TODO: This is to achieve the same behavior as the current system, where hosts without
        // IB config don't care about what is configured.
        // In the future we should also check here whether all interfaces/ports have **no** pkeys assigned to them.
        // If there are any assigned, the state should be marked as not synced.
        return Ok(());
    };

    if config.ib_interfaces.is_empty() {
        // If no IB config is requested, we always treat the config as applied
        // TODO: This is to achieve the same behavior as the current system, where hosts without
        // IB config don't care about what is configured.
        // In the future we should also check here whether all interfaces/ports have **no** pkeys assigned to them.
        // If there are any assigned, the state should be marked as not synced.
        return Ok(());
    }

    // The tenant requested to use IB. In this case
    // - if the tenant network is still utilized (`use_tenant_config == true`), all interfaces that the tenant wants to use should be on the tenant network
    // - if the tenant network is not utilized, all interfaces that the tenant wants to use should be on no network
    // For interfaces that the tenant does not want to use, we will not perform any checks at the moment
    let Some(observation) = observation.as_ref() else {
        return Err(IbConfigNotSyncedReason::MissingObservation {
            reason: "Due to missing IB status observation, it can't be verified whether the IB config is applied at UFM".to_string(),
        });
    };

    let mut misconfigured_guids = Vec::new();
    let mut unknown_guid_states = Vec::new();

    for iface in config.ib_interfaces.iter() {
        let Some(guid) = iface.guid.as_ref() else {
            continue;
        };
        let expected_partition_id = iface.ib_partition_id;

        let Some(actual_iface_state) = observation
            .ib_interfaces
            .iter()
            .find(|iface| iface.guid == *guid)
        else {
            // We can't look up the observation. This should never happen, as the observation field
            // for each interface is always populated.
            unknown_guid_states.push(guid.to_string());
            continue;
        };

        let Some(associated_pkeys) = actual_iface_state.associated_pkeys.as_ref() else {
            unknown_guid_states.push(guid.to_string());
            continue;
        };

        let Some(associated_partition_ids) = actual_iface_state.associated_partition_ids.as_ref()
        else {
            unknown_guid_states.push(guid.to_string());
            continue;
        };

        if use_tenant_network {
            // The interface should use exactly the partition ID that is requested
            if associated_pkeys.len() != 1
                || associated_partition_ids.len() != 1
                || *associated_partition_ids.iter().next().unwrap() != expected_partition_id
            {
                misconfigured_guids
                    .push((guid.to_string(), format!("[\"{expected_partition_id}\"]")));
            }
        } else {
            // The interface should not be on any partition
            if !associated_pkeys.is_empty() || !associated_partition_ids.is_empty() {
                misconfigured_guids.push((guid.to_string(), "[]".to_string()));
            }
        }
    }

    // TODO: Check here whether all interfaces that are not referenced in the config
    // are set to have exactly 0 pkeys configured
    // This is only possible once we know there's no manually
    // configured pkeys anymore in the system

    // If ports are unreachable (down), return PortStateUnobservable
    // This is critical during termination as we need special retry logic
    if !unknown_guid_states.is_empty() {
        let details = format!(
            "IB status observation for interface with GUIDs {} is missing or incomplete. Ports may be down/unreachable.",
            unknown_guid_states.join(",")
        );
        return Err(IbConfigNotSyncedReason::PortStateUnobservable {
            guids: unknown_guid_states,
            details,
        });
    }

    // If there are configuration mismatches, return ConfigurationMismatch
    if !misconfigured_guids.is_empty() {
        let mut errors = String::new();
        for (guid, expectation) in misconfigured_guids.iter() {
            if !errors.is_empty() {
                errors.push('\n');
            }
            write!(
                &mut errors,
                "Interface with GUID {guid} should be assigned to partition IDs {expectation}"
            )
            .unwrap();
        }
        return Err(IbConfigNotSyncedReason::ConfigurationMismatch { details: errors });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialize_legacy_ib_status_observation() {
        let obs1 = r#"{"observed_at": "2024-12-18T23:17:57.919166804Z", "ib_interfaces": []}"#;
        let _deserialized: MachineInfinibandStatusObservation = serde_json::from_str(obs1).unwrap();

        let obs2 = r#"{"observed_at": "2025-06-06T19:47:16.597282585Z", "ib_interfaces": [{"lid": 65535, "guid": "1070fd0300bd7574"}, {"lid": 65535, "guid": "1070fd0300bd7575"}]}"#;
        let deserialized: MachineInfinibandStatusObservation = serde_json::from_str(obs2).unwrap();
        assert!(deserialized.ib_interfaces[0].fabric_id.is_empty());
        assert!(deserialized.ib_interfaces[0].associated_pkeys.is_none());
    }

    #[test]
    fn serialize_ib_status_observation() {
        let obs = MachineInfinibandStatusObservation {
            ib_interfaces: vec![MachineIbInterfaceStatusObservation {
                guid: "Aguid".to_string(),
                lid: 0x10,
                fabric_id: "default".to_string(),
                associated_pkeys: Some([0x13.try_into().unwrap()].into_iter().collect()),
                associated_partition_ids: Some(
                    [uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into()]
                        .into_iter()
                        .collect(),
                ),
            }],
            observed_at: "2025-06-06T19:47:16.597282585Z".parse().unwrap(),
        };
        let serialized = serde_json::to_string(&obs).unwrap();
        assert_eq!(
            serialized,
            r#"{"ib_interfaces":[{"guid":"Aguid","lid":16,"fabric_id":"default","associated_pkeys":["0x13"],"associated_partition_ids":["91609f10-c91d-470d-a260-6293ea0c1200"]}],"observed_at":"2025-06-06T19:47:16.597282585Z"}"#
        );
        let deserialized = serde_json::from_str(&serialized).unwrap();
        assert_eq!(obs, deserialized);
    }

    #[test]
    fn test_ib_config_synced_missing_observation() {
        use crate::instance::config::network::InterfaceFunctionId;

        let config = InstanceInfinibandConfig {
            ib_interfaces: vec![
                crate::instance::config::infiniband::InstanceIbInterfaceConfig {
                    function_id: InterfaceFunctionId::Physical {},
                    ib_partition_id: uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into(),
                    pf_guid: None,
                    guid: Some("946dae03006104f8".to_string()),
                    device: "MT2910 Family [ConnectX-7]".to_string(),
                    vendor: None,
                    device_instance: 1,
                },
            ],
        };
        let result = ib_config_synced(None, Some(&config), true);
        assert!(matches!(
            result,
            Err(IbConfigNotSyncedReason::MissingObservation { .. })
        ));
    }

    #[test]
    fn test_ib_config_synced_port_state_unobservable() {
        use crate::instance::config::network::InterfaceFunctionId;

        let config = InstanceInfinibandConfig {
            ib_interfaces: vec![
                crate::instance::config::infiniband::InstanceIbInterfaceConfig {
                    function_id: InterfaceFunctionId::Physical {},
                    ib_partition_id: uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into(),
                    pf_guid: None,
                    guid: Some("946dae03006104f8".to_string()),
                    device: "MT2910 Family [ConnectX-7]".to_string(),
                    vendor: None,
                    device_instance: 1,
                },
            ],
        };

        let observation = MachineInfinibandStatusObservation {
            ib_interfaces: vec![MachineIbInterfaceStatusObservation {
                guid: "946dae03006104f8".to_string(),
                lid: 0xffff,
                fabric_id: "".to_string(),
                associated_pkeys: None, // Port is down/unobservable
                associated_partition_ids: None,
            }],
            observed_at: chrono::Utc::now(),
        };

        let result = ib_config_synced(Some(&observation), Some(&config), true);

        match result {
            Err(IbConfigNotSyncedReason::PortStateUnobservable { guids, details }) => {
                assert_eq!(guids.len(), 1);
                assert_eq!(guids[0], "946dae03006104f8");
                assert!(details.contains("946dae03006104f8"));
                assert!(details.contains("missing or incomplete"));
            }
            _ => panic!("Expected PortStateUnobservable error, got: {:?}", result),
        }
    }

    #[test]
    fn test_ib_config_synced_ok_when_synced() {
        use carbide_uuid::infiniband::IBPartitionId;

        use crate::instance::config::network::InterfaceFunctionId;
        let partition_id: IBPartitionId =
            uuid::uuid!("91609f10-c91d-470d-a260-6293ea0c1200").into();
        let pkey: PartitionKey = 0x13.try_into().unwrap();

        let config = InstanceInfinibandConfig {
            ib_interfaces: vec![
                crate::instance::config::infiniband::InstanceIbInterfaceConfig {
                    function_id: InterfaceFunctionId::Physical {},
                    ib_partition_id: partition_id,
                    pf_guid: None,
                    guid: Some("946dae03006104f8".to_string()),
                    device: "MT2910 Family [ConnectX-7]".to_string(),
                    vendor: None,
                    device_instance: 1,
                },
            ],
        };

        let observation = MachineInfinibandStatusObservation {
            ib_interfaces: vec![MachineIbInterfaceStatusObservation {
                guid: "946dae03006104f8".to_string(),
                lid: 0x10,
                fabric_id: "default".to_string(),
                associated_pkeys: Some([pkey].into_iter().collect()),
                associated_partition_ids: Some([partition_id].into_iter().collect()),
            }],
            observed_at: chrono::Utc::now(),
        };

        let result = ib_config_synced(Some(&observation), Some(&config), true);
        assert!(result.is_ok());
    }
}
