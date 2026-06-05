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

use model::instance_type::{InstanceType, InstanceTypeMachineCapabilityFilter};

use crate::errors::RpcDataConversionError;
use crate::{common as rpc_common, forge as rpc};

impl TryFrom<rpc::InstanceTypeMachineCapabilityFilterAttributes>
    for InstanceTypeMachineCapabilityFilter
{
    type Error = RpcDataConversionError;

    fn try_from(
        cap: rpc::InstanceTypeMachineCapabilityFilterAttributes,
    ) -> Result<Self, Self::Error> {
        Ok(InstanceTypeMachineCapabilityFilter {
            capability_type: cap.capability_type().try_into()?,
            name: cap.name,
            frequency: cap.frequency,
            capacity: cap.capacity,
            vendor: cap.vendor,
            count: cap.count,
            hardware_revision: cap.hardware_revision,
            cores: cap.cores,
            threads: cap.threads,
            inactive_devices: cap.inactive_devices.map(|l| l.items),
            device_type: cap
                .device_type
                .map(|dt| {
                    rpc::MachineCapabilityDeviceType::try_from(dt)
                        .map_err(|_| {
                            RpcDataConversionError::InvalidValue(
                                "MachineCapabilityDeviceType".to_string(),
                                dt.to_string(),
                            )
                        })
                        .and_then(|rpc_dt| rpc_dt.try_into())
                })
                .transpose()?,
        })
    }
}

impl TryFrom<InstanceTypeMachineCapabilityFilter>
    for rpc::InstanceTypeMachineCapabilityFilterAttributes
{
    type Error = RpcDataConversionError;

    fn try_from(cap: InstanceTypeMachineCapabilityFilter) -> Result<Self, Self::Error> {
        Ok(rpc::InstanceTypeMachineCapabilityFilterAttributes {
            capability_type: rpc::MachineCapabilityType::from(cap.capability_type).into(),
            name: cap.name,
            frequency: cap.frequency,
            capacity: cap.capacity,
            vendor: cap.vendor,
            count: cap.count,
            hardware_revision: cap.hardware_revision,
            cores: cap.cores,
            threads: cap.threads,
            inactive_devices: cap
                .inactive_devices
                .map(|l| rpc_common::Uint32List { items: l }),
            device_type: cap
                .device_type
                .map(|dt| rpc::MachineCapabilityDeviceType::from(dt).into()),
        })
    }
}

impl TryFrom<InstanceType> for rpc::InstanceType {
    type Error = RpcDataConversionError;

    fn try_from(inst_type: InstanceType) -> Result<Self, Self::Error> {
        let mut desired_capabilities =
            Vec::<rpc::InstanceTypeMachineCapabilityFilterAttributes>::new();

        for cap_attrs in inst_type.desired_capabilities {
            desired_capabilities.push(cap_attrs.try_into()?);
        }

        let attributes = rpc::InstanceTypeAttributes {
            desired_capabilities,
        };

        Ok(rpc::InstanceType {
            id: inst_type.id.to_string(),
            version: inst_type.version.to_string(),
            attributes: Some(attributes),
            created_at: Some(inst_type.created.to_string()),
            metadata: Some(rpc::Metadata {
                name: inst_type.metadata.name,
                description: inst_type.metadata.description,
                labels: inst_type
                    .metadata
                    .labels
                    .iter()
                    .map(|(key, value)| rpc::Label {
                        key: key.to_owned(),
                        value: if value.is_empty() {
                            None
                        } else {
                            Some(value.to_owned())
                        },
                    })
                    .collect(),
            }),
            allocation_stats: None,
        })
    }
}

/* ********************************** */
/*              Tests                 */
/* ********************************** */

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use config_version::ConfigVersion;
    use model::machine::capabilities;
    use model::metadata::Metadata;

    use super::*;
    use crate::forge as rpc;

    #[test]
    fn test_model_instance_type_to_rpc_conversion() {
        let version = ConfigVersion::initial();

        let req_type = rpc::InstanceType {
            id: "test_id".to_string(),
            version: version.to_string(),
            metadata: Some(rpc::Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: vec![],
            }),
            allocation_stats: None,
            attributes: Some(rpc::InstanceTypeAttributes {
                desired_capabilities: vec![rpc::InstanceTypeMachineCapabilityFilterAttributes {
                    capability_type: rpc::MachineCapabilityType::CapTypeCpu.into(),
                    name: Some("pentium 4 HT".to_string()),
                    frequency: Some("1.3 GHz".to_string()),
                    capacity: Some("9001 GB".to_string()),
                    vendor: Some("intel".to_string()),
                    count: Some(1),
                    hardware_revision: Some("rev 9001".to_string()),
                    cores: Some(1),
                    threads: Some(2),
                    inactive_devices: Some(rpc_common::Uint32List { items: vec![2, 4] }),
                    device_type: Some(rpc::MachineCapabilityDeviceType::Unknown as i32),
                }],
            }),
            created_at: Some("2023-01-01 00:00:00 UTC".to_string()),
        };

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version,
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![InstanceTypeMachineCapabilityFilter {
                capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                name: Some("pentium 4 HT".to_string()),
                frequency: Some("1.3 GHz".to_string()),
                capacity: Some("9001 GB".to_string()),
                vendor: Some("intel".to_string()),
                count: Some(1),
                hardware_revision: Some("rev 9001".to_string()),
                cores: Some(1),
                threads: Some(2),
                inactive_devices: Some(vec![2, 4]),
                device_type: Some(capabilities::MachineCapabilityDeviceType::Unknown),
            }],
        };

        // Verify that we can go from an internal instance type to the
        // protobuf InstanceType message
        assert_eq!(req_type, rpc::InstanceType::try_from(inst_type).unwrap());
    }

    #[test]
    fn test_model_instance_type_match_fails_on_empty_machine() {
        //
        // Verify that an empty capability set fails to match.
        //

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![InstanceTypeMachineCapabilityFilter {
                capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                ..Default::default()
            }],
        };

        let machine_cap_set = capabilities::MachineCapabilitiesSet {
            cpu: vec![],
            gpu: vec![],
            memory: vec![],
            storage: vec![],
            network: vec![],
            infiniband: vec![],
            dpu: vec![],
        };

        assert!(!inst_type.matches_capability_set(&machine_cap_set));
    }

    #[test]
    fn test_model_instance_type_loose_type_match() {
        //
        // Verify that a general match works on just type
        //

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![InstanceTypeMachineCapabilityFilter {
                capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                ..Default::default()
            }],
        };

        let machine_cap_set = capabilities::MachineCapabilitiesSet {
            cpu: vec![capabilities::MachineCapabilityCpu {
                name: "pentium 4 HT".to_string(),
                vendor: Some("intel".to_string()),
                count: 1,
                cores: Some(1),
                threads: Some(2),
            }],
            gpu: vec![],
            memory: vec![],
            storage: vec![],
            network: vec![],
            infiniband: vec![],
            dpu: vec![],
        };

        assert!(inst_type.matches_capability_set(&machine_cap_set));
    }

    #[test]
    fn test_model_instance_type_zero_count_match() {
        //
        // Verify that a general match works on just type
        // with a zero-count InstanceType filter
        //

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeDpu.try_into().unwrap(),
                    count: Some(0),
                    ..Default::default()
                },
            ],
        };

        let machine_cap_set = capabilities::MachineCapabilitiesSet {
            cpu: vec![capabilities::MachineCapabilityCpu {
                name: "pentium 4 HT".to_string(),
                vendor: Some("intel".to_string()),
                count: 1,
                cores: Some(1),
                threads: Some(2),
            }],
            gpu: vec![],
            memory: vec![],
            storage: vec![],
            network: vec![],
            infiniband: vec![],
            dpu: vec![],
        };

        assert!(inst_type.matches_capability_set(&machine_cap_set));
    }

    #[test]
    fn test_model_instance_type_specific_match() {
        //
        // Verify that a more specific capability set matches
        //

        let machine_cap_set = capabilities::MachineCapabilitiesSet {
            cpu: vec![capabilities::MachineCapabilityCpu {
                name: "pentium 4 HT".to_string(),
                vendor: Some("intel".to_string()),
                count: 1,
                cores: Some(1),
                threads: Some(2),
            }],
            gpu: vec![capabilities::MachineCapabilityGpu {
                name: "rtx6000".to_string(),
                frequency: None,
                vendor: Some("nvidia".to_string()),
                count: 1,
                cores: Some(1),
                threads: Some(2),
                memory_capacity: Some("12 GB".to_string()),
                device_type: Some(capabilities::MachineCapabilityDeviceType::Unknown),
            }],
            memory: vec![capabilities::MachineCapabilityMemory {
                name: "ddr4".to_string(),
                vendor: Some("micron".to_string()),
                count: 1,
                capacity: Some("16 GB".to_string()),
            }],
            storage: vec![capabilities::MachineCapabilityStorage {
                name: "HDD".to_string(),
                vendor: Some("western digital".to_string()),
                count: 1,
                capacity: Some("2 TB".to_string()),
            }],
            network: vec![
                capabilities::MachineCapabilityNetwork {
                    name: "e1000".to_string(),
                    vendor: Some("intel".to_string()),
                    count: 2,
                    device_type: Some(capabilities::MachineCapabilityDeviceType::Unknown),
                },
                capabilities::MachineCapabilityNetwork {
                    name: "e10000".to_string(),
                    vendor: Some("intel".to_string()),
                    count: 1,
                    device_type: Some(capabilities::MachineCapabilityDeviceType::Unknown),
                },
            ],
            infiniband: vec![capabilities::MachineCapabilityInfiniband {
                name: "connectx7".to_string(),
                vendor: "nvidia".to_string(),
                count: 1,
                inactive_devices: vec![2, 4],
            }],
            dpu: vec![capabilities::MachineCapabilityDpu {
                name: "bluefield3".to_string(),
                hardware_revision: Some("abc123".to_string()),
                count: 1,
            }],
        };

        // First test with a simple InstanceType

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![InstanceTypeMachineCapabilityFilter {
                capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                name: Some("pentium 4 HT".to_string()),
                frequency: Some("1.3 GHz".to_string()),
                capacity: None,
                vendor: Some("intel".to_string()),
                count: Some(1),
                hardware_revision: None,
                cores: Some(1),
                threads: Some(2),
                inactive_devices: None,
                device_type: Some(capabilities::MachineCapabilityDeviceType::Unknown),
            }],
        };

        assert!(inst_type.matches_capability_set(&machine_cap_set));

        // Then a fuller instance type

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                    name: Some("pentium 4 HT".to_string()),
                    frequency: Some("1.3 GHz".to_string()),
                    capacity: None,
                    vendor: Some("intel".to_string()),
                    count: Some(1),
                    hardware_revision: None,
                    cores: Some(1),
                    threads: Some(2),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeGpu.try_into().unwrap(),
                    name: Some("rtx6000".to_string()),
                    frequency: None,
                    vendor: Some("nvidia".to_string()),
                    count: Some(1),
                    cores: Some(1),
                    threads: Some(2),
                    capacity: Some("12 GB".to_string()),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeMemory
                        .try_into()
                        .unwrap(),
                    name: Some("ddr4".to_string()),
                    vendor: Some("micron".to_string()),
                    count: Some(1),
                    capacity: Some("16 GB".to_string()),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeStorage
                        .try_into()
                        .unwrap(),
                    name: Some("HDD".to_string()),
                    vendor: Some("western digital".to_string()),
                    count: Some(1),
                    capacity: Some("2 TB".to_string()),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeNetwork
                        .try_into()
                        .unwrap(),
                    name: Some("e10000".to_string()),
                    vendor: Some("intel".to_string()),
                    count: Some(1),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeInfiniband
                        .try_into()
                        .unwrap(),
                    name: Some("connectx7".to_string()),
                    vendor: Some("nvidia".to_string()),
                    count: Some(1),
                    inactive_devices: Some(vec![2, 4]),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeDpu.try_into().unwrap(),
                    name: Some("bluefield3".to_string()),
                    hardware_revision: Some("abc123".to_string()),
                    count: Some(1),
                    ..Default::default()
                },
            ],
        };

        assert!(inst_type.matches_capability_set(&machine_cap_set));

        // Then a fuller instance type but without caring about name/model

        let inst_type = InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities: vec![
                InstanceTypeMachineCapabilityFilter {
                    name: None,
                    capability_type: rpc::MachineCapabilityType::CapTypeCpu.try_into().unwrap(),
                    frequency: Some("1.3 GHz".to_string()),
                    capacity: None,
                    vendor: Some("intel".to_string()),
                    count: Some(1),
                    hardware_revision: None,
                    cores: Some(1),
                    threads: Some(2),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeGpu.try_into().unwrap(),
                    frequency: None,
                    vendor: Some("nvidia".to_string()),
                    count: Some(1),
                    cores: Some(1),
                    threads: Some(2),
                    capacity: Some("12 GB".to_string()),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeMemory
                        .try_into()
                        .unwrap(),
                    vendor: Some("micron".to_string()),
                    count: Some(1),
                    capacity: Some("16 GB".to_string()),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeStorage
                        .try_into()
                        .unwrap(),
                    vendor: Some("western digital".to_string()),
                    count: Some(1),
                    capacity: Some("2 TB".to_string()),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeNetwork
                        .try_into()
                        .unwrap(),
                    vendor: Some("intel".to_string()),
                    count: Some(3), // There are two intel nics of different speeds.  2x of one and 1x of the other.

                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeInfiniband
                        .try_into()
                        .unwrap(),
                    vendor: Some("nvidia".to_string()),
                    count: Some(1),
                    inactive_devices: Some(vec![2, 4]),
                    ..Default::default()
                },
                InstanceTypeMachineCapabilityFilter {
                    capability_type: rpc::MachineCapabilityType::CapTypeDpu.try_into().unwrap(),
                    hardware_revision: Some("abc123".to_string()),
                    count: Some(1),
                    ..Default::default()
                },
            ],
        };

        assert!(inst_type.matches_capability_set(&machine_cap_set));
    }
}
