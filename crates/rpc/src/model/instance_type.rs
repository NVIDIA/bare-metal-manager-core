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

    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, Check, check_cases, check_values};
    use config_version::ConfigVersion;
    use model::machine::capabilities;
    use model::metadata::Metadata;

    use super::*;
    use crate::forge as rpc;

    // A capability set with every category empty -- nothing for a filter to match.
    fn empty_cap_set() -> capabilities::MachineCapabilitiesSet {
        capabilities::MachineCapabilitiesSet {
            cpu: vec![],
            gpu: vec![],
            memory: vec![],
            storage: vec![],
            network: vec![],
            infiniband: vec![],
            dpu: vec![],
        }
    }

    // A capability set holding a single CPU.
    fn cpu_only_cap_set() -> capabilities::MachineCapabilitiesSet {
        capabilities::MachineCapabilitiesSet {
            cpu: vec![capabilities::MachineCapabilityCpu {
                name: "pentium 4 HT".to_string(),
                vendor: Some("intel".to_string()),
                count: 1,
                cores: Some(1),
                threads: Some(2),
            }],
            ..empty_cap_set()
        }
    }

    // A fully-populated capability set spanning every category.
    fn full_cap_set() -> capabilities::MachineCapabilitiesSet {
        capabilities::MachineCapabilitiesSet {
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
        }
    }

    // Wraps a list of desired-capability filters in an otherwise-fixed InstanceType.
    fn inst_type_with(
        desired_capabilities: Vec<InstanceTypeMachineCapabilityFilter>,
    ) -> InstanceType {
        InstanceType {
            id: "test_id".parse().unwrap(),
            deleted: None,
            created: "2023-01-01 00:00:00 UTC".parse().unwrap(),
            version: ConfigVersion::initial(),
            metadata: Metadata {
                name: "fancy name".to_string(),
                description: "".to_string(),
                labels: HashMap::new(),
            },
            desired_capabilities,
        }
    }

    // Verify that an internal InstanceType converts into the protobuf
    // InstanceType message. The error (RpcDataConversionError) is not the
    // contract here, so the row only asserts the converted value.
    #[test]
    fn model_instance_type_converts_to_rpc() {
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

        Case {
            scenario: "internal instance type to protobuf message",
            input: inst_type,
            expect: Yields(req_type),
        }
        .check(|it| rpc::InstanceType::try_from(it).map_err(drop));
    }

    // `matches_capability_set` is a total bool predicate: does an InstanceType's
    // desired-capability filter set match a machine's capabilities? Folds the
    // empty/loose/zero-count/specific cases (the specific test ran three filter
    // sets against the full set) into one table over (InstanceType, set).
    #[test]
    fn instance_type_matches_capability_set() {
        check_values(
            [
                Check {
                    scenario: "empty machine fails to match a typed filter",
                    input: (
                        inst_type_with(vec![InstanceTypeMachineCapabilityFilter {
                            capability_type: rpc::MachineCapabilityType::CapTypeCpu
                                .try_into()
                                .unwrap(),
                            ..Default::default()
                        }]),
                        empty_cap_set(),
                    ),
                    expect: false,
                },
                Check {
                    scenario: "loose match on just the type",
                    input: (
                        inst_type_with(vec![InstanceTypeMachineCapabilityFilter {
                            capability_type: rpc::MachineCapabilityType::CapTypeCpu
                                .try_into()
                                .unwrap(),
                            ..Default::default()
                        }]),
                        cpu_only_cap_set(),
                    ),
                    expect: true,
                },
                Check {
                    scenario: "zero-count filter for an absent type still matches",
                    input: (
                        inst_type_with(vec![
                            InstanceTypeMachineCapabilityFilter {
                                capability_type: rpc::MachineCapabilityType::CapTypeCpu
                                    .try_into()
                                    .unwrap(),
                                ..Default::default()
                            },
                            InstanceTypeMachineCapabilityFilter {
                                capability_type: rpc::MachineCapabilityType::CapTypeDpu
                                    .try_into()
                                    .unwrap(),
                                count: Some(0),
                                ..Default::default()
                            },
                        ]),
                        cpu_only_cap_set(),
                    ),
                    expect: true,
                },
                Check {
                    scenario: "specific single CPU filter matches the full set",
                    input: (
                        inst_type_with(vec![InstanceTypeMachineCapabilityFilter {
                            capability_type: rpc::MachineCapabilityType::CapTypeCpu
                                .try_into()
                                .unwrap(),
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
                        }]),
                        full_cap_set(),
                    ),
                    expect: true,
                },
                Check {
                    scenario: "full multi-category filter set with names matches",
                    input: (
                        inst_type_with(vec![
                            InstanceTypeMachineCapabilityFilter {
                                capability_type: rpc::MachineCapabilityType::CapTypeCpu
                                    .try_into()
                                    .unwrap(),
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
                                capability_type: rpc::MachineCapabilityType::CapTypeGpu
                                    .try_into()
                                    .unwrap(),
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
                                capability_type: rpc::MachineCapabilityType::CapTypeDpu
                                    .try_into()
                                    .unwrap(),
                                name: Some("bluefield3".to_string()),
                                hardware_revision: Some("abc123".to_string()),
                                count: Some(1),
                                ..Default::default()
                            },
                        ]),
                        full_cap_set(),
                    ),
                    expect: true,
                },
                Check {
                    scenario: "full filter set without names/models matches by type/vendor",
                    input: (
                        inst_type_with(vec![
                            InstanceTypeMachineCapabilityFilter {
                                name: None,
                                capability_type: rpc::MachineCapabilityType::CapTypeCpu
                                    .try_into()
                                    .unwrap(),
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
                                capability_type: rpc::MachineCapabilityType::CapTypeGpu
                                    .try_into()
                                    .unwrap(),
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
                                count: Some(3), // Two intel nics of different speeds: 2x one and 1x the other.
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
                                capability_type: rpc::MachineCapabilityType::CapTypeDpu
                                    .try_into()
                                    .unwrap(),
                                hardware_revision: Some("abc123".to_string()),
                                count: Some(1),
                                ..Default::default()
                            },
                        ]),
                        full_cap_set(),
                    ),
                    expect: true,
                },
            ],
            |(inst_type, machine_cap_set)| inst_type.matches_capability_set(&machine_cap_set),
        );
    }

    // A bare proto filter carrying only a capability_type discriminant; every
    // optional field is absent. The base for the proto -> domain rows below.
    fn proto_filter_of_type(
        capability_type: i32,
    ) -> rpc::InstanceTypeMachineCapabilityFilterAttributes {
        rpc::InstanceTypeMachineCapabilityFilterAttributes {
            capability_type,
            name: None,
            frequency: None,
            capacity: None,
            vendor: None,
            count: None,
            hardware_revision: None,
            cores: None,
            threads: None,
            inactive_devices: None,
            device_type: None,
        }
    }

    // A bare domain filter carrying only a capability_type; the base for the
    // domain -> proto rows.
    fn domain_filter_of_type(
        capability_type: capabilities::MachineCapabilityType,
    ) -> InstanceTypeMachineCapabilityFilter {
        InstanceTypeMachineCapabilityFilter {
            capability_type,
            ..Default::default()
        }
    }

    // proto -> domain: every capability_type discriminant maps to its domain
    // counterpart, while the reserved CapTypeInvalid (and any unknown i32, which
    // prost's getter coerces to CapTypeInvalid) is rejected. Error type isn't the
    // contract -- it carries no PartialEq -- so failing rows assert only that it
    // fails.
    #[test]
    fn proto_filter_capability_type_converts_to_domain() {
        check_cases(
            [
                Case {
                    scenario: "CapTypeCpu -> Cpu",
                    input: rpc::MachineCapabilityType::CapTypeCpu as i32,
                    expect: Yields(capabilities::MachineCapabilityType::Cpu),
                },
                Case {
                    scenario: "CapTypeGpu -> Gpu",
                    input: rpc::MachineCapabilityType::CapTypeGpu as i32,
                    expect: Yields(capabilities::MachineCapabilityType::Gpu),
                },
                Case {
                    scenario: "CapTypeMemory -> Memory",
                    input: rpc::MachineCapabilityType::CapTypeMemory as i32,
                    expect: Yields(capabilities::MachineCapabilityType::Memory),
                },
                Case {
                    scenario: "CapTypeStorage -> Storage",
                    input: rpc::MachineCapabilityType::CapTypeStorage as i32,
                    expect: Yields(capabilities::MachineCapabilityType::Storage),
                },
                Case {
                    scenario: "CapTypeNetwork -> Network",
                    input: rpc::MachineCapabilityType::CapTypeNetwork as i32,
                    expect: Yields(capabilities::MachineCapabilityType::Network),
                },
                Case {
                    scenario: "CapTypeInfiniband -> Infiniband",
                    input: rpc::MachineCapabilityType::CapTypeInfiniband as i32,
                    expect: Yields(capabilities::MachineCapabilityType::Infiniband),
                },
                Case {
                    scenario: "CapTypeDpu -> Dpu",
                    input: rpc::MachineCapabilityType::CapTypeDpu as i32,
                    expect: Yields(capabilities::MachineCapabilityType::Dpu),
                },
                Case {
                    scenario: "CapTypeInvalid is rejected",
                    input: rpc::MachineCapabilityType::CapTypeInvalid as i32,
                    expect: Fails,
                },
                Case {
                    scenario: "unset capability_type (0) is rejected",
                    input: 0,
                    expect: Fails,
                },
                Case {
                    scenario: "unknown discriminant coerces to invalid and is rejected",
                    input: 9001,
                    expect: Fails,
                },
            ],
            |capability_type| {
                InstanceTypeMachineCapabilityFilter::try_from(proto_filter_of_type(capability_type))
                    .map(|f| f.capability_type)
                    .map_err(drop)
            },
        );
    }

    // proto -> domain: the optional device_type i32 round-trips each known
    // discriminant, treats absence as None, and rejects an out-of-range value.
    #[test]
    fn proto_filter_device_type_converts_to_domain() {
        check_cases(
            [
                Case {
                    scenario: "absent device_type -> None",
                    input: None,
                    expect: Yields(None),
                },
                Case {
                    scenario: "Unknown -> Some(Unknown)",
                    input: Some(rpc::MachineCapabilityDeviceType::Unknown as i32),
                    expect: Yields(Some(capabilities::MachineCapabilityDeviceType::Unknown)),
                },
                Case {
                    scenario: "Dpu -> Some(Dpu)",
                    input: Some(rpc::MachineCapabilityDeviceType::Dpu as i32),
                    expect: Yields(Some(capabilities::MachineCapabilityDeviceType::Dpu)),
                },
                Case {
                    scenario: "Nvlink -> Some(NvLink)",
                    input: Some(rpc::MachineCapabilityDeviceType::Nvlink as i32),
                    expect: Yields(Some(capabilities::MachineCapabilityDeviceType::NvLink)),
                },
                Case {
                    scenario: "out-of-range device_type is rejected",
                    input: Some(9001),
                    expect: Fails,
                },
            ],
            |device_type| {
                let proto = rpc::InstanceTypeMachineCapabilityFilterAttributes {
                    device_type,
                    ..proto_filter_of_type(rpc::MachineCapabilityType::CapTypeNetwork as i32)
                };
                InstanceTypeMachineCapabilityFilter::try_from(proto)
                    .map(|f| f.device_type)
                    .map_err(drop)
            },
        );
    }

    // proto -> domain: optional scalar fields carry through verbatim, and the
    // inactive_devices list unwraps to its items.
    #[test]
    fn proto_filter_optional_fields_carry_through() {
        let proto = rpc::InstanceTypeMachineCapabilityFilterAttributes {
            name: Some("xeon".to_string()),
            frequency: Some("2.4 GHz".to_string()),
            capacity: Some("256 GB".to_string()),
            vendor: Some("intel".to_string()),
            count: Some(4),
            hardware_revision: Some("rev2".to_string()),
            cores: Some(8),
            threads: Some(16),
            inactive_devices: Some(rpc_common::Uint32List { items: vec![1, 3, 5] }),
            ..proto_filter_of_type(rpc::MachineCapabilityType::CapTypeCpu as i32)
        };

        Case {
            scenario: "populated proto filter -> domain filter",
            input: proto,
            expect: Yields(InstanceTypeMachineCapabilityFilter {
                capability_type: capabilities::MachineCapabilityType::Cpu,
                name: Some("xeon".to_string()),
                frequency: Some("2.4 GHz".to_string()),
                capacity: Some("256 GB".to_string()),
                vendor: Some("intel".to_string()),
                count: Some(4),
                hardware_revision: Some("rev2".to_string()),
                cores: Some(8),
                threads: Some(16),
                inactive_devices: Some(vec![1, 3, 5]),
                device_type: None,
            }),
        }
        .check(|p| InstanceTypeMachineCapabilityFilter::try_from(p).map_err(drop));
    }

    // domain -> proto: each capability_type maps to the proto discriminant as an
    // i32. The conversion is fallible in signature but total over these inputs.
    #[test]
    fn domain_filter_capability_type_converts_to_proto() {
        check_cases(
            [
                Case {
                    scenario: "Cpu -> CapTypeCpu",
                    input: capabilities::MachineCapabilityType::Cpu,
                    expect: Yields(rpc::MachineCapabilityType::CapTypeCpu as i32),
                },
                Case {
                    scenario: "Gpu -> CapTypeGpu",
                    input: capabilities::MachineCapabilityType::Gpu,
                    expect: Yields(rpc::MachineCapabilityType::CapTypeGpu as i32),
                },
                Case {
                    scenario: "Memory -> CapTypeMemory",
                    input: capabilities::MachineCapabilityType::Memory,
                    expect: Yields(rpc::MachineCapabilityType::CapTypeMemory as i32),
                },
                Case {
                    scenario: "Storage -> CapTypeStorage",
                    input: capabilities::MachineCapabilityType::Storage,
                    expect: Yields(rpc::MachineCapabilityType::CapTypeStorage as i32),
                },
                Case {
                    scenario: "Network -> CapTypeNetwork",
                    input: capabilities::MachineCapabilityType::Network,
                    expect: Yields(rpc::MachineCapabilityType::CapTypeNetwork as i32),
                },
                Case {
                    scenario: "Infiniband -> CapTypeInfiniband",
                    input: capabilities::MachineCapabilityType::Infiniband,
                    expect: Yields(rpc::MachineCapabilityType::CapTypeInfiniband as i32),
                },
                Case {
                    scenario: "Dpu -> CapTypeDpu",
                    input: capabilities::MachineCapabilityType::Dpu,
                    expect: Yields(rpc::MachineCapabilityType::CapTypeDpu as i32),
                },
            ],
            |capability_type| {
                rpc::InstanceTypeMachineCapabilityFilterAttributes::try_from(domain_filter_of_type(
                    capability_type,
                ))
                .map(|p| p.capability_type)
                .map_err(drop)
            },
        );
    }

    // domain -> proto: device_type maps each known arm to its proto i32, and an
    // absent device_type stays None.
    #[test]
    fn domain_filter_device_type_converts_to_proto() {
        check_cases(
            [
                Case {
                    scenario: "None -> None",
                    input: None,
                    expect: Yields(None),
                },
                Case {
                    scenario: "Unknown -> Some(Unknown i32)",
                    input: Some(capabilities::MachineCapabilityDeviceType::Unknown),
                    expect: Yields(Some(rpc::MachineCapabilityDeviceType::Unknown as i32)),
                },
                Case {
                    scenario: "Dpu -> Some(Dpu i32)",
                    input: Some(capabilities::MachineCapabilityDeviceType::Dpu),
                    expect: Yields(Some(rpc::MachineCapabilityDeviceType::Dpu as i32)),
                },
                Case {
                    scenario: "NvLink -> Some(Nvlink i32)",
                    input: Some(capabilities::MachineCapabilityDeviceType::NvLink),
                    expect: Yields(Some(rpc::MachineCapabilityDeviceType::Nvlink as i32)),
                },
            ],
            |device_type| {
                let filter = InstanceTypeMachineCapabilityFilter {
                    device_type,
                    ..domain_filter_of_type(capabilities::MachineCapabilityType::Network)
                };
                rpc::InstanceTypeMachineCapabilityFilterAttributes::try_from(filter)
                    .map(|p| p.device_type)
                    .map_err(drop)
            },
        );
    }

    // domain -> proto: optional scalar fields carry through and inactive_devices
    // re-wraps into a Uint32List.
    #[test]
    fn domain_filter_optional_fields_carry_through() {
        let filter = InstanceTypeMachineCapabilityFilter {
            capability_type: capabilities::MachineCapabilityType::Cpu,
            name: Some("xeon".to_string()),
            frequency: Some("2.4 GHz".to_string()),
            capacity: Some("256 GB".to_string()),
            vendor: Some("intel".to_string()),
            count: Some(4),
            hardware_revision: Some("rev2".to_string()),
            cores: Some(8),
            threads: Some(16),
            inactive_devices: Some(vec![1, 3, 5]),
            device_type: None,
        };

        Case {
            scenario: "populated domain filter -> proto filter",
            input: filter,
            expect: Yields(rpc::InstanceTypeMachineCapabilityFilterAttributes {
                capability_type: rpc::MachineCapabilityType::CapTypeCpu as i32,
                name: Some("xeon".to_string()),
                frequency: Some("2.4 GHz".to_string()),
                capacity: Some("256 GB".to_string()),
                vendor: Some("intel".to_string()),
                count: Some(4),
                hardware_revision: Some("rev2".to_string()),
                cores: Some(8),
                threads: Some(16),
                inactive_devices: Some(rpc_common::Uint32List { items: vec![1, 3, 5] }),
                device_type: None,
            }),
        }
        .check(|f| {
            rpc::InstanceTypeMachineCapabilityFilterAttributes::try_from(f).map_err(drop)
        });
    }

    // InstanceType -> proto: the desired_capabilities count is preserved across the
    // conversion, whether the list is empty or holds several filters. Asserting on
    // the count keeps the row a single bool predicate while still exercising the
    // per-filter loop.
    #[test]
    fn model_instance_type_preserves_capability_count() {
        check_cases(
            [
                Case {
                    scenario: "no desired capabilities -> empty attributes",
                    input: inst_type_with(vec![]),
                    expect: Yields(0),
                },
                Case {
                    scenario: "two desired capabilities -> two attributes",
                    input: inst_type_with(vec![
                        domain_filter_of_type(capabilities::MachineCapabilityType::Cpu),
                        domain_filter_of_type(capabilities::MachineCapabilityType::Gpu),
                    ]),
                    expect: Yields(2),
                },
            ],
            |it| {
                rpc::InstanceType::try_from(it)
                    .map(|p| {
                        p.attributes
                            .map(|a| a.desired_capabilities.len())
                            .unwrap_or(0)
                    })
                    .map_err(drop)
            },
        );
    }

    // InstanceType -> proto: an empty label value becomes None in the proto Label,
    // while a non-empty value carries through as Some. Folded to a bool over the
    // produced label's value, keyed by the one label we inject.
    #[test]
    fn model_instance_type_empty_label_value_becomes_none() {
        check_cases(
            [
                Case {
                    scenario: "empty label value -> None",
                    input: "".to_string(),
                    expect: Yields(None),
                },
                Case {
                    scenario: "non-empty label value -> Some",
                    input: "prod".to_string(),
                    expect: Yields(Some("prod".to_string())),
                },
            ],
            |value| {
                let mut inst_type = inst_type_with(vec![]);
                inst_type
                    .metadata
                    .labels
                    .insert("env".to_string(), value);
                rpc::InstanceType::try_from(inst_type)
                    .map(|p| {
                        p.metadata
                            .and_then(|m| m.labels.into_iter().find(|l| l.key == "env"))
                            .and_then(|l| l.value)
                    })
                    .map_err(drop)
            },
        );
    }
}
