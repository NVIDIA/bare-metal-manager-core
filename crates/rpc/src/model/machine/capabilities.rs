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

use model::machine::capabilities::{
    MachineCapabilitiesSet, MachineCapabilityCpu, MachineCapabilityDeviceType,
    MachineCapabilityDpu, MachineCapabilityGpu, MachineCapabilityInfiniband,
    MachineCapabilityMemory, MachineCapabilityNetwork, MachineCapabilityStorage,
    MachineCapabilityType,
};

use crate::errors::RpcDataConversionError;
use crate::forge as rpc;

impl From<MachineCapabilityType> for rpc::MachineCapabilityType {
    fn from(t: MachineCapabilityType) -> Self {
        match t {
            MachineCapabilityType::Cpu => rpc::MachineCapabilityType::CapTypeCpu,
            MachineCapabilityType::Gpu => rpc::MachineCapabilityType::CapTypeGpu,
            MachineCapabilityType::Memory => rpc::MachineCapabilityType::CapTypeMemory,
            MachineCapabilityType::Storage => rpc::MachineCapabilityType::CapTypeStorage,
            MachineCapabilityType::Network => rpc::MachineCapabilityType::CapTypeNetwork,
            MachineCapabilityType::Infiniband => rpc::MachineCapabilityType::CapTypeInfiniband,
            MachineCapabilityType::Dpu => rpc::MachineCapabilityType::CapTypeDpu,
        }
    }
}

impl TryFrom<rpc::MachineCapabilityType> for MachineCapabilityType {
    type Error = RpcDataConversionError;

    fn try_from(t: rpc::MachineCapabilityType) -> Result<Self, Self::Error> {
        match t {
            rpc::MachineCapabilityType::CapTypeInvalid => Err(
                RpcDataConversionError::InvalidArgument(t.as_str_name().to_string()),
            ),
            rpc::MachineCapabilityType::CapTypeCpu => Ok(MachineCapabilityType::Cpu),
            rpc::MachineCapabilityType::CapTypeGpu => Ok(MachineCapabilityType::Gpu),
            rpc::MachineCapabilityType::CapTypeMemory => Ok(MachineCapabilityType::Memory),
            rpc::MachineCapabilityType::CapTypeStorage => Ok(MachineCapabilityType::Storage),
            rpc::MachineCapabilityType::CapTypeNetwork => Ok(MachineCapabilityType::Network),
            rpc::MachineCapabilityType::CapTypeInfiniband => Ok(MachineCapabilityType::Infiniband),
            rpc::MachineCapabilityType::CapTypeDpu => Ok(MachineCapabilityType::Dpu),
        }
    }
}

impl From<MachineCapabilityCpu> for rpc::MachineCapabilityAttributesCpu {
    fn from(cap: MachineCapabilityCpu) -> Self {
        rpc::MachineCapabilityAttributesCpu {
            name: cap.name,
            count: cap.count,
            vendor: cap.vendor,
            cores: cap.cores,
            threads: cap.threads,
        }
    }
}

impl From<MachineCapabilityGpu> for rpc::MachineCapabilityAttributesGpu {
    fn from(cap: MachineCapabilityGpu) -> Self {
        rpc::MachineCapabilityAttributesGpu {
            name: cap.name,
            frequency: cap.frequency,
            vendor: cap.vendor,
            count: cap.count,
            capacity: cap.memory_capacity,
            cores: cap.cores,
            threads: cap.threads,
            device_type: cap
                .device_type
                .map(|dt| rpc::MachineCapabilityDeviceType::from(dt).into()),
        }
    }
}

impl From<MachineCapabilityMemory> for rpc::MachineCapabilityAttributesMemory {
    fn from(cap: MachineCapabilityMemory) -> Self {
        rpc::MachineCapabilityAttributesMemory {
            name: cap.name,
            count: cap.count,
            vendor: cap.vendor,
            capacity: cap.capacity,
        }
    }
}

impl From<MachineCapabilityStorage> for rpc::MachineCapabilityAttributesStorage {
    fn from(cap: MachineCapabilityStorage) -> Self {
        rpc::MachineCapabilityAttributesStorage {
            name: cap.name,
            count: cap.count,
            vendor: cap.vendor,
            capacity: cap.capacity,
        }
    }
}

impl From<MachineCapabilityNetwork> for rpc::MachineCapabilityAttributesNetwork {
    fn from(cap: MachineCapabilityNetwork) -> Self {
        rpc::MachineCapabilityAttributesNetwork {
            name: cap.name,
            count: cap.count,
            vendor: cap.vendor,
            device_type: cap
                .device_type
                .map(|dt| rpc::MachineCapabilityDeviceType::from(dt).into()),
        }
    }
}

impl From<MachineCapabilityInfiniband> for rpc::MachineCapabilityAttributesInfiniband {
    fn from(cap: MachineCapabilityInfiniband) -> Self {
        rpc::MachineCapabilityAttributesInfiniband {
            name: cap.name,
            vendor: Some(cap.vendor),
            count: cap.count,
            inactive_devices: cap.inactive_devices,
        }
    }
}

impl From<MachineCapabilityDpu> for rpc::MachineCapabilityAttributesDpu {
    fn from(cap: MachineCapabilityDpu) -> Self {
        rpc::MachineCapabilityAttributesDpu {
            name: cap.name,
            count: cap.count,
            hardware_revision: cap.hardware_revision,
        }
    }
}

impl From<MachineCapabilitiesSet> for rpc::MachineCapabilitiesSet {
    fn from(cap_set: MachineCapabilitiesSet) -> Self {
        rpc::MachineCapabilitiesSet {
            cpu: cap_set.cpu.into_iter().map(|cap| cap.into()).collect(),
            gpu: cap_set.gpu.into_iter().map(|cap| cap.into()).collect(),
            memory: cap_set.memory.into_iter().map(|cap| cap.into()).collect(),
            storage: cap_set.storage.into_iter().map(|cap| cap.into()).collect(),
            network: cap_set.network.into_iter().map(|cap| cap.into()).collect(),
            infiniband: cap_set
                .infiniband
                .into_iter()
                .map(|cap| cap.into())
                .collect(),
            dpu: cap_set.dpu.into_iter().map(|cap| cap.into()).collect(),
        }
    }
}

impl From<MachineCapabilityDeviceType> for rpc::MachineCapabilityDeviceType {
    fn from(t: MachineCapabilityDeviceType) -> Self {
        match t {
            MachineCapabilityDeviceType::Unknown => rpc::MachineCapabilityDeviceType::Unknown,
            MachineCapabilityDeviceType::Dpu => rpc::MachineCapabilityDeviceType::Dpu,
            MachineCapabilityDeviceType::NvLink => rpc::MachineCapabilityDeviceType::Nvlink,
        }
    }
}

impl TryFrom<rpc::MachineCapabilityDeviceType> for MachineCapabilityDeviceType {
    type Error = RpcDataConversionError;

    fn try_from(t: rpc::MachineCapabilityDeviceType) -> Result<Self, Self::Error> {
        match t {
            rpc::MachineCapabilityDeviceType::Unknown => Ok(MachineCapabilityDeviceType::Unknown),
            rpc::MachineCapabilityDeviceType::Dpu => Ok(MachineCapabilityDeviceType::Dpu),
            rpc::MachineCapabilityDeviceType::Nvlink => Ok(MachineCapabilityDeviceType::NvLink),
        }
    }
}

/* ********************************** */
/*              Tests                 */
/* ********************************** */

#[cfg(test)]
mod tests {

    use carbide_test_support::Check;

    use super::*;
    use crate::forge as rpc;

    // Each per-attribute model -> rpc conversion is a distinct total `From` over a
    // distinct pair of types, so each is one `Check` row exercising that `.into()`.

    #[test]
    fn test_model_cpu_capability_to_rpc_conversion() {
        Check {
            scenario: "cpu capability converts field-for-field",
            input: MachineCapabilityCpu {
                name: "pentium 4 HT".to_string(),
                count: 1,
                vendor: Some("intel".to_string()),
                cores: Some(1),
                threads: Some(2),
            },
            expect: rpc::MachineCapabilityAttributesCpu {
                name: "pentium 4 HT".to_string(),
                count: 1,
                vendor: Some("intel".to_string()),
                cores: Some(1),
                threads: Some(2),
            },
        }
        .check(rpc::MachineCapabilityAttributesCpu::from);
    }

    #[test]
    fn test_model_gpu_capability_to_rpc_conversion() {
        Check {
            scenario: "gpu capability converts (memory_capacity -> capacity, device_type mapped)",
            input: MachineCapabilityGpu {
                name: "RTX 6000".to_string(),
                count: 1,
                frequency: Some("1.2 giggawattz".to_string()),
                vendor: Some("nvidia".to_string()),
                cores: Some(1),
                threads: Some(2),
                memory_capacity: Some("24 GB".to_string()),
                device_type: Some(MachineCapabilityDeviceType::Unknown),
            },
            expect: rpc::MachineCapabilityAttributesGpu {
                name: "RTX 6000".to_string(),
                count: 1,
                frequency: Some("1.2 giggawattz".to_string()),
                vendor: Some("nvidia".to_string()),
                cores: Some(1),
                threads: Some(2),
                capacity: Some("24 GB".to_string()),
                device_type: Some(MachineCapabilityDeviceType::Unknown as i32),
            },
        }
        .check(rpc::MachineCapabilityAttributesGpu::from);
    }

    #[test]
    fn test_model_memory_capability_to_rpc_conversion() {
        Check {
            scenario: "memory capability converts field-for-field",
            input: MachineCapabilityMemory {
                name: "DDR4".to_string(),
                count: 1,
                vendor: Some("crucial".to_string()),
                capacity: Some("32 GB".to_string()),
            },
            expect: rpc::MachineCapabilityAttributesMemory {
                name: "DDR4".to_string(),
                count: 1,
                vendor: Some("crucial".to_string()),
                capacity: Some("32 GB".to_string()),
            },
        }
        .check(rpc::MachineCapabilityAttributesMemory::from);
    }

    #[test]
    fn test_model_storage_capability_to_rpc_conversion() {
        Check {
            scenario: "storage capability converts field-for-field",
            input: MachineCapabilityStorage {
                name: "Spinning Disk".to_string(),
                count: 1,
                vendor: Some("western digital".to_string()),
                capacity: Some("1 TB".to_string()),
            },
            expect: rpc::MachineCapabilityAttributesStorage {
                name: "Spinning Disk".to_string(),
                count: 1,
                vendor: Some("western digital".to_string()),
                capacity: Some("1 TB".to_string()),
            },
        }
        .check(rpc::MachineCapabilityAttributesStorage::from);
    }

    #[test]
    fn test_model_network_capability_to_rpc_conversion() {
        Check {
            scenario: "network capability converts (device_type mapped)",
            input: MachineCapabilityNetwork {
                name: "BCM57414 NetXtreme-E 10Gb/25Gb RDMA Ethernet Controller".to_string(),
                count: 1,
                vendor: Some("0x14e4".to_string()),
                device_type: Some(MachineCapabilityDeviceType::Unknown),
            },
            expect: rpc::MachineCapabilityAttributesNetwork {
                name: "BCM57414 NetXtreme-E 10Gb/25Gb RDMA Ethernet Controller".to_string(),
                count: 1,
                vendor: Some("0x14e4".to_string()),
                device_type: Some(MachineCapabilityDeviceType::Unknown as i32),
            },
        }
        .check(rpc::MachineCapabilityAttributesNetwork::from);
    }

    #[test]
    fn test_model_infiniband_capability_to_rpc_conversion() {
        Check {
            scenario: "infiniband capability converts (vendor wrapped in Some)",
            input: MachineCapabilityInfiniband {
                name: "IB NIC".to_string(),
                count: 4,
                vendor: "IB NIC Vendor".to_string(),
                inactive_devices: vec![0, 2],
            },
            expect: rpc::MachineCapabilityAttributesInfiniband {
                name: "IB NIC".to_string(),
                count: 4,
                vendor: Some("IB NIC Vendor".to_string()),
                inactive_devices: vec![0, 2],
            },
        }
        .check(rpc::MachineCapabilityAttributesInfiniband::from);
    }

    #[test]
    fn test_model_dpu_capability_to_rpc_conversion() {
        Check {
            scenario: "dpu capability converts field-for-field",
            input: MachineCapabilityDpu {
                name: "bf3".to_string(),
                count: 1,
                hardware_revision: Some("uh, 3?".to_string()),
            },
            expect: rpc::MachineCapabilityAttributesDpu {
                name: "bf3".to_string(),
                count: 1,
                hardware_revision: Some("uh, 3?".to_string()),
            },
        }
        .check(rpc::MachineCapabilityAttributesDpu::from);
    }

    // The whole-set conversion delegates to the per-attribute `From` impls above;
    // one `Check` row exercises the aggregate `.into()` over a populated set.
    #[test]
    fn test_model_capability_set_to_rpc_conversion() {
        let expect = rpc::MachineCapabilitiesSet {
            cpu: vec![rpc::MachineCapabilityAttributesCpu {
                name: "xeon".to_string(),
                count: 2,
                vendor: Some("intel".to_string()),
                cores: Some(24),
                threads: Some(48),
            }],
            gpu: vec![rpc::MachineCapabilityAttributesGpu {
                name: "rtx6000".to_string(),
                count: 1,
                frequency: Some("3 GHZ".to_string()),
                capacity: Some("12 GB".to_string()),
                vendor: Some("intel".to_string()),
                cores: Some(4),
                threads: Some(8),
                device_type: Some(MachineCapabilityDeviceType::Unknown as i32),
            }],
            memory: vec![rpc::MachineCapabilityAttributesMemory {
                name: "ddr4".to_string(),
                count: 2,
                capacity: Some("64 GB".to_string()),
                vendor: Some("micron".to_string()),
            }],
            storage: vec![
                rpc::MachineCapabilityAttributesStorage {
                    name: "nvme".to_string(),
                    count: 1,
                    capacity: Some("1 TB".to_string()),
                    vendor: Some("samsung".to_string()),
                },
                rpc::MachineCapabilityAttributesStorage {
                    name: "spinning disk".to_string(),
                    count: 1,
                    capacity: Some("1 TB".to_string()),
                    vendor: Some("maxtor".to_string()),
                },
            ],
            network: vec![rpc::MachineCapabilityAttributesNetwork {
                name: "intel e1000".to_string(),
                count: 1,
                vendor: Some("intel".to_string()),
                device_type: Some(MachineCapabilityDeviceType::Unknown as i32),
            }],
            infiniband: vec![rpc::MachineCapabilityAttributesInfiniband {
                name: "infiniband".to_string(),
                count: 1,
                vendor: Some("mellanox".to_string()),
                inactive_devices: Vec::new(),
            }],
            dpu: vec![rpc::MachineCapabilityAttributesDpu {
                name: "bf3".to_string(),
                count: 1,
                hardware_revision: Some("3".to_string()),
            }],
        };

        let input = MachineCapabilitiesSet {
            cpu: vec![MachineCapabilityCpu {
                name: "xeon".to_string(),
                count: 2,
                vendor: Some("intel".to_string()),
                cores: Some(24),
                threads: Some(48),
            }],
            gpu: vec![MachineCapabilityGpu {
                name: "rtx6000".to_string(),
                count: 1,
                frequency: Some("3 GHZ".to_string()),
                memory_capacity: Some("12 GB".to_string()),
                vendor: Some("intel".to_string()),
                cores: Some(4),
                threads: Some(8),
                device_type: Some(MachineCapabilityDeviceType::Unknown),
            }],
            memory: vec![MachineCapabilityMemory {
                name: "ddr4".to_string(),
                count: 2,
                capacity: Some("64 GB".to_string()),
                vendor: Some("micron".to_string()),
            }],
            storage: vec![
                MachineCapabilityStorage {
                    name: "nvme".to_string(),
                    count: 1,
                    capacity: Some("1 TB".to_string()),
                    vendor: Some("samsung".to_string()),
                },
                MachineCapabilityStorage {
                    name: "spinning disk".to_string(),
                    count: 1,
                    capacity: Some("1 TB".to_string()),
                    vendor: Some("maxtor".to_string()),
                },
            ],
            network: vec![MachineCapabilityNetwork {
                name: "intel e1000".to_string(),
                count: 1,
                vendor: Some("intel".to_string()),
                device_type: Some(MachineCapabilityDeviceType::Unknown),
            }],
            infiniband: vec![MachineCapabilityInfiniband {
                name: "infiniband".to_string(),
                count: 1,
                vendor: "mellanox".to_string(),
                inactive_devices: Vec::new(),
            }],
            dpu: vec![MachineCapabilityDpu {
                name: "bf3".to_string(),
                count: 1,
                hardware_revision: Some("3".to_string()),
            }],
        };

        Check {
            scenario: "populated set converts each attribute vec",
            input,
            expect,
        }
        .check(rpc::MachineCapabilitiesSet::from);
    }
}
