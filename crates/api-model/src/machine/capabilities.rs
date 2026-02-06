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
use std::fmt;

use ::rpc::forge as rpc;
use carbide_uuid::machine::MachineId;
use serde::{Deserialize, Serialize};

use super::infiniband::MachineInfinibandStatusObservation;
use crate::hardware_info::{CpuInfo, InfinibandInterface};
use crate::machine::{HardwareInfo, MachineInterfaceSnapshot, RpcDataConversionError};

lazy_static::lazy_static! {
    static ref BLOCK_STORAGE_REGEX: regex::Regex = regex::Regex::new(r"(Virtual_CDROM\d+|Virtual_SD\d+|NO_MODEL|LOGICAL_VOLUME)").unwrap();
    static ref NVME_STORAGE_REGEX: regex::Regex = regex::Regex::new(r"(NO_MODEL|LOGICAL_VOLUME)").unwrap();
}

/* ********************************** */
/*        MachineCapabilityType       */
/* ********************************** */

/// MachineCapabilityType represents a category
/// of machine capability.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
pub enum MachineCapabilityType {
    #[default]
    Cpu,
    Gpu,
    Memory,
    Storage,
    Network,
    Infiniband,
    Dpu,
}

impl fmt::Display for MachineCapabilityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MachineCapabilityType::Cpu => write!(f, "CPU"),
            MachineCapabilityType::Gpu => write!(f, "GPU"),
            MachineCapabilityType::Memory => write!(f, "MEMORY"),
            MachineCapabilityType::Storage => write!(f, "STORAGE"),
            MachineCapabilityType::Network => write!(f, "NETWORK"),
            MachineCapabilityType::Infiniband => write!(f, "INFINIBAND"),
            MachineCapabilityType::Dpu => write!(f, "DPU"),
        }
    }
}

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

/* ********************************** */
/*         MachineCapabilityCpu       */
/* ********************************** */

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct MachineCapabilityCpu {
    /// CPU model name
    pub name: String,
    /// number of sockets
    pub count: u32,
    /// CPU vendor name
    pub vendor: Option<String>,
    /// cores per socket
    pub cores: Option<u32>,
    /// threads per socket
    pub threads: Option<u32>,
}

impl From<&CpuInfo> for MachineCapabilityCpu {
    fn from(src: &CpuInfo) -> Self {
        MachineCapabilityCpu {
            name: src.model.clone(),
            count: src.sockets,
            vendor: Some(src.vendor.clone()),
            cores: Some(src.cores),
            threads: Some(src.threads),
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

/* ********************************** */
/*         MachineCapabilityGpu       */
/* ********************************** */

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct MachineCapabilityGpu {
    pub name: String,
    pub count: u32,
    pub vendor: Option<String>,
    pub frequency: Option<String>,
    pub memory_capacity: Option<String>,
    pub cores: Option<u32>,
    pub threads: Option<u32>,
    pub device_type: Option<MachineCapabilityDeviceType>,
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

/* ********************************** */
/*       MachineCapabilityMemory      */
/* ********************************** */

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct MachineCapabilityMemory {
    pub name: String,
    pub count: u32,
    pub vendor: Option<String>,
    pub capacity: Option<String>,
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

/* ********************************** */
/*       MachineCapabilityStorage     */
/* ********************************** */

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct MachineCapabilityStorage {
    pub name: String,
    pub count: u32,
    pub vendor: Option<String>,
    pub capacity: Option<String>,
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

/* ********************************** */
/*       MachineCapabilityNetwork     */
/* ********************************** */

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct MachineCapabilityNetwork {
    pub name: String,
    pub count: u32,
    pub vendor: Option<String>,
    pub device_type: Option<MachineCapabilityDeviceType>,
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

/* ********************************** */
/*     MachineCapabilityInfiniband    */
/* ********************************** */

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct MachineCapabilityInfiniband {
    pub name: String,
    pub count: u32,
    pub vendor: String,
    /// The indexes of InfiniBand Devices which are not active and thereby can
    /// not be utilized by Instances.
    /// Inactive devices are devices where for example there is no connection
    /// between the port and the InfiniBand switch.
    /// Example: A `{count: 4, inactive_devices: [1,3]}` means that the devices
    /// with index `0` and `2` of the Host can be utilized, and devices with index
    /// `1` and `3` can not be used.
    pub inactive_devices: Vec<u32>,
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

impl MachineCapabilityInfiniband {
    /// Derives a Machines Infiniband capabilities based on a hardware snapshot
    /// and the current InfiniBand connection status
    pub fn from_ib_interfaces_and_status(
        infiniband_interfaces: &[InfinibandInterface],
        ib_status: Option<&MachineInfinibandStatusObservation>,
    ) -> Vec<Self> {
        // IB interfaces get sorted by PCI Slot ID so that the inactive device
        // indices can be derived correctly
        let mut sorted_ib_interfaces = infiniband_interfaces.to_vec();
        sorted_ib_interfaces.sort_by_key(|iface| match &iface.pci_properties {
            Some(pci_properties) => pci_properties.slot.clone().unwrap_or_default(),
            None => "".to_owned(),
        });
        let mut infiniband_interface_map = HashMap::<String, MachineCapabilityInfiniband>::new();

        for infiniband_interface_info in sorted_ib_interfaces.iter() {
            // Skip any interface where we can't get PCI details.
            // This is how this data is handled in forge-cloud, but
            // does it make sense here?
            let pci_properties = match infiniband_interface_info.pci_properties.as_ref() {
                None => continue,
                Some(p) => p,
            };

            let interface_name = match pci_properties.description.as_ref() {
                None => continue,
                Some(n) => n.clone(),
            };

            // Check if the we have an observation for this device on UFM
            let is_active = ib_status
                .as_ref()
                .and_then(|ib_status| {
                    ib_status
                        .ib_interfaces
                        .iter()
                        .find(|iface| iface.guid == infiniband_interface_info.guid)
                })
                .map(|port_status| port_status.lid != 0xffff_u16)
                .unwrap_or_default();

            let cap = infiniband_interface_map
                .entry(interface_name.clone())
                .or_insert_with(|| MachineCapabilityInfiniband {
                    name: interface_name,
                    count: 0,
                    vendor: pci_properties.vendor.clone(),
                    inactive_devices: Vec::new(),
                });
            cap.count += 1;
            if !is_active {
                cap.inactive_devices.push(cap.count - 1);
            }
        }

        infiniband_interface_map.into_values().collect()
    }
}

/* ********************************** */
/*         MachineCapabilityDpu       */
/* ********************************** */

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct MachineCapabilityDpu {
    pub name: String,
    pub count: u32,
    pub hardware_revision: Option<String>,
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
/* ********************************** */
/*       MachineCapabilitiesSet       */
/* ********************************** */

/// A combined set of all known machine capabilities.
/// The content depends on the original source of the data,
/// and it's expected that that sources could include some
/// combination of discovery, topology, and BOM data.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq)]
pub struct MachineCapabilitiesSet {
    pub cpu: Vec<MachineCapabilityCpu>,
    pub gpu: Vec<MachineCapabilityGpu>,
    pub memory: Vec<MachineCapabilityMemory>,
    pub storage: Vec<MachineCapabilityStorage>,
    pub network: Vec<MachineCapabilityNetwork>,
    pub infiniband: Vec<MachineCapabilityInfiniband>,
    pub dpu: Vec<MachineCapabilityDpu>,
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

/* ********************************************* */
/*       MachineCapabilityDeviceType       */
/* ********************************************* */

/// MachineCapabilityDeviceType describes different types of network devices.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum MachineCapabilityDeviceType {
    Unknown,
    Dpu,
    NvLink,
}

impl fmt::Display for MachineCapabilityDeviceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MachineCapabilityDeviceType::Unknown => write!(f, "UNKNOWN"),
            MachineCapabilityDeviceType::Dpu => write!(f, "DPU"),
            MachineCapabilityDeviceType::NvLink => write!(f, "NVLINK"),
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

impl MachineCapabilitiesSet {
    /// The arrays in each property of a capability set are not guaranteed to
    /// to have deterministic ordering, which is probably fine for most cases.
    /// When deterministic ordering is required, this function can be used to
    /// sorts the vectors found in each property of the capability set.
    pub fn sort(&mut self) {
        self.cpu.sort();
        self.gpu.sort();
        self.storage.sort();
        self.memory.sort();
        self.infiniband.sort();
        self.network.sort();
        self.dpu.sort();
    }

    pub fn from_hardware_info(
        hardware_info: HardwareInfo,
        ib_status: Option<&MachineInfinibandStatusObservation>,
        dpu_machine_ids: Vec<MachineId>,
        machine_interfaces: Vec<MachineInterfaceSnapshot>,
    ) -> Self {
        //
        //  Process GPU data
        //

        let mut gpu_map = HashMap::<String, MachineCapabilityGpu>::new();

        let is_gbx00 = hardware_info.is_gbx00();
        for gpu_info in hardware_info.gpus.into_iter() {
            match gpu_map.get_mut(&gpu_info.name) {
                None => {
                    gpu_map.insert(
                        gpu_info.name.clone(),
                        MachineCapabilityGpu {
                            name: gpu_info.name,
                            count: 1,
                            vendor: None, // hardware_info doesn't provide this.
                            frequency: Some(gpu_info.frequency),
                            cores: None,   // hardware_info doesn't provide this.
                            threads: None, // hardware_info doesn't provide this.
                            memory_capacity: Some(gpu_info.total_memory),
                            device_type: if is_gbx00 {
                                Some(MachineCapabilityDeviceType::NvLink)
                            } else {
                                Some(MachineCapabilityDeviceType::Unknown)
                            },
                        },
                    );
                }
                Some(gpu_cap) => {
                    gpu_cap.count += 1;
                }
            };
        }

        //
        //  Process memory data
        //

        let mut mem_map = HashMap::<String, usize>::new();

        for mem_info in hardware_info.memory_devices.into_iter() {
            let name = mem_info.mem_type.unwrap_or("unknown".to_string());

            mem_map
                .entry(name.clone())
                .and_modify(|e| {
                    *e = e.saturating_add(mem_info.size_mb.unwrap_or_default() as usize)
                })
                .or_insert_with(|| mem_info.size_mb.unwrap_or_default() as usize);
        }

        //
        // Process storage data.
        // NVME and block storage get flattened out into just "storage"
        //

        let mut storage_map = HashMap::<String, MachineCapabilityStorage>::new();

        // Start with any NVME devices.
        for storage_info in hardware_info.nvme_devices.into_iter() {
            // Skip missing models, logical volumes, and virtual storage.
            if NVME_STORAGE_REGEX.is_match(&storage_info.model) {
                continue;
            }

            match storage_map.get_mut(&storage_info.model) {
                None => {
                    storage_map.insert(
                        storage_info.model.clone(),
                        MachineCapabilityStorage {
                            name: storage_info.model.clone(),
                            count: 1,
                            vendor: None,   // hardware_info doesn't provide this.
                            capacity: None, // hardware_info doesn't provide this.
                        },
                    );
                }
                Some(storage_cap) => {
                    storage_cap.count += 1;
                }
            };
        }

        // Next, add in any block storage devices.
        for storage_info in hardware_info.block_devices.into_iter() {
            // Skip missing models, logical volumes, and virtual storage.
            if BLOCK_STORAGE_REGEX.is_match(&storage_info.model) {
                continue;
            }

            match storage_map.get_mut(&storage_info.model) {
                None => {
                    storage_map.insert(
                        storage_info.model.clone(),
                        MachineCapabilityStorage {
                            name: storage_info.model.clone(),
                            count: 1,
                            vendor: None,   // hardware_info doesn't provide this.
                            capacity: None, // hardware_info doesn't provide this.
                        },
                    );
                }
                Some(storage_cap) => {
                    storage_cap.count += 1;
                }
            };
        }

        //
        // Process network interface data
        //

        let mut network_interface_map = HashMap::<String, MachineCapabilityNetwork>::new();

        for network_interface_info in hardware_info.network_interfaces.into_iter() {
            // Skip any interface where we can't get PCI details.
            // This is how this data is handled in forge-cloud, but
            // does it make sense here?
            let pci_properties = match network_interface_info.pci_properties {
                None => continue,
                Some(p) => p,
            };

            let interface_name = match pci_properties.description {
                None => continue,
                Some(n) => n,
            };
            let device_type = match machine_interfaces.iter().find(|i| {
                i.mac_address == network_interface_info.mac_address
                    && i.attached_dpu_machine_id.is_some()
            }) {
                None => MachineCapabilityDeviceType::Unknown,
                Some(_i) => MachineCapabilityDeviceType::Dpu,
            };

            match network_interface_map.get_mut(&interface_name) {
                None => {
                    network_interface_map.insert(
                        interface_name.clone(),
                        MachineCapabilityNetwork {
                            name: interface_name.clone(),
                            count: 1,
                            vendor: Some(pci_properties.vendor),
                            device_type: Some(device_type),
                        },
                    );
                }
                Some(network_interface_cap) => {
                    network_interface_cap.count += 1;
                }
            };
        }

        //
        // Process infiniband data
        //

        let infiniband = MachineCapabilityInfiniband::from_ib_interfaces_and_status(
            &hardware_info.infiniband_interfaces,
            ib_status,
        );

        MachineCapabilitiesSet {
            cpu: hardware_info
                .cpu_info
                .iter()
                .map(MachineCapabilityCpu::from)
                .collect(),
            gpu: gpu_map.into_values().collect(),
            memory: mem_map
                .drain()
                .map(|(mem_type, mem_sum_mb)| MachineCapabilityMemory {
                    name: mem_type,
                    vendor: None, // hardware_info doesn't provide this
                    count: 1,     // We roll up all the memory we find
                    capacity: Some(format!("{mem_sum_mb} MB")),
                })
                .collect(),
            storage: storage_map.into_values().collect(),
            network: network_interface_map.into_values().collect(),
            infiniband,
            dpu: if dpu_machine_ids.is_empty() {
                vec![]
            } else {
                vec![MachineCapabilityDpu {
                    // This name value is what forge-cloud currently does/expects from machine capabilities.
                    // It needs to have _something_ that won't change.  If we decide to start
                    // pulling actual DPU details in the future, it would probably require
                    // forge cloud to also start allowing `name` as an optional field
                    // for instance type capability filters, and we'd have to update existing
                    // instance types in cloud to drop the `name` value while we transition.
                    name: "DPU".to_string(),
                    count: dpu_machine_ids.len().try_into().unwrap_or_else(|e| {
                        tracing::warn!(
                            error=%e,
                            "associated_dpu_machine_ids length uncountable for DPU capability",
                        );
                        0
                    }),
                    hardware_revision: None,
                }]
            },
        }
    }
}

/* ********************************** */
/*              Tests                 */
/* ********************************** */

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use ::rpc::forge as rpc;

    use super::*;
    use crate::hardware_info::*;
    use crate::ib::DEFAULT_IB_FABRIC_NAME;
    use crate::machine::MachineInterfaceId;
    use crate::machine::infiniband::MachineIbInterfaceStatusObservation;
    use crate::{MacAddress, NetworkSegmentId};

    const X86_INFO_JSON: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/hardware_info/test_data/x86_info.json"
    ));

    #[test]
    fn test_model_cpu_capability_to_rpc_conversion() {
        let req_type = rpc::MachineCapabilityAttributesCpu {
            name: "pentium 4 HT".to_string(),
            count: 1,
            vendor: Some("intel".to_string()),
            cores: Some(1),
            threads: Some(2),
        };

        let machine_cap = MachineCapabilityCpu {
            name: "pentium 4 HT".to_string(),
            count: 1,
            vendor: Some("intel".to_string()),
            cores: Some(1),
            threads: Some(2),
        };

        assert_eq!(
            req_type,
            rpc::MachineCapabilityAttributesCpu::from(machine_cap)
        );
    }

    #[test]
    fn test_model_gpu_capability_to_rpc_conversion() {
        let req_type = rpc::MachineCapabilityAttributesGpu {
            name: "RTX 6000".to_string(),
            count: 1,
            frequency: Some("1.2 giggawattz".to_string()),
            vendor: Some("nvidia".to_string()),
            cores: Some(1),
            threads: Some(2),
            capacity: Some("24 GB".to_string()),
            device_type: Some(MachineCapabilityDeviceType::Unknown as i32),
        };

        let machine_cap = MachineCapabilityGpu {
            name: "RTX 6000".to_string(),
            count: 1,
            frequency: Some("1.2 giggawattz".to_string()),
            vendor: Some("nvidia".to_string()),
            cores: Some(1),
            threads: Some(2),
            memory_capacity: Some("24 GB".to_string()),
            device_type: Some(MachineCapabilityDeviceType::Unknown),
        };

        assert_eq!(
            req_type,
            rpc::MachineCapabilityAttributesGpu::from(machine_cap)
        );
    }

    #[test]
    fn test_model_memory_capability_to_rpc_conversion() {
        let req_type = rpc::MachineCapabilityAttributesMemory {
            name: "DDR4".to_string(),
            count: 1,
            vendor: Some("crucial".to_string()),
            capacity: Some("32 GB".to_string()),
        };

        let machine_cap = MachineCapabilityMemory {
            name: "DDR4".to_string(),
            count: 1,
            vendor: Some("crucial".to_string()),
            capacity: Some("32 GB".to_string()),
        };

        assert_eq!(
            req_type,
            rpc::MachineCapabilityAttributesMemory::from(machine_cap)
        );
    }

    #[test]
    fn test_model_storage_capability_to_rpc_conversion() {
        let req_type = rpc::MachineCapabilityAttributesStorage {
            name: "Spinning Disk".to_string(),
            count: 1,
            vendor: Some("western digital".to_string()),
            capacity: Some("1 TB".to_string()),
        };

        let machine_cap = MachineCapabilityStorage {
            name: "Spinning Disk".to_string(),
            count: 1,
            vendor: Some("western digital".to_string()),
            capacity: Some("1 TB".to_string()),
        };

        assert_eq!(
            req_type,
            rpc::MachineCapabilityAttributesStorage::from(machine_cap)
        );
    }

    #[test]
    fn test_model_network_capability_to_rpc_conversion() {
        let req_type = rpc::MachineCapabilityAttributesNetwork {
            name: "BCM57414 NetXtreme-E 10Gb/25Gb RDMA Ethernet Controller".to_string(),
            count: 1,
            vendor: Some("0x14e4".to_string()),
            device_type: Some(MachineCapabilityDeviceType::Unknown as i32),
        };

        let machine_cap = MachineCapabilityNetwork {
            name: "BCM57414 NetXtreme-E 10Gb/25Gb RDMA Ethernet Controller".to_string(),
            count: 1,
            vendor: Some("0x14e4".to_string()),
            device_type: Some(MachineCapabilityDeviceType::Unknown),
        };

        assert_eq!(
            req_type,
            rpc::MachineCapabilityAttributesNetwork::from(machine_cap)
        );
    }

    #[test]
    fn test_model_infiniband_capability_to_rpc_conversion() {
        let req_type = rpc::MachineCapabilityAttributesInfiniband {
            name: "IB NIC".to_string(),
            count: 4,
            vendor: Some("IB NIC Vendor".to_string()),
            inactive_devices: vec![0, 2],
        };

        let machine_cap = MachineCapabilityInfiniband {
            name: "IB NIC".to_string(),
            count: 4,
            vendor: "IB NIC Vendor".to_string(),
            inactive_devices: vec![0, 2],
        };

        assert_eq!(
            req_type,
            rpc::MachineCapabilityAttributesInfiniband::from(machine_cap)
        );
    }

    #[test]
    fn test_model_dpu_capability_to_rpc_conversion() {
        let req_type = rpc::MachineCapabilityAttributesDpu {
            name: "bf3".to_string(),
            count: 1,
            hardware_revision: Some("uh, 3?".to_string()),
        };

        let machine_cap = MachineCapabilityDpu {
            name: "bf3".to_string(),
            count: 1,
            hardware_revision: Some("uh, 3?".to_string()),
        };

        assert_eq!(
            req_type,
            rpc::MachineCapabilityAttributesDpu::from(machine_cap)
        );
    }

    #[test]
    fn test_model_capability_set_to_rpc_conversion() {
        let req_type = rpc::MachineCapabilitiesSet {
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

        let machine_cap = MachineCapabilitiesSet {
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

        assert_eq!(req_type, rpc::MachineCapabilitiesSet::from(machine_cap));
    }

    #[test]
    fn test_model_capability_set_from_hw_info_conversion() {
        let mut machine_cap = MachineCapabilitiesSet {
            cpu: vec![MachineCapabilityCpu {
                name: "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz".to_string(),
                count: 1,
                vendor: Some("GenuineIntel".to_string()),
                cores: Some(18),
                threads: Some(72),
            }],
            gpu: vec![MachineCapabilityGpu {
                name: "NVIDIA H100 PCIe".to_string(),
                count: 1,
                vendor: None,
                frequency: Some("1755 MHz".to_string()),
                memory_capacity: Some("81559 MiB".to_string()),
                cores: None,
                threads: None,
                device_type: Some(MachineCapabilityDeviceType::Unknown),
            }],
            memory: vec![MachineCapabilityMemory {
                name: "DDR4".to_string(),
                count: 1,
                vendor: None,
                capacity: Some("2048 MB".to_string()),
            }],
            storage: vec![
                MachineCapabilityStorage {
                    name: "DELLBOSS_VD".to_string(),
                    count: 3,
                    vendor: None,
                    capacity: None,
                },
                MachineCapabilityStorage {
                    name: "Dell Ent NVMe CM6 RI 1.92TB".to_string(),
                    count: 10,
                    vendor: None,
                    capacity: None,
                },
            ],
            network: vec![
                MachineCapabilityNetwork {
                    name: "BCM57414 NetXtreme-E 10Gb/25Gb RDMA Ethernet Controller".to_string(),
                    count: 2,
                    vendor: Some("0x14e4".to_string()),
                    device_type: Some(MachineCapabilityDeviceType::Unknown),
                },
                MachineCapabilityNetwork {
                    name: "MT42822 BlueField-2 integrated ConnectX-6 Dx network controller"
                        .to_string(),
                    count: 2,
                    vendor: Some("mellanox".to_string()),
                    device_type: Some(MachineCapabilityDeviceType::Dpu),
                },
                MachineCapabilityNetwork {
                    name:
                        "NetXtreme BCM5720 2-port Gigabit Ethernet PCIe (PowerEdge Rx5xx LOM Board)"
                            .to_string(),
                    count: 2,
                    vendor: Some("0x14e4".to_string()),
                    device_type: Some(MachineCapabilityDeviceType::Unknown),
                },
            ],
            infiniband: vec![
                MachineCapabilityInfiniband {
                    name: "MT27800 Family [ConnectX-5]".to_string(),
                    count: 2,
                    vendor: "0x15b3".to_string(),
                    inactive_devices: vec![0, 1],
                },
                MachineCapabilityInfiniband {
                    name: "MT2910 Family [ConnectX-7]".to_string(),
                    count: 4,
                    vendor: "0x15b3".to_string(),
                    inactive_devices: vec![0, 1, 2, 3],
                },
            ],
            dpu: vec![MachineCapabilityDpu {
                name: "DPU".to_string(),
                count: 2,
                hardware_revision: None,
            }],
        };

        // The capabilities are built using hashmaps, so
        // the ordering of the final arrays isn't guaranteed.

        machine_cap.sort();

        let mut compare_cap = MachineCapabilitiesSet::from_hardware_info(
            serde_json::from_slice::<HardwareInfo>(X86_INFO_JSON).unwrap(),
            None,
            vec![
                "fm100dskla0ihp0pn4tv7v1js2k2mo37sl0jjr8141okqg8pjpdpfihaa80"
                    .parse()
                    .unwrap(),
                "fm100dsmu2vhi1042hb8lrunopesh641tiguh6uttjr780ghbk9orl5tcg0"
                    .parse()
                    .unwrap(),
            ],
            vec![
                MachineInterfaceSnapshot {
                    id: MachineInterfaceId::from(uuid::Uuid::nil()),
                    hostname: String::new(),
                    primary_interface: true,
                    mac_address: MacAddress::from_str("08:c0:eb:cb:0e:96").unwrap(),
                    attached_dpu_machine_id: Some(
                        MachineId::from_str(
                            "fm100dsbiu5ckus880v8407u0mkcensa39cule26im5gnpvmuufckacguc0",
                        )
                        .unwrap(),
                    ),
                    domain_id: None,
                    machine_id: None,
                    segment_id: NetworkSegmentId::from(uuid::Uuid::nil()),
                    vendors: Vec::new(),
                    created: chrono::Utc::now(),
                    last_dhcp: None,
                    addresses: Vec::new(),
                    network_segment_type: None,
                    power_shelf_id: None,
                    switch_id: None,
                    association_type: None,
                },
                MachineInterfaceSnapshot {
                    id: MachineInterfaceId::from(uuid::Uuid::nil()),
                    hostname: String::new(),
                    primary_interface: true,
                    mac_address: MacAddress::from_str("08:c0:eb:cb:0e:97").unwrap(),
                    attached_dpu_machine_id: Some(
                        MachineId::from_str(
                            "fm100dsg23d2f4tq4tt5m2hgib5pcldrm3gvefbduau7gj3itgc3iqg3lpg",
                        )
                        .unwrap(),
                    ),
                    domain_id: None,
                    machine_id: None,
                    segment_id: NetworkSegmentId::from(uuid::Uuid::nil()),
                    vendors: Vec::new(),
                    created: chrono::Utc::now(),
                    last_dhcp: None,
                    addresses: Vec::new(),
                    network_segment_type: None,
                    power_shelf_id: None,
                    switch_id: None,
                    association_type: None,
                },
            ],
        );

        compare_cap.sort();

        assert_eq!(machine_cap, compare_cap);
    }

    #[test]
    fn test_model_infinityband_capability_fully_connected() {
        let mut expected_ib_caps = vec![
            MachineCapabilityInfiniband {
                name: "MT27800 Family [ConnectX-5]".to_string(),
                count: 2,
                vendor: "0x15b3".to_string(),
                inactive_devices: vec![],
            },
            MachineCapabilityInfiniband {
                name: "MT2910 Family [ConnectX-7]".to_string(),
                count: 4,
                vendor: "0x15b3".to_string(),
                inactive_devices: vec![],
            },
        ];
        expected_ib_caps.sort();

        let ib_status = MachineInfinibandStatusObservation {
            ib_interfaces: vec![
                MachineIbInterfaceStatusObservation {
                    guid: "946dae03002ac100".to_string(),
                    lid: 1,
                    fabric_id: DEFAULT_IB_FABRIC_NAME.to_string(),
                    associated_pkeys: None,
                    associated_partition_ids: None,
                },
                MachineIbInterfaceStatusObservation {
                    guid: "946dae03002ac101".to_string(),
                    lid: 2,
                    fabric_id: DEFAULT_IB_FABRIC_NAME.to_string(),
                    associated_pkeys: None,
                    associated_partition_ids: None,
                },
                MachineIbInterfaceStatusObservation {
                    guid: "946dae03002ac102".to_string(),
                    lid: 3,
                    fabric_id: DEFAULT_IB_FABRIC_NAME.to_string(),
                    associated_pkeys: None,
                    associated_partition_ids: None,
                },
                MachineIbInterfaceStatusObservation {
                    guid: "946dae03002ac103".to_string(),
                    lid: 4,
                    fabric_id: DEFAULT_IB_FABRIC_NAME.to_string(),
                    associated_pkeys: None,
                    associated_partition_ids: None,
                },
                MachineIbInterfaceStatusObservation {
                    guid: "946dae03002ac752".to_string(),
                    lid: 5,
                    fabric_id: DEFAULT_IB_FABRIC_NAME.to_string(),
                    associated_pkeys: None,
                    associated_partition_ids: None,
                },
                MachineIbInterfaceStatusObservation {
                    guid: "946dae03002ac753".to_string(),
                    lid: 6,
                    fabric_id: DEFAULT_IB_FABRIC_NAME.to_string(),
                    associated_pkeys: None,
                    associated_partition_ids: None,
                },
            ],
            observed_at: chrono::Utc::now(),
        };

        let mut compare_cap = MachineCapabilitiesSet::from_hardware_info(
            serde_json::from_slice::<HardwareInfo>(X86_INFO_JSON).unwrap(),
            Some(&ib_status),
            vec![],
            vec![MachineInterfaceSnapshot {
                id: MachineInterfaceId::from(uuid::Uuid::nil()),
                hostname: String::new(),
                primary_interface: true,
                mac_address: MacAddress::from_str("00:00:00:00:00:00").unwrap(),
                attached_dpu_machine_id: None,
                domain_id: None,
                machine_id: None,
                segment_id: NetworkSegmentId::from(uuid::Uuid::nil()),
                vendors: Vec::new(),
                created: chrono::Utc::now(),
                last_dhcp: None,
                addresses: Vec::new(),
                network_segment_type: None,
                power_shelf_id: None,
                switch_id: None,
                association_type: None,
            }],
        );

        compare_cap.sort();

        assert_eq!(expected_ib_caps, compare_cap.infiniband);
    }

    #[test]
    fn test_model_infinityband_capability_partially_connected() {
        let mut expected_ib_caps = vec![
            MachineCapabilityInfiniband {
                name: "MT27800 Family [ConnectX-5]".to_string(),
                count: 2,
                vendor: "0x15b3".to_string(),
                inactive_devices: vec![0],
            },
            MachineCapabilityInfiniband {
                name: "MT2910 Family [ConnectX-7]".to_string(),
                count: 4,
                vendor: "0x15b3".to_string(),
                inactive_devices: vec![1, 3],
            },
        ];
        expected_ib_caps.sort();

        let ib_status = MachineInfinibandStatusObservation {
            ib_interfaces: vec![
                MachineIbInterfaceStatusObservation {
                    guid: "946dae03002ac752".to_string(),
                    lid: 0xffff_u16,
                    fabric_id: DEFAULT_IB_FABRIC_NAME.to_string(),
                    associated_pkeys: None,
                    associated_partition_ids: None,
                },
                MachineIbInterfaceStatusObservation {
                    guid: "946dae03002ac753".to_string(),
                    lid: 1,
                    fabric_id: DEFAULT_IB_FABRIC_NAME.to_string(),
                    associated_pkeys: None,
                    associated_partition_ids: None,
                },
                MachineIbInterfaceStatusObservation {
                    guid: "946dae03002ac103".to_string(),
                    lid: 2,
                    fabric_id: DEFAULT_IB_FABRIC_NAME.to_string(),
                    associated_pkeys: None,
                    associated_partition_ids: None,
                },
                MachineIbInterfaceStatusObservation {
                    guid: "946dae03002ac101".to_string(),
                    lid: 4,
                    fabric_id: DEFAULT_IB_FABRIC_NAME.to_string(),
                    associated_pkeys: None,
                    associated_partition_ids: None,
                },
                MachineIbInterfaceStatusObservation {
                    guid: "946dae03002ac100".to_string(),
                    lid: 0xffff_u16,
                    fabric_id: DEFAULT_IB_FABRIC_NAME.to_string(),
                    associated_pkeys: None,
                    associated_partition_ids: None,
                },
            ],
            observed_at: chrono::Utc::now(),
        };

        let mut compare_cap = MachineCapabilitiesSet::from_hardware_info(
            serde_json::from_slice::<HardwareInfo>(X86_INFO_JSON).unwrap(),
            Some(&ib_status),
            vec![],
            vec![],
        );

        compare_cap.sort();

        assert_eq!(expected_ib_caps, compare_cap.infiniband);
    }
}
