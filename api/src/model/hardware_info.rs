/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Describes hardware that is discovered by Forge

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::model::{try_convert_vec, RpcDataConversionError};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareInfo {
    #[serde(default)]
    pub network_interfaces: Vec<NetworkInterface>,
    #[serde(default)]
    pub cpus: Vec<Cpu>,
    #[serde(default)]
    pub block_devices: Vec<BlockDevice>,
    pub machine_type: String,
    #[serde(default)]
    pub nvme_devices: Vec<NvmeDevice>,
    #[serde(default)]
    pub dmi_devices: Vec<DmiDevice>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub mac_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_properties: Option<PciDeviceProperties>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cpu {
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub frequency: String,
    #[serde(default)]
    pub number: u32,
    #[serde(default)]
    pub core: u32,
    #[serde(default)]
    pub node: i32,
    #[serde(default)]
    pub socket: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDevice {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub revision: String,
    #[serde(default)]
    pub serial: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeDevice {
    pub model: String,
    pub firmware_rev: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmiDevice {
    pub board_name: String,
    pub board_version: String,
    pub bios_version: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PciDeviceProperties {
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub device: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub numa_node: i32,
    #[serde(default)]
    pub description: Option<String>,
}

// These defines conversions functions from the RPC data model into the internal
// data model (which might also be used in the database).
// It might actually be nicer to have those closer to the rpc crate to avoid
// polluting the internal data model with API concerns, but since this is a
// separate crate we can't have it there (unless we also make the model a
// separate crate).

impl TryFrom<rpc::machine_discovery::Cpu> for Cpu {
    type Error = RpcDataConversionError;

    fn try_from(cpu: rpc::machine_discovery::Cpu) -> Result<Self, Self::Error> {
        Ok(Self {
            vendor: cpu.vendor,
            model: cpu.model,
            frequency: cpu.frequency,
            number: cpu.number,
            core: cpu.core,
            node: cpu.node,
            socket: cpu.socket,
        })
    }
}

impl TryFrom<Cpu> for rpc::machine_discovery::Cpu {
    type Error = RpcDataConversionError;

    fn try_from(cpu: Cpu) -> Result<Self, Self::Error> {
        Ok(Self {
            vendor: cpu.vendor,
            model: cpu.model,
            frequency: cpu.frequency,
            number: cpu.number,
            core: cpu.core,
            node: cpu.node,
            socket: cpu.socket,
        })
    }
}

impl TryFrom<rpc::machine_discovery::BlockDevice> for BlockDevice {
    type Error = RpcDataConversionError;

    fn try_from(dev: rpc::machine_discovery::BlockDevice) -> Result<Self, Self::Error> {
        Ok(Self {
            model: dev.model,
            revision: dev.revision,
            serial: dev.serial,
        })
    }
}

impl TryFrom<BlockDevice> for rpc::machine_discovery::BlockDevice {
    type Error = RpcDataConversionError;

    fn try_from(dev: BlockDevice) -> Result<Self, Self::Error> {
        Ok(Self {
            model: dev.model,
            revision: dev.revision,
            serial: dev.serial,
        })
    }
}

impl TryFrom<rpc::machine_discovery::NvmeDevice> for NvmeDevice {
    type Error = RpcDataConversionError;

    fn try_from(dev: rpc::machine_discovery::NvmeDevice) -> Result<Self, Self::Error> {
        Ok(Self {
            model: dev.model,
            firmware_rev: dev.firmware_rev,
        })
    }
}

impl TryFrom<NvmeDevice> for rpc::machine_discovery::NvmeDevice {
    type Error = RpcDataConversionError;

    fn try_from(dev: NvmeDevice) -> Result<Self, Self::Error> {
        Ok(Self {
            model: dev.model,
            firmware_rev: dev.firmware_rev,
        })
    }
}

impl TryFrom<rpc::machine_discovery::DmiDevice> for DmiDevice {
    type Error = RpcDataConversionError;

    fn try_from(dev: rpc::machine_discovery::DmiDevice) -> Result<Self, Self::Error> {
        Ok(Self {
            board_name: dev.board_name,
            board_version: dev.board_version,
            bios_version: dev.bios_version,
        })
    }
}

impl TryFrom<DmiDevice> for rpc::machine_discovery::DmiDevice {
    type Error = RpcDataConversionError;

    fn try_from(dev: DmiDevice) -> Result<Self, Self::Error> {
        Ok(Self {
            board_name: dev.board_name,
            board_version: dev.board_version,
            bios_version: dev.bios_version,
        })
    }
}

impl TryFrom<rpc::machine_discovery::NetworkInterface> for NetworkInterface {
    type Error = RpcDataConversionError;

    fn try_from(iface: rpc::machine_discovery::NetworkInterface) -> Result<Self, Self::Error> {
        let pci_properties = match iface.pci_properties.map(PciDeviceProperties::try_from) {
            Some(Err(e)) => return Err(e),
            Some(Ok(props)) => Some(props),
            None => None,
        };

        Ok(Self {
            mac_address: iface.mac_address,
            pci_properties,
        })
    }
}

impl TryFrom<NetworkInterface> for rpc::machine_discovery::NetworkInterface {
    type Error = RpcDataConversionError;

    fn try_from(iface: NetworkInterface) -> Result<Self, Self::Error> {
        let pci_properties = match iface
            .pci_properties
            .map(rpc::machine_discovery::PciDeviceProperties::try_from)
        {
            Some(Err(e)) => return Err(e),
            Some(Ok(props)) => Some(props),
            None => None,
        };

        Ok(Self {
            mac_address: iface.mac_address,
            pci_properties,
        })
    }
}

impl TryFrom<rpc::machine_discovery::PciDeviceProperties> for PciDeviceProperties {
    type Error = RpcDataConversionError;

    fn try_from(props: rpc::machine_discovery::PciDeviceProperties) -> Result<Self, Self::Error> {
        Ok(Self {
            vendor: props.vendor,
            device: props.device,
            path: props.path,
            numa_node: props.numa_node,
            description: props.description,
        })
    }
}

impl TryFrom<PciDeviceProperties> for rpc::machine_discovery::PciDeviceProperties {
    type Error = RpcDataConversionError;

    fn try_from(props: PciDeviceProperties) -> Result<Self, Self::Error> {
        Ok(Self {
            vendor: props.vendor,
            device: props.device,
            path: props.path,
            numa_node: props.numa_node,
            description: props.description,
        })
    }
}

impl TryFrom<rpc::machine_discovery::DiscoveryInfo> for HardwareInfo {
    type Error = RpcDataConversionError;

    fn try_from(info: rpc::machine_discovery::DiscoveryInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            network_interfaces: try_convert_vec(info.network_interfaces)?,
            cpus: try_convert_vec(info.cpus)?,
            block_devices: try_convert_vec(info.block_devices)?,
            machine_type: info.machine_type,
            nvme_devices: try_convert_vec(info.nvme_devices)?,
            dmi_devices: try_convert_vec(info.dmi_devices)?,
        })
    }
}

impl TryFrom<HardwareInfo> for rpc::machine_discovery::DiscoveryInfo {
    type Error = RpcDataConversionError;

    fn try_from(info: HardwareInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            network_interfaces: try_convert_vec(info.network_interfaces)?,
            cpus: try_convert_vec(info.cpus)?,
            block_devices: try_convert_vec(info.block_devices)?,
            machine_type: info.machine_type,
            nvme_devices: try_convert_vec(info.nvme_devices)?,
            dmi_devices: try_convert_vec(info.dmi_devices)?,
        })
    }
}

impl HardwareInfo {
    /// Returns whether the machine is deemed to be a DPU based on some properties
    ///
    /// Note that this function currently misclassifies ARM hosts with DPUs as NICs
    /// also as DPUs
    pub fn is_dpu(&self) -> bool {
        let network_interfaces = &self.network_interfaces;
        let machine_type = &self.machine_type;

        const ARM_TYPE: &str = "aarch64";
        if machine_type != ARM_TYPE {
            return false;
        }

        if network_interfaces.is_empty() {
            return false; // has no network interfaces/attribute
        }

        log::debug!("Interfaces Hash found");
        log::debug!(
            "Looking for attributes on interface: {:?}",
            network_interfaces
        );

        // Update list with id's we care about
        let dpu_pci_ids = HashSet::from(["0x15b3:0xa2d6", "0x1af4:0x1000"]);
        does_attributes_contain_dpu_pci_ids(&dpu_pci_ids, &network_interfaces[..])
    }
}

fn does_attributes_contain_dpu_pci_ids(
    dpu_pci_ids: &HashSet<&str>,
    interfaces: &[NetworkInterface],
) -> bool {
    interfaces.iter().any(|interface| {
        log::info!("Interface Info: {:?}", interface);
        let mac_address = interface.mac_address.as_str();
        match &interface.pci_properties {
            None => {
                log::info!(
                    "Unable to find PCI PROPERTIES for interface {}",
                    mac_address
                );
            }
            Some(pci_property) => {
                log::info!("Network interface {} contains necessary information for examination. Checking if this is a DPU.", mac_address);
                // If for some reason there is no vendor/device in pci_properties
                // set to 0'
                let vendor = pci_property.vendor.as_str();
                let device = pci_property.device.as_str();
                let pci_id = format!("{}:{}", vendor, device);

                if dpu_pci_ids.contains(pci_id.as_str()) {
                    log::info!(
                        "VENDOR AND DEVICE INFORMATION MATCHES - PCI_ID {} and MAC_ADDRESS: {}",
                        pci_id,
                        mac_address
                    );
                    return true;
                }

                log::info!("VENDOR AND DEVICE INFORMATION DOES NOT MATCH, INTERFACE {} IS NOT A DPU", mac_address);
            }
        }
        false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_DATA_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/model/hardware_info/test_data"
    );

    #[test]
    fn serialize_blockdev() {
        let dev: BlockDevice = serde_json::from_str("{}").unwrap();
        assert_eq!(
            dev,
            BlockDevice {
                model: "".to_string(),
                revision: "".to_string(),
                serial: "".to_string(),
            }
        );

        let dev1 = BlockDevice {
            model: "disk".to_string(),
            revision: "rev1".to_string(),
            serial: "001".to_string(),
        };

        let serialized = serde_json::to_string(&dev1).unwrap();
        assert_eq!(
            serialized,
            "{\"model\":\"disk\",\"revision\":\"rev1\",\"serial\":\"001\"}"
        );
        assert_eq!(
            serde_json::from_str::<BlockDevice>(&serialized).unwrap(),
            dev1
        );
    }

    #[test]
    fn serialize_cpu() {
        let cpu: Cpu = serde_json::from_str("{}").unwrap();
        assert_eq!(
            cpu,
            Cpu {
                vendor: "".to_string(),
                model: "".to_string(),
                frequency: "".to_string(),
                number: 0,
                core: 0,
                node: 0,
                socket: 0,
            }
        );

        let cpu1 = Cpu {
            vendor: "v1".to_string(),
            model: "m1".to_string(),
            frequency: "f1".to_string(),
            number: 1,
            core: 2,
            node: 3,
            socket: 4,
        };

        let serialized = serde_json::to_string(&cpu1).unwrap();
        assert_eq!(
            serialized,
            "{\"vendor\":\"v1\",\"model\":\"m1\",\"frequency\":\"f1\",\"number\":1,\"core\":2,\"node\":3,\"socket\":4}"
        );
        assert_eq!(serde_json::from_str::<Cpu>(&serialized).unwrap(), cpu1);
    }

    #[test]
    fn serialize_pci_dev_properties() {
        let props: PciDeviceProperties = serde_json::from_str("{}").unwrap();
        assert_eq!(
            props,
            PciDeviceProperties {
                vendor: "".to_string(),
                device: "".to_string(),
                path: "".to_string(),
                numa_node: 0,
                description: None,
            }
        );

        let props1 = PciDeviceProperties {
            vendor: "v1".to_string(),
            device: "d1".to_string(),
            path: "p1".to_string(),
            numa_node: 3,
            description: Some("desc1".to_string()),
        };

        let serialized = serde_json::to_string(&props1).unwrap();
        assert_eq!(
            serialized,
            "{\"vendor\":\"v1\",\"device\":\"d1\",\"path\":\"p1\",\"numa_node\":3,\"description\":\"desc1\"}"
        );
        assert_eq!(
            serde_json::from_str::<PciDeviceProperties>(&serialized).unwrap(),
            props1
        );
    }

    #[test]
    fn deserialize_x86_info() {
        let path = format!("{}/x86_info.json", TEST_DATA_DIR);
        let data = std::fs::read(path).unwrap();
        let info = serde_json::from_slice::<HardwareInfo>(&data).unwrap();
        assert!(!info.is_dpu());
    }

    #[test]
    fn deserialize_dpu_info() {
        let path = format!("{}/dpu_info.json", TEST_DATA_DIR);
        let data = std::fs::read(path).unwrap();
        let info = serde_json::from_slice::<HardwareInfo>(&data).unwrap();
        assert!(info.is_dpu());
    }
}
