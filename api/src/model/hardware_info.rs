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

//! Describes hardware that is discovered by Forge

use std::str::FromStr;

use mac_address::{MacAddress, MacParseError};
use serde::{Deserialize, Serialize};

use crate::model::{try_convert_vec, RpcDataConversionError};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareInfo {
    #[serde(default)]
    pub network_interfaces: Vec<NetworkInterface>,
    #[serde(default)]
    pub infiniband_interfaces: Vec<InfinibandInterface>,
    #[serde(default)]
    pub cpus: Vec<Cpu>,
    #[serde(default)]
    pub block_devices: Vec<BlockDevice>,
    pub machine_type: String,
    #[serde(default)]
    pub nvme_devices: Vec<NvmeDevice>,
    #[serde(default)]
    pub dmi_data: Option<DmiData>,
    pub tpm_ek_certificate: Option<TpmEkCertificate>,
    #[serde(default)]
    pub dpu_info: Option<DpuData>,
    #[serde(default)]
    pub gpus: Vec<Gpu>,
    #[serde(default)]
    pub memory_devices: Vec<MemoryDevice>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    pub mac_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_properties: Option<PciDeviceProperties>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfinibandInterface {
    pub guid: String,

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
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub firmware_rev: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DmiData {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub board_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub board_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bios_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bios_date: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub product_serial: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub board_serial: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub chassis_serial: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub product_name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sys_vendor: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DpuData {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub part_number: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub part_description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub product_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub factory_mac_address: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub firmware_version: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub firmware_date: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub switches: Vec<LldpSwitchData>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LldpSwitchData {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub local_port: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip_address: Vec<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub remote_port: String,
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
    #[serde(default)]
    pub slot: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Gpu {
    name: String,
    serial: String,
    driver_version: String,
    vbios_version: String,
    inforom_version: String,
    total_memory: String,
    frequency: String,
    pci_bus_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryDevice {
    size_mb: Option<u32>,
    mem_type: Option<String>,
}

/// TPM endorsement key certificate
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TpmEkCertificate(Vec<u8>);

impl From<Vec<u8>> for TpmEkCertificate {
    fn from(cert: Vec<u8>) -> Self {
        Self(cert)
    }
}

impl TpmEkCertificate {
    /// Returns the binary content of the certificate
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Converts the certifcate into a byte array
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for TpmEkCertificate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&base64::encode(self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for TpmEkCertificate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let str_value = String::deserialize(deserializer)?;
        let bytes = base64::decode(str_value).map_err(|err| Error::custom(err.to_string()))?;
        Ok(Self(bytes))
    }
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

impl TryFrom<rpc::machine_discovery::DmiData> for DmiData {
    type Error = RpcDataConversionError;

    fn try_from(data: rpc::machine_discovery::DmiData) -> Result<Self, Self::Error> {
        Ok(Self {
            board_name: data.board_name,
            board_version: data.board_version,
            bios_version: data.bios_version,
            bios_date: data.bios_date,
            product_serial: data.product_serial,
            board_serial: data.board_serial,
            chassis_serial: data.chassis_serial,
            product_name: data.product_name,
            sys_vendor: data.sys_vendor,
        })
    }
}

impl TryFrom<DmiData> for rpc::machine_discovery::DmiData {
    type Error = RpcDataConversionError;

    fn try_from(data: DmiData) -> Result<Self, Self::Error> {
        Ok(Self {
            board_name: data.board_name,
            board_version: data.board_version,
            bios_version: data.bios_version,
            bios_date: data.bios_date,
            product_serial: data.product_serial,
            board_serial: data.board_serial,
            chassis_serial: data.chassis_serial,
            product_name: data.product_name,
            sys_vendor: data.sys_vendor,
        })
    }
}

impl TryFrom<rpc::machine_discovery::LldpSwitchData> for LldpSwitchData {
    type Error = RpcDataConversionError;

    fn try_from(data: rpc::machine_discovery::LldpSwitchData) -> Result<Self, Self::Error> {
        Ok(Self {
            name: data.name,
            id: data.id,
            description: data.description,
            local_port: data.local_port,
            ip_address: data.ip_address,
            remote_port: data.remote_port,
        })
    }
}

impl TryFrom<LldpSwitchData> for rpc::machine_discovery::LldpSwitchData {
    type Error = RpcDataConversionError;

    fn try_from(data: LldpSwitchData) -> Result<Self, Self::Error> {
        Ok(Self {
            name: data.name,
            id: data.id,
            description: data.description,
            local_port: data.local_port,
            ip_address: data.ip_address,
            remote_port: data.remote_port,
        })
    }
}

impl TryFrom<rpc::machine_discovery::DpuData> for DpuData {
    type Error = RpcDataConversionError;

    fn try_from(data: rpc::machine_discovery::DpuData) -> Result<Self, Self::Error> {
        Ok(Self {
            part_number: data.part_number,
            part_description: data.part_description,
            product_version: data.product_version,
            factory_mac_address: data.factory_mac_address,
            firmware_version: data.firmware_version,
            firmware_date: data.firmware_date,
            switches: try_convert_vec(data.switches)?,
        })
    }
}

impl TryFrom<DpuData> for rpc::machine_discovery::DpuData {
    type Error = RpcDataConversionError;

    fn try_from(data: DpuData) -> Result<Self, Self::Error> {
        Ok(Self {
            part_number: data.part_number,
            part_description: data.part_description,
            product_version: data.product_version,
            factory_mac_address: data.factory_mac_address,
            firmware_version: data.firmware_version,
            firmware_date: data.firmware_date,
            switches: try_convert_vec(data.switches)?,
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

impl TryFrom<rpc::machine_discovery::InfinibandInterface> for InfinibandInterface {
    type Error = RpcDataConversionError;

    fn try_from(ibface: rpc::machine_discovery::InfinibandInterface) -> Result<Self, Self::Error> {
        let pci_properties = match ibface.pci_properties.map(PciDeviceProperties::try_from) {
            Some(Err(e)) => return Err(e),
            Some(Ok(props)) => Some(props),
            None => None,
        };

        Ok(Self {
            guid: ibface.guid,
            pci_properties,
        })
    }
}

impl TryFrom<InfinibandInterface> for rpc::machine_discovery::InfinibandInterface {
    type Error = RpcDataConversionError;

    fn try_from(ibface: InfinibandInterface) -> Result<Self, Self::Error> {
        let pci_properties = match ibface
            .pci_properties
            .map(rpc::machine_discovery::PciDeviceProperties::try_from)
        {
            Some(Err(e)) => return Err(e),
            Some(Ok(props)) => Some(props),
            None => None,
        };

        Ok(Self {
            guid: ibface.guid,
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
            slot: props.slot,
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
            slot: props.slot,
        })
    }
}

impl From<rpc::machine_discovery::Gpu> for Gpu {
    fn from(value: rpc::machine_discovery::Gpu) -> Self {
        Gpu {
            name: value.name,
            serial: value.serial,
            driver_version: value.driver_version,
            vbios_version: value.vbios_version,
            inforom_version: value.inforom_version,
            total_memory: value.total_memory,
            frequency: value.frequency,
            pci_bus_id: value.pci_bus_id,
        }
    }
}

impl From<Gpu> for rpc::machine_discovery::Gpu {
    fn from(value: Gpu) -> Self {
        rpc::machine_discovery::Gpu {
            name: value.name,
            serial: value.serial,
            driver_version: value.driver_version,
            vbios_version: value.vbios_version,
            inforom_version: value.inforom_version,
            total_memory: value.total_memory,
            frequency: value.frequency,
            pci_bus_id: value.pci_bus_id,
        }
    }
}

impl From<rpc::machine_discovery::MemoryDevice> for MemoryDevice {
    fn from(value: rpc::machine_discovery::MemoryDevice) -> Self {
        MemoryDevice {
            size_mb: value.size_mb,
            mem_type: value.mem_type,
        }
    }
}

impl From<MemoryDevice> for rpc::machine_discovery::MemoryDevice {
    fn from(value: MemoryDevice) -> Self {
        rpc::machine_discovery::MemoryDevice {
            size_mb: value.size_mb,
            mem_type: value.mem_type,
        }
    }
}

impl TryFrom<rpc::machine_discovery::DiscoveryInfo> for HardwareInfo {
    type Error = RpcDataConversionError;

    fn try_from(info: rpc::machine_discovery::DiscoveryInfo) -> Result<Self, Self::Error> {
        let tpm_ek_certificate = info
            .tpm_ek_certificate
            .map(|base64| {
                base64::decode(base64)
                    .map_err(|_| RpcDataConversionError::InvalidBase64Data("tpm_ek_certificate"))
            })
            .transpose()?;

        Ok(Self {
            network_interfaces: try_convert_vec(info.network_interfaces)?,
            infiniband_interfaces: try_convert_vec(info.infiniband_interfaces)?,
            cpus: try_convert_vec(info.cpus)?,
            block_devices: try_convert_vec(info.block_devices)?,
            machine_type: info.machine_type,
            nvme_devices: try_convert_vec(info.nvme_devices)?,
            dmi_data: info.dmi_data.map(DmiData::try_from).transpose()?,
            tpm_ek_certificate: tpm_ek_certificate.map(TpmEkCertificate::from),
            dpu_info: info.dpu_info.map(DpuData::try_from).transpose()?,
            gpus: info.gpus.into_iter().map(Gpu::from).collect(),
            memory_devices: info
                .memory_devices
                .into_iter()
                .map(MemoryDevice::from)
                .collect(),
        })
    }
}

impl TryFrom<HardwareInfo> for rpc::machine_discovery::DiscoveryInfo {
    type Error = RpcDataConversionError;

    fn try_from(info: HardwareInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            network_interfaces: try_convert_vec(info.network_interfaces)?,
            infiniband_interfaces: try_convert_vec(info.infiniband_interfaces)?,
            cpus: try_convert_vec(info.cpus)?,
            block_devices: try_convert_vec(info.block_devices)?,
            machine_type: info.machine_type,
            nvme_devices: try_convert_vec(info.nvme_devices)?,
            dmi_data: info
                .dmi_data
                .map(rpc::machine_discovery::DmiData::try_from)
                .transpose()?,
            tpm_ek_certificate: info
                .tpm_ek_certificate
                .map(|cert| base64::encode(cert.into_bytes())),
            dpu_info: info
                .dpu_info
                .map(rpc::machine_discovery::DpuData::try_from)
                .transpose()?,
            gpus: info
                .gpus
                .into_iter()
                .map(rpc::machine_discovery::Gpu::from)
                .collect(),
            memory_devices: info
                .memory_devices
                .into_iter()
                .map(rpc::machine_discovery::MemoryDevice::from)
                .collect(),
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum HardwareInfoError {
    #[error("DPU Info is missing.")]
    MissingDpuInfo,

    #[error("Mac address conversion error: {0}")]
    MacAddressConversionError(#[from] MacParseError),
}

impl HardwareInfo {
    /// Returns whether the machine is deemed to be a DPU based on some properties
    pub fn is_dpu(&self) -> bool {
        let dmi_data = &self.dmi_data;
        let machine_type = &self.machine_type;

        const ARM_TYPE: &str = "aarch64";
        if machine_type != ARM_TYPE {
            return false;
        }

        // Bluefield's dmi data should return a special string that identifies it as a DPU
        match dmi_data {
            None => false,
            Some(dmi) => dmi.board_name.eq("BlueField SoC"),
        }
    }

    /// This function returns factory_mac_address from dpu_info.
    pub fn factory_mac_address(&self) -> Result<MacAddress, HardwareInfoError> {
        let Some(ref dpu_info) = self.dpu_info else {
            return Err(HardwareInfoError::MissingDpuInfo);
        };

        Ok(MacAddress::from_str(&dpu_info.factory_mac_address)?)
    }

    /// Is this a Dell or Lenovo machine?
    pub fn bmc_vendor(&self) -> BMCVendor {
        match self.dmi_data.as_ref() {
            Some(dmi_info) => match dmi_info.sys_vendor.as_ref() {
                "Lenovo" => BMCVendor::Lenovo,
                "Dell Inc." => BMCVendor::Dell,
                "https://www.mellanox.com" => BMCVendor::Mellanox,
                _ => BMCVendor::Unknown,
            },
            None => BMCVendor::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BMCVendor {
    Lenovo,
    Dell,
    Mellanox,
    Unknown,
}

impl BMCVendor {
    pub fn is_lenovo(self) -> bool {
        self == BMCVendor::Lenovo
    }
    pub fn is_dell(self) -> bool {
        self == BMCVendor::Dell
    }
    pub fn is_mellanox(self) -> bool {
        self == BMCVendor::Mellanox
    }
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
                slot: None,
            }
        );

        let props1 = PciDeviceProperties {
            vendor: "v1".to_string(),
            device: "d1".to_string(),
            path: "p1".to_string(),
            numa_node: 3,
            description: Some("desc1".to_string()),
            slot: Some("0000:4b:00.0".to_string()),
        };

        let serialized = serde_json::to_string(&props1).unwrap();
        assert_eq!(
            serialized,
            "{\"vendor\":\"v1\",\"device\":\"d1\",\"path\":\"p1\",\"numa_node\":3,\"description\":\"desc1\",\"slot\":\"0000:4b:00.0\"}"
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

    #[test]
    fn serialize_tpm_ek_certificate() {
        let cert_data = b"This is not really a certificate".to_vec();
        let cert = TpmEkCertificate::from(cert_data.clone());

        let serialized = serde_json::to_string(&cert).unwrap();
        assert_eq!(serialized, format!("\"{}\"", base64::encode(&cert_data)));

        // Test also how that the certificate looks right within a Json structure
        #[derive(Serialize)]
        struct OptionalCert {
            cert: Option<TpmEkCertificate>,
        }

        let serialized = serde_json::to_string(&OptionalCert { cert: Some(cert) }).unwrap();
        assert_eq!(
            serialized,
            format!("{{\"cert\":\"{}\"}}", base64::encode(&cert_data))
        );
    }

    #[test]
    fn deserialize_tpm_ek_certificate() {
        let cert_data = b"This is not really a certificate".to_vec();
        let encoded = base64::encode(&cert_data);

        let json = format!("\"{}\"", encoded);
        let deserialized: TpmEkCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.as_bytes(), &cert_data);

        // Test also how that the certificate looks right within a Json structure
        #[derive(Deserialize)]
        struct OptionalCert {
            cert: Option<TpmEkCertificate>,
        }

        let json = format!("{{\"cert\":\"{}\"}}", encoded);
        let deserialized: OptionalCert = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.cert.as_ref().map(|cert| cert.as_bytes()),
            Some(cert_data.as_slice())
        );
    }
}
