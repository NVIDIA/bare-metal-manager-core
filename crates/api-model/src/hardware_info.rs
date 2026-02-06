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

//! Describes hardware that is discovered by Forge

#[cfg(not(feature = "linux-build"))]
use std::collections::HashSet;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use ::rpc::errors::RpcDataConversionError;
use base64::prelude::*;
#[cfg(feature = "linux-build")]
use carbide_host_support::hardware_enumeration::aggregate_cpus;
use carbide_uuid::nvlink::NvLinkDomainId;
use forge_network::{MELLANOX_SF_VF_MAC_ADDRESS_IN, MELLANOX_SF_VF_MAC_ADDRESS_OUT};
use mac_address::{MacAddress, MacParseError};
use serde::{Deserialize, Serialize};
use utils::models::arch::CpuArchitecture;

use crate::machine::machine_id::MissingHardwareInfo;
use crate::try_convert_vec;

// TODO: Remove when there's no longer a need to handle the old topology format
#[derive(Deserialize)]
struct HardwareInfoDeserialized {
    #[serde(default)]
    network_interfaces: Vec<NetworkInterface>,
    #[serde(default)]
    infiniband_interfaces: Vec<InfinibandInterface>,
    #[serde(default)]
    cpu_info: Vec<CpuInfo>,
    #[serde(default)]
    block_devices: Vec<BlockDevice>,
    // This should be called machine_arch, but it's serialized directly in/out of a JSONB field in
    // the DB, so renaming it requires a migration or custom Serialize impl.
    machine_type: CpuArchitecture,
    #[serde(default)]
    nvme_devices: Vec<NvmeDevice>,
    #[serde(default)]
    dmi_data: Option<DmiData>,
    tpm_ek_certificate: Option<TpmEkCertificate>,
    #[serde(default)]
    dpu_info: Option<DpuData>,
    #[serde(default)]
    gpus: Vec<Gpu>,
    #[serde(default)]
    memory_devices: Vec<MemoryDevice>,
    #[serde(default)]
    cpus: Vec<Cpu>, // Deprecated in favor of `cpu_info`
    #[serde(default)]
    tpm_description: Option<TpmDescription>,
}

#[cfg(not(feature = "linux-build"))]
fn aggregate_cpus(cpus: &[rpc::machine_discovery::Cpu]) -> Vec<rpc::machine_discovery::CpuInfo> {
    if cpus.is_empty() {
        return Vec::new();
    }

    let socket_count = HashSet::<_>::from_iter(cpus.iter().map(|cpu| cpu.socket)).len();
    let core_count = HashSet::<_>::from_iter(cpus.iter().map(|cpu| (cpu.socket, cpu.core))).len();

    vec![rpc::machine_discovery::CpuInfo {
        model: cpus[0].model.clone(),
        vendor: cpus[0].vendor.clone(),
        sockets: socket_count as u32,
        cores: core_count as u32,
        threads: cpus.len() as u32,
    }]
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "HardwareInfoDeserialized")]
pub struct HardwareInfo {
    #[serde(default)]
    pub network_interfaces: Vec<NetworkInterface>,
    #[serde(default)]
    pub infiniband_interfaces: Vec<InfinibandInterface>,
    #[serde(default)]
    pub cpu_info: Vec<CpuInfo>,
    #[serde(default)]
    pub block_devices: Vec<BlockDevice>,
    // This should be called machine_arch, but it's serialized directly in/out of a JSONB field in
    // the DB, so renaming it requires a migration or custom Serialize impl.
    pub machine_type: CpuArchitecture,
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
    #[serde(default)]
    pub tpm_description: Option<TpmDescription>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInterface {
    #[serde(deserialize_with = "forge_network::deserialize_mlx_mac")]
    pub mac_address: MacAddress,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_properties: Option<PciDeviceProperties>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InfinibandInterface {
    pub guid: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pci_properties: Option<PciDeviceProperties>,
}

// TODO: Remove when there's no longer a need to handle the old topology format
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
pub struct CpuInfo {
    #[serde(default)]
    pub model: String, // CPU model name
    #[serde(default)]
    pub vendor: String, // CPU vendor name
    #[serde(default)]
    pub sockets: u32, // number of sockets
    #[serde(default)]
    pub cores: u32, // cores per socket
    #[serde(default)]
    pub threads: u32, // threads per socket
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockDevice {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub revision: String,
    #[serde(default)]
    pub serial: String,
    #[serde(default)]
    pub device_type: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvmeDevice {
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub firmware_rev: String,
    #[serde(default)]
    pub serial: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    pub name: String,
    pub serial: String,
    pub driver_version: String,
    pub vbios_version: String,
    pub inforom_version: String,
    pub total_memory: String,
    pub frequency: String,
    pub pci_bus_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_info: Option<GpuPlatformInfo>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuPlatformInfo {
    pub chassis_serial: String,
    pub slot_number: u32,
    pub tray_index: u32,
    pub host_id: u32,
    pub module_id: u32,
    pub fabric_guid: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryDevice {
    pub size_mb: Option<u32>,
    pub mem_type: Option<String>,
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

    /// Converts the certificate into a byte array
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for TpmEkCertificate {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&BASE64_STANDARD.encode(self.as_bytes()))
    }
}

impl<'de> Deserialize<'de> for TpmEkCertificate {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let str_value = String::deserialize(deserializer)?;
        let bytes = BASE64_STANDARD
            .decode(str_value)
            .map_err(|err| Error::custom(err.to_string()))?;
        Ok(Self(bytes))
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmDescription {
    pub vendor: String,
    pub firmware_version: String,
    pub tpm_spec: String,
}

impl From<rpc::machine_discovery::TpmDescription> for TpmDescription {
    fn from(value: rpc::machine_discovery::TpmDescription) -> Self {
        TpmDescription {
            vendor: value.vendor.trim_matches('\0').to_string(),
            firmware_version: value.firmware_version.trim_matches('\0').to_string(),
            tpm_spec: value.tpm_spec.trim_matches('\0').to_string(),
        }
    }
}

impl From<TpmDescription> for rpc::machine_discovery::TpmDescription {
    fn from(value: TpmDescription) -> Self {
        rpc::machine_discovery::TpmDescription {
            vendor: value.vendor,
            firmware_version: value.firmware_version,
            tpm_spec: value.tpm_spec,
        }
    }
}

// These defines conversions functions from the RPC data model into the internal
// data model (which might also be used in the database).
// It might actually be nicer to have those closer to the rpc crate to avoid
// polluting the internal data model with API concerns, but since this is a
// separate crate we can't have it there (unless we also make the model a
// separate crate).
//

// The reverse, rpc::machine_discovery::Cpu -> Cpu, isn't needed going forward because
// rpc::machine_discovery::Cpu instances parsed from /proc/cpuinfo are now aggregated directly into
// CpuInfo rather than converted to Cpu. Only when reading the old format back from the
// machine_topologies table in the database do we need this conversion to leverage that same
// aggregation logic as if parsing from /proc/cpuinfo.
// TODO: Remove when there's no longer a need to handle the old topology format
impl TryFrom<&Cpu> for rpc::machine_discovery::Cpu {
    type Error = RpcDataConversionError;

    fn try_from(cpu: &Cpu) -> Result<Self, Self::Error> {
        Ok(Self {
            vendor: cpu.vendor.clone(),
            model: cpu.model.clone(),
            frequency: cpu.frequency.clone(),
            number: cpu.number,
            core: cpu.core,
            node: cpu.node,
            socket: cpu.socket,
        })
    }
}

impl TryFrom<rpc::machine_discovery::CpuInfo> for CpuInfo {
    type Error = RpcDataConversionError;

    fn try_from(cpu_info: rpc::machine_discovery::CpuInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            model: cpu_info.model,
            vendor: cpu_info.vendor,
            sockets: cpu_info.sockets,
            cores: cpu_info.cores,
            threads: cpu_info.threads,
        })
    }
}

impl TryFrom<CpuInfo> for rpc::machine_discovery::CpuInfo {
    type Error = RpcDataConversionError;

    fn try_from(cpu_info: CpuInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            model: cpu_info.model,
            vendor: cpu_info.vendor,
            sockets: cpu_info.sockets,
            cores: cpu_info.cores,
            threads: cpu_info.threads,
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
            device_type: dev.device_type,
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
            device_type: dev.device_type,
        })
    }
}

impl TryFrom<rpc::machine_discovery::NvmeDevice> for NvmeDevice {
    type Error = RpcDataConversionError;

    fn try_from(dev: rpc::machine_discovery::NvmeDevice) -> Result<Self, Self::Error> {
        Ok(Self {
            model: dev.model,
            firmware_rev: dev.firmware_rev,
            serial: dev.serial,
        })
    }
}

impl TryFrom<NvmeDevice> for rpc::machine_discovery::NvmeDevice {
    type Error = RpcDataConversionError;

    fn try_from(dev: NvmeDevice) -> Result<Self, Self::Error> {
        Ok(Self {
            model: dev.model,
            firmware_rev: dev.firmware_rev,
            serial: dev.serial,
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

        // Do what deserialize_ch_64 does in this case.
        let mac_string = if iface.mac_address == MELLANOX_SF_VF_MAC_ADDRESS_IN {
            MELLANOX_SF_VF_MAC_ADDRESS_OUT.to_string()
        } else {
            iface.mac_address
        };

        let mac_address: MacAddress = mac_string
            .parse()
            .map_err(|_| RpcDataConversionError::InvalidMacAddress(mac_string.clone()))?;

        Ok(Self {
            mac_address,
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
            mac_address: iface.mac_address.to_string(),
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

impl TryFrom<GpuPlatformInfo> for rpc::machine_discovery::GpuPlatformInfo {
    type Error = RpcDataConversionError;

    fn try_from(info: GpuPlatformInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            chassis_serial: info.chassis_serial,
            slot_number: info.slot_number,
            tray_index: info.tray_index,
            host_id: info.host_id,
            module_id: info.module_id,
            fabric_guid: info.fabric_guid,
        })
    }
}

impl TryFrom<rpc::machine_discovery::GpuPlatformInfo> for GpuPlatformInfo {
    type Error = RpcDataConversionError;

    fn try_from(info: rpc::machine_discovery::GpuPlatformInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            chassis_serial: info.chassis_serial,
            slot_number: info.slot_number,
            tray_index: info.tray_index,
            host_id: info.host_id,
            module_id: info.module_id,
            fabric_guid: info.fabric_guid,
        })
    }
}

impl TryFrom<Gpu> for rpc::machine_discovery::Gpu {
    type Error = RpcDataConversionError;

    fn try_from(gpu: Gpu) -> Result<Self, Self::Error> {
        let platform_info = match gpu
            .platform_info
            .map(rpc::machine_discovery::GpuPlatformInfo::try_from)
        {
            Some(Err(e)) => return Err(e),
            Some(Ok(info)) => Some(info),
            None => None,
        };

        Ok(Self {
            name: gpu.name,
            serial: gpu.serial,
            driver_version: gpu.driver_version,
            vbios_version: gpu.vbios_version,
            inforom_version: gpu.inforom_version,
            total_memory: gpu.total_memory,
            frequency: gpu.frequency,
            pci_bus_id: gpu.pci_bus_id,
            platform_info,
        })
    }
}

impl TryFrom<rpc::machine_discovery::Gpu> for Gpu {
    type Error = RpcDataConversionError;

    fn try_from(gpu: rpc::machine_discovery::Gpu) -> Result<Self, Self::Error> {
        let platform_info = match gpu.platform_info.map(GpuPlatformInfo::try_from) {
            Some(Err(e)) => return Err(e),
            Some(Ok(info)) => Some(info),
            None => None,
        };

        Ok(Self {
            name: gpu.name,
            serial: gpu.serial,
            driver_version: gpu.driver_version,
            vbios_version: gpu.vbios_version,
            inforom_version: gpu.inforom_version,
            total_memory: gpu.total_memory,
            frequency: gpu.frequency,
            pci_bus_id: gpu.pci_bus_id,
            platform_info,
        })
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

// TODO: Remove when there's no longer a need to handle the old topology format
impl TryFrom<HardwareInfoDeserialized> for HardwareInfo {
    type Error = RpcDataConversionError;

    fn try_from(info: HardwareInfoDeserialized) -> Result<Self, Self::Error> {
        let cpu_info: Vec<CpuInfo> = if info.cpu_info.is_empty() {
            // Convert V1 -> V2 format
            let cpus: Vec<rpc::machine_discovery::Cpu> = info
                .cpus
                .iter()
                .map(rpc::machine_discovery::Cpu::try_from)
                .collect::<Result<Vec<_>, _>>()?;
            aggregate_cpus(&cpus)
                .into_iter()
                .map(CpuInfo::try_from)
                .collect::<Result<Vec<_>, _>>()?
        } else {
            info.cpu_info
        };

        Ok(HardwareInfo {
            network_interfaces: info.network_interfaces,
            infiniband_interfaces: info.infiniband_interfaces,
            cpu_info,
            block_devices: info.block_devices,
            machine_type: info.machine_type,
            nvme_devices: info.nvme_devices,
            dmi_data: info.dmi_data,
            tpm_ek_certificate: info.tpm_ek_certificate,
            dpu_info: info.dpu_info,
            gpus: info.gpus,
            memory_devices: info.memory_devices,
            tpm_description: info.tpm_description,
        })
    }
}

impl TryFrom<rpc::machine_discovery::DiscoveryInfo> for HardwareInfo {
    type Error = RpcDataConversionError;

    #[allow(deprecated)]
    fn try_from(info: rpc::machine_discovery::DiscoveryInfo) -> Result<Self, Self::Error> {
        let tpm_ek_certificate = info
            .tpm_ek_certificate
            .map(|base64| {
                BASE64_STANDARD
                    .decode(base64)
                    .map_err(|_| RpcDataConversionError::InvalidBase64Data("tpm_ek_certificate"))
            })
            .transpose()?;

        let machine_arch = match info.machine_arch {
            // new
            Some(arch) => arch.into(),
            // old
            None => {
                tracing::warn!("DiscoveryInfo missing machine_arch.");
                info.machine_type.parse().unwrap_or_else(|e| {
                    // Unfortunately we don't have the machine_id here.
                    tracing::error!(error = %e, "Error parsing grpc DiscoveryInfo");
                    CpuArchitecture::Unknown
                })
            }
        };

        // TODO: Remove "cpus" when there's no longer a need to handle the old topology format
        let cpu_info: Vec<CpuInfo> = if info.cpu_info.is_empty() {
            match try_convert_vec(info.cpus) {
                Ok(v1_cpus) => aggregate_cpus(&v1_cpus)
                    .into_iter()
                    .map(CpuInfo::try_from)
                    .collect::<Result<Vec<_>, _>>()?,
                Err(_) => Vec::new(),
            }
        } else {
            try_convert_vec(info.cpu_info)?
        };

        Ok(Self {
            network_interfaces: try_convert_vec(info.network_interfaces)?,
            infiniband_interfaces: try_convert_vec(info.infiniband_interfaces)?,
            cpu_info,
            block_devices: try_convert_vec(info.block_devices)?,
            machine_type: machine_arch,
            nvme_devices: try_convert_vec(info.nvme_devices)?,
            dmi_data: info.dmi_data.map(DmiData::try_from).transpose()?,
            tpm_ek_certificate: tpm_ek_certificate.map(TpmEkCertificate::from),
            dpu_info: info.dpu_info.map(DpuData::try_from).transpose()?,
            gpus: try_convert_vec(info.gpus)?,
            memory_devices: info
                .memory_devices
                .into_iter()
                .map(MemoryDevice::from)
                .collect(),
            tpm_description: info.tpm_description.map(std::convert::Into::into),
        })
    }
}

impl TryFrom<HardwareInfo> for rpc::machine_discovery::DiscoveryInfo {
    type Error = RpcDataConversionError;

    // TODO: Remove this directive when there's no longer a need to handle the old topology format
    #[allow(deprecated)]
    fn try_from(info: HardwareInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            network_interfaces: try_convert_vec(info.network_interfaces)?,
            infiniband_interfaces: try_convert_vec(info.infiniband_interfaces)?,
            cpu_info: try_convert_vec(info.cpu_info)?,
            block_devices: try_convert_vec(info.block_devices)?,
            machine_type: info.machine_type.to_string(),
            machine_arch: Some(info.machine_type.into()),
            nvme_devices: try_convert_vec(info.nvme_devices)?,
            dmi_data: info
                .dmi_data
                .map(rpc::machine_discovery::DmiData::try_from)
                .transpose()?,
            tpm_ek_certificate: info
                .tpm_ek_certificate
                .map(|cert| BASE64_STANDARD.encode(cert.into_bytes())),
            dpu_info: info
                .dpu_info
                .map(rpc::machine_discovery::DpuData::try_from)
                .transpose()?,
            gpus: try_convert_vec(info.gpus)?,
            memory_devices: info
                .memory_devices
                .into_iter()
                .map(rpc::machine_discovery::MemoryDevice::from)
                .collect(),
            tpm_description: info.tpm_description.map(std::convert::Into::into),
            attest_key_info: None,
            // TODO: Remove cpus when there's no longer a need to handle the old topology format
            cpus: vec![],
        })
    }
}

#[derive(thiserror::Error, Debug)]
pub enum HardwareInfoError {
    #[error("DPU Info is missing.")]
    MissingDpuInfo,

    #[error("Mac address conversion error: {0}")]
    MacAddressConversionError(#[from] MacParseError),

    #[error("Missing hardware info: {0}")]
    MissingHardwareInfo(#[from] MissingHardwareInfo),
}

impl HardwareInfo {
    /// Returns whether the machine is deemed to be a DPU based on some properties
    pub fn is_dpu(&self) -> bool {
        if self.machine_type != CpuArchitecture::Aarch64 {
            return false;
        }
        self.dmi_data
            .as_ref()
            .is_some_and(|dmi| dmi.board_name.to_lowercase().contains("bluefield"))
    }

    /// This function returns factory_mac_address from dpu_info.
    pub fn factory_mac_address(&self) -> Result<MacAddress, HardwareInfoError> {
        let Some(ref dpu_info) = self.dpu_info else {
            return Err(HardwareInfoError::MissingDpuInfo);
        };

        Ok(MacAddress::from_str(&dpu_info.factory_mac_address)?)
    }

    /// Is this a Dell, Lenovo, etc machine?
    pub fn bmc_vendor(&self) -> bmc_vendor::BMCVendor {
        match self.dmi_data.as_ref() {
            Some(dmi_info) => bmc_vendor::BMCVendor::from_udev_dmi(dmi_info.sys_vendor.as_ref()),
            None => bmc_vendor::BMCVendor::Unknown,
        }
    }

    pub fn all_mac_addresses(&self) -> Vec<MacAddress> {
        self.network_interfaces
            .iter()
            .map(|i| i.mac_address)
            .collect()
    }

    pub fn is_gbx00(&self) -> bool {
        self.dmi_data
            .as_ref()
            .is_some_and(|dmi| dmi.product_name.contains("GB200")) // TODO: for now just do GB200
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineInventory {
    pub components: Vec<MachineInventorySoftwareComponent>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct MachineInventorySoftwareComponent {
    pub name: String,
    pub version: String,
    pub url: String,
}

impl Display for MachineInventorySoftwareComponent {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}:{}", self.url, self.name, self.version)
    }
}

impl TryFrom<::rpc::forge::MachineInventory> for MachineInventory {
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::MachineInventory) -> Result<Self, Self::Error> {
        Ok(MachineInventory {
            components: value
                .components
                .into_iter()
                .map(MachineInventorySoftwareComponent::try_from)
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<::rpc::forge::MachineInventorySoftwareComponent>
    for MachineInventorySoftwareComponent
{
    type Error = RpcDataConversionError;

    fn try_from(value: rpc::forge::MachineInventorySoftwareComponent) -> Result<Self, Self::Error> {
        Ok(MachineInventorySoftwareComponent {
            name: value.name,
            version: value.version,
            url: value.url,
        })
    }
}

impl From<MachineInventory> for rpc::forge::MachineInventory {
    fn from(value: MachineInventory) -> Self {
        rpc::forge::MachineInventory {
            components: value
                .components
                .into_iter()
                .map(|c| rpc::forge::MachineInventorySoftwareComponent {
                    name: c.name,
                    version: c.version,
                    url: c.url,
                })
                .collect(),
        }
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct MachineNvLinkInfo {
    pub domain_uuid: NvLinkDomainId,
    pub gpus: Vec<NvLinkGpu>,
}

impl From<MachineNvLinkInfo> for rpc::forge::MachineNvLinkInfo {
    fn from(value: MachineNvLinkInfo) -> Self {
        rpc::forge::MachineNvLinkInfo {
            domain_uuid: Some(value.domain_uuid),
            gpus: value
                .gpus
                .into_iter()
                .map(rpc::forge::NvLinkGpu::from)
                .collect(),
        }
    }
}

impl From<NvLinkGpu> for rpc::forge::NvLinkGpu {
    fn from(value: NvLinkGpu) -> Self {
        rpc::forge::NvLinkGpu {
            nmx_m_id: value.nmx_m_id,
            tray_index: value.tray_index,
            slot_id: value.slot_id,
            device_id: value.device_id,
            guid: value.guid,
        }
    }
}

impl TryFrom<rpc::forge::MachineNvLinkInfo> for MachineNvLinkInfo {
    type Error = rpc::errors::RpcDataConversionError;

    fn try_from(value: rpc::forge::MachineNvLinkInfo) -> Result<Self, Self::Error> {
        Ok(MachineNvLinkInfo {
            domain_uuid: value.domain_uuid.ok_or(
                rpc::errors::RpcDataConversionError::MissingArgument("domain_uuid"),
            )?,
            gpus: value.gpus.into_iter().map(NvLinkGpu::from).collect(),
        })
    }
}

impl From<rpc::forge::NvLinkGpu> for NvLinkGpu {
    fn from(value: rpc::forge::NvLinkGpu) -> Self {
        NvLinkGpu {
            nmx_m_id: value.nmx_m_id,
            tray_index: value.tray_index,
            slot_id: value.slot_id,
            device_id: value.device_id,
            guid: value.guid,
        }
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct NvLinkGpu {
    pub nmx_m_id: String,
    pub tray_index: i32,
    pub slot_id: i32,
    pub device_id: i32, // For GB200s, 1-based index of GPU in compute tray.
    pub guid: u64,
}

impl From<libnmxm::nmxm_model::Gpu> for NvLinkGpu {
    fn from(gpu: libnmxm::nmxm_model::Gpu) -> Self {
        NvLinkGpu {
            nmx_m_id: gpu.id.unwrap_or_default(),
            tray_index: gpu
                .location_info
                .as_ref()
                .and_then(|info| info.tray_index)
                .unwrap_or_default(),
            slot_id: gpu
                .location_info
                .as_ref()
                .and_then(|info| info.slot_id)
                .unwrap_or_default(),
            device_id: gpu.device_id,
            guid: gpu.device_uid,
        }
    }
}

#[cfg(test)]
mod tests {
    use prost::Message;

    use super::*;

    const DPU_INFO_JSON: &[u8] = include_bytes!("hardware_info/test_data/dpu_info.json");
    const DPU_BF3_INFO_JSON: &[u8] = include_bytes!("hardware_info/test_data/dpu_bf3_info.json");
    const X86_INFO_JSON: &[u8] = include_bytes!("hardware_info/test_data/x86_info.json");
    // TODO: Remove when there's no longer a need to handle the old topology format
    const X86_V1_CPU_INFO_JSON: &[u8] =
        include_bytes!("hardware_info/test_data/x86_v1_cpu_info.json");

    #[test]
    fn test_machine_inventory_json_representation() {
        let inventory = MachineInventory {
            components: vec![
                MachineInventorySoftwareComponent {
                    name: "foo".to_string(),
                    version: "1.0".to_string(),
                    url: "".to_string(),
                },
                MachineInventorySoftwareComponent {
                    name: "bar".to_string(),
                    version: "2.0".to_string(),
                    url: "nvidia.com".to_string(),
                },
            ],
        };
        let json = serde_json::to_string(&inventory).unwrap();
        assert_eq!(
            json,
            r#"{"components":[{"name":"foo","version":"1.0","url":""},{"name":"bar","version":"2.0","url":"nvidia.com"}]}"#
        );
    }

    #[test]
    fn serialize_blockdev() {
        let dev: BlockDevice = serde_json::from_str("{}").unwrap();
        assert_eq!(
            dev,
            BlockDevice {
                model: "".to_string(),
                revision: "".to_string(),
                serial: "".to_string(),
                device_type: "".to_string(),
            }
        );

        let dev1 = BlockDevice {
            model: "disk".to_string(),
            revision: "rev1".to_string(),
            serial: "001".to_string(),
            device_type: "device_type".to_string(),
        };

        let serialized = serde_json::to_string(&dev1).unwrap();
        assert_eq!(
            serialized,
            r#"{"model":"disk","revision":"rev1","serial":"001","device_type":"device_type"}"#
        );
        assert_eq!(
            serde_json::from_str::<BlockDevice>(&serialized).unwrap(),
            dev1
        );
    }

    #[test]
    fn serialize_cpu_info() {
        let cpu_info: CpuInfo = serde_json::from_str("{}").unwrap();
        assert_eq!(
            cpu_info,
            CpuInfo {
                model: "".to_string(),
                vendor: "".to_string(),
                sockets: 0,
                cores: 0,
                threads: 0,
            }
        );

        let cpu_info1 = CpuInfo {
            model: "m1".to_string(),
            vendor: "v1".to_string(),
            sockets: 2,
            cores: 32,
            threads: 64,
        };

        let serialized = serde_json::to_string(&cpu_info1).unwrap();
        assert_eq!(
            serialized,
            "{\"model\":\"m1\",\"vendor\":\"v1\",\"sockets\":2,\"cores\":32,\"threads\":64}"
        );
        assert_eq!(
            serde_json::from_str::<CpuInfo>(&serialized).unwrap(),
            cpu_info1
        );
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
        let info = serde_json::from_slice::<HardwareInfo>(X86_INFO_JSON).unwrap();
        assert!(!info.is_dpu());
    }

    #[test]
    fn deserialize_dpu_info() {
        let info = serde_json::from_slice::<HardwareInfo>(DPU_INFO_JSON).unwrap();
        assert!(info.is_dpu());

        // Make sure deserialize_ch_64 works as expected, where
        // the source dpu_info.json file for this has ch:64 as
        // the mac_address.
        assert_eq!(
            info.network_interfaces[1].mac_address.to_string(),
            "00:00:00:00:00:64"
        );
    }

    #[test]
    fn deserialize_dpu_bf3_info() {
        let info = serde_json::from_slice::<HardwareInfo>(DPU_BF3_INFO_JSON).unwrap();
        assert!(info.is_dpu());
    }

    #[test]
    fn serialize_tpm_ek_certificate() {
        let cert_data = b"This is not really a certificate".to_vec();
        let cert = TpmEkCertificate::from(cert_data.clone());

        let serialized = serde_json::to_string(&cert).unwrap();
        assert_eq!(
            serialized,
            format!("\"{}\"", BASE64_STANDARD.encode(&cert_data))
        );

        // Test also how that the certificate looks right within a Json structure
        #[derive(Serialize)]
        struct OptionalCert {
            cert: Option<TpmEkCertificate>,
        }

        let serialized = serde_json::to_string(&OptionalCert { cert: Some(cert) }).unwrap();
        assert_eq!(
            serialized,
            format!("{{\"cert\":\"{}\"}}", BASE64_STANDARD.encode(&cert_data))
        );
    }

    #[test]
    fn deserialize_tpm_ek_certificate() {
        let cert_data = b"This is not really a certificate".to_vec();
        let encoded = BASE64_STANDARD.encode(&cert_data);

        let json = format!("\"{encoded}\"");
        let deserialized: TpmEkCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.as_bytes(), &cert_data);

        // Test also how that the certificate looks right within a Json structure
        #[derive(Deserialize)]
        struct OptionalCert {
            cert: Option<TpmEkCertificate>,
        }

        let json = format!("{{\"cert\":\"{encoded}\"}}");
        let deserialized: OptionalCert = serde_json::from_str(&json).unwrap();
        assert_eq!(
            deserialized.cert.as_ref().map(|cert| cert.as_bytes()),
            Some(cert_data.as_slice())
        );
    }

    // TODO: Remove this test when there's no longer a need to handle the old topology format
    #[test]
    #[allow(deprecated)]
    fn test_v1_discovery_info_decode() -> Result<(), Box<dyn std::error::Error>> {
        let hardware_info = serde_json::from_slice::<HardwareInfo>(X86_INFO_JSON).unwrap();
        let mut info =
            rpc::machine_discovery::DiscoveryInfo::try_from(hardware_info.clone()).unwrap();
        info.cpus = serde_json::from_slice::<Vec<Cpu>>(X86_V1_CPU_INFO_JSON)
            .unwrap()
            .iter()
            .map(rpc::machine_discovery::Cpu::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        info.cpu_info = Vec::new();

        let bytes = info.encode_to_vec();
        let decoded = rpc::machine_discovery::DiscoveryInfo::decode(&*bytes).unwrap();
        let decoded_hardware_info = HardwareInfo::try_from(decoded).unwrap();

        assert_eq!(decoded_hardware_info, hardware_info);
        Ok(())
    }
}
