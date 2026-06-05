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

use base64::prelude::*;
use carbide_network::{MELLANOX_SF_VF_MAC_ADDRESS_IN, MELLANOX_SF_VF_MAC_ADDRESS_OUT};
use carbide_utils::arch::CpuArchitecture;
use carbide_utils::try_convert_vec;
use mac_address::MacAddress;
use model::hardware_info::{
    BlockDevice, CpuInfo, DmiData, DpuData, Gpu, GpuPlatformInfo, HardwareInfo,
    InfinibandInterface, LldpSwitchData, MachineInventory, MachineInventorySoftwareComponent,
    MachineNvLinkInfo, MemoryDevice, NetworkInterface, NvLinkGpu, NvmeDevice, PciDeviceProperties,
    TpmDescription, TpmEkCertificate,
};

use crate as rpc;
use crate::errors::RpcDataConversionError;

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

impl TryFrom<rpc::machine_discovery::DiscoveryInfo> for HardwareInfo {
    type Error = RpcDataConversionError;

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
            Some(arch) => rpc::utils::cpu_architecture_from_rpc(arch),
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

        let cpu_info: Vec<CpuInfo> = try_convert_vec(info.cpu_info)?;

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

    fn try_from(info: HardwareInfo) -> Result<Self, Self::Error> {
        Ok(Self {
            network_interfaces: try_convert_vec(info.network_interfaces)?,
            infiniband_interfaces: try_convert_vec(info.infiniband_interfaces)?,
            cpu_info: try_convert_vec(info.cpu_info)?,
            block_devices: try_convert_vec(info.block_devices)?,
            machine_type: info.machine_type.to_string(),
            machine_arch: Some(rpc::utils::cpu_architecture_to_rpc(info.machine_type)),
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
        })
    }
}

impl TryFrom<crate::forge::MachineInventory> for MachineInventory {
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

impl TryFrom<crate::forge::MachineInventorySoftwareComponent>
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

impl From<MachineNvLinkInfo> for rpc::forge::MachineNvLinkInfo {
    fn from(value: MachineNvLinkInfo) -> Self {
        rpc::forge::MachineNvLinkInfo {
            domain_uuid: Some(value.domain_uuid),
            gpus: value
                .gpus
                .into_iter()
                .map(rpc::forge::NvLinkGpu::from)
                .collect(),
            chassis_serial: value.chassis_serial,
        }
    }
}

impl From<NvLinkGpu> for rpc::forge::NvLinkGpu {
    fn from(value: NvLinkGpu) -> Self {
        rpc::forge::NvLinkGpu {
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
            chassis_serial: value.chassis_serial,
            gpus: value.gpus.into_iter().map(NvLinkGpu::from).collect(),
        })
    }
}

impl From<rpc::forge::NvLinkGpu> for NvLinkGpu {
    fn from(value: rpc::forge::NvLinkGpu) -> Self {
        NvLinkGpu {
            tray_index: value.tray_index,
            slot_id: value.slot_id,
            device_id: value.device_id,
            guid: value.guid,
        }
    }
}
