/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::borrow::Cow;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use mac_address::MacAddress;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::redfish;
use crate::redfish::update_service::UpdateServiceConfig;
static NEXT_MAC_ADDRESS: AtomicU32 = AtomicU32::new(1);

/// Represents static information we know ahead of time about a host or DPU (independent of any
/// state we get from carbide like IP addresses or machine ID's.) Intended to be immutable and
/// easily cloneable.
#[derive(Debug, Clone)]
pub enum MachineInfo {
    Host(HostMachineInfo),
    Dpu(DpuMachineInfo),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostMachineInfo {
    pub bmc_mac_address: MacAddress,
    pub serial: String,
    pub dpus: Vec<DpuMachineInfo>,
    pub non_dpu_mac_address: Option<MacAddress>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DpuMachineInfo {
    pub bmc_mac_address: MacAddress,
    pub host_mac_address: MacAddress,
    pub oob_mac_address: MacAddress,
    pub serial: String,
    pub nic_mode: bool,
    pub firmware_versions: DpuFirmwareVersions,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DpuFirmwareVersions {
    pub bmc: Option<String>,
    pub uefi: Option<String>,
    pub cec: Option<String>,
    pub nic: Option<String>,
}

impl Default for DpuMachineInfo {
    fn default() -> Self {
        Self::new(false, Default::default())
    }
}

impl DpuMachineInfo {
    pub fn new(nic_mode: bool, firmware_versions: DpuFirmwareVersions) -> Self {
        let bmc_mac_address = next_mac();
        let host_mac_address = next_mac();
        let oob_mac_address = next_mac();
        Self {
            bmc_mac_address,
            host_mac_address,
            oob_mac_address,
            nic_mode,
            firmware_versions,
            serial: format!("MT{}", oob_mac_address.to_string().replace(':', "")),
        }
    }
}

impl HostMachineInfo {
    pub fn new(dpus: Vec<DpuMachineInfo>) -> Self {
        let bmc_mac_address = next_mac();
        Self {
            bmc_mac_address,
            serial: bmc_mac_address.to_string().replace(':', ""),
            non_dpu_mac_address: if dpus.is_empty() {
                Some(next_mac())
            } else {
                None
            },
            dpus,
        }
    }

    pub fn primary_dpu(&self) -> Option<&DpuMachineInfo> {
        self.dpus.first()
    }

    pub fn system_mac_address(&self) -> Option<MacAddress> {
        self.primary_dpu()
            .map(|d| d.host_mac_address)
            .or(self.non_dpu_mac_address)
    }
}

impl MachineInfo {
    pub fn manager_config(&self) -> redfish::manager::Config {
        match self {
            MachineInfo::Dpu(dpu) => redfish::manager::Config {
                id: "Bluefield_BMC",
                eth_interfaces: vec![
                    redfish::ethernet_interface::builder(
                        &redfish::ethernet_interface::manager_resource("Bluefield_BMC", "eth0"),
                    )
                    .mac_address(dpu.bmc_mac_address)
                    .interface_enabled(true)
                    .build(),
                ],
                firmware_version: "BF-23.10-4",
            },
            MachineInfo::Host(host) => redfish::manager::Config {
                id: "iDRAC.Embedded.1",
                eth_interfaces: vec![
                    redfish::ethernet_interface::builder(
                        &redfish::ethernet_interface::manager_resource("iDRAC.Embedded.1", "NIC.1"),
                    )
                    .mac_address(host.bmc_mac_address)
                    .interface_enabled(true)
                    .build(),
                ],
                firmware_version: "6.00.30.00",
            },
        }
    }
    pub fn bmc_vendor(&self) -> redfish::oem::BmcVendor {
        match self {
            MachineInfo::Host(_) => redfish::oem::BmcVendor::Dell,
            MachineInfo::Dpu(_) => redfish::oem::BmcVendor::Nvidia,
        }
    }

    pub fn system_config(
        &self,
        power_control: Arc<dyn crate::PowerControl>,
    ) -> redfish::computer_system::SystemConfig {
        match self {
            MachineInfo::Host(_) => {
                let power_control = Some(power_control.clone());
                let serial_number = self.product_serial().clone();
                let system_id = "System.Embedded.1";
                let eth_interfaces = self
                    .dhcp_mac_addresses()
                    .into_iter()
                    .enumerate()
                    .map(|(index, mac)| {
                        let eth_id = Cow::Owned(format!("NIC.Slot.{}", index + 1));
                        let resource =
                            redfish::ethernet_interface::system_resource(system_id, &eth_id);
                        redfish::ethernet_interface::builder(&resource)
                            .mac_address(mac)
                            .interface_enabled(true)
                            .build()
                    })
                    .collect();
                let boot_opt_builder = |id: &str| {
                    redfish::boot_option::builder(&redfish::boot_option::resource(system_id, id))
                        .boot_option_reference(id)
                };
                redfish::computer_system::SystemConfig {
                    systems: vec![redfish::computer_system::SingleSystemConfig {
                        id: Cow::Borrowed(system_id),
                        eth_interfaces,
                        serial_number,
                        boot_order_mode: redfish::computer_system::BootOrderMode::DellOem,
                        power_control,
                        chassis: vec!["System.Embedded.1".into()],
                        boot_options: vec![
                            boot_opt_builder("Boot0000")
                                .display_name("HTTP Device 1: NIC in Slot 5 Port 1")
                                .build(),
                            boot_opt_builder("Boot0001")
                                .display_name("Unavailable: ubuntu")
                                .build(),
                            boot_opt_builder("Boot0002")
                                .display_name(
                                    "PCIe SSD in Slot 2 in Bay 1: EFI Fixed Disk Boot Device 1",
                                )
                                .build(),
                            boot_opt_builder("Boot0003")
                                .display_name("Unavailable: Linux Default")
                                .build(),
                            boot_opt_builder("Boot0004")
                                .display_name("Unavailable: ubuntu")
                                .build(),
                        ],
                        bios_mode: redfish::computer_system::BiosMode::DellOem,
                        base_bios: redfish::bios::builder(&redfish::bios::resource(system_id))
                            .attributes(json!({
                                "BootSeqRetry": "Disabled",
                                "SetBootOrderEn": "NIC.HttpDevice.1-1,Disk.Bay.2:Enclosure.Internal.0-1",
                                "InBandManageabilityInterface": "Enabled",
                                "UefiVariableAccess": "Standard",
                                "SerialComm": "OnConRedir",
                                "SerialPortAddress": "Com1",
                                "FailSafeBaud": "115200",
                                "ConTermType": "Vt100Vt220",
                                "RedirAfterBoot": "Enabled",
                                "SriovGlobalEnable": "Enabled",
                                "TpmSecurity": "On",
                                "Tpm2Algorithm": "SHA256",
                                "Tpm2Hierarchy": "Enabled",
                                "HttpDev1EnDis": "Enabled",
                                "PxeDev1EnDis": "Disabled",
                                "HttpDev1Interface": "NIC.Slot.5-1",
                            }))
                            .build(),
                    }],
                }
            }
            MachineInfo::Dpu(dpu) => {
                let system_id = "Bluefield";
                let boot_opt_builder = |id: &str| {
                    redfish::boot_option::builder(&redfish::boot_option::resource(system_id, id))
                        .boot_option_reference(id)
                };
                let mocked_mac_no_colons = dpu
                    .oob_mac_address
                    .to_string()
                    .replace(':', "")
                    .to_ascii_uppercase();
                let nic_mode = if dpu.nic_mode { "NicMode" } else { "DpuMode" };
                redfish::computer_system::SystemConfig {
                    systems: vec![redfish::computer_system::SingleSystemConfig {
                        id: Cow::Borrowed("Bluefield"),
                        eth_interfaces: vec![
                            redfish::ethernet_interface::builder(
                                &redfish::ethernet_interface::system_resource("Bluefield", "eth0"),
                            )
                            .mac_address(dpu.host_mac_address)
                            .interface_enabled(true)
                            .build(),
                            redfish::ethernet_interface::builder(
                                &redfish::ethernet_interface::system_resource("Bluefield", "oob0"),
                            )
                            .mac_address(dpu.oob_mac_address)
                            .interface_enabled(true)
                            .build(),
                        ],
                        chassis: vec!["Bluefield_BMC".into()],
                        serial_number: self.product_serial().clone(),
                        boot_order_mode: redfish::computer_system::BootOrderMode::Generic,
                        power_control: Some(power_control),
                        boot_options: vec![
                            boot_opt_builder("Boot0040")
                                .display_name("ubuntu0")
                                .uefi_device_path("HD(1,GPT,2FAFB38D-05F6-DF41-AE01-F9991E2CC0F0,0x800,0x19000)/\\EFI\\ubuntu\\shimaa64.efi")
                                .build(),
                            boot_opt_builder("Boot0000")
                                .display_name("NET-NIC_P0-IPV4")
                                .uefi_device_path(&format!("PciRoot(0x0)/Pci(0x0,0x0)/Pci(0x0,0x0)/Pci(0x0,0x0)/Pci(0x0,0x0)/MAC({mocked_mac_no_colons},0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)"))
                                .build(),
                            boot_opt_builder("Boot0001").display_name("NET-NIC_P0-IPV6")
                                .uefi_device_path(&format!("PciRoot(0x0)/Pci(0x0,0x0)/Pci(0x0,0x0)/Pci(0x0,0x0)/Pci(0x0,0x0)/MAC({mocked_mac_no_colons},0x1)/IPv6(0000:0000:0000:0000:0000:0000:0000:0000,0x0,Static,0000:0000:0000:0000:0000:0000:0000:0000,0x40,0000:0000:0000:0000:0000:0000:0000:0000)"))
                                .build()
                        ],
                        bios_mode: redfish::computer_system::BiosMode::Generic,
                        base_bios: redfish::bios::builder(&redfish::bios::resource(system_id))
                            .attributes(json!({
                                "NicMode": nic_mode,
                                "HostPrivilegeLevel": "Unavailable",
                                "InternalCPUModel": "Unavailable",
                            }))
                            .build(),
                    }],
                }
            }
        }
    }

    pub fn chassis_config(&self) -> redfish::chassis::ChassisConfig {
        match self {
            Self::Host(h) => dell_chassis_config(h),
            Self::Dpu(_) => {
                let bmc_chassis_id = "Bluefield_BMC";
                let cpu0_chassis_id = "CPU_0";
                let card1_chassis_id = "Card1";
                let network_adapter_id = "NvidiaNetworkAdapter";

                let nvidia_network_adapter = |chassis_id: &str| {
                    redfish::network_adapter::builder(&redfish::network_adapter::chassis_resource(
                        chassis_id,
                        network_adapter_id,
                    ))
                    .manufacturer("Nvidia")
                    .network_device_functions(
                        &redfish::network_device_function::chassis_collection(
                            chassis_id,
                            network_adapter_id,
                        ),
                        vec![],
                    )
                    .build()
                };

                redfish::chassis::ChassisConfig {
                    chassis: vec![
                        redfish::chassis::SingleChassisConfig {
                            id: Cow::Borrowed(bmc_chassis_id),
                            serial_number: None,
                            network_adapters: Some(vec![nvidia_network_adapter(bmc_chassis_id)]),
                            pcie_devices: Some(vec![]),
                        },
                        redfish::chassis::SingleChassisConfig {
                            id: Cow::Borrowed("Bluefield_DPU_IRoT"),
                            serial_number: None,
                            network_adapters: None,
                            pcie_devices: None,
                        },
                        redfish::chassis::SingleChassisConfig {
                            id: Cow::Borrowed("Bluefield_ERoT"),
                            serial_number: None,
                            network_adapters: None,
                            pcie_devices: None,
                        },
                        redfish::chassis::SingleChassisConfig {
                            id: Cow::Borrowed(cpu0_chassis_id),
                            serial_number: None,
                            network_adapters: Some(vec![nvidia_network_adapter(cpu0_chassis_id)]),
                            pcie_devices: Some(vec![]),
                        },
                        redfish::chassis::SingleChassisConfig {
                            id: Cow::Borrowed(card1_chassis_id),
                            serial_number: None,
                            network_adapters: Some(vec![nvidia_network_adapter(cpu0_chassis_id)]),
                            pcie_devices: Some(vec![]),
                        },
                    ],
                }
            }
        }
    }

    pub fn update_service_config(&self) -> UpdateServiceConfig {
        let fw_inv_builder = |id: &str| {
            redfish::software_inventory::builder(
                &redfish::software_inventory::firmware_inventory_resource(id),
            )
        };
        match self {
            Self::Host(_) => UpdateServiceConfig {
                firmware_inventory: vec![],
            },
            Self::Dpu(dpu) => {
                let base_mac = dpu.host_mac_address.to_string().replace(':', "");
                let sys_image = format!(
                    "{}:{}00:00{}:{}",
                    &base_mac[0..4],
                    &base_mac[4..6],
                    &base_mac[6..8],
                    &base_mac[8..12]
                );
                UpdateServiceConfig {
                    firmware_inventory: vec![
                        Some(fw_inv_builder("DPU_SYS_IMAGE").version(&sys_image).build()),
                        dpu.firmware_versions
                            .bmc
                            .as_ref()
                            .map(|v| fw_inv_builder("BMC_Firmware").version(v).build()),
                        dpu.firmware_versions
                            .cec
                            .as_ref()
                            .map(|v| fw_inv_builder("Bluefield_FW_ERoT").version(v).build()),
                        dpu.firmware_versions
                            .uefi
                            .as_ref()
                            .map(|v| fw_inv_builder("DPU_UEFI").version(v).build()),
                        dpu.firmware_versions
                            .nic
                            .as_ref()
                            .map(|v| fw_inv_builder("DPU_NIC").version(v).build()),
                    ]
                    .into_iter()
                    .flatten()
                    .collect(),
                }
            }
        }
    }

    pub fn chassis_serial(&self) -> Option<String> {
        match self {
            Self::Host(h) => Some(h.serial.clone()),
            Self::Dpu(_) => None,
        }
    }

    pub fn product_serial(&self) -> &String {
        match self {
            Self::Host(h) => &h.serial,
            Self::Dpu(d) => &d.serial,
        }
    }

    pub fn bmc_mac_address(&self) -> MacAddress {
        match self {
            Self::Host(h) => h.bmc_mac_address,
            Self::Dpu(d) => d.bmc_mac_address,
        }
    }

    /// Returns the mac addresses this system would use to request DHCP on boot
    pub fn dhcp_mac_addresses(&self) -> Vec<MacAddress> {
        match self {
            Self::Host(h) => {
                if h.dpus.is_empty() {
                    h.non_dpu_mac_address.map(|m| vec![m]).unwrap_or_default()
                } else {
                    h.dpus.iter().map(|d| d.host_mac_address).collect()
                }
            }
            Self::Dpu(d) => vec![d.oob_mac_address],
        }
    }

    // If this is a DPU, return its host mac address
    pub fn host_mac_address(&self) -> Option<MacAddress> {
        if let Self::Dpu(d) = self {
            Some(d.host_mac_address)
        } else {
            None
        }
    }
}

fn next_mac() -> MacAddress {
    let next_mac_num = NEXT_MAC_ADDRESS.fetch_add(1, Ordering::Acquire);

    let bytes: Vec<u8> = [0x02u8, 0x01]
        .into_iter()
        .chain(next_mac_num.to_be_bytes())
        .collect();

    let mac_bytes = <[u8; 6]>::try_from(bytes).unwrap();

    MacAddress::from(mac_bytes)
}

fn dell_chassis_config(h: &HostMachineInfo) -> redfish::chassis::ChassisConfig {
    let chassis_id = "System.Embedded.1";
    let net_adapter_builder = |id: &str| {
        redfish::network_adapter::builder(&redfish::network_adapter::chassis_resource(
            chassis_id, id,
        ))
    };
    let pcie_device_builder = |id: &str| {
        redfish::pcie_device::builder(&redfish::pcie_device::chassis_resource(chassis_id, id))
    };
    let mut network_adapters = vec![
        net_adapter_builder("NIC.Embedded.1")
            .manufacturer("Broadcom Inc. and subsidiaries")
            .build(),
        net_adapter_builder("NIC.Integrated.1")
            .manufacturer("Broadcom Inc. and subsidiaries")
            .build(),
    ];
    let mut pcie_devices = Vec::new();
    for (index, dpu) in h.dpus.iter().enumerate() {
        let network_adapter_id = format!("NIC.Slot.{}", index + 1);
        let function_id = format!("NIC.Slot.{}-1", index + 1);
        let func_resource = &redfish::network_device_function::chassis_resource(
            chassis_id,
            &network_adapter_id,
            &function_id,
        );
        let function = redfish::network_device_function::builder(func_resource)
            .ethernet(serde_json::json!({
                "MACAddress": &dpu.host_mac_address,
            }))
            .oem(redfish::oem::dell::network_device_function::dpu_dell_nic_info(&function_id, dpu))
            .build();

        network_adapters.push(
            net_adapter_builder(&network_adapter_id)
                .manufacturer("Mellanox Technologies")
                .model("BlueField-2 SmartNIC Main Card")
                .part_number("MBF2H5")
                .serial_number(&dpu.serial)
                .network_device_functions(
                    &redfish::network_device_function::chassis_collection(
                        chassis_id,
                        &network_adapter_id,
                    ),
                    vec![function],
                )
                .status(redfish::resource::Status::Ok)
                .build(),
        );
        let pcie_device_id = format!("mat_dpu_{}", index + 1);

        // Set the BF3 Part Number based on whether the DPU is supposed to be in NIC mode or not
        // Use a BF3 SuperNIC OPN if the DPU is supposed to be in NIC mode. Otherwise, use
        // a BF3 DPU OPN. Site explorer assumes that BF3 SuperNICs must be in NIC mode and that
        // BF3 DPUs must be in DPU mode. It will not ingest a host if any of the BF3 DPUs in the host
        // are in NIC mode or if any of the BF3 SuperNICs in the host are in DPU mode.
        // OPNs taken from: https://docs.nvidia.com/networking/display/bf3dpu
        let part_number = match dpu.nic_mode {
            true => "900-9D3B4-00CC-EA0",
            false => "900-9D3B6-00CV-AA0",
        };

        pcie_devices.push(
            pcie_device_builder(&pcie_device_id)
                .mat_dpu()
                .description("MT43244 BlueField-3 integrated ConnectX-7 network controller")
                .firmware_version("32.41.1000")
                .manufacturer("Mellanox Technologies")
                .part_number(part_number)
                .serial_number(&dpu.serial)
                .status(redfish::resource::Status::Ok)
                .build(),
        )
    }

    if h.dpus.is_empty()
        && let Some(mac) = h.non_dpu_mac_address
    {
        let network_adapter_id = "NIC.Slot.1";
        let serial = mac.to_string().replace(':', "");
        // Build a non-DPU NetworkAdapter
        let resource = redfish::network_adapter::chassis_resource(chassis_id, network_adapter_id);
        network_adapters.push(
            redfish::network_adapter::builder(&resource)
                .manufacturer("Rooftop Technologies")
                .model("Rooftop 10 Kilobit Ethernet Adapter")
                .part_number("31337")
                .serial_number(&serial)
                .status(redfish::resource::Status::Ok)
                .build(),
        );
    }
    redfish::chassis::ChassisConfig {
        chassis: vec![redfish::chassis::SingleChassisConfig {
            id: Cow::Borrowed(chassis_id),
            serial_number: Some(h.serial.clone()),
            network_adapters: Some(network_adapters),
            pcie_devices: Some(pcie_devices),
        }],
    }
}
