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

use std::borrow::Cow;
use std::sync::Arc;

use bmc_vendor::BMCVendor;
use carbide_utils::arch::CpuArchitecture;
use mac_address::MacAddress;
use rpc::machine_discovery::{BlockDevice, CpuInfo, DiscoveryInfo, DmiData, MemoryDevice};
use serde_json::json;

use crate::{BootOptionKind, Callbacks, hw, redfish};

/// Values are taken from a Redfish dump of a real ProLiant DL380a Gen11
/// (iLO 6 v1.58, BIOS U58 v2.22) with a BlueField-3 SuperNIC installed.
pub struct HpeProliantDl380aGen11<'a> {
    pub bmc_mac_address: MacAddress,
    pub product_serial_number: Cow<'a, str>,
    pub nics: Vec<(hw::nic::SlotNumber, hw::nic::Nic<'a>)>,
}

const MODEL: &str = "ProLiant DL380a Gen11";
const SKU: &str = "P54903-B21";

impl HpeProliantDl380aGen11<'_> {
    pub fn manager_config(&self) -> redfish::manager::Config {
        redfish::manager::Config {
            managers: vec![redfish::manager::SingleConfig {
                id: "1",
                eth_interfaces: Some(vec![
                    redfish::ethernet_interface::builder(
                        &redfish::ethernet_interface::manager_resource("1", "1"),
                    )
                    .description("Manager Dedicated Network Interface")
                    .mac_address(self.bmc_mac_address)
                    .interface_enabled(true)
                    .build(),
                ]),
                host_interfaces: None,
                firmware_version: Some("iLO 6 v1.58"),
                oem: Some(redfish::manager::Oem::Hpe),
            }],
        }
    }

    pub fn system_config(&self, callbacks: Arc<dyn Callbacks>) -> redfish::computer_system::Config {
        let system_id = "1";

        let eth_interfaces = self
            .nics
            .iter()
            .enumerate()
            .map(|(index, (_slot, nic))| {
                let eth_id = format!("DA00000{index}");
                let resource = redfish::ethernet_interface::system_resource(system_id, &eth_id);
                redfish::ethernet_interface::builder(&resource)
                    .mac_address(nic.mac_address)
                    .interface_enabled(true)
                    .build()
            })
            .collect();

        let boot_opt_builder = |id: &str, kind| {
            redfish::boot_option::builder(&redfish::boot_option::resource(system_id, id), kind)
                .boot_option_reference(id)
        };
        let boot_options = self
            .nics
            .iter()
            .map(|(slot_number, nic)| {
                (
                    format!(
                        "HTTP(IPv4) in Slot {slot_number} Port 1 : Nvidia Network Adapter - {}",
                        nic.mac_address
                    ),
                    BootOptionKind::Network,
                )
            })
            .chain(std::iter::once((
                "NVMe Drive 1 : Internal NVMe SSD".to_string(),
                BootOptionKind::Disk,
            )))
            .enumerate()
            .map(|(index, (display_name, kind))| {
                boot_opt_builder(&format!("Boot{index:04X}"), kind)
                    .display_name(&display_name)
                    .build()
            })
            .collect::<Vec<_>>();

        redfish::computer_system::Config {
            systems: vec![redfish::computer_system::SingleSystemConfig {
                id: Cow::Borrowed(system_id),
                manufacturer: Some("HPE".into()),
                model: Some(MODEL.into()),
                eth_interfaces: Some(eth_interfaces),
                serial_number: Some(self.product_serial_number.to_string().into()),
                boot_order_mode: redfish::computer_system::BootOrderMode::Generic,
                callbacks: Some(callbacks),
                chassis: vec![system_id.into()],
                boot_options: Some(boot_options.into()),
                bios_mode: redfish::computer_system::BiosMode::Generic,
                oem: redfish::computer_system::Oem::Generic,
                log_services: None,
                storage: None,
                processors: None,
                secure_boot_available: true,
                // Locked-down production state expected by nico: USB boot off,
                // virtualization on, UEFI HTTP boot available, serial console
                // redirected to the iLO virtual serial port (the attribute set
                // libredfish's HPE driver reads and writes).
                base_bios: Some(
                    redfish::bios::builder(&redfish::bios::resource(system_id))
                        .odata_context("/redfish/v1/$metadata#Bios.Bios")
                        .attributes(json!({
                            "UsbBoot": "Disabled",
                            "IntelProcVtd": "Enabled",
                            "Dhcpv4": "Enabled",
                            "HttpSupport": "Auto",
                            "EmbeddedSerialPort": "Com2Irq3",
                            "EMSConsole": "Virtual",
                            "SerialConsoleBaudRate": "BaudRate115200",
                            "SerialConsoleEmulation": "Vt100Plus",
                            "SerialConsolePort": "Virtual",
                            "UefiSerialDebugLevel": "ErrorsOnly",
                            "VirtualSerialPort": "Com1Irq4",
                        }))
                        .build(),
                ),
            }],
        }
    }

    pub fn chassis_config(&self) -> redfish::chassis::ChassisConfig {
        let chassis_id = "1";

        let network_adapters = self
            .nics
            .iter()
            .map(|(slot, nic)| {
                redfish::network_adapter::builder_from_nic(
                    &redfish::network_adapter::chassis_resource(
                        chassis_id,
                        &format!("DA00000{slot}"),
                    ),
                    nic,
                )
                .status(redfish::resource::Status::Ok)
                .build()
            })
            .collect();

        let pcie_devices = self
            .nics
            .iter()
            .map(|(slot, nic)| {
                let pcie_device_id = format!("mat_{}", slot);
                redfish::pcie_device::builder_from_nic(
                    &redfish::pcie_device::chassis_resource(chassis_id, &pcie_device_id),
                    nic,
                )
                .status(redfish::resource::Status::Ok)
                .build()
            })
            .collect();

        redfish::chassis::ChassisConfig {
            chassis: vec![redfish::chassis::SingleChassisConfig {
                id: Cow::Borrowed(chassis_id),
                chassis_type: "RackMount".into(),
                manufacturer: Some("HPE".into()),
                model: Some(MODEL.into()),
                part_number: Some(SKU.into()),
                serial_number: Some(self.product_serial_number.to_string().into()),
                network_adapters: Some(network_adapters),
                pcie_devices: Some(pcie_devices),
                ..redfish::chassis::SingleChassisConfig::defaults()
            }],
        }
    }

    pub fn update_service_config(&self) -> redfish::update_service::UpdateServiceConfig {
        redfish::update_service::UpdateServiceConfig {
            firmware_inventory: vec![],
        }
    }

    pub fn discovery_info(&self) -> DiscoveryInfo {
        DiscoveryInfo {
            network_interfaces: self
                .nics
                .iter()
                .map(|(slot, nic)| nic.discovery_info(*slot))
                .collect(),
            infiniband_interfaces: vec![],
            cpu_info: vec![CpuInfo {
                model: "INTEL(R) XEON(R) GOLD 6542Y".into(),
                vendor: "GenuineIntel".into(),
                sockets: 2,
                cores: 24,
                threads: 48,
            }],
            block_devices: (0..2)
                .map(|n| BlockDevice {
                    model: "VO001920KXPTN".into(),
                    revision: "HPK0".into(),
                    serial: format!("KNC8N5359I0108R1{}", if n == 0 { "X" } else { "W" }),
                    device_type: "disk".into(),
                })
                .collect(),
            machine_type: CpuArchitecture::X86_64.to_string(),
            machine_arch: Some(rpc::utils::cpu_architecture_to_rpc(CpuArchitecture::X86_64)),
            nvme_devices: (0..2)
                .map(|n| rpc::machine_discovery::NvmeDevice {
                    model: "VO001920KXPTN".into(),
                    firmware_rev: "HPK0".into(),
                    serial: format!("KNC8N5359I0108R1{}", if n == 0 { "X" } else { "W" }),
                })
                .collect(),
            dmi_data: Some(DmiData {
                board_name: MODEL.into(),
                board_version: "".into(),
                bios_version: "2.22".into(),
                bios_date: "06/19/2024".into(),
                product_serial: self.product_serial_number.to_string(),
                board_serial: "PYFCA0ARHJM00Z".into(),
                chassis_serial: self.product_serial_number.to_string(),
                product_name: MODEL.into(),
                sys_vendor: hw::bmc_vendor_to_udev_dmi(BMCVendor::Hpe).into(),
            }),
            dpu_info: None,
            gpus: vec![],
            memory_devices: (0..16)
                .map(|_| MemoryDevice {
                    size_mb: Some(16384),
                    mem_type: Some("DDR5".into()),
                })
                .collect(),
            tpm_ek_certificate: None,
            tpm_description: None,
            ..Default::default()
        }
    }
}
