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

use mac_address::MacAddress;
use rpc::machine_discovery::{BlockDevice, CpuInfo, DiscoveryInfo, DmiData, MemoryDevice};
use serde_json::json;
use utils::models::arch::CpuArchitecture;

use crate::{PowerControl, hw, redfish};

pub struct DellPowerEdgeR750<'a> {
    pub bmc_mac_address: MacAddress,
    pub product_serial_number: Cow<'a, str>,
    pub nics: Vec<(hw::nic::SlotNumber, hw::nic::Nic)>,
    pub embedded_nic: EmbeddedNic,
}

pub struct EmbeddedNic {
    pub port_1: MacAddress,
    pub port_2: MacAddress,
}

impl DellPowerEdgeR750<'_> {
    fn sensor_layout() -> redfish::sensor::Layout {
        redfish::sensor::Layout {
            temperature: 10,
            fan: 10,
            power: 20,
            current: 10,
            leak: 0,
        }
    }

    pub fn manager_config(&self) -> redfish::manager::Config {
        redfish::manager::Config {
            managers: vec![redfish::manager::SingleConfig {
                id: "iDRAC.Embedded.1",
                eth_interfaces: vec![
                    redfish::ethernet_interface::builder(
                        &redfish::ethernet_interface::manager_resource("iDRAC.Embedded.1", "NIC.1"),
                    )
                    .mac_address(self.bmc_mac_address)
                    .interface_enabled(true)
                    .build(),
                ],
                firmware_version: "6.00.30.00",
                oem: Some(redfish::manager::Oem::Dell),
            }],
        }
    }

    pub fn system_config(&self, pc: Arc<dyn PowerControl>) -> redfish::computer_system::Config {
        let power_control = Some(pc);
        let serial_number = Some(self.product_serial_number.to_string().into());
        let system_id = "System.Embedded.1";

        let eth_interfaces = [
            (1, &self.embedded_nic.port_1),
            (2, &self.embedded_nic.port_2),
        ]
        .into_iter()
        .map(|(port, mac)| {
            let eth_id = format!("NIC.Embedded.{port}-1-1");
            let resource = redfish::ethernet_interface::system_resource(system_id, &eth_id);
            redfish::ethernet_interface::builder(&resource)
                .description(&format!("Embedded NIC 1 Port {port} Partition 1"))
                .mac_address(*mac)
                .interface_enabled(true)
                .build()
        })
        .chain(self.nics.iter().map(|(slot_number, nic)| {
            let eth_id = format!("NIC.Slot.{slot_number}-1");
            let resource = redfish::ethernet_interface::system_resource(system_id, &eth_id);
            redfish::ethernet_interface::builder(&resource)
                .description(&format!("NIC in Slot {slot_number} Port 1"))
                .mac_address(nic.mac_address)
                .interface_enabled(true)
                .build()
        }))
        .collect();

        let boot_opt_builder = |id: &str| {
            redfish::boot_option::builder(&redfish::boot_option::resource(system_id, id))
                .boot_option_reference(id)
        };
        let boot_options = self
            .nics
            .iter()
            .map(|(slot_number, _)| format!("HTTP Device 1: NIC in Slot {slot_number} Port 1"))
            .chain(std::iter::once(
                "PCIe SSD in Slot 2 in Bay 1: EFI Fixed Disk Boot Device 1".to_string(),
            ))
            .enumerate()
            .map(|(index, display_name)| {
                boot_opt_builder(&format!("Boot{index:04X}"))
                    .display_name(&display_name)
                    .build()
            })
            .collect();

        redfish::computer_system::Config {
            systems: vec![redfish::computer_system::SingleSystemConfig {
                id: Cow::Borrowed(system_id),
                manufacturer: Some("Dell Inc.".into()),
                model: Some("PowerEdge R750".into()),
                eth_interfaces: Some(eth_interfaces),
                serial_number,
                boot_order_mode: redfish::computer_system::BootOrderMode::DellOem,
                power_control,
                chassis: vec!["System.Embedded.1".into()],
                boot_options: Some(boot_options),
                bios_mode: redfish::computer_system::BiosMode::DellOem,
                oem: redfish::computer_system::Oem::Generic,
                log_services: None,
                base_bios: Some(redfish::bios::builder(&redfish::bios::resource(system_id))
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
                    .build()),
            }],
        }
    }

    pub fn chassis_config(&self) -> redfish::chassis::ChassisConfig {
        let chassis_id = "System.Embedded.1";
        let net_adapter_builder = |id: &str| {
            redfish::network_adapter::builder(&redfish::network_adapter::chassis_resource(
                chassis_id, id,
            ))
        };
        let network_adapters = std::iter::once(
            net_adapter_builder("NIC.Embedded.1")
                .manufacturer("Broadcom Inc. and subsidiaries")
                .build(),
        )
        .chain(self.nics.iter().map(|(slot, nic)| {
            let network_adapter_id = format!("NIC.Slot.{slot}");
            let function_id = format!("NIC.Slot.{slot}-1");
            let func_resource = &redfish::network_device_function::chassis_resource(
                chassis_id,
                &network_adapter_id,
                &function_id,
            );
            let function = redfish::network_device_function::builder(func_resource)
                .ethernet(json!({"MACAddress": &nic.mac_address}))
                .oem(redfish::oem::dell::network_device_function::dell_nic_info(
                    &function_id,
                    *slot,
                    &nic.serial_number,
                ))
                .build();
            redfish::network_adapter::builder_from_nic(
                &redfish::network_adapter::chassis_resource(chassis_id, &network_adapter_id),
                nic,
            )
            .network_device_functions(
                &redfish::network_device_function::chassis_collection(
                    chassis_id,
                    &network_adapter_id,
                ),
                vec![function],
            )
            .status(redfish::resource::Status::Ok)
            .build()
        }))
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
                manufacturer: Some("Dell Inc.".into()),
                part_number: Some("01J4WFA05".into()),
                model: Some("PowerEdge R750".into()),
                serial_number: Some(self.product_serial_number.to_string().into()),
                network_adapters: Some(network_adapters),
                pcie_devices: Some(pcie_devices),
                sensors: Some(redfish::sensor::generate_chassis_sensors(
                    chassis_id,
                    Self::sensor_layout(),
                )),
                assembly: None,
                oem: None,
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
                model: "Intel(R) Xeon(R) Gold 6354 CPU @ 3.00GHz".into(),
                vendor: "GenuineIntel".into(),
                sockets: 2,
                cores: 18,
                threads: 36,
            }],
            block_devices: vec![
                BlockDevice {
                    model: "Dell Ent NVMe v2 AGN RI U.2 1.92TB".into(),
                    revision: "2.3.0".into(),
                    serial: "FAKESERNUM0".into(),
                    device_type: "".into(),
                },
                BlockDevice {
                    model: "Dell Ent NVMe v2 AGN RI U.2 1.92TB".into(),
                    revision: "2.3.0".into(),
                    serial: "FAKESERNUM1".into(),
                    device_type: "".into(),
                },
            ],
            machine_type: CpuArchitecture::X86_64.to_string(),
            machine_arch: Some(CpuArchitecture::X86_64.into()),
            nvme_devices: vec![],
            dmi_data: Some(DmiData {
                board_name: "01J4WF".into(),
                board_version: "A05".into(),
                bios_version: "1.13.2".into(),
                bios_date: "12/19/2023".into(),
                product_serial: self.product_serial_number.to_string(),
                board_serial: format!(".{}.FAKESERNUM2.", self.product_serial_number),
                chassis_serial: self.product_serial_number.to_string(),
                product_name: "PowerEdge R750".into(),
                sys_vendor: "Dell".into(),
            }),
            dpu_info: None,
            gpus: vec![],
            memory_devices: (0..8)
                .map(|_| MemoryDevice {
                    size_mb: Some(16384),
                    mem_type: Some("DDR4".into()),
                })
                .collect(),
            tpm_ek_certificate: None,
            tpm_description: None,
            ..Default::default()
        }
    }
}
