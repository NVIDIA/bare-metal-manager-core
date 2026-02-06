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
use serde_json::json;

use crate::{PowerControl, hw, redfish};

pub type SlotNumber = usize;

pub struct DellPowerEdgeR750<'a> {
    pub bmc_mac_address: MacAddress,
    pub product_serial_number: Cow<'a, str>,
    pub nics: Vec<(SlotNumber, hw::nic::Nic)>,
    pub embedded_nic: EmbeddedNic,
}

pub struct EmbeddedNic {
    pub port_1: MacAddress,
    pub port_2: MacAddress,
}

impl DellPowerEdgeR750<'_> {
    pub fn manager_config(&self) -> redfish::manager::Config {
        redfish::manager::Config {
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
        }
    }

    pub fn system_config(&self, pc: Arc<dyn PowerControl>) -> redfish::computer_system::Config {
        let power_control = Some(pc);
        let serial_number = self.product_serial_number.to_string().into();
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
                eth_interfaces,
                serial_number,
                boot_order_mode: redfish::computer_system::BootOrderMode::DellOem,
                power_control,
                chassis: vec!["System.Embedded.1".into()],
                boot_options,
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
                manufacturer: Some("Dell Inc.".into()),
                part_number: Some("01J4WFA05".into()),
                model: Some("PowerEdge R750".into()),
                serial_number: Some(self.product_serial_number.to_string().into()),
                network_adapters: Some(network_adapters),
                pcie_devices: Some(pcie_devices),
            }],
        }
    }

    pub fn update_service_config(&self) -> redfish::update_service::UpdateServiceConfig {
        redfish::update_service::UpdateServiceConfig {
            firmware_inventory: vec![],
        }
    }
}
