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

use serde_json::json;

use crate::{PowerControl, hw, redfish};

pub struct WiwynnGB200Nvl<'a> {
    pub product_serial_number: Cow<'a, str>,
    pub dpu1: hw::bluefield3::Bluefield3<'a>,
    pub dpu2: hw::bluefield3::Bluefield3<'a>,
}

impl WiwynnGB200Nvl<'_> {
    pub fn manager_config(&self) -> redfish::manager::Config {
        redfish::manager::Config {
            managers: vec![
                redfish::manager::SingleConfig {
                    id: "BMC_0",
                    eth_interfaces: vec![], // TODO: eth0 / eth1 / hmcusb0 / hostusb0
                    firmware_version: "25.06-2_NV_WW_02",
                },
                redfish::manager::SingleConfig {
                    id: "HGX_BMC_0",
                    eth_interfaces: vec![], // TODO: usb0
                    firmware_version: "GB200Nvl-25.06-A",
                },
            ],
        }
    }

    pub fn system_config(&self, pc: Arc<dyn PowerControl>) -> redfish::computer_system::Config {
        let system_id = "System_0";
        let power_control = Some(pc);
        let serial_number = Some(self.product_serial_number.to_string().into());
        let boot_opt_builder = |id: &str| {
            redfish::boot_option::builder(&redfish::boot_option::resource(system_id, id))
                .boot_option_reference(id)
        };
        let boot_options = [
            boot_opt_builder("Boot0020")
                .display_name("Ubuntu")
                .uefi_device_path("HD(1,GPT,C07AA982-7D30-4663-9538-776771BBED85,0x800,0x219800)/\\EFI\\ubuntu\\shimaa64.efi")
                .build()
        ].into_iter().chain([&self.dpu1, &self.dpu2].into_iter().enumerate().map(|(index, dpu)| {
            let mac = dpu.host_mac_address.to_string().replace(":", "").to_uppercase();
            let display_name = format!("UEFI HTTPv4 (MAC:{mac})");
            boot_opt_builder(&format!("Boot{index:04X}"))
                .display_name(&display_name)
                .uefi_device_path(&format!("MAC({mac},0x1)/IPv4(0.0.0.0,0x0,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)/Uri()"))
                .build()
        })).collect();

        redfish::computer_system::Config {
            systems: vec![
                redfish::computer_system::SingleSystemConfig {
                    id: system_id.into(),
                    manufacturer: Some("WIWYNN".into()),
                    model: Some("GB200 NVL".into()),
                    eth_interfaces: None,
                    serial_number,
                    boot_order_mode: redfish::computer_system::BootOrderMode::ViaSettings,
                    power_control,
                    chassis: vec!["BMC_0".into()],
                    boot_options: Some(boot_options),
                    bios_mode: redfish::computer_system::BiosMode::Generic,
                    base_bios: Some(
                        redfish::bios::builder(&redfish::bios::resource(system_id))
                            .attributes(json!({
                                "EmbeddedUefiShell": "Enabled",
                            }))
                            .build(),
                    ),
                },
                redfish::computer_system::SingleSystemConfig {
                    id: "HGX_Baseboard_0".into(),
                    manufacturer: Some("NVIDIA".into()),
                    model: Some("GB200 NVL".into()),
                    chassis: vec!["HGX_Chassis_0".into()],
                    eth_interfaces: None,
                    power_control: None,
                    boot_options: None,
                    serial_number: None,
                    boot_order_mode: redfish::computer_system::BootOrderMode::Generic,
                    bios_mode: redfish::computer_system::BiosMode::Generic,
                    base_bios: None,
                },
            ],
        }
    }

    pub fn chassis_config(&self) -> redfish::chassis::ChassisConfig {
        let dpu_chassis = |chassis_id: &'static str, bf3: &hw::bluefield3::Bluefield3<'_>| {
            let nic = bf3.host_nic();
            let network_adapters = Some(vec![
                redfish::network_adapter::builder_from_nic(
                    &redfish::network_adapter::chassis_resource(chassis_id, chassis_id),
                    &nic,
                )
                .status(redfish::resource::Status::Ok)
                .build(),
            ]);

            redfish::chassis::SingleChassisConfig {
                id: chassis_id.into(),
                chassis_type: Cow::Borrowed("Card"),
                manufacturer: nic.manufacturer,
                part_number: nic.part_number,
                model: Some("GB200 NVL".into()),
                serial_number: None,
                network_adapters,
                pcie_devices: Some(vec![]),
                sensors: None,
            }
        };
        redfish::chassis::ChassisConfig {
            chassis: vec![
                redfish::chassis::SingleChassisConfig {
                    id: "Chassis_0".into(),
                    chassis_type: Cow::Borrowed("RackMount"),
                    manufacturer: Some("NVIDIA".into()),
                    part_number: Some("B81.11810.000D".into()),
                    model: Some("GB200 NVL".into()),
                    serial_number: None,
                    network_adapters: None,
                    pcie_devices: None,
                    sensors: None,
                },
                dpu_chassis("Riser_Slot1_BlueField_3_Card", &self.dpu1),
                dpu_chassis("Riser_Slot2_BlueField_3_Card", &self.dpu2),
            ],
        }
    }

    pub fn update_service_config(&self) -> redfish::update_service::UpdateServiceConfig {
        redfish::update_service::UpdateServiceConfig {
            firmware_inventory: vec![],
        }
    }
}
