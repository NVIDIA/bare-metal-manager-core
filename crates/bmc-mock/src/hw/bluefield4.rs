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

use carbide_utils::arch::CpuArchitecture;
use mac_address::MacAddress;
use rpc::machine_discovery::{DiscoveryInfo, DmiData, DpuData};
use serde_json::json;

use crate::{Callbacks, LogService, LogServices, hw, redfish};

#[derive(Clone, Copy, Debug)]
pub enum Mode {
    // B4240V installed on VR NVL.
    B4240V,
    // Air Cooled Bluefield-4 DPU
    B4240,
}

pub struct Bluefield4<'a> {
    pub product_serial_number: Cow<'a, str>,
    pub host_mac_address: MacAddress,
    pub bmc_mac_address: MacAddress,
    pub mode: Mode,
}

impl Bluefield4<'_> {
    fn sensor_layout() -> redfish::sensor::Layout {
        // BF4 Card1 dump contains 96 sensors total. The generic mock
        // layout currently models Temperature, Fan, Power, Current,
        // and Voltage.  Missing BF4 ReadingType counts: Percent=64,
        // Frequency=2, EnergyJoules=1.
        redfish::sensor::Layout {
            temperature: 5,
            fan: 0,
            power: 6,
            current: 0,
            voltage: 18,
        }
    }

    pub fn chassis_config(&self) -> redfish::chassis::ChassisConfig {
        redfish::chassis::ChassisConfig {
            chassis: vec![
                redfish::chassis::SingleChassisConfig {
                    id: "Bluefield_BMC".into(),
                    chassis_type: "Component".into(),
                    manufacturer: Some("Nvidia".into()),
                    model: Some(self.model().into()),
                    part_number: Some(self.part_number().into()),
                    pcie_devices: Some(vec![]),
                    sensors: Some(vec![]),
                    serial_number: Some(self.product_serial_number.to_string().into()),
                    ..redfish::chassis::SingleChassisConfig::defaults()
                },
                redfish::chassis::SingleChassisConfig {
                    id: "Bluefield_BMC_ERoT".into(),
                    chassis_type: "Component".into(),
                    manufacturer: Some(Cow::Borrowed("NVIDIA")),
                    serial_number: Some("".into()),
                    ..redfish::chassis::SingleChassisConfig::defaults()
                },
                redfish::chassis::SingleChassisConfig {
                    id: "Bluefield_CPU_ERoT".into(),
                    chassis_type: "Component".into(),
                    manufacturer: Some(Cow::Borrowed("NVIDIA")),
                    serial_number: Some("".into()),
                    ..redfish::chassis::SingleChassisConfig::defaults()
                },
                redfish::chassis::SingleChassisConfig {
                    id: "Bluefield_NIC".into(),
                    chassis_type: "Component".into(),
                    manufacturer: Some(Cow::Borrowed("NVIDIA")),
                    serial_number: Some("".into()),
                    ..redfish::chassis::SingleChassisConfig::defaults()
                },
                redfish::chassis::SingleChassisConfig {
                    id: "Card1".into(),
                    chassis_type: "Card".into(),
                    pcie_devices: Some(vec![]),
                    sensors: Some(redfish::sensor::generate_chassis_sensors(
                        "Card1",
                        Self::sensor_layout(),
                    )),
                    ..redfish::chassis::SingleChassisConfig::defaults()
                },
                redfish::chassis::SingleChassisConfig {
                    id: "MCTP_SPI_DEV".into(),
                    chassis_type: "".into(),
                    pcie_devices: Some(vec![]),
                    sensors: Some(vec![]),
                    ..redfish::chassis::SingleChassisConfig::defaults()
                },
            ],
        }
    }

    pub fn system_config(&self, callbacks: Arc<dyn Callbacks>) -> redfish::computer_system::Config {
        let system_id = "Bluefield";
        redfish::computer_system::Config {
            systems: vec![redfish::computer_system::SingleSystemConfig {
                id: Cow::Borrowed("Bluefield"),
                manufacturer: None,
                model: None,
                eth_interfaces: Some(vec![]),
                chassis: vec!["Bluefield_BMC".into()],
                serial_number: None,
                boot_order_mode: redfish::computer_system::BootOrderMode::ViaSettings,
                callbacks: Some(callbacks),
                boot_options: Some(redfish::computer_system::BootOptionsConfig::NullMembers),
                bios_mode: redfish::computer_system::BiosMode::Generic,
                oem: redfish::computer_system::Oem::NvidiaBluefield,
                base_bios: Some(
                    redfish::bios::builder(&redfish::bios::resource(system_id))
                        .attributes(json!({}))
                        .build(),
                ),
                log_services: Some(Arc::new(Bf4LogServices {
                    event_log: DpuEventLog {
                        entries: vec!["DPU Warm Reset".to_string()],
                    },
                })),
                storage: Some(vec![]),
                processors: Some(vec![]),
                secure_boot_available: true,
            }],
        }
    }

    pub fn manager_config(&self) -> redfish::manager::Config {
        redfish::manager::Config {
            managers: vec![redfish::manager::SingleConfig {
                id: "Bluefield_BMC",
                eth_interfaces: Some(vec![
                    redfish::ethernet_interface::builder(
                        &redfish::ethernet_interface::manager_resource("Bluefield_BMC", "eth0"),
                    )
                    .mac_address(self.bmc_mac_address)
                    .interface_enabled(true)
                    .build(),
                ]),
                host_interfaces: None,
                firmware_version: Some("BF4-26.01-2"),
                oem: None,
            }],
        }
    }

    pub fn update_service_config(&self) -> redfish::update_service::UpdateServiceConfig {
        redfish::update_service::UpdateServiceConfig {
            firmware_inventory: vec![],
        }
    }

    pub fn host_nic(&self) -> hw::nic::Nic<'static> {
        match self.mode {
            Mode::B4240 => hw::nic::Nic {
                mac_address: self.host_mac_address,
                serial_number: Some(format!("{}", self.product_serial_number).into()),
                manufacturer: Some("Mellanox Technologies".into()),
                model: Some("B4240".into()),
                description: Some("CX9 Family [ConnectX-9]".into()),
                part_number: Some(self.part_number().into()),
                firmware_version: Some("82.48.0802".into()),
                is_mat_dpu: true,
            },
            Mode::B4240V => hw::nic::Nic {
                mac_address: self.host_mac_address,
                serial_number: Some(format!("{}", self.product_serial_number).into()),
                manufacturer: Some("NVIDIA".into()),
                model: Some("NVIDIA BlueField-4 B4240V 800G Liquid Cooled DPU, Dual-port 400GbE / NDR, QSFP112, PCIe Gen6 x16, 64 Arm cores, 128GB LPDDR5x, integrated BMC, Crypto Enabled, Secure Boot Enabled".into()),
                description: None,
                part_number: Some(self.part_number().into()),
                firmware_version: None,
                is_mat_dpu: true,
            },
        }
    }

    pub fn discovery_info(&self) -> DiscoveryInfo {
        DiscoveryInfo {
            machine_type: CpuArchitecture::Aarch64.to_string(),
            machine_arch: Some(rpc::utils::cpu_architecture_to_rpc(
                CpuArchitecture::Aarch64,
            )),
            dmi_data: Some(DmiData {
                board_name: "BlueField-4 DPU".into(),
                product_serial: self.product_serial_number.to_string(),
                board_serial: carbide_utils::DEFAULT_DPU_DMI_BOARD_SERIAL_NUMBER.into(),
                chassis_serial: carbide_utils::DEFAULT_DPU_DMI_CHASSIS_SERIAL_NUMBER.into(),
                product_name: "BlueField-4 DPU".into(),
                sys_vendor: "Nvidia".into(),
                ..Default::default()
            }),
            dpu_info: Some(DpuData {
                part_number: self.part_number().into(),
                part_description: format!("NVIDIA BlueField-4 {}", self.part_number()),
                factory_mac_address: self.host_mac_address.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    pub fn model(&self) -> &'static str {
        match self.mode {
            Mode::B4240V => "B4240V",
            Mode::B4240 => "B4240",
        }
    }

    fn part_number(&self) -> &'static str {
        match self.mode {
            Mode::B4240 => "900-9D4B4-CWAA-TSA",
            Mode::B4240V => "900-9D4A4-00CB-TS4",
        }
    }
}

struct DpuEventLog {
    entries: Vec<String>,
}

impl LogService for DpuEventLog {
    fn id(&self) -> &str {
        "EventLog"
    }

    fn entries(&self, collection: &redfish::Collection<'_>) -> Vec<serde_json::Value> {
        self.entries
            .iter()
            .enumerate()
            .map(|(idx, entry)| {
                redfish::log_service::event_entry(collection, &idx.to_string())
                    .message(entry)
                    // These are not required by specification but
                    // required by libredfish. Making it happy. However, in future
                    // we may want to simulate these fields as well.
                    .severity("OK")
                    .created("2026-02-12T02:06:58+00:00")
                    .build()
            })
            .collect()
    }
}

struct Bf4LogServices {
    event_log: DpuEventLog,
}

impl LogServices for Bf4LogServices {
    fn services(&self) -> Vec<&(dyn LogService + '_)> {
        vec![&self.event_log as &dyn LogService]
    }
}
