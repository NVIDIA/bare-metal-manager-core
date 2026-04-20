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
use std::fmt;

use rpc::PciDeviceProperties;
use rpc::machine_discovery::{Gpu, GpuPlatformInfo, InfinibandInterface, MemoryDevice};

use crate::redfish;

#[derive(Clone, Copy)]
pub enum BoardIndex {
    Board0,
    Board1,
}

impl fmt::Display for BoardIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Board0 => "0",
            Self::Board1 => "1",
        }
        .fmt(f)
    }
}

pub struct BiancaBoard<'a> {
    pub index: BoardIndex,
    pub cpu_serial_number: Cow<'a, str>,
    pub gpu_serial_number: Cow<'a, str>,
}

pub struct GpuChassisIds {
    pub chassis_id: Cow<'static, str>,
    pub pcie_device_id: Cow<'static, str>,
}

impl BiancaBoard<'_> {
    pub fn hgx_cpu_chassis(&self, id: Cow<'static, str>) -> redfish::chassis::SingleChassisConfig {
        let sensors = redfish::sensor::generate_chassis_sensors(
            &id,
            redfish::sensor::Layout {
                temperature: 2,
                power: 3,
                leak: 2, // Voltage
                fan: 0,
                current: 0,
                // + 1 Energy
                // + 72 CPU core utilzation
                // + 1 Memory Frequency
            },
        );
        redfish::chassis::SingleChassisConfig {
            id,
            chassis_type: "Component".into(),
            manufacturer: Some("NVIDIA".into()),
            part_number: Some("900-2G548-0001-000".into()),
            model: Some("Grace A02P".into()),
            serial_number: Some(self.cpu_serial_number.to_string().into()),
            sensors: Some(sensors),
            ..redfish::chassis::SingleChassisConfig::defaults()
        }
    }

    pub fn hgx_gpu_chassis(
        &self,
        ids: [GpuChassisIds; 2],
    ) -> [redfish::chassis::SingleChassisConfig; 2] {
        ids.map(|ids| {
            let sensors = redfish::sensor::generate_chassis_sensors(
                &ids.chassis_id,
                redfish::sensor::Layout {
                    temperature: 3,
                    power: 2,
                    leak: 1, // Voltage
                    fan: 0,
                    current: 0,
                    // + 1 Energy
                },
            );
            redfish::chassis::SingleChassisConfig {
                chassis_type: "Component".into(),
                manufacturer: Some("NVIDIA".into()),
                part_number: Some("NA".into()),
                model: Some("GB200 186GB HBM3e".into()),
                serial_number: Some(self.gpu_serial_number.to_string().into()),
                pcie_devices: Some(vec![
                    redfish::pcie_device::builder(&redfish::pcie_device::chassis_resource(
                        &ids.chassis_id,
                        &ids.pcie_device_id,
                    ))
                    .manufacturer("NVIDIA")
                    .model("GB200 186GB HBM3e")
                    .part_number("2941-892-A1")
                    .serial_number(&self.gpu_serial_number)
                    .build(),
                ]),
                id: ids.chassis_id,
                sensors: Some(sensors),
                ..redfish::chassis::SingleChassisConfig::defaults()
            }
        })
    }

    pub fn discovery_gpu(&self) -> [Gpu; 2] {
        [0, 1].map(|gpun| Gpu {
            name: "NVIDIA GB200".into(),
            serial: self.gpu_serial_number.to_string(),
            driver_version: "580.126.16".into(),
            vbios_version: "97.00.B9.00.76".into(),
            inforom_version: "G548.0201.00.06".into(),
            total_memory: "189471 MiB".into(),
            frequency: "2062 MHz".into(),
            pci_bus_id: self.pcie_address(gpun).to_string(),
            platform_info: Some(GpuPlatformInfo {
                chassis_serial: format!("182100000000{}{gpun}", self.index),
                slot_number: 24,
                tray_index: 14,
                host_id: 1,
                module_id: self.module_id(gpun),
                fabric_guid: format!("0xfeeeeeeeeeeeee{gpun:02x}"),
            }),
        })
    }

    pub fn discovery_memory(&self) -> MemoryDevice {
        MemoryDevice {
            size_mb: Some(491520),
            mem_type: Some("LPDDR5".into()),
        }
    }

    fn pcie_address(&self, gpu_index: u8) -> &'static str {
        match (self.index, gpu_index) {
            (BoardIndex::Board0, 0) => "00000008:01:00.0",
            (BoardIndex::Board0, 1) => "00000009:01:00.0",
            (BoardIndex::Board1, 0) => "00000018:01:00.0",
            (BoardIndex::Board1, 1) => "00000019:01:00.0",
            _ => panic!("unexpected gpu index: {gpu_index}"),
        }
    }

    fn module_id(&self, gpu_index: u8) -> u32 {
        match (self.index, gpu_index) {
            (BoardIndex::Board0, 0) => 2,
            (BoardIndex::Board0, 1) => 1,
            (BoardIndex::Board1, 0) => 4,
            (BoardIndex::Board1, 1) => 3,
            _ => panic!("unexpected gpu index: {gpu_index}"),
        }
    }
}

pub struct IoBoard<'a> {
    pub index: BoardIndex,
    pub serial_number: Cow<'a, str>,
}

impl IoBoard<'_> {
    pub fn as_chassis(&self, id: Cow<'static, str>) -> redfish::chassis::SingleChassisConfig {
        let sensors = redfish::sensor::generate_chassis_sensors(
            &id,
            redfish::sensor::Layout {
                temperature: 4,
                ..Default::default()
            },
        );
        redfish::chassis::SingleChassisConfig {
            chassis_type: "Component".into(),
            manufacturer: Some("Nvidia".into()),
            part_number: Some("900-24768-0002-000".into()),
            model: Some("2x ConnectX-7 Mezz".into()),
            serial_number: Some(self.serial_number.to_string().into()),
            network_adapters: Some(
                (0..2)
                    .map(|n| {
                        redfish::network_adapter::builder(
                            &redfish::network_adapter::chassis_resource(
                                &id,
                                &format!("{id}_CX7_{n}"),
                            ),
                        )
                        .manufacturer("Nvidia")
                        .model("2x ConnectX-7 Mezz")
                        .part_number("900-24768-0002-000")
                        .serial_number(&self.serial_number)
                        .build()
                    })
                    .collect(),
            ),
            pcie_devices: Some(vec![]),
            sensors: Some(sensors),
            id,
            ..redfish::chassis::SingleChassisConfig::defaults()
        }
    }

    pub fn discovery_infiniband(&self) -> [InfinibandInterface; 2] {
        [0, 1].map(|n| {
            let numa_node = self.numa_node();
            let domain = self.pcie_domain(n);
            let device_name = if domain == 0 {
                Cow::Borrowed("ibp3s0")
            } else {
                format!("ibP{domain}p3s0").into()
            };
            InfinibandInterface {
                pci_properties: Some(PciDeviceProperties {
                    vendor: "Mellanox Technologies".into(),
                    device: "MT2910 Family [ConnectX-7]".into(),
                    path: format!(
                        "/devices/pci{domain:02x}:00\
                             /{domain:02x}:00:00.0\
                             /{domain:02x}:01:00.0\
                             /{domain:02x}:02:00.0\
                             /{domain:02x}:03:00.0\
                             /infiniband/{device_name}"
                    ),
                    numa_node,
                    description: Some("MT2910 Family [ConnectX-7]".into()),
                    slot: format!("{domain}:03:00.0").into(),
                }),
                guid: format!("7c8c09000000000{n}"),
            }
        })
    }

    fn numa_node(&self) -> i32 {
        match self.index {
            BoardIndex::Board0 => 0,
            BoardIndex::Board1 => 1,
        }
    }

    fn pcie_domain(&self, dev_number: u8) -> u32 {
        match (self.index, dev_number) {
            (BoardIndex::Board0, 0) => 0x0000,
            (BoardIndex::Board0, 1) => 0x0002,
            (BoardIndex::Board1, 0) => 0x0010,
            (BoardIndex::Board1, 1) => 0x0012,
            _ => panic!("unexpected dev number: {dev_number}"),
        }
    }
}
