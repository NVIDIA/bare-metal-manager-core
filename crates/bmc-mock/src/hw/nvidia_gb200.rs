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
                voltage: 2,
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

    fn gpu_base_index(&self) -> usize {
        match self.index {
            BoardIndex::Board0 => 0,
            BoardIndex::Board1 => 2,
        }
    }

    pub fn gpu_chassis_ids(&self) -> [GpuChassisIds; 2] {
        let base = self.gpu_base_index();
        [0, 1].map(|local| {
            let n = base + local;
            GpuChassisIds {
                chassis_id: format!("HGX_GPU_{n}").into(),
                pcie_device_id: format!("GPU_{n}").into(),
            }
        })
    }

    pub fn hgx_gpu_processors(&self, system_id: &str) -> [redfish::processor::Processor; 2] {
        self.gpu_chassis_ids().map(|ids| {
            let voltage_sensor_id =
                redfish::sensor::sensor_id(redfish::sensor::SensorKind::Voltage, 1);
            redfish::processor::gpu(
                system_id,
                &ids.pcie_device_id,
                redfish::sensor::chassis_resource(&ids.chassis_id, &voltage_sensor_id)
                    .odata_id
                    .as_ref(),
            )
        })
    }

    pub fn hgx_gpu_chassis(&self) -> [redfish::chassis::SingleChassisConfig; 2] {
        self.gpu_chassis_ids().map(|ids| {
            let sensors = redfish::sensor::generate_chassis_sensors(
                &ids.chassis_id,
                redfish::sensor::Layout {
                    temperature: 3,
                    power: 2,
                    voltage: 1,
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
}

pub struct IoBoard<'a> {
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
}
