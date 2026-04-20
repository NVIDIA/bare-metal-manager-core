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

use crate::redfish;

pub struct NvidiaGB300Gpu<'a> {
    pub serial_number: Cow<'a, str>,
}

impl NvidiaGB300Gpu<'_> {
    pub fn as_hgx_chassis(&self, id: Cow<'static, str>) -> redfish::chassis::SingleChassisConfig {
        let sensors = redfish::sensor::generate_chassis_sensors(
            &id,
            redfish::sensor::Layout {
                temperature: 3,
                power: 2,
                leak: 1, // Leak + Voltage
                fan: 0,
                current: 0,
                // + 1 Energy
            },
        );
        redfish::chassis::SingleChassisConfig {
            id,
            chassis_type: "Component".into(),
            manufacturer: Some("NVIDIA".into()),
            part_number: Some("SC57C26750".into()),
            model: Some("NVIDIA GB300".into()),
            serial_number: Some(self.serial_number.to_string().into()),
            sensors: Some(sensors),
            ..redfish::chassis::SingleChassisConfig::defaults()
        }
    }
}

pub struct NvidiaGB300Cpu<'a> {
    pub serial_number: Cow<'a, str>,
}

impl NvidiaGB300Cpu<'_> {
    pub fn as_hgx_chassis(&self, id: Cow<'static, str>) -> redfish::chassis::SingleChassisConfig {
        let sensors = redfish::sensor::generate_chassis_sensors(
            &id,
            redfish::sensor::Layout {
                temperature: 2,
                power: 5,
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
            part_number: Some("900-2G548-0081-000".into()),
            model: Some("Grace A02P".into()),
            serial_number: Some(self.serial_number.to_string().into()),
            sensors: Some(sensors),
            ..redfish::chassis::SingleChassisConfig::defaults()
        }
    }
}

pub struct NvidiaGB300IoBoard<'a> {
    pub serial_number: Cow<'a, str>,
}

impl NvidiaGB300IoBoard<'_> {
    pub fn as_chassis(&self, id: Cow<'static, str>) -> redfish::chassis::SingleChassisConfig {
        let sensors = redfish::sensor::generate_chassis_sensors(
            &id,
            redfish::sensor::Layout {
                temperature: 8,
                ..Default::default()
            },
        );
        redfish::chassis::SingleChassisConfig {
            id,
            chassis_type: "Component".into(),
            manufacturer: Some("Nvidia".into()),
            part_number: Some("900-9X86E-00CX-ST0           ".into()),
            model: Some("P4768-B01".into()),
            serial_number: Some(self.serial_number.to_string().into()),
            sensors: Some(sensors),
            ..redfish::chassis::SingleChassisConfig::defaults()
        }
    }
}
