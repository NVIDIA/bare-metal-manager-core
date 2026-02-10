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

use rand::Rng;
use serde_json::json;

use crate::json::{JsonExt, JsonPatch};
use crate::redfish;
use crate::redfish::Builder;

pub fn chassis_collection(chassis_id: &str) -> redfish::Collection<'static> {
    let odata_id = format!("/redfish/v1/Chassis/{chassis_id}/Sensors");
    redfish::Collection {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#SensorCollection.SensorCollection"),
        name: Cow::Borrowed("Sensors Collection"),
    }
}

pub fn chassis_resource<'a>(chassis_id: &str, sensor_id: &'a str) -> redfish::Resource<'a> {
    let odata_id = format!("{}/{sensor_id}", chassis_collection(chassis_id).odata_id);
    redfish::Resource {
        odata_id: Cow::Owned(odata_id),
        odata_type: Cow::Borrowed("#Sensor.v1_6_0.Sensor"),
        id: Cow::Borrowed(sensor_id),
        name: Cow::Borrowed("Sensor"),
    }
}

pub fn builder(resource: &redfish::Resource) -> SensorBuilder {
    SensorBuilder {
        id: Cow::Owned(resource.id.to_string()),
        value: resource.json_patch().patch(json!({
            "Status": redfish::resource::Status::Ok.into_json(),
        })),
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Layout {
    pub temperature: usize,
    pub fan: usize,
    pub power: usize,
    pub current: usize,
}

impl Layout {
    pub const fn total(&self) -> usize {
        self.temperature + self.fan + self.power + self.current
    }
}

#[derive(Debug, Clone)]
pub struct Sensor {
    pub id: Cow<'static, str>,
    value: serde_json::Value,
}

impl Sensor {
    pub fn to_json(&self) -> serde_json::Value {
        self.value.clone()
    }
}

pub struct SensorBuilder {
    id: Cow<'static, str>,
    value: serde_json::Value,
}

impl Builder for SensorBuilder {
    fn apply_patch(self, patch: serde_json::Value) -> Self {
        Self {
            value: self.value.patch(patch),
            id: self.id,
        }
    }
}

impl SensorBuilder {
    pub fn name(self, value: &str) -> Self {
        self.add_str_field("Name", value)
    }

    pub fn reading_f64(self, value: f64) -> Self {
        self.apply_patch(json!({ "Reading": value }))
    }

    pub fn reading_u32(self, value: u32) -> Self {
        self.apply_patch(json!({ "Reading": value }))
    }

    pub fn reading_type(self, value: &str) -> Self {
        self.add_str_field("ReadingType", value)
    }

    pub fn reading_units(self, value: &str) -> Self {
        self.add_str_field("ReadingUnits", value)
    }

    pub fn physical_context(self, value: &str) -> Self {
        self.add_str_field("PhysicalContext", value)
    }

    pub fn build(self) -> Sensor {
        Sensor {
            id: self.id,
            value: self.value,
        }
    }
}

enum SensorKind {
    Temperature,
    Fan,
    Power,
    Current,
}

impl SensorKind {
    fn id_prefix(&self) -> &'static str {
        match self {
            SensorKind::Temperature => "Temp",
            SensorKind::Fan => "Fan",
            SensorKind::Power => "Power",
            SensorKind::Current => "Current",
        }
    }

    fn name_prefix(&self) -> &'static str {
        match self {
            SensorKind::Temperature => "Temperature Sensor",
            SensorKind::Fan => "Fan Sensor",
            SensorKind::Power => "Power Sensor",
            SensorKind::Current => "Current Sensor",
        }
    }

    fn reading_type(&self) -> &'static str {
        match self {
            SensorKind::Temperature => "Temperature",
            SensorKind::Fan => "Rotational",
            SensorKind::Power => "Power",
            SensorKind::Current => "Current",
        }
    }

    fn reading_units(&self) -> &'static str {
        match self {
            SensorKind::Temperature => "Cel",
            SensorKind::Fan => "RPM",
            SensorKind::Power => "W",
            SensorKind::Current => "A",
        }
    }

    fn physical_context(&self) -> &'static str {
        match self {
            SensorKind::Temperature => "Intake",
            SensorKind::Fan => "Fan",
            SensorKind::Power => "PowerSupply",
            SensorKind::Current => "SystemBoard",
        }
    }
}

pub fn generate_chassis_sensors(chassis_id: &str, layout: Layout) -> Vec<Sensor> {
    let mut rng = rand::rng();
    let mut sensors = Vec::with_capacity(layout.total());
    append_sensors(
        &mut sensors,
        chassis_id,
        layout.temperature,
        SensorKind::Temperature,
        &mut rng,
    );
    append_sensors(
        &mut sensors,
        chassis_id,
        layout.fan,
        SensorKind::Fan,
        &mut rng,
    );
    append_sensors(
        &mut sensors,
        chassis_id,
        layout.power,
        SensorKind::Power,
        &mut rng,
    );
    append_sensors(
        &mut sensors,
        chassis_id,
        layout.current,
        SensorKind::Current,
        &mut rng,
    );
    sensors
}

fn append_sensors(
    sensors: &mut Vec<Sensor>,
    chassis_id: &str,
    count: usize,
    kind: SensorKind,
    rng: &mut impl Rng,
) {
    for index in 1..=count {
        let sensor_id = format!("{}_{}", kind.id_prefix(), index);
        let sensor_name = format!("{} {}", kind.name_prefix(), index);
        let sensor = builder(&chassis_resource(chassis_id, &sensor_id))
            .name(&sensor_name)
            .reading_type(kind.reading_type())
            .reading_units(kind.reading_units())
            .physical_context(kind.physical_context());
        let sensor = match kind {
            SensorKind::Temperature => sensor.reading_f64(random_tenths(rng, 28.0..=42.0)),
            SensorKind::Fan => sensor.reading_u32(rng.random_range(3800..=9400)),
            SensorKind::Power => sensor.reading_f64(random_tenths(rng, 130.0..=780.0)),
            SensorKind::Current => sensor.reading_f64(random_tenths(rng, 1.5..=42.0)),
        };
        sensors.push(sensor.build());
    }
}

fn random_tenths(rng: &mut impl Rng, range: std::ops::RangeInclusive<f64>) -> f64 {
    let value = rng.random_range(range);
    (value * 10.0).round() / 10.0
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{Layout, generate_chassis_sensors};

    #[test]
    fn generated_sensors_follow_layout_and_ranges() {
        let sensors = generate_chassis_sensors(
            "System.Embedded.1",
            Layout {
                temperature: 10,
                fan: 10,
                power: 20,
                current: 10,
            },
        );
        assert_eq!(sensors.len(), 50);

        let mut by_type: HashMap<String, usize> = HashMap::new();
        for sensor in sensors {
            let json = sensor.to_json();
            let reading_type = json["ReadingType"].as_str().unwrap().to_string();
            let reading = json["Reading"].as_f64().unwrap();
            *by_type.entry(reading_type.clone()).or_default() += 1;

            match reading_type.as_str() {
                "Temperature" => assert!((28.0..=42.0).contains(&reading)),
                "Rotational" => assert!((3800.0..=9400.0).contains(&reading)),
                "Power" => assert!((130.0..=780.0).contains(&reading)),
                "Current" => assert!((1.5..=42.0).contains(&reading)),
                _ => panic!("unexpected ReadingType"),
            }
        }

        assert_eq!(by_type.get("Temperature").copied().unwrap_or_default(), 10);
        assert_eq!(by_type.get("Rotational").copied().unwrap_or_default(), 10);
        assert_eq!(by_type.get("Power").copied().unwrap_or_default(), 20);
        assert_eq!(by_type.get("Current").copied().unwrap_or_default(), 10);
    }
}
