/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use libredfish::model::sel::LogEntry;
use libredfish::model::{
    power::Power, software_inventory::SoftwareInventory, thermal::Thermal, ResourceHealth,
    ResourceState,
};
use libredfish::{Endpoint, Redfish, RedfishClientPool};
use opentelemetry::metrics::{MeterProvider as _, Unit};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::MeterProvider;

use crate::HealthError;

pub struct HardwareHealth {
    thermal: Thermal,
    power: Power,
    logs: Vec<LogEntry>,
    firmware: Vec<SoftwareInventory>,
}

/// get all the metrics we want from the bmc
// none of these are a patch/post and will not affect the bmc doing other patch/post ops
pub fn get_metrics(redfish: Box<dyn Redfish>) -> Result<HardwareHealth, HealthError> {
    // get the temperature, fans, voltages, power supplies data from the bmc
    let thermal = redfish.get_thermal_metrics()?;
    let power = redfish.get_power_metrics()?;
    // get the system/hardware event log
    let logs = redfish.get_system_event_log()?;
    // get system firmware components versions, such as uefi, bmc, sbios, me, etc
    let components = redfish.get_software_inventories()?;
    let mut firmware = Vec::new();
    for component in components.iter() {
        let version = redfish.get_firmware(component.as_str())?;
        firmware.push(version);
    }
    let health = HardwareHealth {
        thermal,
        power,
        logs,
        firmware,
    };
    Ok(health)
}

pub fn display_state(state: Option<ResourceState>) -> String {
    match state {
        Some(x) => format!("{}", x),
        None => "Unknown".to_string(),
    }
}

pub fn display_health(health: Option<ResourceHealth>) -> String {
    match health {
        Some(x) => format!("{}", x),
        None => "Unknown".to_string(),
    }
}

// the attribute keys and values are specified in
// https://opentelemetry.io/docs/specs/otel/metrics/semantic_conventions/hardware-metrics/
// in the hw.temperature section.
// hw.id, hw.type are required.
// hw.host.id and hw.sensor_location are recommended
// hw.state and hw.health are custom attributes based on redfish schema
pub async fn export_metrics(
    provider: MeterProvider,
    health: HardwareHealth,
    machine_id: String,
) -> Result<(), HealthError> {
    // build or get meter for each machine
    let meter = provider.meter(machine_id.clone());

    let temperature_sensors = meter
        .i64_observable_gauge("hw.temperature")
        .with_description("Temperature sensors for this hardware")
        .with_unit(Unit::new("Celsius"))
        .init();
    for temperature in health.thermal.temperatures.iter() {
        if temperature.reading_celsius.is_none() {
            // don't add the reading if there's no value provided
            continue;
        }
        let sensor_name = temperature.name.clone().as_str().replace(" ", "_");
        let sensor_state = display_state(temperature.status.state);
        let sensor_health = display_health(temperature.status.health);
        temperature_sensors.observe(
            temperature.reading_celsius.unwrap(),
            &[
                KeyValue::new("hw.id", sensor_name),
                KeyValue::new("hw.type", "temperature"),
                KeyValue::new("hw.sensor_location", temperature.name.clone()),
                KeyValue::new("hw.host.id", machine_id.clone()),
                KeyValue::new("hw.state", sensor_state),
                KeyValue::new("hw.health", sensor_health),
            ],
        )
    }

    let fan_sensors = meter
        .i64_observable_gauge("hw.fan.speed")
        .with_description("Fans for this hardware")
        .with_unit(Unit::new("rpm"))
        .init();
    for fan in health.thermal.fans.iter() {
        let sensor_name = fan.fan_name.clone().as_str().replace(" ", "_");
        let sensor_state = display_state(fan.status.state);
        let sensor_health = display_health(fan.status.health);
        fan_sensors.observe(
            fan.reading.clone(),
            &[
                KeyValue::new("hw.id", sensor_name),
                KeyValue::new("hw.type", "fan"),
                KeyValue::new("hw.sensor_location", fan.fan_name.clone()),
                KeyValue::new("hw.host.id", machine_id.clone()),
                KeyValue::new("hw.state", sensor_state),
                KeyValue::new("hw.health", sensor_health),
            ],
        )
    }

    let voltage_sensors = meter
        .f64_observable_gauge("hw.voltage")
        .with_description("Voltages for this hardware")
        .with_unit(Unit::new("V"))
        .init();
    for voltage in health.power.voltages.iter() {
        if voltage.reading_volts.is_none() {
            continue;
        }
        let sensor_name = voltage.name.clone().as_str().replace(" ", "_");
        let sensor_state = display_state(voltage.status.state);
        let sensor_health = display_health(voltage.status.health);
        voltage_sensors.observe(
            voltage.reading_volts.unwrap(),
            &[
                KeyValue::new("hw.id", sensor_name),
                KeyValue::new("hw.type", "voltage"),
                KeyValue::new("hw.sensor_location", voltage.name.clone()),
                KeyValue::new("hw.host.id", machine_id.clone()),
                KeyValue::new("hw.state", sensor_state),
                KeyValue::new("hw.health", sensor_health),
            ],
        )
    }

    let power_supplies_output_watts_sensors = meter
        .f64_observable_gauge("hw.power_supply.output")
        .with_description("Last output Wattage for this hardware")
        .with_unit(Unit::new("Watts"))
        .init();
    let power_supplies_utilization_sensors = meter
        .f64_observable_gauge("hw.power_supply.utilization")
        .with_description("Utilization of power supply capacity")
        .with_unit(Unit::new("%"))
        .init();
    let power_supplies_input_voltage_sensors = meter
        .i64_observable_gauge("hw.power_supply.input")
        .with_description("Input line Voltage")
        .with_unit(Unit::new("V"))
        .init();
    for power_supply in health.power.power_supplies.iter() {
        let sensor_name = power_supply.name.clone().as_str().replace(" ", "_");
        let sensor_state = display_state(power_supply.status.state);
        let sensor_health = display_health(power_supply.status.health);
        power_supplies_output_watts_sensors.observe(
            power_supply.last_power_output_watts.clone(),
            &[
                KeyValue::new("hw.id", sensor_name.clone()),
                KeyValue::new("hw.type", "power_supply"),
                KeyValue::new("hw.model", power_supply.model.clone()),
                KeyValue::new("hw.serial", power_supply.serial_number.clone()),
                KeyValue::new("hw.host.id", machine_id.clone()),
                KeyValue::new("hw.state", sensor_state.clone()),
                KeyValue::new("hw.health", sensor_health.clone()),
            ],
        );
        power_supplies_input_voltage_sensors.observe(
            power_supply.line_input_voltage.clone(),
            &[
                KeyValue::new("hw.id", sensor_name.clone()),
                KeyValue::new("hw.type", "power_supply"),
                KeyValue::new("hw.model", power_supply.model.clone()),
                KeyValue::new("hw.serial", power_supply.serial_number.clone()),
                KeyValue::new("hw.host.id", machine_id.clone()),
                KeyValue::new("hw.state", sensor_state.clone()),
                KeyValue::new("hw.health", sensor_health.clone()),
            ],
        );
        let utilization: f64 = (power_supply.last_power_output_watts.clone()
            / power_supply.power_capacity_watts.clone() as f64)
            * 100.0;
        power_supplies_utilization_sensors.observe(
            utilization,
            &[
                KeyValue::new("hw.id", sensor_name.clone()),
                KeyValue::new("hw.type", "power_supply"),
                KeyValue::new("hw.model", power_supply.model.clone()),
                KeyValue::new("hw.serial", power_supply.serial_number.clone()),
                KeyValue::new("hw.host.id", machine_id.clone()),
                KeyValue::new("hw.state", sensor_state.clone()),
                KeyValue::new("hw.health", sensor_health.clone()),
            ],
        );
    }
    let firmware_sensors = meter
        .u64_observable_gauge("firmware.version")
        .with_description("Firmware versions for components on this system")
        .init();
    for firmware in health.firmware.iter() {
        if firmware.version.is_none() {
            continue;
        }
        let sensor_name = firmware.id.clone().as_str().replace(" ", "_");
        let sensor_value = firmware.version.clone().unwrap();
        firmware_sensors.observe(
            health.firmware.len() as u64,
            &[
                KeyValue::new("firmware.id", sensor_name.clone()),
                KeyValue::new("firmware.version", sensor_value.clone()),
                KeyValue::new("hw.type", "firmware"),
                KeyValue::new("hw.host.id", machine_id.clone()),
            ],
        )
    }
    let event_log_sensors = meter
        .u64_observable_gauge("events.log")
        .with_description("System Event Log for this system")
        .init();
    for log_entry in health.logs.iter() {
        let sensor_name = log_entry.id.clone().as_str().replace(" ", "_");
        event_log_sensors.observe(
            health.logs.len() as u64,
            &[
                KeyValue::new("sel.id", sensor_name.clone()),
                KeyValue::new("sel.timestamp", log_entry.created.clone()),
                KeyValue::new("sel.message", log_entry.message.clone()),
                KeyValue::new("hw.type", "sel"),
                KeyValue::new("hw.host.id", machine_id.clone()),
            ],
        )
    }

    Ok(())
}

/// get a single machine's health metrics and export it
pub async fn scrape_machine_health(
    provider: MeterProvider,
    endpoint: Endpoint,
    machine_id: String,
) -> Result<(), HealthError> {
    let health = tokio::task::spawn_blocking(move || -> Result<HardwareHealth, HealthError> {
        let pool = RedfishClientPool::builder().build()?;
        let redfish = pool.create_client(endpoint.clone())?;
        let health = get_metrics(redfish)?;
        Ok(health)
    })
    .await??;

    export_metrics(provider.clone(), health, machine_id).await
}
