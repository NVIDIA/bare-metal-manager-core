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

use libredfish::model::power::{PowerSupply, Voltages};
use libredfish::model::sel::LogEntry;
use libredfish::model::thermal::{Fan, Temperature};
use libredfish::model::{power::Power, software_inventory::SoftwareInventory, thermal::Thermal};
use libredfish::{Endpoint, Redfish, RedfishClientPool};
use opentelemetry::metrics::{MeterProvider as _, Unit};
use opentelemetry::KeyValue;
use opentelemetry_api::metrics::Meter;
use opentelemetry_sdk::metrics::MeterProvider;
use sha2::{Digest, Sha256};

use crate::HealthError;

pub struct HardwareHealth {
    thermal: Thermal,
    power: Power,
    logs: Vec<LogEntry>,
    firmware: Vec<SoftwareInventory>,
}

#[derive(Clone, Debug, Hash)]
pub struct HealthHashData {
    pub firmware_digest: String,
    pub sel_count: usize,
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
    let mut firmware = Vec::with_capacity(components.len());
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

fn export_temperatures(
    meter: Meter,
    temperatures: Vec<Temperature>,
    machine_id: &str,
) -> Result<(), HealthError> {
    let temperature_sensors = meter
        .i64_observable_gauge("hw.temperature")
        .with_description("Temperature sensors for this hardware")
        .with_unit(Unit::new("Celsius"))
        .init();
    for temperature in temperatures.iter() {
        if temperature.reading_celsius.is_none() {
            // don't add the reading if there's no value provided
            continue;
        }
        let sensor_name = temperature.name.clone().as_str().replace(" ", "_");
        temperature_sensors.observe(
            temperature.reading_celsius.unwrap(),
            &[
                KeyValue::new("hw.id", sensor_name),
                KeyValue::new("hw.host.id", machine_id.to_string()),
            ],
        )
    }
    Ok(())
}

fn export_fans(meter: Meter, fans: Vec<Fan>, machine_id: &str) -> Result<(), HealthError> {
    let fan_sensors = meter
        .i64_observable_gauge("hw.fan.speed")
        .with_description("Fans for this hardware")
        .with_unit(Unit::new("rpm"))
        .init();
    for fan in fans.iter() {
        let sensor_name = fan.fan_name.clone().as_str().replace(" ", "_");
        fan_sensors.observe(
            fan.reading.clone(),
            &[
                KeyValue::new("hw.id", sensor_name),
                KeyValue::new("hw.host.id", machine_id.to_string()),
            ],
        )
    }
    Ok(())
}

fn export_voltages(
    meter: Meter,
    voltages: Vec<Voltages>,
    machine_id: &str,
) -> Result<(), HealthError> {
    let voltage_sensors = meter
        .f64_observable_gauge("hw.voltage")
        .with_description("Voltages for this hardware")
        .with_unit(Unit::new("V"))
        .init();
    for voltage in voltages.iter() {
        if voltage.reading_volts.is_none() {
            continue;
        }
        let sensor_name = voltage.name.clone().as_str().replace(" ", "_");
        voltage_sensors.observe(
            voltage.reading_volts.unwrap(),
            &[
                KeyValue::new("hw.id", sensor_name),
                KeyValue::new("hw.host.id", machine_id.to_string()),
            ],
        )
    }
    Ok(())
}

fn export_power_supplies(
    meter: Meter,
    power_supplies: Vec<PowerSupply>,
    machine_id: &str,
) -> Result<(), HealthError> {
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
    for power_supply in power_supplies.iter() {
        let sensor_name = power_supply.name.clone().as_str().replace(" ", "_");
        power_supplies_output_watts_sensors.observe(
            power_supply.last_power_output_watts.clone(),
            &[
                KeyValue::new("hw.id", sensor_name.clone()),
                KeyValue::new("hw.host.id", machine_id.to_string()),
            ],
        );
        power_supplies_input_voltage_sensors.observe(
            power_supply.line_input_voltage.clone(),
            &[
                KeyValue::new("hw.id", sensor_name.clone()),
                KeyValue::new("hw.host.id", machine_id.to_string()),
            ],
        );
        let mut utilization: f64 = 0.0;
        if power_supply.power_capacity_watts > 0 {
            utilization = (power_supply.last_power_output_watts.clone()
                / power_supply.power_capacity_watts.clone() as f64)
                * 100.0;
        }
        power_supplies_utilization_sensors.observe(
            utilization,
            &[
                KeyValue::new("hw.id", sensor_name.clone()),
                KeyValue::new("hw.host.id", machine_id.to_string()),
            ],
        );
    }
    Ok(())
}

fn export_firmware_versions(
    meter: Meter,
    firmwares: Vec<SoftwareInventory>,
    machine_id: &str,
) -> Result<(), HealthError> {
    let firmware_sensors = meter
        .u64_observable_gauge("firmware.version")
        .with_description("Firmware versions for components on this system")
        .init();
    for firmware in firmwares.iter() {
        if firmware.version.is_none() {
            continue;
        }
        let sensor_name = firmware.id.clone().as_str().replace(" ", "_");
        let sensor_value = firmware.version.clone().unwrap();
        firmware_sensors.observe(
            firmwares.len() as u64,
            &[
                KeyValue::new("firmware.id", sensor_name.clone()),
                KeyValue::new("firmware.version", sensor_value.clone()),
                KeyValue::new("hw.type", "firmware"),
                KeyValue::new("hw.host.id", machine_id.to_string()),
            ],
        )
    }
    Ok(())
}

fn export_system_event_log(_logs: Vec<LogEntry>, _machine_id: &str) -> Result<(), HealthError> {
    // TODO: export logs to loki
    Ok(())
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
    last_firmware_digest: String,
    last_sel_count: usize,
    machine_id: &str,
) -> Result<(String, usize), HealthError> {
    // build or get meter for each machine
    let meter = provider.meter(machine_id.to_string());

    export_temperatures(meter.clone(), health.thermal.temperatures, machine_id)?;
    export_fans(meter.clone(), health.thermal.fans, machine_id)?;
    export_voltages(meter.clone(), health.power.voltages, machine_id)?;
    export_power_supplies(meter.clone(), health.power.power_supplies, machine_id)?;

    // only send firmware data if something changed from the last update
    let mut hasher = Sha256::new();
    for firmware in health.firmware.iter() {
        if firmware.version.is_none() {
            continue;
        }
        hasher.update(firmware.id.clone());
        hasher.update(firmware.version.clone().unwrap());
    }
    let firmware_digest_bytes = hasher.finalize();
    let mut firmware_digest = format!("{:x?}", firmware_digest_bytes);
    let mut sel_count = health.logs.len();

    if firmware_digest != last_firmware_digest {
        export_firmware_versions(meter.clone(), health.firmware.clone(), machine_id)?;
    } else {
        firmware_digest.clear();
    }

    if sel_count != last_sel_count {
        export_system_event_log(health.logs.clone(), machine_id)?;
    } else {
        sel_count = 0;
    }
    Ok((firmware_digest, sel_count))
}

/// get a single machine's health metrics and export it
pub async fn scrape_machine_health(
    provider: MeterProvider,
    endpoint: Endpoint,
    machine_id: &str,
    last_firmware_digest: String,
    last_sel_count: usize,
) -> Result<(String, usize), HealthError> {
    let health = tokio::task::spawn_blocking(move || -> Result<HardwareHealth, HealthError> {
        let pool = RedfishClientPool::builder().build()?;
        let redfish = pool.create_client(endpoint.clone())?;
        let health = get_metrics(redfish)?;
        Ok(health)
    })
    .await??;

    export_metrics(
        provider.clone(),
        health,
        last_firmware_digest,
        last_sel_count,
        machine_id,
    )
    .await
}
