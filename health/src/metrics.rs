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

use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use health_report::{
    HealthAlertClassification, HealthProbeAlert, HealthProbeSuccess, HealthReport,
};
use libredfish::model::power::{PowerSupply, Voltages};
use libredfish::model::sel::LogEntry;
use libredfish::model::sensor::{GPUSensors, ReadingType};
use libredfish::model::thermal::{Fan, Temperature};
use libredfish::model::{power::Power, software_inventory::SoftwareInventory, thermal::Thermal};
use libredfish::model::{ResourceHealth, ResourceState};
use libredfish::{PowerState, Redfish, RedfishClientPool, RedfishError};
use opentelemetry::logs::{AnyValue, LogRecord, Logger};
use opentelemetry::metrics::Meter;
use opentelemetry::metrics::{MeterProvider as _, Unit};
use opentelemetry::Key;
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::MeterProvider;
use report::HealthCheck;
use rpc::forge_tls_client::ForgeClientT;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use std::sync::Arc;
use std::time::SystemTime;

use crate::HealthError;

pub struct HardwareHealth {
    thermal: Thermal,
    power: Power,
    power_state: PowerState,
    gpu_sensors: Option<Vec<GPUSensors>>,
    logs: Vec<LogEntry>,
    firmware: Vec<SoftwareInventory>,
}

pub struct DpuHealth {
    thermal: Option<Thermal>,
    reachable: bool,
    attempted: bool,
}

#[derive(Clone, Debug, Hash)]
pub struct HealthHashData {
    pub description: String,
    pub firmware_digest: String,
    pub sel_count: usize,
    pub last_polled_ts: i64, // last time we polled the bmc (every 30 minutes at least)
    pub last_recorded_ts: i64, // last time we pushed firmware versions and sel to loki, even if nothing changed (every 24 hours)
    pub last_host_error_ts: i64, // last time we encountered an error scraping metrics from host bmc
    pub last_dpu_error_ts: i64, // last time we encountered an error scraping the dpu bmc metrics
    pub host_error_count: usize,
    pub dpu_error_count: usize,
    pub host: String,
    pub dpu: String,
    pub port: u16,
    pub dpu_port: u16,
    pub user: String,
    pub dpu_user: String,
    pub password: String,
    pub dpu_password: String,
}

/// get all the metrics we want from the bmc
// none of these are a patch/post and will not affect the bmc doing other patch/post ops
pub async fn get_metrics(
    redfish: Box<dyn Redfish>,
    last_polled_ts: i64,
) -> Result<HardwareHealth, HealthError> {
    // get the temperature, fans, voltages, power supplies, gpu sensors data from the bmc
    let thermal = redfish.get_thermal_metrics().await?;
    let power = redfish.get_power_metrics().await?;
    let power_state = redfish.get_power_state().await?;
    let gpu_sensors = match redfish.get_gpu_sensors().await {
        Ok(v) => Some(v),
        Err(RedfishError::NotSupported(_)) => None,
        Err(e) => return Err(e.into()),
    };

    // get the system/hardware event log
    let mut logs: Vec<LogEntry> = Vec::new();
    let mut firmware: Vec<SoftwareInventory> = Vec::new();
    let now: DateTime<Utc> = Utc::now();
    // poll every 30 minutes for firmware versions and sel logs
    if (now.timestamp() - last_polled_ts) > (30 * 60) {
        logs = redfish.get_system_event_log().await?;
        // get system firmware components versions, such as uefi, bmc, sbios, me, etc
        let components = redfish.get_software_inventories().await?;
        for component in components.iter() {
            let version = redfish.get_firmware(component.as_str()).await?;
            firmware.push(version);
        }
    }
    let health = HardwareHealth {
        thermal,
        power,
        power_state,
        gpu_sensors,
        logs,
        firmware,
    };
    Ok(health)
}

pub async fn get_dpu_metrics(redfish: Box<dyn Redfish>) -> Result<Thermal, HealthError> {
    let dpu_thermal = redfish.get_thermal_metrics().await?;
    Ok(dpu_thermal)
}

fn export_temperatures(
    meter: Meter,
    temperatures: Vec<Temperature>,
    machine_id: &str,
    is_dpu: bool,
) -> Result<(), HealthError> {
    let gauge_name = if is_dpu {
        "hw.dpu.temperature".to_string()
    } else {
        "hw.temperature".to_string()
    };
    let temperature_sensors = meter
        .i64_observable_gauge(gauge_name)
        .with_description("Temperature sensors for this hardware")
        .with_unit(Unit::new("Celsius"))
        .init();
    for temperature in temperatures.iter() {
        if temperature.reading_celsius.is_none() {
            // don't add the reading if there's no value provided
            continue;
        }
        let sensor_name = temperature.name.clone().as_str().replace(' ', "_");
        temperature_sensors.observe(
            temperature.reading_celsius.unwrap() as i64,
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
        let sensor_name = match &fan.fan_name {
            Some(fan_name) => fan_name.replace(' ', "_"),
            None => continue,
        };
        fan_sensors.observe(
            fan.reading,
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
    voltages: Option<Vec<Voltages>>,
    machine_id: &str,
) -> Result<(), HealthError> {
    if voltages.is_none() {
        return Ok(());
    }
    let voltage_sensors = meter
        .f64_observable_gauge("hw.voltage")
        .with_description("Voltages for this hardware")
        .with_unit(Unit::new("V"))
        .init();
    for voltage in voltages.unwrap().iter() {
        if voltage.reading_volts.is_none() {
            continue;
        }
        let sensor_name = voltage.name.clone().as_str().replace(' ', "_");
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
    power_supplies: Option<Vec<PowerSupply>>,
    power_state: PowerState,
    machine_id: &str,
) -> Result<(), HealthError> {
    if power_supplies.is_none() {
        return Ok(());
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
    let power_state_sensor = meter
        .i64_observable_up_down_counter("hw.power_state")
        .with_description("Power state")
        .init();
    let power_state_value: i64 = match power_state {
        PowerState::On => 1,
        _ => 0,
    };
    power_state_sensor.observe(
        power_state_value,
        &[
            KeyValue::new("hw.id", "power_state".to_string()),
            KeyValue::new("hw.host.id", machine_id.to_string()),
        ],
    );
    for power_supply in power_supplies.unwrap().iter() {
        if power_supply.last_power_output_watts.is_none()
            || power_supply.power_capacity_watts.is_none()
        {
            continue;
        }
        let last_power_output_watts = power_supply.last_power_output_watts.unwrap();
        let power_capacity_watts = power_supply.power_capacity_watts.unwrap();
        let sensor_name = power_supply.name.clone().as_str().replace(' ', "_");
        power_supplies_output_watts_sensors.observe(
            last_power_output_watts,
            &[
                KeyValue::new("hw.id", sensor_name.clone()),
                KeyValue::new("hw.host.id", machine_id.to_string()),
            ],
        );
        if let Some(line_input_voltage) = power_supply.line_input_voltage {
            power_supplies_input_voltage_sensors.observe(
                line_input_voltage,
                &[
                    KeyValue::new("hw.id", sensor_name.clone()),
                    KeyValue::new("hw.host.id", machine_id.to_string()),
                ],
            );
        }
        let mut utilization: f64 = 0.0;
        if power_capacity_watts > 0 {
            utilization = (last_power_output_watts / power_capacity_watts as f64) * 100.0;
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

fn export_gpu_sensors(
    meter: Meter,
    gpu_sensors: Vec<GPUSensors>,
    machine_id: &str,
) -> Result<(), HealthError> {
    let [mut voltage, mut temp, mut power, mut energy] = [
        ("voltage", "V"),
        ("temperature", "Celsius"),
        ("power", "Watts"),
        ("energy", "Joules"),
    ]
    .map(|(name, unit)| {
        meter
            .f64_observable_gauge(format!("hw.gpu.{name}"))
            .with_description(format!("GPU {name} readings"))
            .with_unit(Unit::new(unit))
            .init()
    });
    for gpu in gpu_sensors.iter() {
        for sensor in &gpu.sensors {
            let (Some(reading), Some(reading_type), Some(name)) = (
                sensor.reading,
                sensor.reading_type,
                sensor.name.as_ref().or(sensor.id.as_ref()),
            ) else {
                continue;
            };
            let name = name.as_str().replace(' ', "_");
            match reading_type {
                ReadingType::Temperature => &mut temp,
                ReadingType::Power => &mut power,
                ReadingType::EnergyJoules => &mut energy,
                ReadingType::Voltage => &mut voltage,
                _ => continue,
            }
            .observe(
                reading,
                &[
                    KeyValue::new("hw.id", name),
                    KeyValue::new("hw.gpu.id", gpu.gpu_id.clone()),
                    KeyValue::new("hw.host.id", machine_id.to_string()),
                ],
            );
        }
    }

    Ok(())
}

fn export_otel_logs(
    logger: Arc<Box<dyn Logger + Send + Sync>>,
    firmwares: Vec<SoftwareInventory>,
    logs: Vec<LogEntry>,
    machine_id: &str,
    description: &str,
) -> Result<(), HealthError> {
    let dt = SystemTime::now();
    let mut log_hdr = LogRecord::builder().build();
    log_hdr.timestamp = Some(dt);
    log_hdr.observed_timestamp = dt;
    log_hdr.body = Some(AnyValue::from(description.to_string()));
    log_hdr.attributes = Some(vec![
        (
            Key::from("machine_id".to_string()),
            AnyValue::from(machine_id.to_string()),
        ),
        (
            Key::from("type".to_string()),
            AnyValue::from("description".to_string()),
        ),
    ]);

    logger.emit(log_hdr);

    for firmware in firmwares.iter() {
        if firmware.version.is_none() {
            continue;
        }
        let mut log_record = LogRecord::builder().build();
        log_record.timestamp = Some(dt);
        log_record.observed_timestamp = dt;
        log_record.body = Some(AnyValue::from(
            format!(
                "Component: {}, Version: {}\n",
                firmware.id,
                firmware.version.clone().unwrap()
            )
            .to_string(),
        ));
        log_record.attributes = Some(vec![
            (
                Key::from("machine_id".to_string()),
                AnyValue::from(machine_id.to_string()),
            ),
            (
                Key::from("type".to_string()),
                AnyValue::from("firmware".to_string()),
            ),
        ]);
        logger.emit(log_record);
    }

    for sel_entry in logs.iter() {
        let mut log_record = LogRecord::builder().build();
        log_record.timestamp = Some(dt);
        log_record.observed_timestamp = dt;
        log_record.body = Some(AnyValue::from(
            format!(
                "ID: {}, Created: {}, Severity: {}, Message: {}\n",
                sel_entry.id, sel_entry.created, sel_entry.severity, sel_entry.message
            )
            .to_string(),
        ));
        log_record.attributes = Some(vec![
            (
                Key::from("machine_id".to_string()),
                AnyValue::from(machine_id.to_string()),
            ),
            (
                Key::from("type".to_string()),
                AnyValue::from("sel".to_string()),
            ),
        ]);
        logger.emit(log_record);
    }
    Ok(())
}

// the attribute keys and values are specified in
// https://opentelemetry.io/docs/specs/otel/metrics/semantic_conventions/hardware-metrics/
// in the hw.temperature section.
// hw.id, hw.type are required.
// hw.host.id and hw.sensor_location are recommended
// hw.state and hw.health are custom attributes based on redfish schema
#[allow(clippy::too_many_arguments)]
pub async fn export_metrics(
    provider: MeterProvider,
    logger: Arc<Box<dyn Logger + Send + Sync>>,
    health: HardwareHealth,
    dpu_health: DpuHealth,
    last_firmware_digest: String,
    last_sel_count: usize,
    last_recorded_ts: i64,
    description: String,
    machine_id: &str,
) -> Result<(String, usize, i64, i64, bool, bool), HealthError> {
    // build or get meter for each machine
    let meter = provider.meter(machine_id.to_string());
    let now: DateTime<Utc> = Utc::now();
    let mut polled_ts: i64 = 0;
    let mut recorded_ts: i64 = 0;
    export_temperatures(
        meter.clone(),
        health.thermal.temperatures,
        machine_id,
        false,
    )?;
    export_fans(meter.clone(), health.thermal.fans, machine_id)?;
    export_voltages(meter.clone(), health.power.voltages, machine_id)?;
    export_power_supplies(
        meter.clone(),
        health.power.power_supplies,
        health.power_state,
        machine_id,
    )?;

    if let Some(thermal) = dpu_health.thermal {
        export_temperatures(meter.clone(), thermal.temperatures, machine_id, true)?;
    }
    if let Some(gpu_sensors) = health.gpu_sensors {
        export_gpu_sensors(meter.clone(), gpu_sensors, machine_id)?;
    }

    let mut firmware_digest = String::new();
    let mut sel_count = health.logs.len();
    if !health.firmware.is_empty() {
        polled_ts = now.timestamp();
        let mut hasher = Sha256::new();
        for firmware in health.firmware.iter() {
            if firmware.version.is_none() {
                continue;
            }
            hasher.update(firmware.id.clone());
            hasher.update(firmware.version.clone().unwrap());
        }
        let firmware_digest_bytes = hasher.finalize();
        firmware_digest = general_purpose::STANDARD_NO_PAD.encode(firmware_digest_bytes);
    }
    if (!firmware_digest.is_empty() && firmware_digest != last_firmware_digest)
        || (sel_count > 0 && sel_count != last_sel_count)
        || (now.timestamp() - last_recorded_ts) > (24 * 60 * 60)
    {
        export_otel_logs(
            logger,
            health.firmware.clone(),
            health.logs.clone(),
            machine_id,
            &description,
        )?;
        recorded_ts = polled_ts;
    } else {
        firmware_digest.clear();
        sel_count = 0;
    }

    Ok((
        firmware_digest,
        sel_count,
        polled_ts,
        recorded_ts,
        dpu_health.reachable,
        dpu_health.attempted,
    ))
}

/// get a single machine's health metrics and export it
pub async fn scrape_machine_health(
    client: &mut ForgeClientT,
    provider: MeterProvider,
    logger: Arc<Box<dyn Logger + Send + Sync>>,
    machine_id: &str,
    health_hash: &HealthHashData,
) -> Result<(String, usize, i64, i64, bool, bool), HealthError> {
    let pool = RedfishClientPool::builder().build()?;
    let endpoint = libredfish::Endpoint {
        host: health_hash.host.clone(),
        port: match health_hash.port {
            0 => None,
            x => Some(x),
        },
        user: Some(health_hash.user.clone()),
        password: Some(health_hash.password.clone()),
    };
    let redfish = pool.create_client(endpoint.clone()).await?;
    let health = get_metrics(redfish, health_hash.last_polled_ts).await?;

    // try dpu metrics
    let mut scrape_dpu = true;
    if health_hash.dpu_error_count > 0 {
        let now: DateTime<Utc> = Utc::now();
        if health_hash.dpu_error_count < 24 {
            // try every 30 minutes for 12 hours
            if (now.timestamp() - health_hash.last_dpu_error_ts) < (30 * 60) {
                scrape_dpu = false;
            }
        } else if health_hash.dpu_error_count < 36 {
            // try every 60 minutes for next 12 hours
            if (now.timestamp() - health_hash.last_dpu_error_ts) < (60 * 60) {
                scrape_dpu = false;
            }
        } else {
            // try once a day
            if (now.timestamp() - health_hash.last_dpu_error_ts) < (24 * 60 * 60) {
                scrape_dpu = false;
            }
        }
    }
    let dpu_health = if scrape_dpu {
        let dpu_endpoint = libredfish::Endpoint {
            host: health_hash.dpu.clone(),
            port: match health_hash.dpu_port {
                0 => None,
                x => Some(x),
            },
            user: Some(health_hash.dpu_user.clone()),
            password: Some(health_hash.dpu_password.clone()),
        };

        let dpu_redfish = pool.create_client(dpu_endpoint.clone()).await?;
        match get_dpu_metrics(dpu_redfish).await {
            Ok(x) => DpuHealth {
                thermal: Some(x),
                reachable: true,
                attempted: true,
            },
            Err(_e) => DpuHealth {
                thermal: None,
                reachable: false,
                attempted: true, // increase dpu error count in hash and backoff
            },
        }
    } else {
        DpuHealth {
            thermal: None,
            reachable: false,
            attempted: false,
        }
    };

    export_health_report(client, &health, machine_id).await?;

    export_metrics(
        provider.clone(),
        logger,
        health,
        dpu_health,
        health_hash.firmware_digest.clone(),
        health_hash.sel_count,
        health_hash.last_recorded_ts,
        health_hash.description.clone(),
        machine_id,
    )
    .await
}

async fn export_health_report(
    client: &mut ForgeClientT,
    health: &HardwareHealth,
    machine_id: &str,
) -> Result<(), HealthError> {
    let mut report = HealthReport {
        source: "hardware-health".to_string(),
        observed_at: None,
        successes: vec![],
        alerts: vec![],
    };

    report_resources(
        &mut report,
        health
            .thermal
            .fans
            .iter()
            .map(|r| (r.name.as_ref().or(r.fan_name.as_ref()), r.status.health)),
        HealthCheck::FanSpeed,
    );

    report_resources(
        &mut report,
        health
            .thermal
            .temperatures
            .iter()
            .map(|r| (Some(&r.name), r.status.health)),
        HealthCheck::Temperature,
    );

    if let Some(voltages) = &health.power.voltages {
        report_resources(
            &mut report,
            voltages.iter().map(|r| (Some(&r.name), r.status.health)),
            HealthCheck::Voltage,
        );
    }

    if let Some(power_supplies) = &health.power.power_supplies {
        let health_check = HealthCheck::PowerSupply;
        let id = health_check.to_stable_id();
        for power_supply in power_supplies {
            let Some(state) = power_supply.status.state else {
                continue;
            };
            let target = Some(power_supply.name.clone());
            match state {
                ResourceState::Enabled => report.successes.push(HealthProbeSuccess {
                    id: id.clone(),
                    target,
                }),
                state => report.alerts.push(HealthProbeAlert {
                    id: id.clone(),
                    target,
                    in_alert_since: None,
                    message: format!("{}: {}", state, health_check.get_message()),
                    tenant_message: None,
                    classifications: vec![HealthAlertClassification::from_str("Hardware").unwrap()],
                }),
            }
        }
    }

    let request = tonic::Request::new(rpc::forge::HardwareHealthReport {
        machine_id: Some(rpc::MachineId {
            id: machine_id.to_string(),
        }),
        report: Some(report.into()),
    });

    client
        .record_hardware_health_report(request)
        .await
        .map_err(HealthError::ApiInvocationError)?;

    Ok(())
}

fn report_resources<'a>(
    report: &mut HealthReport,
    resources: impl Iterator<Item = (Option<&'a String>, Option<ResourceHealth>)>,
    health_check: HealthCheck,
) {
    for resource in resources {
        let classification = match resource.1 {
            Some(ResourceHealth::Warning) => Some("Warning"),
            Some(ResourceHealth::Critical) => Some("Critical"),
            _ => None,
        };
        if let Some(c) = classification {
            report.alerts.push(HealthProbeAlert {
                id: health_check.to_stable_id(),
                in_alert_since: None,
                message: health_check.get_message().to_string(),
                tenant_message: None,
                classifications: vec![
                    HealthAlertClassification::from_str("Hardware").unwrap(),
                    HealthAlertClassification::from_str(c).unwrap(),
                ],
                target: resource.0.cloned(),
            })
        } else {
            report.successes.push(HealthProbeSuccess {
                id: health_check.to_stable_id(),
                target: resource.0.cloned(),
            });
        }
    }
}

mod report {
    use std::str::FromStr;

    use health_report::HealthProbeId;
    use serde::Serialize;

    // The things we check on to ensure a machine is in good health
    #[derive(Debug, Serialize, PartialEq)]
    pub enum HealthCheck {
        Voltage,
        Temperature,
        FanSpeed,
        PowerSupply,
    }

    impl HealthCheck {
        pub fn to_stable_id(&self) -> HealthProbeId {
            HealthProbeId::from_str(match self {
                Self::Voltage => "Voltage",
                Self::Temperature => "Temperature",
                Self::FanSpeed => "FanSpeed",
                Self::PowerSupply => "PowerSupply",
            })
            .unwrap()
        }

        pub fn get_message(&self) -> &'static str {
            match self {
                Self::Voltage => "Voltage out of bounds",
                Self::Temperature => "Temperature out of bounds",
                Self::FanSpeed => "Fan speed out of bounds",
                Self::PowerSupply => "Power supply issue",
            }
        }
    }
}
