/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{StreamExt, stream};
use health_report::{HealthAlertClassification, HealthProbeId};
use nv_redfish::ServiceRoot;
use nv_redfish::chassis::{Chassis, PowerSupply};
use nv_redfish::computer_system::{ComputerSystem, Drive, Memory, Processor, Storage};
use nv_redfish::resource::Health as BmcHealth;
use nv_redfish::sensor::SensorRef;
use nv_redfish_core::{Bmc, EntityTypeRef, ToSnakeCase};

use crate::api_client::{BmcAddr, BmcEndpoint, HealthReportSink};
use crate::collector::PeriodicCollector;
use crate::metrics::{CollectorRegistry, GaugeMetrics, GaugeReading, MetricLabel, sanitize_unit};
use crate::{HealthError, collector};

/// Configuration for health monitor
pub struct HealthMonitorConfig {
    pub report_sink: Option<Arc<dyn HealthReportSink>>,
    pub state_refresh_interval: Duration,
    pub sensor_fetch_concurrency: usize,
    pub collector_registry: Arc<CollectorRegistry>,
}

/// Health monitor for a single BMC endpoint
pub struct HealthMonitor<B: Bmc> {
    endpoint: Arc<BmcEndpoint>,
    bmc: Arc<B>,
    state: Option<HealthMonitorState<B>>,
    report_sink: Option<Arc<dyn HealthReportSink>>,
    state_refresh_interval: Duration,
    sensor_fetch_concurrency: usize,
    metrics: Arc<GaugeMetrics>,
}

impl<B: Bmc + 'static> PeriodicCollector<B> for HealthMonitor<B> {
    type Config = HealthMonitorConfig;

    fn new_runner(
        bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        let serial = endpoint
            .machine
            .as_ref()
            .and_then(|m| m.machine_serial.clone())
            .unwrap_or_default();
        let machine_id = endpoint
            .machine
            .as_ref()
            .map(|m| m.machine_id.to_string())
            .unwrap_or_default();
        let metrics = config.collector_registry.create_gauge_metrics(
            format!("health_gauge_{}", endpoint.addr.hash_key()),
            "BMC Sensor readings",
            vec![
                ("serial_number".to_string(), serial),
                ("machine_id".to_string(), machine_id),
                ("bmc_mac".to_string(), endpoint.addr.mac.clone()),
            ],
        )?;

        Ok(Self {
            bmc,
            endpoint,
            state: None,
            report_sink: config.report_sink,
            state_refresh_interval: config.state_refresh_interval,
            sensor_fetch_concurrency: config.sensor_fetch_concurrency,
            metrics,
        })
    }

    async fn run_iteration(&mut self) -> Result<collector::IterationResult, HealthError> {
        self.run_monitor_iteration().await
    }

    fn collector_type(&self) -> &'static str {
        "health_monitor"
    }
}

/// Monitored entity with its associated sensors
enum MonitoredEntity<B: Bmc> {
    Processor {
        entity: Arc<Processor<B>>,
        sensor: SensorRef<B>,
        system: Arc<ComputerSystem<B>>,
    },
    Memory {
        entity: Arc<Memory<B>>,
        sensor: SensorRef<B>,
        system: Arc<ComputerSystem<B>>,
    },
    Drive {
        entity: Arc<Drive<B>>,
        sensor: SensorRef<B>,
        system: Arc<ComputerSystem<B>>,
        storage: Arc<Storage<B>>,
    },
    PowerSupply {
        entity: Arc<PowerSupply<B>>,
        sensor: SensorRef<B>,
        chassis: Arc<Chassis<B>>,
    },
    Chassis {
        entity: Arc<Chassis<B>>,
        sensor: SensorRef<B>,
    },
}

#[derive(Debug, Clone, Copy)]
enum SensorHealth {
    Ok,
    Warning,
    Critical,
    SensorFailure,
}

impl SensorHealth {
    fn to_classification(self) -> &'static str {
        match self {
            Self::Ok => "SensorOk",
            Self::Warning => "SensorWarning",
            Self::Critical => "SensorCritical",
            Self::SensorFailure => "SensorFailure",
        }
    }
}

#[derive(Debug)]
struct SensorHealthData {
    entity_type: String,
    sensor_id: String,
    reading: f64,
    reading_type: String,
    unit: String,
    upper_critical: Option<f64>,
    lower_critical: Option<f64>,
    upper_caution: Option<f64>,
    lower_caution: Option<f64>,
    range_max: Option<f64>,
    range_min: Option<f64>,
    bmc_health: Option<BmcHealth>,
}

impl SensorHealthData {
    fn fmt_range(low: Option<f64>, high: Option<f64>) -> String {
        match (low, high) {
            (None, None) => "not set".to_string(),
            (Some(l), Some(h)) => format!("{:.1} to {:.1}", l, h),
            (Some(l), None) => format!("min {:.1}", l),
            (None, Some(h)) => format!("max {:.1}", h),
        }
    }

    fn classify(&self) -> SensorHealth {
        if let Some(max) = self.range_max
            && self.reading > max
            && self.range_max > self.range_min
        {
            return SensorHealth::SensorFailure;
        }

        if let Some(min) = self.range_min
            && self.reading < min
            && self.range_max > self.range_min
        {
            return SensorHealth::SensorFailure;
        }

        if let Some(upper_critical) = self.upper_critical
            && self.reading >= upper_critical
            && self.upper_critical > self.lower_critical
        {
            return SensorHealth::Critical;
        }

        if let Some(lower_critical) = self.lower_critical
            && self.reading <= lower_critical
            && self.upper_critical > self.lower_critical
        {
            return SensorHealth::Critical;
        }

        if let Some(upper_caution) = self.upper_caution
            && self.reading >= upper_caution
            && self.upper_caution > self.lower_caution
        {
            return SensorHealth::Warning;
        }
        if let Some(lower_caution) = self.lower_caution
            && self.reading <= lower_caution
            && self.upper_caution > self.lower_caution
        {
            return SensorHealth::Warning;
        }

        SensorHealth::Ok
    }

    fn to_health_result(&self, health: SensorHealth) -> SensorHealthResult {
        let probe_id = HealthProbeId::from_str("BMC_Sensor").expect("cannot fail");

        let bmc_reports_ok = matches!(self.bmc_health, Some(BmcHealth::Ok));

        match health {
            SensorHealth::Ok => SensorHealthResult::Success(health_report::HealthProbeSuccess {
                id: probe_id,
                target: Some(self.sensor_id.clone()),
            }),
            health => {
                if bmc_reports_ok {
                    tracing::warn!(
                        sensor_id = %self.sensor_id,
                        entity_type = %self.entity_type,
                        reading = self.reading,
                        unit = %self.unit,
                        reading_type = %self.reading_type,
                        valid_range = %Self::fmt_range(self.range_min, self.range_max),
                        caution_range = %Self::fmt_range(self.lower_caution, self.upper_caution),
                        critical_range = %Self::fmt_range(self.lower_critical, self.upper_critical),
                        calculated_status = ?health,
                        "Threshold check indicates issue but BMC reports sensor as OK - likely incorrect thresholds, reporting OK"
                    );
                    return SensorHealthResult::Success(health_report::HealthProbeSuccess {
                        id: probe_id,
                        target: Some(self.sensor_id.clone()),
                    });
                }

                let status = match health {
                    SensorHealth::Warning => "Warning",
                    SensorHealth::Critical => "Critical",
                    SensorHealth::SensorFailure => "Sensor Failure",
                    SensorHealth::Ok => "Ok",
                };

                let message = format!(
                    "{} '{}': {} - reading {:.2}{} ({}), valid range: {}, caution: {}, critical: {}",
                    self.entity_type,
                    self.sensor_id,
                    status,
                    self.reading,
                    self.unit,
                    self.reading_type,
                    Self::fmt_range(self.range_min, self.range_max),
                    Self::fmt_range(self.lower_caution, self.upper_caution),
                    Self::fmt_range(self.lower_critical, self.upper_critical),
                );
                let classifications = if let Ok(classification) = health.to_classification().parse()
                {
                    vec![classification, HealthAlertClassification::hardware()]
                } else {
                    vec![HealthAlertClassification::hardware()]
                };
                SensorHealthResult::Alert(health_report::HealthProbeAlert {
                    id: probe_id,
                    target: Some(self.sensor_id.clone()),
                    in_alert_since: None,
                    message,
                    tenant_message: None,
                    classifications,
                })
            }
        }
    }
}

enum SensorHealthResult {
    Success(health_report::HealthProbeSuccess),
    Alert(health_report::HealthProbeAlert),
}

/// Trait for entities that can record sensor metrics
trait SensorRecordable<B: Bmc> {
    fn metric_prefix(&self) -> &'static str;
    fn sensor(&self) -> &SensorRef<B>;
    fn base_attributes(&self) -> Vec<MetricLabel>;
    fn entity_specific_attributes(&self) -> Vec<MetricLabel>;
    fn record_entity_metrics(&self, gauge: &GaugeMetrics, attributes: Vec<MetricLabel>);
}

impl<B: Bmc> SensorRecordable<B> for MonitoredEntity<B> {
    fn metric_prefix(&self) -> &'static str {
        "hw_sensor"
    }

    fn sensor(&self) -> &SensorRef<B> {
        match self {
            MonitoredEntity::Processor { sensor, .. }
            | MonitoredEntity::Memory { sensor, .. }
            | MonitoredEntity::Drive { sensor, .. }
            | MonitoredEntity::PowerSupply { sensor, .. }
            | MonitoredEntity::Chassis { sensor, .. } => sensor,
        }
    }

    fn base_attributes(&self) -> Vec<MetricLabel> {
        match self {
            MonitoredEntity::Processor { entity, system, .. } => vec![
                ("processor_id".to_string(), entity.raw().base.id.clone()),
                ("system_id".to_string(), system.raw().base.id.clone()),
            ],
            MonitoredEntity::Memory { entity, system, .. } => vec![
                ("memory_id".to_string(), entity.raw().base.id.clone()),
                ("system_id".to_string(), system.raw().base.id.clone()),
            ],
            MonitoredEntity::Drive {
                entity,
                system,
                storage,
                ..
            } => vec![
                ("drive_id".to_string(), entity.raw().base.id.clone()),
                ("storage_id".to_string(), storage.raw().base.id.clone()),
                ("system_id".to_string(), system.raw().base.id.clone()),
            ],
            MonitoredEntity::PowerSupply {
                entity, chassis, ..
            } => vec![
                ("powersupply_id".to_string(), entity.raw().base.id.clone()),
                ("chassis_id".to_string(), chassis.raw().base.id.clone()),
            ],
            MonitoredEntity::Chassis { entity, .. } => {
                vec![("chassis_id".to_string(), entity.raw().base.id.clone())]
            }
        }
    }

    fn entity_specific_attributes(&self) -> Vec<MetricLabel> {
        let mut attrs = Vec::new();

        match self {
            MonitoredEntity::Processor { entity, .. } => {
                if let Some(processor_type) = entity.raw().processor_type.flatten() {
                    attrs.push((
                        "processor_type".to_string(),
                        processor_type.to_snake_case().to_string(),
                    ));
                }
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push(("model".to_string(), model));
                }
            }
            MonitoredEntity::Memory { entity, .. } => {
                if let Some(device_type) = entity.raw().memory_device_type.flatten() {
                    attrs.push((
                        "device_type".to_string(),
                        device_type.to_snake_case().to_string(),
                    ));
                }
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push(("model".to_string(), model));
                }
            }
            MonitoredEntity::Drive { entity, .. } => {
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push(("model".to_string(), model));
                }
            }
            MonitoredEntity::PowerSupply { entity, .. } => {
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push(("model".to_string(), model));
                }
            }
            MonitoredEntity::Chassis { entity, .. } => {
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push(("model".to_string(), model));
                }
            }
        }

        attrs
    }

    fn record_entity_metrics(&self, metrics: &GaugeMetrics, attributes: Vec<MetricLabel>) {
        match self {
            MonitoredEntity::Drive { entity, .. } => {
                if let Some(lifetime) = entity.raw().predicted_media_life_left_percent.flatten() {
                    metrics.record(
                        GaugeReading::new(
                            entity.raw().id().to_string(),
                            "hw",
                            "drive_predicted_media_life_left",
                            "percentage",
                            lifetime,
                        )
                        .with_labels(attributes),
                    );
                }
            }
            MonitoredEntity::PowerSupply { entity, .. } => {
                if let Some(capacity) = entity.raw().power_capacity_watts.flatten() {
                    metrics.record(
                        GaugeReading::new(
                            entity.raw().id().to_string(),
                            "hw",
                            "powersupply_capacity",
                            "watts",
                            capacity,
                        )
                        .with_labels(attributes),
                    );
                }
            }
            _ => {}
        }
    }
}

trait ResultExt<T, E> {
    fn log_and_ok(self, context: &str, bmc_addr: &BmcAddr) -> Option<T>
    where
        E: std::fmt::Debug;
}

impl<T, E> ResultExt<T, E> for Result<T, E> {
    fn log_and_ok(self, context: &str, bmc_addr: &BmcAddr) -> Option<T>
    where
        E: std::fmt::Debug,
    {
        match self {
            Ok(val) => Some(val),
            Err(e) => {
                tracing::warn!(error = ?e, context, bmc_addr=?bmc_addr, "Operation failed");
                None
            }
        }
    }
}

struct HealthMonitorState<B: Bmc> {
    entities: Vec<MonitoredEntity<B>>,
    last_entity_refresh: Instant,
}

impl<B: Bmc + 'static> HealthMonitor<B> {
    async fn run_monitor_iteration(&mut self) -> Result<collector::IterationResult, HealthError> {
        let needs_entity_refresh = self
            .state
            .as_ref()
            .map(|s| s.last_entity_refresh.elapsed() > self.state_refresh_interval)
            .unwrap_or(true);

        let mut refresh_triggered = false;
        let mut entity_count = None;

        if needs_entity_refresh {
            tracing::info!("Refreshing entity state for BMC: {}", self.endpoint.addr.ip);
            match self.discover_entities().await {
                Ok(entities) => {
                    let count = entities.len();
                    tracing::info!("Entity refresh complete. Found {} entities", count);

                    self.state = Some(HealthMonitorState {
                        entities,
                        last_entity_refresh: Instant::now(),
                    });
                    refresh_triggered = true;
                }
                Err(e) => {
                    tracing::error!(error=?e, "Failed to discover entities");
                    if self.state.is_none() {
                        return Err(e);
                    }
                    // Keep using old state if discovery fails
                }
            }
        }

        if let Some(state) = &self.state {
            let (successes, alerts) = self.fetch_and_update_sensors(state).await?;
            entity_count = Some(successes.len() + alerts.len());

            if let (Some(machine), Some(report_sink)) = (&self.endpoint.machine, &self.report_sink)
            {
                let machine_id = machine.machine_id;

                let report = health_report::HealthReport {
                    source: "hardware-health".to_string(),
                    observed_at: Some(chrono::Utc::now()),
                    successes,
                    alerts,
                };

                tracing::info!(
                    machine_id = %machine_id,
                    success_count = report.successes.len(),
                    alert_count = report.alerts.len(),
                    "Sending hardware health report"
                );

                if let Err(e) = report_sink.submit_health_report(&machine_id, report).await {
                    tracing::warn!(
                        machine_id = %machine_id,
                        error = ?e,
                        "Failed to submit health report"
                    );
                }
            }
        }

        Ok(collector::IterationResult {
            refresh_triggered,
            entity_count,
        })
    }

    async fn discover_processor_entities(
        &self,
        system: Arc<ComputerSystem<B>>,
    ) -> Vec<MonitoredEntity<B>> {
        let processors = system
            .processors()
            .await
            .log_and_ok("Failed to get processors", &self.endpoint.addr)
            .unwrap_or_default();

        stream::iter(processors)
            .then(|processor| async move {
                let processor = Arc::new(processor);
                let env_sensors = processor
                    .environment_sensors()
                    .await
                    .log_and_ok(
                        "Failed to get processors enviroment sensors",
                        &self.endpoint.addr,
                    )
                    .unwrap_or_default();
                let metric_sensors = processor
                    .metrics_sensors()
                    .await
                    .log_and_ok(
                        "Failed to get processors metric sensors",
                        &self.endpoint.addr,
                    )
                    .unwrap_or_default();
                (processor, env_sensors.into_iter().chain(metric_sensors))
            })
            .flat_map(|(processor, sensors)| {
                let system = system.clone();
                stream::iter(sensors.map(move |sensor| MonitoredEntity::Processor {
                    entity: processor.clone(),
                    sensor,
                    system: system.clone(),
                }))
            })
            .collect()
            .await
    }

    async fn discover_memory_entities(
        &self,
        system: Arc<ComputerSystem<B>>,
    ) -> Vec<MonitoredEntity<B>> {
        let memory_modules = system
            .memory_modules()
            .await
            .log_and_ok("Failed to get memory modules", &self.endpoint.addr)
            .unwrap_or_default();

        stream::iter(memory_modules)
            .then(|memory| async move {
                let memory = Arc::new(memory);
                let env_sensors = memory
                    .environment_sensors()
                    .await
                    .log_and_ok(
                        "Failed to get memory enviroment sensors",
                        &self.endpoint.addr,
                    )
                    .unwrap_or_default();
                (memory, env_sensors.into_iter())
            })
            .flat_map(|(memory, sensors)| {
                let system = system.clone();
                stream::iter(sensors.map(move |sensor| MonitoredEntity::Memory {
                    entity: memory.clone(),
                    sensor,
                    system: system.clone(),
                }))
            })
            .collect()
            .await
    }

    async fn discover_drive_entities(
        &self,
        system: Arc<ComputerSystem<B>>,
    ) -> Vec<MonitoredEntity<B>> {
        let storage_list = system
            .storage_controllers()
            .await
            .log_and_ok("Failed to get storage", &self.endpoint.addr)
            .unwrap_or_default();

        stream::iter(storage_list)
            .then(|storage| async move {
                let storage = Arc::new(storage);
                let drives = storage
                    .drives()
                    .await
                    .log_and_ok("Failed to get drives", &self.endpoint.addr)
                    .unwrap_or_default();
                (storage, drives)
            })
            .flat_map(|(storage, drives)| {
                let system = system.clone();
                stream::iter(drives).then(move |drive| {
                    let storage = storage.clone();
                    let system = system.clone();
                    async move {
                        let drive = Arc::new(drive);
                        let env_sensors = drive
                            .environment_sensors()
                            .await
                            .log_and_ok(
                                "Failed to get drives enviroment sensors",
                                &self.endpoint.addr,
                            )
                            .unwrap_or_default();
                        (drive, storage, system, env_sensors.into_iter())
                    }
                })
            })
            .flat_map(|(drive, storage, system, sensors)| {
                stream::iter(sensors.map(move |sensor| MonitoredEntity::Drive {
                    entity: drive.clone(),
                    sensor,
                    system: system.clone(),
                    storage: storage.clone(),
                }))
            })
            .collect()
            .await
    }

    async fn discover_power_supply_entities(
        &self,
        chassis: Arc<Chassis<B>>,
    ) -> Vec<MonitoredEntity<B>> {
        let power_supplies = chassis
            .power_supplies()
            .await
            .log_and_ok("Failed to get power supplies", &self.endpoint.addr)
            .unwrap_or_default();

        stream::iter(power_supplies)
            .then(|ps| async move {
                let ps = Arc::new(ps);
                let metric_sensors = ps
                    .metrics_sensors()
                    .await
                    .log_and_ok(
                        "Failed to get power supplies metrics sensors",
                        &self.endpoint.addr,
                    )
                    .unwrap_or_default();
                (ps, metric_sensors.into_iter())
            })
            .flat_map(|(ps, sensors)| {
                let chassis = chassis.clone();
                stream::iter(sensors.map(move |sensor| MonitoredEntity::PowerSupply {
                    entity: ps.clone(),
                    sensor,
                    chassis: chassis.clone(),
                }))
            })
            .collect()
            .await
    }

    async fn discover_chassis_entities(&self, chassis: Arc<Chassis<B>>) -> Vec<MonitoredEntity<B>> {
        if let Ok(sensors) = chassis.sensors().await {
            sensors
                .into_iter()
                .map(move |sensor| MonitoredEntity::Chassis {
                    entity: chassis.clone(),
                    sensor,
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    async fn discover_entities(&self) -> Result<Vec<MonitoredEntity<B>>, HealthError> {
        let service_root = ServiceRoot::new(self.bmc.clone()).await?;
        let systems = service_root.systems().await?.members().await?;
        let chassis_list = service_root.chassis().await?.members().await?;

        let mut entities = Vec::new();
        let mut sensor_ids = HashSet::new();

        for system in systems {
            let system = Arc::new(system);

            for entity in self.discover_processor_entities(system.clone()).await {
                sensor_ids.insert(entity.sensor().odata_id().clone());
                entities.push(entity);
            }

            for entity in self.discover_memory_entities(system.clone()).await {
                sensor_ids.insert(entity.sensor().odata_id().clone());
                entities.push(entity);
            }

            for entity in self.discover_drive_entities(system).await {
                sensor_ids.insert(entity.sensor().odata_id().clone());
                entities.push(entity);
            }
        }

        for chassis in chassis_list {
            let chassis = Arc::new(chassis);

            for entity in self.discover_power_supply_entities(chassis.clone()).await {
                sensor_ids.insert(entity.sensor().odata_id().clone());
                entities.push(entity);
            }

            for entity in self.discover_chassis_entities(chassis).await {
                // Only add not discovered sensors
                if sensor_ids.insert(entity.sensor().odata_id().clone()) {
                    entities.push(entity);
                }
            }
        }

        let validation_results: Vec<_> = stream::iter(entities)
            .map(|entity| async move {
                match entity.sensor().fetch().await {
                    Ok(sensor_data) => {
                        let is_valid = matches!(
                            (
                                sensor_data.reading.flatten(),
                                sensor_data.reading_type.flatten(),
                                sensor_data.reading_units.as_ref().and_then(|u| u.as_ref()),
                            ),
                            (Some(_), Some(_), Some(units)) if !units.is_empty()
                        );
                        (entity, is_valid)
                    }
                    // We will treat http errors as transient, and assume sensor is valid
                    Err(e) => {
                        tracing::warn!(error = ?e, bmc_addr=?self.endpoint.addr,
                            "Could not get sensor data for validation, assuming sensor is valid");
                        (entity, true)
                    }
                }
            })
            .buffer_unordered(self.sensor_fetch_concurrency)
            .collect()
            .await;

        let mut validated_entities = Vec::new();
        for (entity, is_valid) in validation_results {
            if is_valid {
                validated_entities.push(entity);
            }
        }

        tracing::info!(
            bmc = self.endpoint.addr.mac,
            total_valid = validated_entities.len(),
            "Discovered hardware entities with sensors"
        );

        Ok(validated_entities)
    }

    async fn fetch_and_update_sensors(
        &self,
        state: &HealthMonitorState<B>,
    ) -> Result<
        (
            Vec<health_report::HealthProbeSuccess>,
            Vec<health_report::HealthProbeAlert>,
        ),
        HealthError,
    > {
        self.metrics.begin_update();
        let futures: Vec<_> = state
            .entities
            .iter()
            .map(|entity| self.update_sensor(entity))
            .collect();

        let health_data: Vec<_> = stream::iter(futures)
            .buffer_unordered(self.sensor_fetch_concurrency)
            .filter_map(|data| async move { data })
            .collect()
            .await;

        let mut successes = Vec::new();
        let mut alerts = Vec::new();

        for data in health_data {
            let health = data.classify();
            match data.to_health_result(health) {
                SensorHealthResult::Success(s) => successes.push(s),
                SensorHealthResult::Alert(a) => alerts.push(a),
            }
        }
        self.metrics.sweep_stale();

        Ok((successes, alerts))
    }

    async fn update_sensor(&self, entity: &MonitoredEntity<B>) -> Option<SensorHealthData> {
        let sensor = match entity.sensor().fetch().await {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!(
                    sensor_id = %entity.sensor().odata_id(),
                    entity_type = entity.metric_prefix(),
                    error = ?e,
                    "Failed to fetch sensor data"
                );
                return None;
            }
        };

        let Some((reading, reading_type, unit)) = sensor
            .reading
            .flatten()
            .zip(sensor.reading_type.flatten())
            .zip(sensor.reading_units.clone().flatten())
            .filter(|(_, reading)| !reading.is_empty())
            .map(|((r, rt), u)| (r, rt, u))
        else {
            tracing::warn!(
                sensor_id = %sensor.base.id,
                entity_type = entity.metric_prefix(),
                sensor = ?sensor,
                "Sensor missing required fields (reading, reading_type, or units)"
            );
            return None;
        };

        let attributes: Vec<_> =
            std::iter::once(("sensor_name".to_string(), sensor.base.id.clone()))
                .chain(entity.base_attributes())
                .chain(
                    sensor
                        .physical_context
                        .flatten()
                        .map(|phc| phc.to_snake_case())
                        .or({
                            Some(match entity {
                                MonitoredEntity::Processor { .. } => "cpu",
                                MonitoredEntity::Memory { .. } => "memory",
                                MonitoredEntity::Drive { .. } => "storage_device",
                                MonitoredEntity::PowerSupply { .. } => "power_supply",
                                MonitoredEntity::Chassis { .. } => "chassis",
                            })
                        })
                        .map(|phc| ("physical_context".to_string(), phc.to_string())),
                )
                .chain(entity.entity_specific_attributes())
                .collect();

        self.metrics.record(
            GaugeReading::new(
                sensor.id().to_string(),
                "hw_sensor",
                reading_type.to_snake_case(),
                sanitize_unit(&unit),
                reading,
            )
            .with_labels(attributes.clone()),
        );
        entity.record_entity_metrics(&self.metrics, attributes);

        let (upper_critical, lower_critical, upper_caution, lower_caution) =
            if let Some(thresholds) = &sensor.thresholds {
                (
                    thresholds
                        .upper_critical
                        .as_ref()
                        .and_then(|t| t.reading.flatten()),
                    thresholds
                        .lower_critical
                        .as_ref()
                        .and_then(|t| t.reading.flatten()),
                    thresholds
                        .upper_caution
                        .as_ref()
                        .and_then(|t| t.reading.flatten()),
                    thresholds
                        .lower_caution
                        .as_ref()
                        .and_then(|t| t.reading.flatten()),
                )
            } else {
                (None, None, None, None)
            };

        let bmc_health = sensor
            .status
            .as_ref()
            .and_then(|s| s.health.and_then(std::convert::identity));

        Some(SensorHealthData {
            entity_type: entity.metric_prefix().replace("hw_", ""),
            sensor_id: sensor.base.id.clone(),
            reading,
            reading_type: reading_type.to_snake_case().to_string(),
            unit,
            upper_critical,
            lower_critical,
            upper_caution,
            lower_caution,
            range_max: sensor.reading_range_max.flatten(),
            range_min: sensor.reading_range_min.flatten(),
            bmc_health,
        })
    }
}
