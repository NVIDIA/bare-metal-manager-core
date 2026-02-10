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
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::{StreamExt, stream};
use nv_redfish::ServiceRoot;
use nv_redfish::chassis::{Chassis, PowerSupply};
use nv_redfish::computer_system::{ComputerSystem, Drive, Memory, Processor, Storage};
use nv_redfish::sensor::SensorRef;
use nv_redfish_core::{Bmc, EntityTypeRef, ToSnakeCase};

use crate::HealthError;
use crate::collectors::{IterationResult, PeriodicCollector};
use crate::endpoint::{BmcAddr, BmcEndpoint, EndpointMetadata};
use crate::metrics::{MetricLabel, sanitize_unit};
use crate::sink::{CollectorEvent, DataSink, EventContext, HealthOverride, MetricSample};

mod monitor_health;

use monitor_health::{SensorHealthData, SensorHealthResult};

/// Configuration for sensor collector
pub struct SensorCollectorConfig {
    pub data_sink: Option<Arc<dyn DataSink>>,
    pub state_refresh_interval: Duration,
    pub sensor_fetch_concurrency: usize,
    pub include_sensor_thresholds: bool,
}

/// Sensor collector for a single BMC endpoint
pub struct SensorCollector<B: Bmc> {
    endpoint: Arc<BmcEndpoint>,
    bmc: Arc<B>,
    event_context: EventContext,
    state: Option<SensorCollectorState<B>>,
    data_sink: Option<Arc<dyn DataSink>>,
    state_refresh_interval: Duration,
    sensor_fetch_concurrency: usize,
    include_sensor_thresholds: bool,
}

impl<B: Bmc + 'static> PeriodicCollector<B> for SensorCollector<B> {
    type Config = SensorCollectorConfig;

    fn new_runner(
        bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        let event_context = EventContext::from_endpoint(endpoint.as_ref(), "sensor_collector");
        Ok(Self {
            bmc,
            endpoint,
            event_context,
            state: None,
            data_sink: config.data_sink,
            state_refresh_interval: config.state_refresh_interval,
            sensor_fetch_concurrency: config.sensor_fetch_concurrency,
            include_sensor_thresholds: config.include_sensor_thresholds,
        })
    }

    async fn run_iteration(&mut self) -> Result<IterationResult, HealthError> {
        self.run_monitor_iteration().await
    }

    fn collector_type(&self) -> &'static str {
        "sensor_collector"
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

/// Trait for entities that can record sensor metrics
trait SensorRecordable<B: Bmc> {
    fn metric_prefix(&self) -> &'static str;
    fn sensor(&self) -> &SensorRef<B>;
    fn base_attributes(&self) -> Vec<MetricLabel>;
    fn entity_specific_attributes(&self) -> Vec<MetricLabel>;
    fn entity_metrics(&self, attributes: &[MetricLabel]) -> Vec<MetricSample>;
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
                (Cow::Borrowed("processor_id"), entity.raw().base.id.clone()),
                (Cow::Borrowed("system_id"), system.raw().base.id.clone()),
            ],
            MonitoredEntity::Memory { entity, system, .. } => vec![
                (Cow::Borrowed("memory_id"), entity.raw().base.id.clone()),
                (Cow::Borrowed("system_id"), system.raw().base.id.clone()),
            ],
            MonitoredEntity::Drive {
                entity,
                system,
                storage,
                ..
            } => vec![
                (Cow::Borrowed("drive_id"), entity.raw().base.id.clone()),
                (Cow::Borrowed("storage_id"), storage.raw().base.id.clone()),
                (Cow::Borrowed("system_id"), system.raw().base.id.clone()),
            ],
            MonitoredEntity::PowerSupply {
                entity, chassis, ..
            } => vec![
                (
                    Cow::Borrowed("powersupply_id"),
                    entity.raw().base.id.clone(),
                ),
                (Cow::Borrowed("chassis_id"), chassis.raw().base.id.clone()),
            ],
            MonitoredEntity::Chassis { entity, .. } => {
                vec![(Cow::Borrowed("chassis_id"), entity.raw().base.id.clone())]
            }
        }
    }

    fn entity_specific_attributes(&self) -> Vec<MetricLabel> {
        let mut attrs = Vec::new();

        match self {
            MonitoredEntity::Processor { entity, .. } => {
                if let Some(processor_type) = entity.raw().processor_type.flatten() {
                    attrs.push((
                        Cow::Borrowed("processor_type"),
                        processor_type.to_snake_case().to_string(),
                    ));
                }
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push((Cow::Borrowed("model"), model));
                }
            }
            MonitoredEntity::Memory { entity, .. } => {
                if let Some(device_type) = entity.raw().memory_device_type.flatten() {
                    attrs.push((
                        Cow::Borrowed("device_type"),
                        device_type.to_snake_case().to_string(),
                    ));
                }
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push((Cow::Borrowed("model"), model));
                }
            }
            MonitoredEntity::Drive { entity, .. } => {
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push((Cow::Borrowed("model"), model));
                }
            }
            MonitoredEntity::PowerSupply { entity, .. } => {
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push((Cow::Borrowed("model"), model));
                }
            }
            MonitoredEntity::Chassis { entity, .. } => {
                if let Some(model) = entity.raw().model.clone().flatten() {
                    attrs.push((Cow::Borrowed("model"), model));
                }
            }
        }

        attrs
    }

    fn entity_metrics(&self, attributes: &[MetricLabel]) -> Vec<MetricSample> {
        match self {
            MonitoredEntity::Drive { entity, .. } => {
                if let Some(lifetime) = entity.raw().predicted_media_life_left_percent.flatten() {
                    vec![MetricSample {
                        key: entity.raw().id().to_string(),
                        name: "hw".to_string(),
                        metric_type: "drive_predicted_media_life_left".to_string(),
                        unit: "percentage".to_string(),
                        value: lifetime,
                        labels: attributes.to_vec(),
                    }]
                } else {
                    Vec::new()
                }
            }
            MonitoredEntity::PowerSupply { entity, .. } => {
                if let Some(capacity) = entity.raw().power_capacity_watts.flatten() {
                    vec![MetricSample {
                        key: entity.raw().id().to_string(),
                        name: "hw".to_string(),
                        metric_type: "powersupply_capacity".to_string(),
                        unit: "watts".to_string(),
                        value: capacity,
                        labels: attributes.to_vec(),
                    }]
                } else {
                    Vec::new()
                }
            }
            _ => Vec::new(),
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

struct SensorCollectorState<B: Bmc> {
    entities: Vec<MonitoredEntity<B>>,
    last_entity_refresh: Instant,
}

impl<B: Bmc + 'static> SensorCollector<B> {
    fn emit_event(&self, event: CollectorEvent) {
        if let Some(data_sink) = &self.data_sink {
            data_sink.handle_event(&self.event_context, &event);
        }
    }

    async fn run_monitor_iteration(&mut self) -> Result<IterationResult, HealthError> {
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

                    self.state = Some(SensorCollectorState {
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

            let report = health_report::HealthReport {
                source: "hardware-health".to_string(),
                observed_at: Some(chrono::Utc::now()),
                successes,
                alerts,
            };

            tracing::info!(
                endpoint = %self.endpoint.addr.mac,
                success_count = report.successes.len(),
                alert_count = report.alerts.len(),
                "Sending hardware health report"
            );

            self.emit_event(CollectorEvent::HealthOverride(HealthOverride {
                machine_id: self.endpoint.metadata.as_ref().and_then(|m| match m {
                    EndpointMetadata::Machine(machine) => Some(machine.machine_id),
                    EndpointMetadata::Switch(_) => None,
                }),
                report: Arc::new(report),
            }));
        }

        Ok(IterationResult {
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
            bmc = %self.endpoint.addr.mac,
            total_valid = validated_entities.len(),
            "Discovered hardware entities with sensors"
        );

        Ok(validated_entities)
    }

    async fn fetch_and_update_sensors(
        &self,
        state: &SensorCollectorState<B>,
    ) -> Result<
        (
            Vec<health_report::HealthProbeSuccess>,
            Vec<health_report::HealthProbeAlert>,
        ),
        HealthError,
    > {
        self.emit_event(CollectorEvent::MetricCollectionStart);
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
            match data.to_health_result() {
                SensorHealthResult::Success(s) => successes.push(s),
                SensorHealthResult::Alert(a) => alerts.push(a),
            }
        }
        self.emit_event(CollectorEvent::MetricCollectionEnd);

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

        let mut attributes = entity.base_attributes();
        attributes.reserve(6);
        attributes.push((Cow::Borrowed("sensor_name"), sensor.base.id.clone()));

        if let Some(thresholds) = sensor
            .thresholds
            .as_ref()
            .filter(|_| self.include_sensor_thresholds)
        {
            attributes.push((
                Cow::Borrowed("upper_critical_threshold"),
                thresholds
                    .upper_critical
                    .as_ref()
                    .and_then(|th| th.reading.flatten())
                    .unwrap_or_default()
                    .to_string(),
            ));
            attributes.push((
                Cow::Borrowed("lower_critical_threshold"),
                thresholds
                    .lower_critical
                    .as_ref()
                    .and_then(|th| th.reading.flatten())
                    .unwrap_or_default()
                    .to_string(),
            ));
        }

        let physical_context = sensor
            .physical_context
            .flatten()
            .map(|phc| phc.to_snake_case().to_string())
            .unwrap_or_else(|| {
                match entity {
                    MonitoredEntity::Processor { .. } => "cpu",
                    MonitoredEntity::Memory { .. } => "memory",
                    MonitoredEntity::Drive { .. } => "storage_device",
                    MonitoredEntity::PowerSupply { .. } => "power_supply",
                    MonitoredEntity::Chassis { .. } => "chassis",
                }
                .to_string()
            });
        attributes.push((Cow::Borrowed("physical_context"), physical_context));
        attributes.extend(entity.entity_specific_attributes());

        let derived_metrics = entity.entity_metrics(&attributes);
        let metric_type = reading_type.to_snake_case().to_string();
        self.emit_event(CollectorEvent::Metric(MetricSample {
            key: sensor.id().to_string(),
            name: "hw_sensor".to_string(),
            metric_type: metric_type.clone(),
            unit: sanitize_unit(&unit),
            value: reading,
            labels: attributes,
        }));

        for metric in derived_metrics {
            self.emit_event(CollectorEvent::Metric(metric));
        }

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
            reading_type: metric_type,
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
