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
use std::sync::atomic::{AtomicUsize, Ordering};

use futures::{StreamExt, stream};
use nv_redfish::core::{Bmc, EntityTypeRef, ToSnakeCase};
use nv_redfish::sensor::SensorLink;

use crate::HealthError;
use crate::collectors::inventory::{DiscoveredEntity, SharedInventory};
use crate::collectors::runtime::{IterationResult, PeriodicCollector};
use crate::endpoint::BmcEndpoint;
use crate::metrics::sanitize_unit;
use crate::sink::{CollectorEvent, DataSink, EventContext, MetricSample, SensorThresholdContext};

/// Configuration for the sensor collector.
pub struct SensorCollectorConfig<B: Bmc> {
    pub data_sink: Option<Arc<dyn DataSink>>,
    pub(crate) shared: SharedInventory<B>,
    pub sensor_fetch_concurrency: usize,
    pub include_sensor_thresholds: bool,
}

/// Sensor collector for a single BMC endpoint
pub struct SensorCollector<B: Bmc> {
    endpoint: Arc<BmcEndpoint>,
    event_context: EventContext,
    shared: SharedInventory<B>,
    data_sink: Option<Arc<dyn DataSink>>,
    sensor_fetch_concurrency: usize,
    include_sensor_thresholds: bool,
}

impl<B: Bmc + 'static> PeriodicCollector<B> for SensorCollector<B> {
    type Config = SensorCollectorConfig<B>;

    fn new_runner(
        _bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        let event_context = EventContext::from_endpoint(endpoint.as_ref(), "sensor_collector");
        Ok(Self {
            endpoint,
            event_context,
            shared: config.shared,
            data_sink: config.data_sink,
            sensor_fetch_concurrency: config.sensor_fetch_concurrency.max(1),
            include_sensor_thresholds: config.include_sensor_thresholds,
        })
    }

    async fn run_iteration(&mut self) -> Result<IterationResult, HealthError> {
        let Some(inventory) = self.shared.load_full() else {
            tracing::debug!(
                bmc_addr = ?self.endpoint.addr,
                "No entity inventory available yet; skipping sensor iteration"
            );
            return Ok(IterationResult {
                refresh_triggered: false,
                entity_count: None,
                fetch_failures: 0,
            });
        };

        tracing::debug!(
            bmc_addr = ?self.endpoint.addr,
            generation = inventory.generation,
            inventory_age_secs = inventory.discovered_at.elapsed().as_secs(),
            entity_count = inventory.entities.len(),
            "Reading entity inventory snapshot for sensor iteration"
        );

        let fetch_failures = AtomicUsize::new(0);
        self.emit_event(CollectorEvent::MetricCollectionStart);

        // Entity-level derived metrics (drive media life, PSU capacity), once
        // per entity.
        for entity in &inventory.entities {
            self.emit_derived_metrics(entity);
        }

        // Build the fetch futures borrowing from the shared snapshot, then
        // drive them concurrently. Each future borrows `&self`, the entity, and
        // its sensor (all alive for as long as `inventory` is held here).
        let this = &*self;
        let failures = &fetch_failures;
        let futures: Vec<_> = inventory
            .entities
            .iter()
            .flat_map(|entity| {
                entity
                    .sensors()
                    .iter()
                    .map(move |sensor| this.update_sensor(entity, sensor, failures))
            })
            .collect();

        let processed: usize = stream::iter(futures)
            .buffer_unordered(self.sensor_fetch_concurrency)
            .collect::<Vec<usize>>()
            .await
            .into_iter()
            .sum();

        self.emit_event(CollectorEvent::MetricCollectionEnd);

        Ok(IterationResult {
            refresh_triggered: false,
            entity_count: Some(processed),
            fetch_failures: fetch_failures.load(Ordering::Relaxed),
        })
    }

    fn collector_type(&self) -> &'static str {
        "sensor_collector"
    }

    async fn stop(&mut self) {
        self.emit_event(CollectorEvent::CollectorRemoved);
    }
}

impl<B: Bmc + 'static> SensorCollector<B> {
    fn emit_event(&self, event: CollectorEvent) {
        if let Some(data_sink) = &self.data_sink {
            data_sink.handle_event(&self.event_context, &event);
        }
    }

    fn emit_derived_metrics(&self, entity: &DiscoveredEntity<B>) {
        let derived = entity.derived_metrics();
        if derived.is_empty() {
            return;
        }
        let mut attributes = entity.base_attributes();
        attributes.extend(entity.entity_specific_attributes());
        for metric in derived {
            self.emit_event(CollectorEvent::Metric(
                MetricSample {
                    key: format!("{}/{}", entity.key(), metric.metric_type),
                    name: "hw".to_string(),
                    metric_type: metric.metric_type.to_string(),
                    unit: metric.unit.to_string(),
                    value: metric.value,
                    labels: attributes.clone(),
                    context: None,
                }
                .into(),
            ));
        }
    }

    async fn update_sensor(
        &self,
        entity: &DiscoveredEntity<B>,
        sensor_link: &SensorLink<B>,
        fetch_failures: &AtomicUsize,
    ) -> usize {
        let sensor = match sensor_link.fetch().await {
            Ok(s) => s,
            Err(e) => {
                fetch_failures.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    sensor_id = %sensor_link.odata_id(),
                    entity_type = entity.entity_type(),
                    error = ?e,
                    "Failed to fetch sensor data"
                );
                return 0;
            }
        };

        let Some(bmc_health) = sensor
            .status
            .as_ref()
            .and_then(|s| s.health.and_then(std::convert::identity))
        else {
            tracing::debug!(
                sensor_id = %sensor.base.id,
                entity_type = entity.entity_type(),
                "Sensor does not have health status field, skipping"
            );
            return 0;
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
                entity_type = entity.entity_type(),
                "Sensor missing required fields (reading, reading_type, or units)"
            );
            return 0;
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
            .unwrap_or_else(|| entity.physical_context_fallback().to_string());
        attributes.push((Cow::Borrowed("physical_context"), physical_context));
        attributes.extend(entity.entity_specific_attributes());

        let metric_type = reading_type.to_snake_case().to_string();
        let unit = sanitize_unit(&unit);

        let (
            upper_fatal,
            lower_fatal,
            upper_critical,
            lower_critical,
            upper_caution,
            lower_caution,
        ) = if let Some(thresholds) = &sensor.thresholds {
            (
                thresholds
                    .upper_fatal
                    .as_ref()
                    .and_then(|t| t.reading.flatten()),
                thresholds
                    .lower_fatal
                    .as_ref()
                    .and_then(|t| t.reading.flatten()),
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
            (None, None, None, None, None, None)
        };

        self.emit_event(CollectorEvent::Metric(
            MetricSample {
                key: sensor.odata_id().to_string(),
                name: "hw_sensor".to_string(),
                metric_type,
                unit,
                value: reading,
                labels: attributes,
                context: Some(SensorThresholdContext {
                    entity_type: entity.entity_type().to_string(),
                    sensor_id: sensor.base.id.clone(),
                    upper_fatal,
                    lower_fatal,
                    upper_critical,
                    lower_critical,
                    upper_caution,
                    lower_caution,
                    range_max: sensor.reading_range_max.flatten(),
                    range_min: sensor.reading_range_min.flatten(),
                    bmc_health,
                }),
            }
            .into(),
        ));

        1
    }
}
