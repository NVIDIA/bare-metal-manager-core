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

use std::sync::Arc;

use dashmap::DashMap;

use super::{BoxFuture, CollectorEvent, DataSink, EventContext};
use crate::HealthError;
use crate::metrics::{CollectorRegistry, GaugeMetrics, GaugeReading, MetricsManager};

pub struct PrometheusSink {
    collector_registry: Arc<CollectorRegistry>, // Hold onto the registry to ensure it lives as long as the sink
    stream_metrics: DashMap<String, Arc<GaugeMetrics>>,
}

impl PrometheusSink {
    pub fn new(
        metrics_manager: Arc<MetricsManager>,
        metrics_prefix: &str,
    ) -> Result<Self, HealthError> {
        let collector_registry =
            Arc::new(metrics_manager.create_collector_registry(
                "sink_prometheus_collector".to_string(),
                metrics_prefix,
            )?);
        Ok(Self {
            collector_registry,
            stream_metrics: DashMap::new(),
        })
    }

    fn stream_key(context: &EventContext) -> String {
        format!("{}::{}", context.endpoint_key, context.collector_type)
    }

    fn sanitize_id(value: &str) -> String {
        value
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() {
                    c.to_ascii_lowercase()
                } else {
                    '_'
                }
            })
            .collect()
    }

    fn stream_metric_id(context: &EventContext) -> String {
        format!(
            "sink_gauge_metrics_{}_{}",
            Self::sanitize_id(&context.endpoint_key),
            Self::sanitize_id(&context.collector_type)
        )
    }

    fn stream_static_labels(context: &EventContext) -> Vec<(String, String)> {
        let mut labels = vec![
            ("endpoint_key".to_string(), context.endpoint_key.clone()),
            ("endpoint_mac".to_string(), context.endpoint_mac.clone()),
            ("endpoint_ip".to_string(), context.endpoint_ip.clone()),
            ("collector_type".to_string(), context.collector_type.clone()),
        ];

        if let Some(machine_id) = context.machine_id.clone() {
            labels.push(("machine_id".to_string(), machine_id));
        }
        if let Some(serial) = context.switch_serial.clone() {
            labels.push(("switch_serial".to_string(), serial));
        }

        labels
    }

    fn get_or_create_stream_metrics(
        &self,
        context: &EventContext,
    ) -> Result<Arc<GaugeMetrics>, HealthError> {
        let stream_key = Self::stream_key(context);
        if let Some(entry) = self.stream_metrics.get(&stream_key) {
            return Ok(entry.value().clone());
        }

        let metrics = self.collector_registry.create_gauge_metrics(
            Self::stream_metric_id(context),
            "Metrics forwarded through sink pipeline",
            Self::stream_static_labels(context),
        )?;

        match self.stream_metrics.entry(stream_key) {
            dashmap::mapref::entry::Entry::Occupied(existing) => Ok(existing.get().clone()),
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(metrics.clone());
                Ok(metrics)
            }
        }
    }
}

impl DataSink for PrometheusSink {
    fn handle_event<'a>(
        &'a self,
        context: EventContext,
        event: CollectorEvent,
    ) -> BoxFuture<'a, Result<(), HealthError>> {
        Box::pin(async move {
            let stream_key = Self::stream_key(&context);

            match event {
                CollectorEvent::MetricCollectionStart => {
                    let stream_metrics = self.get_or_create_stream_metrics(&context)?;
                    stream_metrics.begin_update();
                }
                CollectorEvent::Metric(sample) => {
                    let stream_metrics = self.get_or_create_stream_metrics(&context)?;
                    stream_metrics.record(
                        GaugeReading::new(
                            format!(
                                "{}::{}::{}::{}",
                                context.endpoint_key, sample.key, sample.metric_type, sample.unit
                            ),
                            sample.name,
                            sample.metric_type,
                            sample.unit,
                            sample.value,
                        )
                        .with_labels(sample.labels),
                    );
                }
                CollectorEvent::MetricCollectionEnd => {
                    if let Some(entry) = self.stream_metrics.get(&stream_key) {
                        entry.value().sweep_stale();
                    }
                }
                CollectorEvent::Log(_)
                | CollectorEvent::Firmware(_)
                | CollectorEvent::HealthOverride(_) => {}
            }

            Ok(())
        })
    }
}
