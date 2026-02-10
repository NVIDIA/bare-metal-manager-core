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

use super::{CollectorEvent, DataSink, EventContext, MetricSample};
use crate::HealthError;
use crate::metrics::{CollectorRegistry, GaugeMetrics, GaugeReading, MetricsManager};

pub struct PrometheusSink {
    collector_registry: Arc<CollectorRegistry>, // Hold onto the registry to ensure it lives as long as the sink
    stream_metrics: DashMap<String, DashMap<&'static str, Arc<GaugeMetrics>>>,
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
            Self::sanitize_id(context.endpoint_key()),
            Self::sanitize_id(context.collector_type)
        )
    }

    fn metric_reading_key(context: &EventContext, sample: &MetricSample) -> String {
        let endpoint = context.endpoint_key();
        const KEY_SEPARATOR: &str = "::";
        let separators_len = KEY_SEPARATOR.len() * 3;
        let mut key = String::with_capacity(
            endpoint.len()
                + sample.key.len()
                + sample.metric_type.len()
                + sample.unit.len()
                + separators_len,
        );
        key.push_str(endpoint);
        key.push_str(KEY_SEPARATOR);
        key.push_str(&sample.key);
        key.push_str(KEY_SEPARATOR);
        key.push_str(&sample.metric_type);
        key.push_str(KEY_SEPARATOR);
        key.push_str(&sample.unit);
        key
    }

    fn stream_static_labels(context: &EventContext) -> Vec<(String, String)> {
        let mut labels = vec![
            (
                "endpoint_key".to_string(),
                context.endpoint_key().to_string(),
            ),
            ("endpoint_mac".to_string(), context.addr.mac.clone()),
            ("endpoint_ip".to_string(), context.addr.ip.to_string()),
            (
                "collector_type".to_string(),
                context.collector_type.to_string(),
            ),
        ];

        if let Some(machine_id) = context.machine_id() {
            labels.push(("machine_id".to_string(), machine_id.to_string()));
        }
        if let Some(serial) = context.switch_serial() {
            labels.push(("switch_serial".to_string(), serial.to_string()));
        }

        labels
    }

    fn get_or_create_stream_metrics(
        &self,
        context: &EventContext,
    ) -> Result<Arc<GaugeMetrics>, HealthError> {
        if let Some(endpoint_metrics) = self.stream_metrics.get(context.endpoint_key())
            && let Some(entry) = endpoint_metrics.get(context.collector_type)
        {
            return Ok(entry.value().clone());
        }

        let metrics = self.collector_registry.create_gauge_metrics(
            Self::stream_metric_id(context),
            "Metrics forwarded through sink pipeline",
            Self::stream_static_labels(context),
        )?;

        let endpoint_metrics = self
            .stream_metrics
            .entry(context.endpoint_key().to_string())
            .or_default();

        match endpoint_metrics.entry(context.collector_type) {
            dashmap::mapref::entry::Entry::Occupied(existing) => Ok(existing.get().clone()),
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(metrics.clone());
                Ok(metrics)
            }
        }
    }
}

impl DataSink for PrometheusSink {
    fn handle_event(
        &self,
        context: &EventContext,
        event: &CollectorEvent,
    ) -> Result<(), HealthError> {
        match event {
            CollectorEvent::MetricCollectionStart => {
                let stream_metrics = self.get_or_create_stream_metrics(context)?;
                stream_metrics.begin_update();
            }
            CollectorEvent::Metric(sample) => {
                let stream_metrics = self.get_or_create_stream_metrics(context)?;
                stream_metrics.record(
                    GaugeReading::new(
                        Self::metric_reading_key(context, sample),
                        sample.name.clone(),
                        sample.metric_type.clone(),
                        sample.unit.clone(),
                        sample.value,
                    )
                    .with_labels(sample.labels.clone()),
                );
            }
            CollectorEvent::MetricCollectionEnd => {
                if let Some(endpoint_metrics) = self.stream_metrics.get(context.endpoint_key())
                    && let Some(entry) = endpoint_metrics.get(context.collector_type)
                {
                    entry.value().sweep_stale();
                }
            }
            CollectorEvent::Log(_)
            | CollectorEvent::Firmware(_)
            | CollectorEvent::HealthOverride(_) => {}
        }

        Ok(())
    }
}
