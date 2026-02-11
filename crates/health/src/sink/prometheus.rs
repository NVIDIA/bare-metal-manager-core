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

    fn metric_reading_key(sample: &MetricSample) -> String {
        const KEY_SEPARATOR: &str = "::";
        let separators_len = KEY_SEPARATOR.len() * 2;
        let mut key = String::with_capacity(
            sample.key.len() + sample.metric_type.len() + sample.unit.len() + separators_len,
        );
        key.push_str(&sample.key);
        key.push_str(KEY_SEPARATOR);
        key.push_str(&sample.metric_type);
        key.push_str(KEY_SEPARATOR);
        key.push_str(&sample.unit);
        key
    }

    fn stream_static_labels(context: &EventContext) -> Vec<(Cow<'static, str>, String)> {
        let mut labels = vec![
            (
                Cow::Borrowed("endpoint_key"),
                context.endpoint_key().to_string(),
            ),
            (Cow::Borrowed("endpoint_mac"), context.addr.mac.to_string()),
            (Cow::Borrowed("endpoint_ip"), context.addr.ip.to_string()),
            (
                Cow::Borrowed("collector_type"),
                context.collector_type.to_string(),
            ),
        ];

        if let Some(machine_id) = context.machine_id() {
            labels.push((Cow::Borrowed("machine_id"), machine_id.to_string()));
        }
        if let Some(serial) = context.switch_serial() {
            labels.push((Cow::Borrowed("switch_serial"), serial.to_string()));
        }

        labels
    }

    fn get_or_create_stream_metrics(
        &self,
        context: &EventContext,
    ) -> Result<Arc<GaugeMetrics>, HealthError> {
        if let Some(endpoint_metrics) = self.stream_metrics.get::<str>(context.endpoint_key())
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
    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        match event {
            CollectorEvent::MetricCollectionStart => {
                match self.get_or_create_stream_metrics(context) {
                    Ok(stream_metrics) => stream_metrics.begin_update(),
                    Err(error) => {
                        tracing::warn!(
                            ?error,
                            endpoint_key = context.endpoint_key(),
                            collector = context.collector_type,
                            "Failed to initialize Prometheus stream metrics"
                        );
                    }
                }
            }
            CollectorEvent::Metric(sample) => match self.get_or_create_stream_metrics(context) {
                Ok(stream_metrics) => {
                    stream_metrics.record(
                        GaugeReading::new(
                            Self::metric_reading_key(sample),
                            sample.name.clone(),
                            sample.metric_type.clone(),
                            sample.unit.clone(),
                            sample.value,
                        )
                        .with_labels(sample.labels.clone()),
                    );
                }
                Err(error) => {
                    tracing::warn!(
                        ?error,
                        endpoint_key = context.endpoint_key(),
                        collector = context.collector_type,
                        metric = sample.name,
                        metric_type = sample.metric_type,
                        "Failed to record Prometheus metric sample"
                    );
                }
            },
            CollectorEvent::MetricCollectionEnd => {
                if let Some(endpoint_metrics) =
                    self.stream_metrics.get::<str>(context.endpoint_key())
                    && let Some(entry) = endpoint_metrics.get(context.collector_type)
                {
                    entry.value().sweep_stale();
                }
            }
            CollectorEvent::Log(_)
            | CollectorEvent::Firmware(_)
            | CollectorEvent::HealthOverride(_) => {}
        }
    }
}
