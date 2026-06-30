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

use super::{CollectorEvent, DataSink, EventContext};
use crate::config::TracingSinkConfig;

/// Sink that writes health events through the process tracing subscriber.
pub struct TracingSink {
    include_diagnostics: bool,
}

impl TracingSink {
    /// Builds a tracing sink from configuration.
    pub fn new(config: &TracingSinkConfig) -> Self {
        Self {
            include_diagnostics: config.include_diagnostics,
        }
    }
}

impl DataSink for TracingSink {
    fn sink_type(&self) -> &'static str {
        "tracing_sink"
    }

    fn handle_event(&self, context: &EventContext, event: &CollectorEvent) {
        match event {
            CollectorEvent::MetricCollectionStart => {
                tracing::info!(
                    endpoint = %context.endpoint_key(),
                    collector = %context.collector_type,
                    "Metric collection start"
                );
            }
            CollectorEvent::Metric(metric) => {
                tracing::info!(
                    endpoint = %context.endpoint_key(),
                    collector = %context.collector_type,
                    metric = %metric.name,
                    key = %metric.key,
                    metric_type = %metric.metric_type,
                    unit = %metric.unit,
                    value = metric.value,
                    "Metric event"
                );
            }
            CollectorEvent::MetricCollectionEnd => {
                tracing::info!(
                    endpoint = %context.endpoint_key(),
                    collector = %context.collector_type,
                    "Metric collection end"
                );
            }
            CollectorEvent::CollectorRemoved => {
                tracing::info!(
                    endpoint = %context.endpoint_key(),
                    collector = %context.collector_type,
                    "Collector removed"
                );
            }
            CollectorEvent::Log(record) => {
                let has_included_diagnostics =
                    self.include_diagnostics && record.diagnostic_record.is_some();

                let record = record.emitted_log_record(self.include_diagnostics);

                if has_included_diagnostics {
                    tracing::info!(
                        endpoint = %context.endpoint_key(),
                        collector = %context.collector_type,
                        machine_id = context.machine_id().map(tracing::field::display),
                        machine_serial = context.machine_serial(),
                        driver_version = context.driver_version(),
                        component_type = context.component_type(),
                        nvlink_domain_uuid = context.nvlink_domain_uuid().map(tracing::field::display),
                        severity = %record.severity,
                        body = %record.body,
                        attributes = ?record.attributes,
                        "Log event"
                    );
                } else {
                    tracing::info!(
                        endpoint = %context.endpoint_key(),
                        collector = %context.collector_type,
                        machine_id = context.machine_id().map(tracing::field::display),
                        machine_serial = context.machine_serial(),
                        driver_version = context.driver_version(),
                        component_type = context.component_type(),
                        nvlink_domain_uuid = context.nvlink_domain_uuid().map(tracing::field::display),
                        severity = %record.severity,
                        body = %record.body,
                        "Log event"
                    );
                }
            }
            CollectorEvent::Firmware(info) => {
                tracing::info!(
                    endpoint = %context.endpoint_key(),
                    collector = %context.collector_type,
                    firmware_name = %info.component,
                    version = %info.version,
                    "Firmware info event"
                );
            }
            CollectorEvent::HealthReport(report) => {
                tracing::info!(
                    endpoint = %context.endpoint_key(),
                    collector = %context.collector_type,
                    machine_id = ?context.machine_id(),
                    success_count = report.successes.len(),
                    alert_count = report.alerts.len(),
                    alerts = ?report.alerts,
                    report_source = report.source.as_str(),
                    target = ?report.target,
                    "Health report event"
                );
            }
        }
    }
}
