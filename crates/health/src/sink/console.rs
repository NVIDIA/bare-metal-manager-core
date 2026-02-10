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
use crate::HealthError;

pub struct ConsoleSink;

impl DataSink for ConsoleSink {
    fn handle_event(
        &self,
        context: &EventContext,
        event: &CollectorEvent,
    ) -> Result<(), HealthError> {
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
            CollectorEvent::Log(record) => {
                tracing::info!(
                    endpoint = %context.endpoint_key(),
                    collector = %context.collector_type,
                    severity = %record.severity,
                    body = %record.body,
                    "Log event"
                );
            }
            CollectorEvent::Firmware(info) => {
                tracing::info!(
                    endpoint = %context.endpoint_key(),
                    collector = %context.collector_type,
                    component = %info.component,
                    version = %info.version,
                    "Firmware info event"
                );
            }
            CollectorEvent::HealthOverride(override_event) => {
                tracing::info!(
                    endpoint = %context.endpoint_key(),
                    collector = %context.collector_type,
                    machine_id = ?override_event.machine_id,
                    success_count = override_event.report.successes.len(),
                    alert_count = override_event.report.alerts.len(),
                    "Health override event"
                );
            }
        }
        Ok(())
    }
}
