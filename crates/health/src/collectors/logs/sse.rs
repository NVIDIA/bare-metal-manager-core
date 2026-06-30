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

use async_trait::async_trait;
use futures::StreamExt;
use nv_redfish::core::{Bmc, EntityTypeRef};
use nv_redfish::event_service::{Event, EventStreamPayload};
use nv_redfish::resource::Health;

use super::diagnostic::{
    DiagnosticPayload, make_diagnostic_record, nullable_ref, nullable_str, redfish_enum_string,
};
use crate::HealthError;
use crate::collectors::runtime::{EventStream, StreamingCollector, open_sse_stream};
use crate::endpoint::BmcEndpoint;
use crate::sink::{CollectorEvent, LogRecord};

/// Configuration for the Redfish SSE log collector.
pub struct SseLogCollectorConfig {
    /// Attach Redfish diagnostic payloads to emitted log records.
    pub include_diagnostics: bool,
}

pub struct SseLogCollector<B: Bmc> {
    bmc: Arc<B>,
    include_diagnostics: bool,
}

#[async_trait]
impl<B: Bmc + 'static> StreamingCollector<B> for SseLogCollector<B> {
    type Config = SseLogCollectorConfig;

    fn new_runner(
        bmc: Arc<B>,
        _endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError> {
        Ok(Self {
            bmc,
            include_diagnostics: config.include_diagnostics,
        })
    }

    async fn connect(&mut self) -> Result<EventStream<'_>, HealthError> {
        let sse_stream = open_sse_stream(Arc::clone(&self.bmc)).await?;

        let bmc = Arc::clone(&self.bmc);
        let include_diagnostics = self.include_diagnostics;
        let event_stream: EventStream<'_> = sse_stream
            .flat_map(move |result| {
                let events = map_payload(result, bmc.as_ref(), include_diagnostics);
                futures::stream::iter(events)
            })
            .boxed();

        Ok(event_stream)
    }

    fn collector_type(&self) -> &'static str {
        "sse_logs"
    }
}

fn health_to_severity(h: &Health) -> &'static str {
    match h {
        Health::Ok => "OK",
        Health::Warning => "Warning",
        Health::Critical => "Critical",
        _ => "Unknown",
    }
}

fn map_payload<B: Bmc>(
    result: Result<EventStreamPayload, HealthError>,
    bmc: &B,
    include_diagnostics: bool,
) -> Vec<Result<CollectorEvent, HealthError>> {
    match result {
        Ok(EventStreamPayload::Event(event)) => event_to_logs(&event, bmc, include_diagnostics),
        Ok(EventStreamPayload::MetricReport(_)) => Vec::new(),
        Err(e) => vec![Err(e)],
    }
}

/// Converts one Redfish SSE event into collector log events.
fn event_to_logs<B: Bmc>(
    event: &Event,
    bmc: &B,
    include_diagnostics: bool,
) -> Vec<Result<CollectorEvent, HealthError>> {
    event
        .events
        .iter()
        .flat_map(|nav| {
            let resolved = futures::FutureExt::now_or_never(nav.get(bmc));
            if resolved.is_none() {
                tracing::warn!(
                    odata_id = %nav.odata_id(),
                    "sse event record requires additional fetch to resolve, skipping"
                );
            }
            resolved
        })
        .filter_map(|result| match result {
            Ok(record) => Some(record),
            Err(error) => {
                tracing::warn!(?error, "failed to resolve sse event record, skipping");
                None
            }
        })
        .map(|record| {
            let body = record.message.as_deref().unwrap_or("").to_string();

            let severity = record
                .message_severity
                .as_ref()
                .map(health_to_severity)
                .or(record.severity.as_deref())
                .unwrap_or("Unknown")
                .to_string();

            // Reuse the same Redfish log-entry reference for the parent log
            // attribute and the diagnostic correlation attribute.
            let log_entry_id = record
                .log_entry
                .as_ref()
                .map(|log_entry_ref| log_entry_ref.odata_id().to_string());

            let mut attributes = vec![
                (Cow::Borrowed("message_id"), record.message_id.clone()),
                (
                    Cow::Borrowed("event_type"),
                    format!("{:?}", record.event_type),
                ),
            ];
            if let Some(event_id) = &record.event_id {
                attributes.push((Cow::Borrowed("event_id"), event_id.clone()));
            }
            if let Some(timestamp) = &record.event_timestamp {
                attributes.push((Cow::Borrowed("event_timestamp"), timestamp.to_string()));
            }
            if let Some(args) = &record.message_args {
                attributes.push((
                    Cow::Borrowed("message_args"),
                    serde_json::to_string(args).unwrap_or_default(),
                ));
            }
            if let Some(ms) = &record.message_severity {
                attributes.push((
                    Cow::Borrowed("message_severity"),
                    health_to_severity(ms).to_string(),
                ));
            }
            if let Some(origin) = &record.origin_of_condition {
                attributes.push((
                    Cow::Borrowed("origin_of_condition"),
                    origin.odata_id.to_string(),
                ));
            }
            if let Some(log_entry_id) = &log_entry_id {
                attributes.push((Cow::Borrowed("log_entry_id"), log_entry_id.clone()));
            }
            if let Some(group_id) = record.event_group_id {
                attributes.push((Cow::Borrowed("event_group_id"), group_id.to_string()));
            }
            if let Some(resolution) = &record.resolution {
                attributes.push((Cow::Borrowed("resolution"), resolution.clone()));
            }

            let diagnostic_record = if include_diagnostics {
                make_diagnostic_record(DiagnosticPayload {
                    diagnostic_data: nullable_str(&record.diagnostic_data),
                    diagnostic_data_type: nullable_ref(&record.diagnostic_data_type)
                        .and_then(redfish_enum_string),
                    oem_diagnostic_data_type: nullable_str(&record.oem_diagnostic_data_type),
                    additional_data_uri: nullable_str(&record.additional_data_uri),
                    additional_data_size_bytes: nullable_ref(&record.additional_data_size_bytes)
                        .copied(),
                    message_id: Some(record.message_id.as_str()),
                    event_id: record.event_id.as_deref(),
                    log_entry_id: log_entry_id.as_deref(),
                })
            } else {
                None
            };

            Ok(CollectorEvent::Log(Box::new(LogRecord {
                body,
                severity,
                attributes,
                diagnostic_record,
            })))
        })
        .collect()
}
