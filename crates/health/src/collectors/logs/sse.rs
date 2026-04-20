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

use crate::HealthError;
use crate::collectors::runtime::{EventStream, StreamingCollector, open_sse_stream};
use crate::endpoint::BmcEndpoint;
use crate::sink::{CollectorEvent, LogRecord};

pub struct SseLogCollectorConfig;

pub struct SseLogCollector<B: Bmc> {
    bmc: Arc<B>,
}

#[async_trait]
impl<B: Bmc + 'static> StreamingCollector<B> for SseLogCollector<B> {
    type Config = SseLogCollectorConfig;

    fn new_runner(
        bmc: Arc<B>,
        _endpoint: Arc<BmcEndpoint>,
        _config: Self::Config,
    ) -> Result<Self, HealthError> {
        Ok(Self { bmc })
    }

    async fn connect(&mut self) -> Result<EventStream<'_>, HealthError> {
        let sse_stream = open_sse_stream(Arc::clone(&self.bmc)).await?;

        let bmc = Arc::clone(&self.bmc);
        let event_stream: EventStream<'_> = sse_stream
            .flat_map(move |result| {
                let events = map_payload(result, bmc.as_ref());
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
) -> Vec<Result<CollectorEvent, HealthError>> {
    match result {
        Ok(EventStreamPayload::Event(event)) => event_to_logs(&event, bmc),
        Ok(EventStreamPayload::MetricReport(_)) => Vec::new(),
        Err(e) => vec![Err(e)],
    }
}

fn event_to_logs<B: Bmc>(event: &Event, bmc: &B) -> Vec<Result<CollectorEvent, HealthError>> {
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
            if let Some(log_entry_ref) = &record.log_entry {
                attributes.push((
                    Cow::Borrowed("log_entry_id"),
                    log_entry_ref.odata_id().to_string(),
                ));
            }
            if let Some(group_id) = record.event_group_id {
                attributes.push((Cow::Borrowed("event_group_id"), group_id.to_string()));
            }
            if let Some(resolution) = &record.resolution {
                attributes.push((Cow::Borrowed("resolution"), resolution.clone()));
            }

            Ok(CollectorEvent::Log(Box::new(LogRecord {
                body,
                severity,
                attributes,
            })))
        })
        .collect()
}
