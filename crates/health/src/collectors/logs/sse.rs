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
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use nv_redfish::core::{Bmc, EntityTypeRef};
use nv_redfish::event_service::{Event, EventStreamPayload};
use nv_redfish::resource::Health;

use super::diagnostic::{
    DiagnosticPayload, make_diagnostic_record, nullable_ref, nullable_str, redfish_enum_string,
};
use super::redfish::{
    RedfishLogFields, add_redfish_analyzer_attributes, normalize_redfish_severity, nvidia_error_id,
    redfish_event_type_string, redfish_log_type,
};
use crate::HealthError;
use crate::collectors::runtime::{
    EventStream, StreamingCollector, StreamingConnectResult, open_sse_stream,
};
use crate::endpoint::BmcEndpoint;
use crate::sink::{CollectorEvent, LogRecord};

const EVENT_RECORD_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, carbide_instrument::LabelValue)]
enum EventRecordResolutionFailure {
    Fetch,
    Timeout,
}

#[derive(carbide_instrument::Event)]
#[event(
    event_name = "redfish_sse_event_record_resolution_failed",
    metric_name = "carbide_health_redfish_sse_event_record_resolution_failures_total",
    component = "nico-hardware-health",
    log = warn,
    metric = counter,
    message = "failed to resolve Redfish SSE event record",
    describe = "Number of Redfish SSE event records dropped after a referenced record could not be resolved, by failure reason."
)]
struct EventRecordResolutionFailed {
    #[label]
    reason: EventRecordResolutionFailure,
    #[context]
    odata_id: String,
    #[context]
    error: String,
}

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

    async fn connect(&mut self) -> Result<StreamingConnectResult<'_>, HealthError> {
        let sse_stream = open_sse_stream(Arc::clone(&self.bmc)).await?;

        let bmc = Arc::clone(&self.bmc);
        let include_diagnostics = self.include_diagnostics;
        let event_stream: EventStream<'_> = sse_stream
            .then(move |result| {
                let bmc = Arc::clone(&bmc);
                async move { map_payload(result, bmc.as_ref(), include_diagnostics).await }
            })
            .flat_map(futures::stream::iter)
            .boxed();

        Ok(StreamingConnectResult::Connected(event_stream))
    }

    fn collector_type(&self) -> &'static str {
        "sse_logs"
    }
}

fn health_to_severity(h: &Health) -> Option<&'static str> {
    match h {
        Health::Ok => Some("OK"),
        Health::Warning => Some("Warning"),
        Health::Critical => Some("Critical"),
        // UnsupportedValue means the BMC sent a value the Health enum couldn't
        // parse (e.g. wrong capitalisation like "CRITICAL" instead of "Critical").
        // Return None so the caller can fall back to the raw Severity string.
        _ => None,
    }
}

async fn map_payload<B: Bmc>(
    result: Result<EventStreamPayload, HealthError>,
    bmc: &B,
    include_diagnostics: bool,
) -> Vec<Result<CollectorEvent, HealthError>> {
    match result {
        Ok(EventStreamPayload::Event(event)) => {
            event_to_logs(&event, bmc, include_diagnostics).await
        }
        Ok(EventStreamPayload::MetricReport(_)) => Vec::new(),
        Err(e) => vec![Err(e)],
    }
}

/// Converts one Redfish SSE event into collector log events.
async fn event_to_logs<B: Bmc>(
    event: &Event,
    bmc: &B,
    include_diagnostics: bool,
) -> Vec<Result<CollectorEvent, HealthError>> {
    event_to_logs_with_timeout(
        event,
        bmc,
        include_diagnostics,
        EVENT_RECORD_RESOLUTION_TIMEOUT,
    )
    .await
}

async fn event_to_logs_with_timeout<B: Bmc>(
    event: &Event,
    bmc: &B,
    include_diagnostics: bool,
    resolution_timeout: Duration,
) -> Vec<Result<CollectorEvent, HealthError>> {
    let mut logs = Vec::with_capacity(event.events.len());
    let deadline = tokio::time::Instant::now() + resolution_timeout;

    for nav in &event.events {
        if let Some(record) = resolve_event_record(nav, bmc, deadline).await {
            logs.push(Ok(record_to_log(&record, include_diagnostics)));
        }
    }

    logs
}

async fn resolve_event_record<B: Bmc>(
    nav: &nv_redfish::core::NavProperty<nv_redfish::schema::event::EventRecord>,
    bmc: &B,
    deadline: tokio::time::Instant,
) -> Option<Arc<nv_redfish::schema::event::EventRecord>> {
    let odata_id = nav.odata_id().to_string();
    match tokio::time::timeout_at(deadline, nav.get(bmc)).await {
        Ok(Ok(record)) => Some(record),
        Ok(Err(error)) => {
            carbide_instrument::emit(EventRecordResolutionFailed {
                reason: EventRecordResolutionFailure::Fetch,
                odata_id,
                error: error.to_string(),
            });
            None
        }
        Err(error) => {
            carbide_instrument::emit(EventRecordResolutionFailed {
                reason: EventRecordResolutionFailure::Timeout,
                odata_id,
                error: error.to_string(),
            });
            None
        }
    }
}

fn record_to_log(
    record: &nv_redfish::schema::event::EventRecord,
    include_diagnostics: bool,
) -> CollectorEvent {
    let diagnostic_data_type =
        nullable_ref(&record.diagnostic_data_type).and_then(redfish_enum_string);
    let redfish_fields = RedfishLogFields {
        message: record.message.as_deref(),
        message_args: record.message_args.as_deref(),
        diagnostic_data_type: diagnostic_data_type.as_deref(),
        has_cper: record.cper.is_some(),
    };
    let log_type = redfish_log_type(redfish_fields);
    let body = record.message.as_deref().unwrap_or_default().to_string();

    let severity = record
        .message_severity
        .as_ref()
        .and_then(health_to_severity)
        .or_else(|| record.severity.as_deref().map(normalize_redfish_severity))
        .unwrap_or("Unknown")
        .to_string();

    // Reuse the same Redfish log-entry reference for the parent log attribute
    // and the diagnostic correlation attribute.
    let log_entry_id = record
        .log_entry
        .as_ref()
        .map(|log_entry_ref| log_entry_ref.odata_id().to_string());

    let mut attributes = vec![(Cow::Borrowed("message_id"), record.message_id.clone())];
    if let Some(event_type) = redfish_event_type_string(Some(&record.event_type)) {
        attributes.push((Cow::Borrowed("event_type"), event_type));
    }
    add_redfish_analyzer_attributes(
        &mut attributes,
        log_type,
        Some(severity.as_str()),
        nvidia_error_id(record.base.base.oem.as_ref()),
    );
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
    if let Some(sev) = record
        .message_severity
        .as_ref()
        .and_then(health_to_severity)
    {
        attributes.push((Cow::Borrowed("message_severity"), sev.to_string()));
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
            diagnostic_data_type,
            oem_diagnostic_data_type: nullable_str(&record.oem_diagnostic_data_type),
            additional_data_uri: nullable_str(&record.additional_data_uri),
            additional_data_size_bytes: nullable_ref(&record.additional_data_size_bytes).copied(),
            message_id: Some(record.message_id.as_str()),
            event_id: record.event_id.as_deref(),
            log_entry_id: log_entry_id.as_deref(),
        })
    } else {
        None
    };

    CollectorEvent::Log(Box::new(LogRecord {
        body,
        severity,
        attributes,
        diagnostic_record,
    }))
}

#[cfg(test)]
mod tests {
    use axum::routing::get;
    use axum::{Json, Router};
    use bmc_mock::test_support::axum_http_client::AxumRouterHttpClient;
    use nv_redfish::bmc_http::{BmcCredentials, CacheSettings, HttpBmc};
    use serde_json::{Value, json};
    use url::Url;

    use super::*;

    type TestBmc = HttpBmc<AxumRouterHttpClient>;

    fn test_bmc(router: Router) -> TestBmc {
        HttpBmc::new(
            AxumRouterHttpClient::new(router),
            Url::parse("https://bmc-mock.local").expect("valid test URL"),
            BmcCredentials::new("root".to_string(), "password".to_string()),
            CacheSettings::with_capacity(8),
        )
    }

    fn referenced_event(paths: &[&str]) -> Event {
        serde_json::from_value(json!({
            "@odata.id": "/redfish/v1/EventService/Events/1",
            "Id": "1",
            "Name": "Test event",
            "Events": paths
                .iter()
                .map(|path| json!({"@odata.id": path}))
                .collect::<Vec<_>>(),
        }))
        .expect("valid referenced Redfish event")
    }

    fn c12_platform_record(path: &str) -> Value {
        json!({
            "@odata.id": path,
            "MemberId": "0",
            "EventType": "Alert",
            "MessageId": "IANA.0.1.CPLD-PSEQ-FAULT",
            "MessageSeverity": "Critical",
            "MessageArgs": ["CPLD_0", ""],
            "Message": "",
            "Oem": {
                "Nvidia": {
                    "ErrorId": "CPLD-PSEQ-FAULT"
                }
            },
            "OriginOfCondition": {
                "@odata.id": "/redfish/v1/Chassis/HGX_Baseboard_0"
            }
        })
    }

    fn log_record(event: &CollectorEvent) -> &LogRecord {
        let CollectorEvent::Log(record) = event else {
            panic!("expected log event");
        };
        record
    }

    fn attribute<'a>(record: &'a LogRecord, key: &str) -> Option<&'a str> {
        record
            .attributes
            .iter()
            .find(|(candidate, _)| candidate.as_ref() == key)
            .map(|(_, value)| value.as_str())
    }

    #[tokio::test]
    async fn referenced_event_record_is_awaited_and_emitted() {
        let path = "/redfish/v1/EventService/Events/records/1";
        let payload = c12_platform_record(path);
        let router = Router::new().route(
            path,
            get(move || {
                let payload = payload.clone();
                async move { Json(payload) }
            }),
        );
        let bmc = test_bmc(router);

        let logs = event_to_logs_with_timeout(
            &referenced_event(&[path]),
            &bmc,
            false,
            Duration::from_secs(1),
        )
        .await;

        assert_eq!(logs.len(), 1);
        let event = logs[0].as_ref().expect("resolved record should be emitted");
        let record = log_record(event);
        assert_eq!(record.body, "");
        assert_eq!(
            attribute(record, "oem.nvidia.error_id"),
            Some("CPLD-PSEQ-FAULT")
        );
        assert_eq!(
            attribute(record, "redfish.event.type"),
            Some("redfish_event")
        );
        assert_eq!(
            attribute(record, "redfish.event.severity"),
            Some("Critical")
        );
        assert_eq!(attribute(record, "event_type"), Some("Alert"));
    }

    #[tokio::test]
    async fn failed_reference_does_not_drop_sibling_record() {
        let missing_path = "/redfish/v1/EventService/Events/records/missing";
        let good_path = "/redfish/v1/EventService/Events/records/good";
        let payload = c12_platform_record(good_path);
        let router = Router::new().route(
            good_path,
            get(move || {
                let payload = payload.clone();
                async move { Json(payload) }
            }),
        );
        let bmc = test_bmc(router);

        let logs = event_to_logs_with_timeout(
            &referenced_event(&[missing_path, good_path]),
            &bmc,
            false,
            Duration::from_secs(1),
        )
        .await;

        assert_eq!(logs.len(), 1);
        let event = logs[0].as_ref().expect("good sibling should be emitted");
        assert_eq!(
            attribute(log_record(event), "oem.nvidia.error_id"),
            Some("CPLD-PSEQ-FAULT")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn referenced_event_record_batch_fetch_is_bounded() {
        let first_path = "/redfish/v1/EventService/Events/records/hung-1";
        let second_path = "/redfish/v1/EventService/Events/records/hung-2";
        let router = Router::new()
            .route(
                first_path,
                get(|| async { std::future::pending::<Json<Value>>().await }),
            )
            .route(
                second_path,
                get(|| async { std::future::pending::<Json<Value>>().await }),
            );
        let bmc = test_bmc(router);
        let started_at = tokio::time::Instant::now();

        let logs = event_to_logs(&referenced_event(&[first_path, second_path]), &bmc, false).await;

        assert!(logs.is_empty());
        assert_eq!(EVENT_RECORD_RESOLUTION_TIMEOUT, Duration::from_secs(10));
        assert_eq!(
            tokio::time::Instant::now() - started_at,
            EVENT_RECORD_RESOLUTION_TIMEOUT
        );
    }

    #[test]
    fn diagnostic_payload_remains_behind_sink_gate() {
        let record: nv_redfish::schema::event::EventRecord = serde_json::from_value(json!({
            "@odata.id": "/redfish/v1/EventService/Events/records/cper",
            "MemberId": "0",
            "EventType": "Alert",
            "MessageId": "ResourceEvent.1.0.ResourceErrorsDetected",
            "Message": "PCIe error",
            "MessageSeverity": "Critical",
            "DiagnosticData": "base64-cper-payload",
            "DiagnosticDataType": "CPER",
            "CPER": {}
        }))
        .expect("valid CPER event record");

        let without_diagnostics = record_to_log(&record, false);
        let without_diagnostics = log_record(&without_diagnostics);
        assert_eq!(without_diagnostics.body, "PCIe error");
        assert!(without_diagnostics.diagnostic_record.is_none());

        let with_diagnostics = record_to_log(&record, true);
        let with_diagnostics = log_record(&with_diagnostics);
        assert_eq!(with_diagnostics.body, "PCIe error");
        assert!(with_diagnostics.diagnostic_record.is_some());
        assert_eq!(
            with_diagnostics.emitted_log_record(false).body,
            "PCIe error"
        );

        let emitted = with_diagnostics.emitted_log_record(true);
        let body: Value = serde_json::from_str(&emitted.body).expect("diagnostic body is JSON");
        assert_eq!(body["message"], "PCIe error");
        assert_eq!(body["diagnostic_data"], "base64-cper-payload");
    }

    #[test]
    fn health_to_severity_known_variants() {
        assert_eq!(health_to_severity(&Health::Critical), Some("Critical"));
        assert_eq!(health_to_severity(&Health::Warning), Some("Warning"));
        assert_eq!(health_to_severity(&Health::Ok), Some("OK"));
    }

    #[test]
    fn health_to_severity_unsupported_returns_none() {
        // UnsupportedValue fires when the BMC sends an unexpected case variant
        // (e.g. "CRITICAL" instead of "Critical"). Returning None lets the caller
        // fall back to the raw Severity string.
        assert_eq!(health_to_severity(&Health::UnsupportedValue), None);
    }

    #[test]
    fn normalize_severity_case_insensitive() {
        let cases = [
            ("Critical", "Critical"),
            ("CRITICAL", "Critical"),
            ("critical", "Critical"),
            ("Warning", "Warning"),
            ("WARNING", "Warning"),
            ("warning", "Warning"),
            ("OK", "OK"),
            ("Ok", "OK"),
            ("ok", "OK"),
            ("unknown_value", "Unknown"),
            ("", "Unknown"),
        ];
        for (input, expected) in cases {
            assert_eq!(
                normalize_redfish_severity(input),
                expected,
                "normalize_severity({input:?})"
            );
        }
    }

    /// Verifies the full severity resolution chain:
    /// - Known Health variant → its canonical string
    /// - UnsupportedValue → falls back to raw severity string (normalized)
    /// - UnsupportedValue with no raw severity → "Unknown"
    #[test]
    fn severity_resolution_chain() {
        // Known Health::Critical wins over anything in raw severity.
        assert_eq!(
            health_to_severity(&Health::Critical)
                .or_else(|| Some(normalize_redfish_severity("WARNING"))),
            Some("Critical"),
            "known Health should win"
        );

        // UnsupportedValue falls back to normalized raw severity.
        let fallback = health_to_severity(&Health::UnsupportedValue)
            .or_else(|| Some(normalize_redfish_severity("CRITICAL")));
        assert_eq!(
            fallback,
            Some("Critical"),
            "UnsupportedValue should fall back to raw"
        );

        // UnsupportedValue with no raw severity produces None from the chain.
        let no_raw: Option<&str> = health_to_severity(&Health::UnsupportedValue).or(None);
        assert!(
            no_raw.is_none(),
            "UnsupportedValue with no raw should be None"
        );
    }

    /// Verifies that message_severity attribute is omitted for UnsupportedValue.
    #[test]
    fn health_to_severity_omits_attribute_for_unsupported() {
        // health_to_severity returns None for UnsupportedValue, so the caller
        // skips pushing the message_severity OTLP attribute.
        assert!(
            health_to_severity(&Health::UnsupportedValue).is_none(),
            "UnsupportedValue must return None so the attribute is not emitted"
        );
        // All known variants return Some so the attribute IS emitted.
        assert!(health_to_severity(&Health::Critical).is_some());
        assert!(health_to_severity(&Health::Warning).is_some());
        assert!(health_to_severity(&Health::Ok).is_some());
    }
}
