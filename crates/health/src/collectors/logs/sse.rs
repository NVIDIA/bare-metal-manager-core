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
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use futures::StreamExt;
use nv_redfish::core::{Bmc, EntityTypeRef, NavProperty};
use nv_redfish::event_service::{Event, EventStreamPayload};
use tokio::sync::Semaphore;

use super::diagnostic::{
    DiagnosticPayload, make_diagnostic_record, nullable_ref, nullable_str, redfish_enum_string,
};
use super::redfish::{
    RedfishLogFields, RedfishSeverity, add_redfish_analyzer_attributes, event_diagnostic_is_cper,
    nvidia_error_id, redfish_event_type_string, redfish_log_type,
};
use crate::HealthError;
use crate::collectors::runtime::{
    EventStream, StreamingCollector, StreamingConnectResult, open_sse_stream,
};
use crate::endpoint::BmcEndpoint;
use crate::sink::{CollectorEvent, LogRecord};

const EVENT_RECORD_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(10);
const EVENT_RECORD_RETRY_INITIAL_BACKOFF: Duration = Duration::from_millis(100);
const EVENT_RECORD_RETRY_MAX_BACKOFF: Duration = Duration::from_secs(1);

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

    /// Bounds event-record resolution to the endpoint Redfish operation limit.
    pub request_concurrency: NonZeroUsize,
}

pub struct SseLogCollector<B: Bmc> {
    bmc: Arc<B>,
    include_diagnostics: bool,
    request_concurrency: usize,
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
            request_concurrency: config.request_concurrency.get(),
        })
    }

    async fn connect(&mut self) -> Result<StreamingConnectResult<'_>, HealthError> {
        let sse_stream = open_sse_stream(Arc::clone(&self.bmc)).await?;

        let event_stream = map_event_stream(
            sse_stream,
            Arc::clone(&self.bmc),
            self.include_diagnostics,
            self.request_concurrency,
        );

        Ok(StreamingConnectResult::Connected(event_stream))
    }

    fn collector_type(&self) -> &'static str {
        "sse_logs"
    }
}

fn map_event_stream<'a, B, S>(
    sse_stream: S,
    bmc: Arc<B>,
    include_diagnostics: bool,
    request_concurrency: usize,
) -> EventStream<'a>
where
    B: Bmc + 'static,
    S: futures::Stream<Item = Result<EventStreamPayload, HealthError>> + Send + 'a,
{
    let fetch_permits = Arc::new(Semaphore::new(request_concurrency));

    sse_stream
        .map(move |result| {
            let bmc = Arc::clone(&bmc);
            let fetch_permits = Arc::clone(&fetch_permits);
            async move {
                map_payload(
                    result,
                    bmc.as_ref(),
                    include_diagnostics,
                    fetch_permits.as_ref(),
                )
                .await
            }
        })
        .buffered(request_concurrency)
        .flat_map(futures::stream::iter)
        .boxed()
}

async fn map_payload<B: Bmc>(
    result: Result<EventStreamPayload, HealthError>,
    bmc: &B,
    include_diagnostics: bool,
    fetch_permits: &Semaphore,
) -> Vec<Result<CollectorEvent, HealthError>> {
    match result {
        Ok(EventStreamPayload::Event(event)) => {
            event_to_logs(
                &event,
                bmc,
                include_diagnostics,
                fetch_permits,
                EVENT_RECORD_RESOLUTION_TIMEOUT,
            )
            .await
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
    fetch_permits: &Semaphore,
    resolution_timeout: Duration,
) -> Vec<Result<CollectorEvent, HealthError>> {
    let deadline = tokio::time::Instant::now() + resolution_timeout;

    futures::future::join_all(
        event
            .events
            .iter()
            .map(|nav| resolve_event_record(nav, bmc, fetch_permits, deadline)),
    )
    .await
    .into_iter()
    .flatten()
    .map(|record| Ok(record_to_log(&record, include_diagnostics)))
    .collect()
}

async fn resolve_event_record<B: Bmc>(
    nav: &nv_redfish::core::NavProperty<nv_redfish::schema::event::EventRecord>,
    bmc: &B,
    fetch_permits: &Semaphore,
    deadline: tokio::time::Instant,
) -> Option<Arc<nv_redfish::schema::event::EventRecord>> {
    let odata_id = nav.odata_id().to_string();
    let is_reference = matches!(nav, NavProperty::Reference(_));
    let mut retry_backoff = EVENT_RECORD_RETRY_INITIAL_BACKOFF;

    loop {
        let get_record = async {
            let _permit = if is_reference {
                Some(
                    fetch_permits
                        .acquire()
                        .await
                        .expect("event record fetch semaphore remains open"),
                )
            } else {
                None
            };
            nav.get(bmc).await
        };

        match tokio::time::timeout_at(deadline, get_record).await {
            Ok(Ok(record)) => return Some(record),
            Ok(Err(error)) if is_reference => {
                let retry_at = (tokio::time::Instant::now() + retry_backoff).min(deadline);
                tokio::time::sleep_until(retry_at).await;
                if retry_at == deadline {
                    carbide_instrument::emit(EventRecordResolutionFailed {
                        reason: EventRecordResolutionFailure::Fetch,
                        odata_id,
                        error: error.to_string(),
                    });
                    return None;
                }
                retry_backoff = (retry_backoff * 2).min(EVENT_RECORD_RETRY_MAX_BACKOFF);
            }
            Ok(Err(error)) => {
                carbide_instrument::emit(EventRecordResolutionFailed {
                    reason: EventRecordResolutionFailure::Fetch,
                    odata_id,
                    error: error.to_string(),
                });
                return None;
            }
            Err(error) => {
                carbide_instrument::emit(EventRecordResolutionFailed {
                    reason: EventRecordResolutionFailure::Timeout,
                    odata_id,
                    error: error.to_string(),
                });
                return None;
            }
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
        has_cper: record.cper.is_some()
            || nullable_ref(&record.diagnostic_data_type).is_some_and(event_diagnostic_is_cper),
    };
    let log_type = redfish_log_type(redfish_fields);
    let body = record.message.as_deref().unwrap_or_default().to_string();

    // Fallback for a missing or unreadable Severity
    let severity = record
        .message_severity
        .as_ref()
        .and_then(RedfishSeverity::from_health)
        .or_else(|| record.severity.as_deref().map(RedfishSeverity::from_raw))
        .unwrap_or(RedfishSeverity::Unknown);

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
        severity,
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
    if let Some(message_severity) = record
        .message_severity
        .as_ref()
        .and_then(RedfishSeverity::from_health)
    {
        attributes.push((
            Cow::Borrowed("message_severity"),
            message_severity.as_str().to_string(),
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
    if let Some(oem) = &record.base.base.oem {
        attributes.push((
            Cow::Borrowed("redfish.oem"),
            oem.additional_properties.to_string(),
        ));
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
        severity: severity.into(),
        attributes,
        diagnostic_record,
    }))
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::{Json, Router};
    use bmc_mock::test_support::axum_http_client::AxumRouterHttpClient;
    use futures::FutureExt;
    use nv_redfish::bmc_http::{BmcCredentials, CacheSettings, HttpBmc};
    use serde_json::{Value, json};
    use url::Url;

    use super::*;
    use crate::endpoint::test_support::{mac, test_endpoint};
    use crate::sink::LogSeverity;

    async fn event_to_logs_with_timeout<B: Bmc>(
        event: &Event,
        bmc: &B,
        include_diagnostics: bool,
        resolution_timeout: Duration,
    ) -> Vec<Result<CollectorEvent, HealthError>> {
        let fetch_permits = Semaphore::new(event.events.len().max(1));
        event_to_logs(
            event,
            bmc,
            include_diagnostics,
            &fetch_permits,
            resolution_timeout,
        )
        .await
    }

    #[tokio::test]
    async fn sse_event_preserves_oem_extensions() -> Result<(), HealthError> {
        let payload = serde_json::from_value(serde_json::json!({
            "@odata.id": "/redfish/v1/EventService/SSE#/Event1",
            "@odata.type": "#Event.v1_0_0.Event",
            "Id": "1",
            "Name": "Event Array",
            "Events": [
                {
                    "@odata.id": "/redfish/v1/EventService/SSE#/Events/1",
                    "MemberId": "1",
                    "EventType": "Alert",
                    "MessageId": "Example.1.0.Event",
                    "Oem": {
                        "Nvidia": {
                            "ErrorId": "example-error-id"
                        }
                    }
                }
            ]
        }))?;

        let endpoint = test_endpoint(mac("00:11:22:33:44:55"));

        let fetch_permits = Semaphore::new(1);
        let events = map_payload(Ok(payload), endpoint.bmc().as_ref(), false, &fetch_permits).await;

        let [Ok(CollectorEvent::Log(record))] = events.as_slice() else {
            panic!("expected one SSE log record");
        };

        let oem = record
            .attributes
            .iter()
            .find_map(|(key, value)| (key.as_ref() == "redfish.oem").then_some(value));

        assert_eq!(
            oem.map(String::as_str),
            Some(r#"{"Nvidia":{"ErrorId":"example-error-id"}}"#)
        );

        Ok(())
    }

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

    #[tokio::test(start_paused = true)]
    async fn referenced_event_record_is_retried_until_available() {
        let path = "/redfish/v1/EventService/Events/records/delayed";
        let payload = c12_platform_record(path);
        let request_count = Arc::new(AtomicUsize::new(0));
        let handler_request_count = Arc::clone(&request_count);
        let router = Router::new().route(
            path,
            get(move || {
                let payload = payload.clone();
                let request_count = Arc::clone(&handler_request_count);
                async move {
                    if request_count.fetch_add(1, Ordering::SeqCst) == 0 {
                        StatusCode::NOT_FOUND.into_response()
                    } else {
                        Json(payload).into_response()
                    }
                }
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

        assert_eq!(request_count.load(Ordering::SeqCst), 2);
        assert_eq!(logs.len(), 1);
        let event = logs[0]
            .as_ref()
            .expect("record should be emitted after retry");
        assert_eq!(
            attribute(log_record(event), "oem.nvidia.error_id"),
            Some("CPLD-PSEQ-FAULT")
        );
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
    async fn hung_reference_does_not_drop_ready_sibling_record() {
        let hung_path = "/redfish/v1/EventService/Events/records/hung";
        let good_path = "/redfish/v1/EventService/Events/records/good";
        let payload = c12_platform_record(good_path);
        let router = Router::new()
            .route(
                hung_path,
                get(|| async { std::future::pending::<Json<Value>>().await }),
            )
            .route(
                good_path,
                get(move || {
                    let payload = payload.clone();
                    async move { Json(payload) }
                }),
            );
        let bmc = test_bmc(router);
        let resolution_timeout = Duration::from_secs(1);
        let started_at = tokio::time::Instant::now();

        let logs = event_to_logs_with_timeout(
            &referenced_event(&[hung_path, good_path]),
            &bmc,
            false,
            resolution_timeout,
        )
        .await;

        assert_eq!(tokio::time::Instant::now() - started_at, resolution_timeout);
        assert_eq!(logs.len(), 1);
        let event = logs[0].as_ref().expect("ready sibling should be emitted");
        assert_eq!(
            attribute(log_record(event), "oem.nvidia.error_id"),
            Some("CPLD-PSEQ-FAULT")
        );
    }

    #[tokio::test(start_paused = true)]
    async fn request_concurrency_limits_event_record_gets() {
        let first_path = "/redfish/v1/EventService/Events/records/hung";
        let second_path = "/redfish/v1/EventService/Events/records/waiting";
        let first_request_started = Arc::new(tokio::sync::Notify::new());
        let second_request_started = Arc::new(tokio::sync::Notify::new());
        let first_notification = Arc::clone(&first_request_started);
        let second_notification = Arc::clone(&second_request_started);
        let payload = c12_platform_record(second_path);
        let router = Router::new()
            .route(
                first_path,
                get(move || {
                    let first_notification = Arc::clone(&first_notification);
                    async move {
                        first_notification.notify_one();
                        std::future::pending::<Json<Value>>().await
                    }
                }),
            )
            .route(
                second_path,
                get(move || {
                    let second_notification = Arc::clone(&second_notification);
                    let payload = payload.clone();
                    async move {
                        second_notification.notify_one();
                        Json(payload)
                    }
                }),
            );
        let bmc = test_bmc(router);
        let event = referenced_event(&[first_path, second_path]);
        let fetch_permits = Arc::new(Semaphore::new(1));
        let task_permits = Arc::clone(&fetch_permits);

        let task = tokio::spawn(async move {
            event_to_logs(
                &event,
                &bmc,
                false,
                task_permits.as_ref(),
                Duration::from_secs(1),
            )
            .await
        });

        first_request_started.notified().await;
        assert_eq!(fetch_permits.available_permits(), 0);
        assert!(second_request_started.notified().now_or_never().is_none());

        task.await.expect("event resolution task should complete");
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

        let logs = event_to_logs_with_timeout(
            &referenced_event(&[first_path, second_path]),
            &bmc,
            false,
            EVENT_RECORD_RESOLUTION_TIMEOUT,
        )
        .await;

        assert!(logs.is_empty());
        assert_eq!(EVENT_RECORD_RESOLUTION_TIMEOUT, Duration::from_secs(10));
        assert_eq!(
            tokio::time::Instant::now() - started_at,
            EVENT_RECORD_RESOLUTION_TIMEOUT
        );
    }

    #[tokio::test(start_paused = true)]
    async fn slow_payload_does_not_block_sse_stream_polling() {
        let hung_path = "/redfish/v1/EventService/Events/records/hung";
        let good_path = "/redfish/v1/EventService/Events/records/good";
        let good_request_started = Arc::new(tokio::sync::Notify::new());
        let request_notification = Arc::clone(&good_request_started);
        let payload = c12_platform_record(good_path);
        let router = Router::new()
            .route(
                hung_path,
                get(|| async { std::future::pending::<Json<Value>>().await }),
            )
            .route(
                good_path,
                get(move || {
                    let request_notification = Arc::clone(&request_notification);
                    let payload = payload.clone();
                    async move {
                        request_notification.notify_one();
                        Json(payload)
                    }
                }),
            );
        let bmc = Arc::new(test_bmc(router));
        let sse_stream = futures::stream::iter([
            Ok(EventStreamPayload::Event(referenced_event(&[hung_path]))),
            Ok(EventStreamPayload::Event(referenced_event(&[good_path]))),
        ]);
        let mut event_stream = map_event_stream(sse_stream, bmc, false, 2);
        let next_event = tokio::spawn(async move { event_stream.next().await });

        tokio::time::timeout(Duration::from_secs(1), good_request_started.notified())
            .await
            .expect("later SSE payload should be polled before the first payload times out");

        let event = next_event
            .await
            .expect("event stream task should complete")
            .expect("ready payload should emit an event")
            .expect("ready payload should emit a log");
        assert_eq!(
            attribute(log_record(&event), "oem.nvidia.error_id"),
            Some("CPLD-PSEQ-FAULT")
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

    fn severity_record(
        message_severity: Option<&str>,
        severity: Option<&str>,
    ) -> nv_redfish::schema::event::EventRecord {
        let mut value = json!({
            "@odata.id": "/redfish/v1/EventService/Events/records/1",
            "MemberId": "0",
            "EventType": "Alert",
            "MessageId": "Example.1.0.Event",
        });
        if let Some(message_severity) = message_severity {
            value["MessageSeverity"] = json!(message_severity);
        }
        if let Some(severity) = severity {
            value["Severity"] = json!(severity);
        }
        serde_json::from_value(value).expect("valid event record")
    }

    /// Exercises the severity chain through `record_to_log`: the schema field
    /// wins, a value the schema could not parse falls back to the raw
    /// `Severity` string, and `message_severity` is emitted only when the
    /// schema field parsed.
    #[test]
    fn severity_resolution_chain() {
        let event = record_to_log(&severity_record(Some("Critical"), Some("WARNING")), false);
        let record = log_record(&event);
        assert_eq!(record.severity, LogSeverity::Fatal);
        assert_eq!(
            attribute(record, "redfish.event.severity"),
            Some("Critical")
        );
        assert_eq!(attribute(record, "message_severity"), Some("Critical"));

        // "CRITICAL" is outside the schema, so MessageSeverity lands on
        // UnsupportedValue and the raw Severity string carries the value.
        let event = record_to_log(&severity_record(Some("CRITICAL"), Some("Critical")), false);
        let record = log_record(&event);
        assert_eq!(record.severity, LogSeverity::Fatal);
        assert_eq!(
            attribute(record, "redfish.event.severity"),
            Some("Critical")
        );
        assert_eq!(attribute(record, "message_severity"), None);

        let event = record_to_log(&severity_record(None, None), false);
        let record = log_record(&event);
        assert_eq!(record.severity, LogSeverity::Unspecified);
        assert_eq!(attribute(record, "redfish.event.severity"), Some("Unknown"));
        assert_eq!(attribute(record, "message_severity"), None);

        let event = record_to_log(&severity_record(Some("Meltdown"), None), false);
        let record = log_record(&event);
        assert_eq!(record.severity, LogSeverity::Unspecified);
        assert_eq!(attribute(record, "redfish.event.severity"), Some("Unknown"));
        assert_eq!(attribute(record, "message_severity"), None);
    }
}
