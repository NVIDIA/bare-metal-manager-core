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

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use prometheus::{Counter, Gauge, Histogram, HistogramOpts, IntGauge, Opts};
use tokio_util::sync::CancellationToken;

use super::client::{GnmiClient, nvue_subscribe_paths};
use super::proto;
use super::sample_processor::{GnmiSampleProcessor, NVUE_GNMI_SAMPLE_STREAM_ID, now_unix_secs};
use crate::HealthError;
use crate::collectors::Collector;
use crate::collectors::runtime::{BackoffConfig, ExponentialBackoff, StreamingConnectionGuard};
use crate::config::NvueGnmiConfig;
use crate::endpoint::BmcEndpoint;
use crate::metrics::CollectorRegistry;
use crate::sink::{DataSink, EventContext};

// gRPC ConnectivityState values for `connection_state`. 0 (UNKNOWN) is the gauge default.
const IDLE: i64 = 1;
const CONNECTING: i64 = 2;
const READY: i64 = 3;
const TRANSIENT_FAILURE: i64 = 4;
const SHUTDOWN: i64 = 5;

pub(crate) struct GnmiStreamMetrics {
    pub(crate) connection_state: IntGauge,
    /// binary "is this stream live right now?" -- guard-managed, mirrors SSE's `connected` gauge
    pub(crate) connected: IntGauge,
    pub(crate) reconnections_total: Counter,
    pub(crate) server_initiated_closures_total: Counter,
    pub(crate) connection_established_timestamp: Gauge,
    pub(crate) notifications_received_total: Counter,
    pub(crate) last_notification_timestamp: Gauge,
    pub(crate) notification_processing_seconds: Histogram,
    pub(crate) stream_errors_total: Counter,
    pub(crate) monitored_entities: Gauge,
}

impl GnmiStreamMetrics {
    fn new(
        registry: &prometheus::Registry,
        prefix: &str,
        stream_name: &str,
        const_labels: HashMap<String, String>,
    ) -> Result<Self, HealthError> {
        let connection_state = IntGauge::with_opts(
            Opts::new(
                format!("{prefix}_nvue_gnmi{stream_name}_connection_state"),
                "gRPC connection state: 0=UNKNOWN, 1=IDLE, 2=CONNECTING, 3=READY, 4=TRANSIENT_FAILURE, 5=SHUTDOWN",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(connection_state.clone()))?;

        let connected = IntGauge::with_opts(
            Opts::new(
                format!("{prefix}_nvue_gnmi{stream_name}_stream_connected"),
                "1 while the stream is connected (READY), 0 otherwise. Mirrors the SSE collector's stream_connected gauge for aggregate streaming dashboards.",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(connected.clone()))?;

        let reconnections_total = Counter::with_opts(
            Opts::new(
                format!("{prefix}_nvue_gnmi{stream_name}_reconnections_total"),
                "Total reconnection attempts",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(reconnections_total.clone()))?;

        let server_initiated_closures_total = Counter::with_opts(
            Opts::new(
                format!("{prefix}_nvue_gnmi{stream_name}_server_initiated_closures_total"),
                "Total times the server closed the stream cleanly",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(server_initiated_closures_total.clone()))?;

        let connection_established_timestamp = Gauge::with_opts(
            Opts::new(
                format!("{prefix}_nvue_gnmi{stream_name}_connection_established_timestamp"),
                "Unix timestamp when current connection was established. Compute uptime via time() - this_metric.",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(connection_established_timestamp.clone()))?;

        let notifications_received_total = Counter::with_opts(
            Opts::new(
                format!("{prefix}_nvue_gnmi{stream_name}_notifications_received_total"),
                "Total notification messages received",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(notifications_received_total.clone()))?;

        let last_notification_timestamp = Gauge::with_opts(
            Opts::new(
                format!("{prefix}_nvue_gnmi{stream_name}_last_notification_timestamp"),
                "Unix timestamp of most recent notification",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(last_notification_timestamp.clone()))?;

        let notification_processing_seconds = Histogram::with_opts(
            HistogramOpts::new(
                format!("{prefix}_nvue_gnmi{stream_name}_notification_processing_seconds"),
                "Per-notification processing time",
            )
            .const_labels(const_labels.clone())
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0]),
        )?;
        registry.register(Box::new(notification_processing_seconds.clone()))?;

        let stream_errors_total = Counter::with_opts(
            Opts::new(
                format!("{prefix}_nvue_gnmi{stream_name}_stream_errors_total"),
                "Total stream errors",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(stream_errors_total.clone()))?;

        let monitored_entities = Gauge::with_opts(
            Opts::new(
                format!("{prefix}_nvue_gnmi{stream_name}_monitored_entities"),
                "Unique entities in most recent notification batch",
            )
            .const_labels(const_labels),
        )?;
        registry.register(Box::new(monitored_entities.clone()))?;

        Ok(Self {
            connection_state,
            connected,
            reconnections_total,
            server_initiated_closures_total,
            connection_established_timestamp,
            notifications_received_total,
            last_notification_timestamp,
            notification_processing_seconds,
            stream_errors_total,
            monitored_entities,
        })
    }
}

struct GnmiStreamConfig {
    client: GnmiClient,
    paths: Vec<proto::Path>,
    sample_interval_nanos: u64,
}

pub fn spawn_gnmi_collector(
    endpoint: &BmcEndpoint,
    gnmi_config: &NvueGnmiConfig,
    collector_registry: Arc<CollectorRegistry>,
    data_sink: Option<Arc<dyn DataSink>>,
) -> Result<Collector, HealthError> {
    let switch_id = endpoint
        .metadata
        .as_ref()
        .and_then(|m| m.serial_number().map(str::to_string))
        .unwrap_or_else(|| endpoint.addr.mac.to_string());
    let switch_ip = endpoint.addr.ip.to_string();
    let sample_event_context = EventContext::from_endpoint(endpoint, NVUE_GNMI_SAMPLE_STREAM_ID);

    let (username, password) = match endpoint.credentials() {
        crate::endpoint::BmcCredentials::UsernamePassword { username, password } => {
            (Some(username), password)
        }
        crate::endpoint::BmcCredentials::SessionToken { .. } => {
            return Err(HealthError::GnmiError(
                "gNMI collector does not support SessionToken credentials; expected UsernamePassword"
                    .into(),
            ));
        }
    };
    let client = GnmiClient::new(
        switch_id.clone(),
        &switch_ip,
        gnmi_config.gnmi_port,
        username,
        password,
        gnmi_config.request_timeout,
    );

    let registry = collector_registry.registry();
    let prefix = collector_registry.prefix().clone();

    let sample_const_labels = HashMap::from([
        (
            "collector_type".to_string(),
            NVUE_GNMI_SAMPLE_STREAM_ID.to_string(),
        ),
        ("endpoint_key".to_string(), endpoint.hash_key().into_owned()),
    ]);

    let sample_stream_metrics = GnmiStreamMetrics::new(registry, &prefix, "", sample_const_labels)?;

    let sample_config = GnmiStreamConfig {
        client,
        paths: nvue_subscribe_paths(&gnmi_config.paths),
        sample_interval_nanos: gnmi_config.sample_interval.as_nanos() as u64,
    };

    let sample_processor = GnmiSampleProcessor {
        data_sink,
        event_context: sample_event_context,
        switch_id,
    };

    Ok(Collector::spawn_task(move |cancel_token| async move {
        gnmi_sample_task(
            cancel_token,
            sample_config,
            sample_stream_metrics,
            sample_processor,
        )
        .await;
    }))
}

async fn gnmi_sample_task(
    cancel_token: CancellationToken,
    config: GnmiStreamConfig,
    stream_metrics: GnmiStreamMetrics,
    sample_processor: GnmiSampleProcessor,
) {
    let mut backoff = ExponentialBackoff::new(&BackoffConfig {
        initial: Duration::from_secs(2),
        max: Duration::from_secs(60),
    });

    loop {
        stream_metrics.connection_state.set(CONNECTING);

        let Some(stream) = cancel_token
            .run_until_cancelled(
                config
                    .client
                    .subscribe_sample(&config.paths, config.sample_interval_nanos),
            )
            .await
        else {
            stream_metrics.connection_state.set(SHUTDOWN);
            return;
        };

        match stream {
            Err(e) => {
                stream_metrics.connection_state.set(TRANSIENT_FAILURE);
                stream_metrics.reconnections_total.inc();
                tracing::warn!(
                    error = ?e,
                    switch_id = %sample_processor.switch_id,
                    "nvue_gnmi SAMPLE: connection failed, backing off"
                );
            }
            Ok(mut stream) => {
                stream_metrics.connection_state.set(READY);
                stream_metrics
                    .connection_established_timestamp
                    .set(now_unix_secs());
                let _conn_guard = StreamingConnectionGuard::inc(stream_metrics.connected.clone());
                backoff.reset();
                tracing::info!(
                    switch_id = %sample_processor.switch_id,
                    "nvue_gnmi SAMPLE: stream connected"
                );

                loop {
                    let Some(msg) = cancel_token.run_until_cancelled(stream.message()).await else {
                        stream_metrics.connection_state.set(SHUTDOWN);
                        tracing::info!(
                            switch_id = %sample_processor.switch_id,
                            "nvue_gnmi SAMPLE: cancelled, shutting down"
                        );
                        return;
                    };

                    match msg {
                        Ok(Some(resp)) => {
                            sample_processor.process_subscribe_response(&resp, &stream_metrics);
                        }
                        Ok(None) => {
                            stream_metrics.connection_state.set(IDLE);
                            stream_metrics.server_initiated_closures_total.inc();
                            tracing::info!(
                                switch_id = %sample_processor.switch_id,
                                "nvue_gnmi SAMPLE: stream closed by server, reconnecting"
                            );
                            backoff.reset();
                            break;
                        }
                        Err(e) => {
                            stream_metrics.connection_state.set(TRANSIENT_FAILURE);
                            stream_metrics.stream_errors_total.inc();
                            stream_metrics.reconnections_total.inc();
                            tracing::warn!(
                                error = ?e,
                                switch_id = %sample_processor.switch_id,
                                "nvue_gnmi SAMPLE: stream error, reconnecting"
                            );
                            break;
                        }
                    }
                }
            }
        }

        if cancel_token
            .run_until_cancelled(tokio::time::sleep(backoff.next_delay()))
            .await
            .is_none()
        {
            stream_metrics.connection_state.set(SHUTDOWN);
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_labels() -> HashMap<String, String> {
        HashMap::from([
            ("switch_id".to_string(), "test-switch".to_string()),
            ("switch_ip".to_string(), "10.0.0.1".to_string()),
        ])
    }

    #[test]
    fn test_stream_metrics_registers_all_counters() {
        let registry = prometheus::Registry::new();
        let metrics = GnmiStreamMetrics::new(&registry, "test", "", test_labels()).unwrap();

        metrics.reconnections_total.inc();
        assert_eq!(metrics.reconnections_total.get(), 1.0);

        metrics.server_initiated_closures_total.inc();
        assert_eq!(metrics.server_initiated_closures_total.get(), 1.0);

        metrics.stream_errors_total.inc();
        assert_eq!(metrics.stream_errors_total.get(), 1.0);
    }

    #[test]
    fn test_stream_metrics_server_closures_independent_from_reconnections() {
        let registry = prometheus::Registry::new();
        let metrics = GnmiStreamMetrics::new(&registry, "test", "", test_labels()).unwrap();

        metrics.server_initiated_closures_total.inc();
        metrics.server_initiated_closures_total.inc();
        assert_eq!(metrics.server_initiated_closures_total.get(), 2.0);
        assert_eq!(metrics.reconnections_total.get(), 0.0);

        metrics.reconnections_total.inc();
        assert_eq!(metrics.reconnections_total.get(), 1.0);
        assert_eq!(metrics.server_initiated_closures_total.get(), 2.0);
    }

    #[test]
    fn test_stream_metrics_duplicate_registration_fails() {
        let registry = prometheus::Registry::new();
        let _ = GnmiStreamMetrics::new(&registry, "test", "", test_labels()).unwrap();
        let result = GnmiStreamMetrics::new(&registry, "test", "", test_labels());
        assert!(result.is_err());
    }

    #[test]
    fn test_stream_metrics_distinct_stream_names_coexist() {
        let registry = prometheus::Registry::new();
        let sample = GnmiStreamMetrics::new(&registry, "test", "", test_labels()).unwrap();
        let events_labels = HashMap::from([
            ("switch_id".to_string(), "test-switch".to_string()),
            ("switch_ip".to_string(), "10.0.0.2".to_string()),
        ]);
        let events = GnmiStreamMetrics::new(&registry, "test", "_events", events_labels).unwrap();

        sample.server_initiated_closures_total.inc();
        assert_eq!(sample.server_initiated_closures_total.get(), 1.0);
        assert_eq!(events.server_initiated_closures_total.get(), 0.0);
    }
}
