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
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::stream::BoxStream;
use futures::{StreamExt, TryStreamExt};
use http::header::InvalidHeaderValue;
use http::{HeaderMap, StatusCode, header};
use nv_redfish::ServiceRoot;
use nv_redfish::bmc_http::reqwest::{BmcError, Client as ReqwestClient};
use nv_redfish::bmc_http::{CacheSettings, HttpBmc};
use nv_redfish::core::Bmc;
use nv_redfish::event_service::EventStreamPayload;
use prometheus::{Counter, Gauge, Histogram, HistogramOpts, IntCounter, IntGauge, Opts};
use rand::Rng;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::HealthError;
use crate::config::Config as AppConfig;
use crate::discovery::BmcClient;
use crate::endpoint::BmcEndpoint;
use crate::limiter::RateLimiter;
use crate::metrics::{
    CollectorRegistry, ComponentKind, MetricsManager, operation_duration_buckets_seconds,
};
use crate::sink::{CollectorEvent, DataSink, EventContext};

/// Result of a collector iteration
#[derive(Debug, Clone)]
pub struct IterationResult {
    /// Whether a refresh was triggered (data was fetched vs cached)
    pub refresh_triggered: bool,
    /// Number of entities collected, if applicable
    pub entity_count: Option<usize>,
    /// Number of partial fetch failures tolerated during the iteration
    pub fetch_failures: usize,
}

pub trait PeriodicCollector<B: Bmc>: Send + 'static {
    type Config: Send + 'static;

    fn new_runner(
        bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError>
    where
        Self: Sized;

    fn run_iteration(
        &mut self,
    ) -> impl std::future::Future<Output = Result<IterationResult, HealthError>> + Send;

    /// Returns the type identifier for this collector
    fn collector_type(&self) -> &'static str;
}

pub type EventStream<'a> = BoxStream<'a, Result<CollectorEvent, HealthError>>;

/// Trait for collectors that maintain a long-lived stream (SSE, gRPC, etc.)
/// runtime.rs creates the BMC client and injects it, the collector opens the stream and maps payloads to events
#[async_trait]
pub trait StreamingCollector<B: Bmc>: Send + 'static {
    type Config: Send + 'static;

    fn new_runner(
        bmc: Arc<B>,
        endpoint: Arc<BmcEndpoint>,
        config: Self::Config,
    ) -> Result<Self, HealthError>
    where
        Self: Sized;

    /// Open or reopen the streaming connection using the injected BMC.
    async fn connect(&mut self) -> Result<EventStream<'_>, HealthError>;

    fn collector_type(&self) -> &'static str;
}

pub struct BackoffConfig {
    pub initial: Duration,
    pub max: Duration,
}

impl Default for BackoffConfig {
    fn default() -> Self {
        Self {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
        }
    }
}

pub struct ExponentialBackoff {
    initial: Duration,
    max: Duration,
    current: Duration,
}

impl ExponentialBackoff {
    pub fn new(config: &BackoffConfig) -> Self {
        Self {
            initial: config.initial,
            max: config.max,
            current: config.initial,
        }
    }

    pub fn next_delay(&mut self) -> Duration {
        let base = self.current;
        self.current = (self.current * 2).min(self.max);
        let jitter_ms = rand::rng().random_range(0..base.as_millis().max(1) as u64);
        base + Duration::from_millis(jitter_ms)
    }

    pub fn reset(&mut self) {
        self.current = self.initial;
    }
}

pub type SseStream = Pin<
    Box<
        dyn futures::TryStream<
                Ok = EventStreamPayload,
                Error = HealthError,
                Item = Result<EventStreamPayload, HealthError>,
            > + Send,
    >,
>;

/// Open a Redfish SSE event stream from a BMC.
pub async fn open_sse_stream<B: Bmc + 'static>(bmc: Arc<B>) -> Result<SseStream, HealthError> {
    let root = ServiceRoot::new(bmc)
        .await
        .map_err(|e| HealthError::BmcError(Box::new(e)))?;

    let event_service = root
        .event_service()
        .await
        .map_err(|e| HealthError::BmcError(Box::new(e)))?
        .ok_or_else(|| {
            HealthError::SseNotAvailable("BMC does not expose an EventService".to_string())
        })?;

    let stream = event_service
        .events()
        .await
        .map_err(|e| HealthError::BmcError(Box::new(e)))?;

    Ok(Box::pin(
        stream.map_err(|e| HealthError::BmcError(Box::new(e))),
    ))
}

pub struct StreamMetrics {
    connected: IntGauge,
    reconnections_total: Counter,
    items_processed_total: Counter,
    stream_errors_total: Counter,
}

impl StreamMetrics {
    fn new(
        registry: &prometheus::Registry,
        prefix: &str,
        const_labels: HashMap<String, String>,
    ) -> Result<Self, HealthError> {
        let connected = IntGauge::with_opts(
            Opts::new(
                format!("{prefix}_stream_connected"),
                "1 while the stream is connected, 0 otherwise",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(connected.clone()))?;

        let reconnections_total = Counter::with_opts(
            Opts::new(
                format!("{prefix}_stream_reconnections_total"),
                "Total reconnection attempts",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(reconnections_total.clone()))?;

        let items_processed_total = Counter::with_opts(
            Opts::new(
                format!("{prefix}_stream_items_processed_total"),
                "Total stream items processed",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(items_processed_total.clone()))?;

        let stream_errors_total = Counter::with_opts(
            Opts::new(
                format!("{prefix}_stream_errors_total"),
                "Total stream errors",
            )
            .const_labels(const_labels),
        )?;
        registry.register(Box::new(stream_errors_total.clone()))?;

        Ok(Self {
            connected,
            reconnections_total,
            items_processed_total,
            stream_errors_total,
        })
    }
}

/// RAII guard: increments `active_sse_connections` on construction, decrements on drop.
/// Ensures every exit path from a connected stream (cancel, error, end, reconnect) dec's.
struct SseConnectionGuard(IntGauge);

impl SseConnectionGuard {
    fn inc(gauge: IntGauge) -> Self {
        gauge.inc();
        Self(gauge)
    }
}

impl Drop for SseConnectionGuard {
    fn drop(&mut self) {
        self.0.dec();
    }
}

pub struct Collector {
    handle: JoinHandle<()>,
    cancel_token: CancellationToken,
}

fn create_bmc(
    client: ReqwestClient,
    endpoint: &BmcEndpoint,
    health_options: &AppConfig,
) -> Result<Arc<BmcClient>, HealthError> {
    let bmc_url = match &health_options.bmc_proxy_url {
        Some(url) => url.clone(),
        None => endpoint
            .addr
            .to_url()
            .map_err(|e| HealthError::GenericError(e.to_string()))?,
    };

    let headers = if health_options.bmc_proxy_url.is_some() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::FORWARDED,
            format!("host={}", endpoint.addr.ip)
                .parse()
                .map_err(|e: InvalidHeaderValue| HealthError::GenericError(e.to_string()))?,
        );
        headers
    } else {
        HeaderMap::new()
    };

    let initial_credentials = endpoint.credentials();
    Ok(Arc::new(HttpBmc::with_custom_headers(
        client,
        bmc_url,
        initial_credentials.into(),
        CacheSettings::with_capacity(health_options.cache_size),
        headers,
    )))
}

pub struct CollectorStartContext {
    pub limiter: Arc<dyn RateLimiter>,
    pub iteration_interval: Duration,
    pub collector_registry: Arc<CollectorRegistry>,
    pub metrics_manager: Arc<MetricsManager>,
    pub client: ReqwestClient,
    pub health_options: Arc<AppConfig>,
}

pub struct StreamingCollectorStartContext {
    pub backoff_config: BackoffConfig,
    pub collector_registry: Arc<CollectorRegistry>,
    pub client: ReqwestClient,
    pub health_options: Arc<AppConfig>,
}

impl Collector {
    pub fn start<C: PeriodicCollector<BmcClient>>(
        endpoint: Arc<BmcEndpoint>,
        config: C::Config,
        start_context: CollectorStartContext,
    ) -> Result<Self, HealthError> {
        let CollectorStartContext {
            limiter,
            iteration_interval,
            collector_registry,
            metrics_manager,
            client,
            health_options,
        } = start_context;

        let cancel_token = CancellationToken::new();
        let cancel_token_clone = cancel_token.clone();

        let bmc = create_bmc(client, &endpoint, &health_options)?;

        let mut runner = C::new_runner(bmc.clone(), endpoint.clone(), config)?;

        let endpoint_key = endpoint.hash_key().to_string();
        let const_labels = HashMap::from([
            (
                "collector_type".to_string(),
                runner.collector_type().to_string(),
            ),
            ("endpoint_key".to_string(), endpoint_key),
        ]);

        let registry = collector_registry.registry();

        let iteration_histogram = Histogram::with_opts(
            HistogramOpts::new(
                format!(
                    "{}_collector_iteration_seconds",
                    collector_registry.prefix()
                ),
                "Duration of collector iterations",
            )
            .const_labels(const_labels.clone())
            .buckets(operation_duration_buckets_seconds()),
        )?;
        registry.register(Box::new(iteration_histogram.clone()))?;

        let refresh_counter = Counter::with_opts(
            Opts::new(
                format!("{}_collector_refresh_total", collector_registry.prefix()),
                "Count of collector refreshes",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(refresh_counter.clone()))?;

        let entities_gauge = Gauge::with_opts(
            Opts::new(
                format!("{}_monitored_entities", collector_registry.prefix()),
                "Number of entities being monitored",
            )
            .const_labels(const_labels.clone()),
        )?;
        registry.register(Box::new(entities_gauge.clone()))?;

        let fetch_failures_counter = IntCounter::with_opts(
            Opts::new(
                format!(
                    "{}_collector_fetch_failures_total",
                    collector_registry.prefix()
                ),
                "Count of partial collector fetch failures",
            )
            .const_labels(const_labels),
        )?;
        registry.register(Box::new(fetch_failures_counter.clone()))?;

        let component_metrics = metrics_manager.component_metrics();

        let handle = tokio::spawn(async move {
            let collector_type = runner.collector_type();
            let _collector_registry = collector_registry;
            loop {
                tokio::select! {
                    _ = cancel_token_clone.cancelled() => {
                        tracing::info!(endpoint = ?endpoint.addr, "collector cancelled");
                        break;
                    }
                    _ = async {
                        limiter.acquire().await;

                        let start = Instant::now();
                        let iteration_result = run_iteration_with_auth_refresh(
                            &mut runner,
                            &endpoint,
                            &bmc,
                        ).await;
                        let duration = start.elapsed();

                        iteration_histogram.observe(duration.as_secs_f64());
                        component_metrics.record_operation(
                            ComponentKind::Collector,
                            collector_type,
                            duration,
                            iteration_result.is_ok(),
                        );

                        match iteration_result {
                            Ok(result) => {
                                if result.refresh_triggered {
                                    refresh_counter.inc();
                                }

                                if let Some(entity_count) = result.entity_count {
                                    entities_gauge.set(entity_count as f64);
                                }

                                if result.fetch_failures > 0 {
                                    let fetch_failures = result.fetch_failures as u64;
                                    fetch_failures_counter.inc_by(fetch_failures);
                                }
                            }
                            Err(e) => {
                                tracing::error!(
                                    error = ?e,
                                    endpoint = ?endpoint.addr,
                                    collector_type = collector_type,
                                    "Error during collector iteration"
                                );
                            }
                        }

                        tokio::time::sleep(iteration_interval).await;
                    } => {
                    }
                }
            }
        });

        Ok(Self {
            handle,
            cancel_token,
        })
    }

    pub fn start_streaming<S: StreamingCollector<BmcClient>>(
        endpoint: Arc<BmcEndpoint>,
        config: S::Config,
        data_sink: Arc<dyn DataSink>,
        start_context: StreamingCollectorStartContext,
    ) -> Result<Self, HealthError> {
        let StreamingCollectorStartContext {
            backoff_config,
            collector_registry,
            client,
            health_options,
        } = start_context;

        let cancel_token = CancellationToken::new();
        let cancel_clone = cancel_token.clone();

        let bmc = create_bmc(client, &endpoint, &health_options)?;

        let mut collector = S::new_runner(bmc, endpoint.clone(), config)?;
        let event_context = EventContext::from_endpoint(&endpoint, collector.collector_type());

        let endpoint_key = endpoint.hash_key().to_string();
        let const_labels = HashMap::from([
            (
                "collector_type".to_string(),
                collector.collector_type().to_string(),
            ),
            ("endpoint_key".to_string(), endpoint_key),
        ]);

        let registry = collector_registry.registry();
        let metrics = StreamMetrics::new(registry, collector_registry.prefix(), const_labels)?;

        let handle = tokio::spawn(async move {
            let collector_type = collector.collector_type();
            let _collector_registry = collector_registry;
            let mut backoff = ExponentialBackoff::new(&backoff_config);

            loop {
                tracing::info!(
                    collector_type,
                    endpoint = ?endpoint.addr,
                    "streaming collector connecting"
                );

                let Some(stream_result) =
                    cancel_clone.run_until_cancelled(collector.connect()).await
                else {
                    return;
                };

                match stream_result {
                    Err(e) => {
                        metrics.reconnections_total.inc();
                        tracing::error!(
                            error = ?e,
                            collector_type,
                            endpoint = ?endpoint.addr,
                            "streaming collector connection failed"
                        );
                    }
                    Ok(mut stream) => {
                        // the guard lives exactly as long as we hold an open stream; Drop
                        // handles dec for every exit path (shutdown, error, stream end).
                        let _conn_guard = SseConnectionGuard::inc(metrics.connected.clone());
                        backoff.reset();
                        tracing::info!(
                            collector_type,
                            endpoint = ?endpoint.addr,
                            "streaming collector connected"
                        );

                        loop {
                            let Some(item) = cancel_clone.run_until_cancelled(stream.next()).await
                            else {
                                tracing::info!(
                                    collector_type,
                                    endpoint = ?endpoint.addr,
                                    "streaming collector shutting down"
                                );
                                return;
                            };

                            match item {
                                Some(Ok(event)) => {
                                    metrics.items_processed_total.inc();
                                    data_sink.handle_event(&event_context, &event);
                                }
                                Some(Err(e)) => {
                                    metrics.stream_errors_total.inc();
                                    metrics.reconnections_total.inc();
                                    tracing::error!(
                                        error = ?e,
                                        collector_type,
                                        endpoint = ?endpoint.addr,
                                        "streaming collector stream error, reconnecting"
                                    );
                                    break;
                                }
                                None => {
                                    tracing::info!(
                                        collector_type,
                                        endpoint = ?endpoint.addr,
                                        "streaming collector stream ended, reconnecting"
                                    );
                                    break;
                                }
                            }
                        }
                    }
                }

                let delay = backoff.next_delay();
                if cancel_clone
                    .run_until_cancelled(tokio::time::sleep(delay))
                    .await
                    .is_none()
                {
                    return;
                }
            }
        });

        Ok(Self {
            handle,
            cancel_token,
        })
    }

    pub async fn stop(self) {
        self.cancel_token.cancel();
        let _ = self.handle.await;
    }
}

async fn run_iteration_with_auth_refresh<C: PeriodicCollector<BmcClient>>(
    runner: &mut C,
    endpoint: &Arc<BmcEndpoint>,
    bmc: &Arc<BmcClient>,
) -> Result<IterationResult, HealthError> {
    match runner.run_iteration().await {
        Ok(result) => Ok(result),
        Err(error) if is_auth_error(&error) => {
            tracing::warn!(
                error = ?error,
                endpoint = ?endpoint.addr,
                "Authentication failed, refreshing BMC credentials and retrying once"
            );

            let credentials = endpoint.refresh().await.map_err(|refresh_error| {
                HealthError::GenericError(format!(
                    "Failed to refresh credentials after auth error: {refresh_error}"
                ))
            })?;

            // We set credentials and wait till next iteration, to avoid credential fetch loop.
            bmc.set_credentials(credentials.into());
            Err(error)
        }
        Err(error) => Err(error),
    }
}

fn is_auth_error(error: &HealthError) -> bool {
    match error {
        HealthError::HttpError(message) => {
            message.contains("HTTP 401") || message.contains("HTTP 403")
        }
        HealthError::BmcError(inner) => {
            inner
                .downcast_ref::<BmcError>()
                .is_some_and(is_auth_bmc_error)
                || inner
                    .downcast_ref::<nv_redfish::Error<BmcClient>>()
                    .is_some_and(|err| match err {
                        nv_redfish::Error::Bmc(bmc_error) => is_auth_bmc_error(bmc_error),
                        _ => false,
                    })
        }
        _ => false,
    }
}

fn is_auth_bmc_error(error: &BmcError) -> bool {
    matches!(
        error,
        BmcError::InvalidResponse { status, .. }
            if *status == StatusCode::UNAUTHORIZED || *status == StatusCode::FORBIDDEN
    )
}
