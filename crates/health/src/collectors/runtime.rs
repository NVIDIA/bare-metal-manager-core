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
use std::time::{Duration, Instant};

use http::header::InvalidHeaderValue;
use http::{HeaderMap, StatusCode, header};
use nv_redfish::bmc_http::reqwest::{BmcError, Client as ReqwestClient};
use nv_redfish::bmc_http::{CacheSettings, HttpBmc};
use nv_redfish::core::Bmc;
use prometheus::{Counter, Gauge, Histogram, HistogramOpts, IntCounter, Opts};
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

pub struct Collector {
    handle: JoinHandle<()>,
    cancel_token: CancellationToken,
}

pub struct CollectorStartContext {
    pub limiter: Arc<dyn RateLimiter>,
    pub iteration_interval: Duration,
    pub collector_registry: Arc<CollectorRegistry>,
    pub metrics_manager: Arc<MetricsManager>,
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
        let bmc = Arc::new(HttpBmc::with_custom_headers(
            client,
            bmc_url,
            initial_credentials.into(),
            CacheSettings::with_capacity(health_options.cache_size),
            headers,
        ));

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
                        tracing::info!("Collector cancelled for addr: {:?}", endpoint.addr);
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
            bmc.set_credentials(credentials.into())
                .map_err(HealthError::GenericError)?;
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
