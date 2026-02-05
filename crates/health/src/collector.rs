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
use http::{HeaderMap, header};
use nv_redfish_bmc_http::reqwest::Client as ReqwestClient;
use nv_redfish_bmc_http::{CacheSettings, HttpBmc};
use nv_redfish_core::Bmc;
use prometheus::{Counter, Gauge, Histogram, HistogramOpts, Opts};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::HealthError;
use crate::api_client::BmcEndpoint;
use crate::config::Config as AppConfig;
use crate::discovery::BmcClient;
use crate::limiter::RateLimiter;
use crate::metrics::CollectorRegistry;

/// Result of a collector iteration
#[derive(Debug, Clone)]
pub struct IterationResult {
    /// Whether a refresh was triggered (data was fetched vs cached)
    pub refresh_triggered: bool,
    /// Number of entities collected, if applicable
    pub entity_count: Option<usize>,
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

impl Collector {
    pub fn new(handle: JoinHandle<()>, cancel_token: CancellationToken) -> Self {
        Self {
            handle,
            cancel_token,
        }
    }

    pub fn start<C: PeriodicCollector<BmcClient>>(
        endpoint: Arc<BmcEndpoint>,
        limiter: Arc<dyn RateLimiter>,
        iteration_interval: Duration,
        config: C::Config,
        collector_registry: Arc<CollectorRegistry>,
        client: ReqwestClient,
        health_options: &AppConfig,
    ) -> Result<Self, HealthError> {
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

        let bmc = Arc::new(HttpBmc::with_custom_headers(
            client,
            bmc_url,
            endpoint.credentials.clone().into(),
            CacheSettings::with_capacity(health_options.cache_size),
            headers,
        ));

        let mut runner = C::new_runner(bmc, endpoint.clone(), config)?;

        let endpoint_key = endpoint.addr.hash_key().to_string();
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
            .const_labels(const_labels.clone()),
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
            .const_labels(const_labels),
        )?;
        registry.register(Box::new(entities_gauge.clone()))?;

        let handle = tokio::spawn(async move {
            let collector_type = runner.collector_type();
            // We keep to prevent registry clean_up on drop, after handle is dropped,
            // collector_registry will be dropped and unregister the metrics.
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
                        let iteration_result = runner.run_iteration().await;
                        let duration = start.elapsed();

                        iteration_histogram.observe(
                            duration.as_secs_f64(),
                        );

                        match iteration_result {
                            Ok(result) => {
                                if result.refresh_triggered {
                                    refresh_counter.inc();
                                }

                                if let Some(entity_count) = result.entity_count {
                                    entities_gauge.set(
                                        entity_count as f64,
                                    );
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
                        // Iteration completed
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
