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

use std::sync::Arc;
use std::time::Duration;

use carbide_instrument::emit;
use tonic::transport::Channel;

use super::collector_metrics::metrics_service_client::MetricsServiceClient;
use super::convert::build_metrics_export_request;
use super::{OtlpExportFailed, OtlpSignal, connect_replacement_target, target_endpoint};
use crate::collectors::{BackoffConfig, ExponentialBackoff};
use crate::config::{OtlpTargetConfig, OtlpTlsConfig};
use crate::sink::otlp::OtlpMetricsQueue;
use crate::sink::{EventContext, MetricSample};

pub(crate) struct OtlpMetricsDrainTask {
    queue: Arc<OtlpMetricsQueue>,
    target: OtlpTargetConfig,
    metric_name_prefix: String,
}

impl OtlpMetricsDrainTask {
    pub fn new(
        queue: Arc<OtlpMetricsQueue>,
        target: OtlpTargetConfig,
        metric_name_prefix: String,
    ) -> Self {
        Self {
            queue,
            target,
            metric_name_prefix,
        }
    }

    fn drain_batch(&self, batch: &mut Vec<(EventContext, MetricSample)>) {
        let remaining = self.target.batch_size.saturating_sub(batch.len());

        for _ in 0..remaining {
            match self.queue.pop() {
                Some((_key, value)) => batch.push(value),
                None => break,
            }
        }
    }

    pub async fn run(self) {
        let mut client = self.connect().await;

        let mut batch = Vec::with_capacity(self.target.batch_size);
        let mut interval = tokio::time::interval(self.target.flush_interval);

        // Non-TLS targets use the default only to construct a dormant interval;
        // the select guard below disables reloads for them. Start after one full
        // period and delay missed ticks so stalled drains do not initiate a
        // burst of replacement connections when they resume.
        let tls_reload_period = self
            .target
            .tls
            .as_ref()
            .map_or(OtlpTlsConfig::DEFAULT_RELOAD_INTERVAL, |tls| {
                tls.reload_interval
            });

        let mut tls_reload_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + tls_reload_period,
            tls_reload_period,
        );

        tls_reload_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            tokio::select! {
                _ = self.queue.notified() => {
                    self.drain_batch(&mut batch);

                    if batch.len() >= self.target.batch_size {
                        self.flush(&mut client, &mut batch).await;
                        interval.reset();
                    }
                }
                _ = interval.tick() => {
                    self.drain_batch(&mut batch);
                    if !batch.is_empty() {
                        self.flush(&mut client, &mut batch).await;
                    }
                }
                _ = tls_reload_interval.tick(), if self.target.tls.is_some() => {
                    match connect_replacement_target(&self.target).await {
                        Ok(channel) => {
                            client = MetricsServiceClient::new(channel);

                            tracing::debug!(
                                endpoint = %self.target.endpoint,
                                "refreshed otlp metrics TLS material"
                            );
                        }
                        Err(error) => {
                            tracing::warn!(
                                ?error,
                                endpoint = %self.target.endpoint,
                                "failed to reload otlp metrics TLS material, keeping current client"
                            );
                        }
                    }
                }
            }
        }
    }

    async fn connect(&self) -> MetricsServiceClient<Channel> {
        let mut backoff = ExponentialBackoff::new(&BackoffConfig {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
        });

        loop {
            let endpoint = match target_endpoint(&self.target).await {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    let delay = backoff.next_delay();

                    tracing::warn!(
                        ?error,
                        endpoint = %self.target.endpoint,
                        retry_in = ?delay,
                        "failed to configure otlp metrics connection"
                    );

                    tokio::time::sleep(delay).await;
                    continue;
                }
            };

            match endpoint.connect().await {
                Ok(channel) => {
                    tracing::info!(
                        endpoint = %self.target.endpoint,
                        "connected to otlp metrics collector"
                    );

                    return MetricsServiceClient::new(channel);
                }
                Err(error) => {
                    let delay = backoff.next_delay();

                    tracing::warn!(
                        ?error,
                        endpoint = %self.target.endpoint,
                        retry_in = ?delay,
                        "failed to connect to otlp metrics collector"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    async fn flush(
        &self,
        client: &mut MetricsServiceClient<Channel>,
        batch: &mut Vec<(EventContext, MetricSample)>,
    ) {
        if batch.is_empty() {
            return;
        }

        let request = build_metrics_export_request(batch, &self.metric_name_prefix);
        batch.clear();

        let point_count = request
            .resource_metrics
            .iter()
            .flat_map(|rm| &rm.scope_metrics)
            .flat_map(|sm| &sm.metrics)
            .count();

        if point_count == 0 {
            return;
        }

        const MAX_RETRIES: usize = 5;

        let mut backoff = ExponentialBackoff::new(&BackoffConfig {
            initial: Duration::from_millis(100),
            max: Duration::from_secs(10),
        });

        for attempt in 0..=MAX_RETRIES {
            match client.export(request.clone()).await {
                Ok(_) => {
                    tracing::debug!(
                        endpoint = %self.target.endpoint,
                        point_count,
                        "exported metrics to otlp target"
                    );

                    break;
                }
                Err(status) if is_retryable(&status) && attempt < MAX_RETRIES => {
                    let delay = backoff.next_delay();
                    tracing::warn!(
                        grpc_status_code = ?status.code(),
                        error = status.message(),
                        endpoint = %self.target.endpoint,
                        attempt,
                        retry_in = ?delay,
                        "retryable otlp metrics export error"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(status) => {
                    emit(OtlpExportFailed {
                        signal: OtlpSignal::Metrics,
                        code: status.code().into(),
                        error: status.message().to_string(),
                        record_count: point_count,
                        attempt,
                        endpoint: self.target.endpoint.clone(),
                    });
                    break;
                }
            }
        }
    }
}

fn is_retryable(status: &tonic::Status) -> bool {
    matches!(
        status.code(),
        tonic::Code::Unavailable
            | tonic::Code::DeadlineExceeded
            | tonic::Code::ResourceExhausted
            | tonic::Code::Aborted
            | tonic::Code::Internal
    )
}
