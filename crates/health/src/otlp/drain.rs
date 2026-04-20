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

use tonic::transport::Channel;

use super::collector_logs::logs_service_client::LogsServiceClient;
use super::convert::build_export_request;
use crate::collectors::{BackoffConfig, ExponentialBackoff};
use crate::sink::otlp::OtlpQueue;
use crate::sink::{CollectorEvent, EventContext};

pub(crate) struct OtlpDrainTask {
    queue: Arc<OtlpQueue>,
    endpoint: String,
    batch_size: usize,
    flush_interval: Duration,
}

impl OtlpDrainTask {
    pub fn new(
        queue: Arc<OtlpQueue>,
        endpoint: String,
        batch_size: usize,
        flush_interval: Duration,
    ) -> Self {
        Self {
            queue,
            endpoint,
            batch_size,
            flush_interval,
        }
    }

    fn drain_batch(&self, batch: &mut Vec<(EventContext, CollectorEvent)>) {
        let remaining = self.batch_size.saturating_sub(batch.len());
        for _ in 0..remaining {
            match self.queue.pop() {
                Some((_key, value)) => batch.push(value),
                None => break,
            }
        }
    }

    pub async fn run(self) {
        let mut client = match self.connect().await {
            Some(c) => c,
            None => return,
        };

        let mut batch = Vec::with_capacity(self.batch_size);
        let mut interval = tokio::time::interval(self.flush_interval);

        loop {
            tokio::select! {
                _ = self.queue.notified() => {
                    self.drain_batch(&mut batch);
                    if batch.len() >= self.batch_size {
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
            }
        }
    }

    async fn connect(&self) -> Option<LogsServiceClient<Channel>> {
        let endpoint = match Channel::from_shared(self.endpoint.clone()) {
            Ok(e) => e,
            Err(error) => {
                tracing::error!(
                    ?error,
                    endpoint = %self.endpoint,
                    "invalid otlp endpoint uri, stopping drain"
                );
                return None;
            }
        };

        let mut backoff = ExponentialBackoff::new(&BackoffConfig {
            initial: Duration::from_secs(1),
            max: Duration::from_secs(30),
        });

        loop {
            match endpoint.connect().await {
                Ok(channel) => {
                    tracing::info!(endpoint = %self.endpoint, "connected to otlp collector");
                    return Some(LogsServiceClient::new(channel));
                }
                Err(error) => {
                    let delay = backoff.next_delay();
                    tracing::warn!(
                        ?error,
                        endpoint = %self.endpoint,
                        retry_in = ?delay,
                        "failed to connect to otlp collector"
                    );
                    tokio::time::sleep(delay).await;
                }
            }
        }
    }

    async fn flush(
        &self,
        client: &mut LogsServiceClient<Channel>,
        batch: &mut Vec<(EventContext, CollectorEvent)>,
    ) {
        if batch.is_empty() {
            return;
        }

        let request = build_export_request(batch);
        batch.clear();

        let record_count = request
            .resource_logs
            .iter()
            .flat_map(|rl| &rl.scope_logs)
            .map(|sl| sl.log_records.len())
            .sum::<usize>();

        if record_count == 0 {
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
                    tracing::debug!(record_count, "exported logs to otlp collector");
                    break;
                }
                Err(status) if is_retryable(&status) && attempt < MAX_RETRIES => {
                    let delay = backoff.next_delay();
                    tracing::warn!(
                        code = ?status.code(),
                        message = status.message(),
                        attempt,
                        retry_in = ?delay,
                        "retryable otlp export error"
                    );
                    tokio::time::sleep(delay).await;
                }
                Err(status) => {
                    tracing::error!(
                        code = ?status.code(),
                        message = status.message(),
                        record_count,
                        attempt,
                        "otlp export failed, dropping batch"
                    );
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
