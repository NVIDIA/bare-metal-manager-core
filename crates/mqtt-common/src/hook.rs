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

//! MQTT hook implementation for publishing state changes.

use std::sync::Arc;

use mqttea::{MqtteaClient, MqtteaClientError};
use tokio::sync::mpsc;
use tokio::time::error::Elapsed;
use tokio::time::{Instant, timeout_at};
use tokio_util::sync::CancellationToken;

use crate::metrics::MqttHookMetrics;

/// Internal queue item containing pre-serialized MQTT message with deadline.
pub struct QueuedMessage {
    pub topic: String,
    pub payload: Vec<u8>,
    /// Deadline by which this message must be published.
    pub deadline: Instant,
}

/// Trait for MQTT publishing, enabling test mocks.
#[async_trait::async_trait]
pub trait MqttPublisher: Send + Sync + 'static {
    /// Publish a message to the given topic.
    async fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<(), MqtteaClientError>;
}

#[async_trait::async_trait]
impl MqttPublisher for MqtteaClient {
    async fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<(), MqtteaClientError> {
        MqtteaClient::publish(self, topic, payload).await
    }
}

#[async_trait::async_trait]
impl<T: MqttPublisher> MqttPublisher for Arc<T> {
    async fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<(), MqtteaClientError> {
        T::publish(self, topic, payload).await
    }
}

/// Background task that processes queued messages and publishes to MQTT.
pub async fn process_events<P: MqttPublisher>(
    mut receiver: mpsc::Receiver<QueuedMessage>,
    client: P,
    metrics: MqttHookMetrics,
    cancel_token: CancellationToken,
) {
    while let Some(Some(msg)) = cancel_token.run_until_cancelled(receiver.recv()).await {
        match timeout_at(msg.deadline, client.publish(&msg.topic, msg.payload)).await {
            Ok(Ok(())) => {
                tracing::debug!(topic = %msg.topic, "Published state change to MQTT");
                metrics.record_success();
            }
            Ok(Err(e)) => {
                tracing::warn!(
                    topic = %msg.topic,
                    error = %e,
                    "Failed to publish state change to MQTT"
                );
                metrics.record_publish_error();
            }
            Err(Elapsed { .. }) => {
                tracing::warn!(
                    topic = %msg.topic,
                    "MQTT publish timed out"
                );
                metrics.record_timeout();
            }
        }
    }
    tracing::debug!("MQTT state change hook background task stopped");
}
