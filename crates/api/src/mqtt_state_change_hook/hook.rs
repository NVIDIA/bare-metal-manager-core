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
use std::time::Duration;

use carbide_uuid::machine::MachineId;
use model::machine::ManagedHostState;
use mqttea::{MqtteaClient, MqtteaClientError};
use opentelemetry::metrics::Meter;
use tokio::sync::mpsc;
use tokio::time::error::Elapsed;
use tokio::time::{Instant, timeout_at};

use crate::mqtt_state_change_hook::message::ManagedHostStateChangeMessage;
use crate::mqtt_state_change_hook::metrics::MqttHookMetrics;
use crate::state_controller::state_change_emitter::{StateChangeEvent, StateChangeHook};

/// Topic prefix for state change messages.
const TOPIC_PREFIX: &str = "carbide/v1/machine";

/// Internal queue item containing pre-serialized MQTT message with deadline.
struct QueuedMessage {
    topic: String,
    payload: Vec<u8>,
    /// Deadline by which this message must be published.
    deadline: Instant,
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

/// MQTT hook that publishes `ManagedHostState` changes to the MQTT broker.
///
/// Implements the AsyncAPI specification in `carbide.yaml`, publishing to
/// `carbide/v1/machine/{machineId}/state`.
///
/// This hook maintains an internal queue and processes events in a background task.
/// If the queue is full, events are dropped and a warning is logged.
pub struct MqttStateChangeHook {
    sender: mpsc::Sender<QueuedMessage>,
    publish_timeout: Duration,
    metrics: MqttHookMetrics,
}

impl MqttStateChangeHook {
    /// Create a new MQTT state change hook.
    ///
    /// Spawns a background task to process queued events.
    /// Emits metrics:
    /// - `forge_dsx_event_bus_publish_count`: Total number of MQTT publish attempts
    /// - `forge_dsx_event_bus_queue_depth`: Current queue depth
    pub fn new<P: MqttPublisher>(
        client: P,
        publish_timeout: Duration,
        queue_capacity: usize,
        meter: &Meter,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(queue_capacity);
        let metrics = MqttHookMetrics::new(meter, sender.downgrade());
        tokio::spawn(process_events(receiver, client, metrics.clone()));
        Self {
            sender,
            publish_timeout,
            metrics,
        }
    }

    fn build_topic(machine_id: &MachineId) -> String {
        format!("{}/{}/state", TOPIC_PREFIX, machine_id)
    }
}

impl StateChangeHook<MachineId, ManagedHostState> for MqttStateChangeHook {
    fn on_state_changed(&self, event: &StateChangeEvent<'_, MachineId, ManagedHostState>) {
        // Serialize immediately to avoid cloning state
        let message =
            ManagedHostStateChangeMessage::new(event.object_id, event.new_state, event.timestamp);
        let topic = Self::build_topic(event.object_id);

        match message.to_json_bytes() {
            Ok(payload) => {
                let deadline = Instant::now() + self.publish_timeout;
                let queued = QueuedMessage {
                    topic,
                    payload,
                    deadline,
                };
                if let Err(e) = self.sender.try_send(queued) {
                    tracing::warn!("MQTT state change event dropped (queue full): {e}");
                    self.metrics.record_overflow();
                }
            }
            Err(e) => {
                tracing::error!(
                    machine_id = %event.object_id,
                    error = %e,
                    "Failed to serialize state change message"
                );
                self.metrics.record_serialization_error();
            }
        }
    }
}

/// Background task that processes queued messages and publishes to MQTT.
async fn process_events<P: MqttPublisher>(
    mut receiver: mpsc::Receiver<QueuedMessage>,
    client: P,
    metrics: MqttHookMetrics,
) {
    while let Some(msg) = receiver.recv().await {
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use opentelemetry::global;
    use tokio::sync::Barrier;

    use super::*;

    fn test_meter() -> opentelemetry::metrics::Meter {
        global::meter("test")
    }

    fn test_machine_id() -> MachineId {
        use carbide_uuid::machine::{MachineIdSource, MachineType};
        MachineId::new(
            MachineIdSource::ProductBoardChassisSerial,
            [0; 32],
            MachineType::Host,
        )
    }

    fn make_event<'a>(
        id: &'a MachineId,
        state: &'a ManagedHostState,
    ) -> StateChangeEvent<'a, MachineId, ManagedHostState> {
        StateChangeEvent {
            object_id: id,
            previous_state: None,
            new_state: state,
            timestamp: chrono::Utc::now(),
        }
    }

    /// Publisher that signals via channel when publish completes.
    struct SignalingPublisher {
        sender: tokio::sync::mpsc::UnboundedSender<(String, Vec<u8>)>,
    }

    impl SignalingPublisher {
        fn new() -> (
            Self,
            tokio::sync::mpsc::UnboundedReceiver<(String, Vec<u8>)>,
        ) {
            let (sender, receiver) = tokio::sync::mpsc::unbounded_channel();
            (Self { sender }, receiver)
        }
    }

    #[async_trait::async_trait]
    impl MqttPublisher for SignalingPublisher {
        async fn publish(&self, topic: &str, payload: Vec<u8>) -> Result<(), MqtteaClientError> {
            let _ = self.sender.send((topic.to_string(), payload));
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_events_are_published() {
        let (publisher, mut receiver) = SignalingPublisher::new();
        let hook = MqttStateChangeHook::new(publisher, Duration::from_secs(1), 16, &test_meter());

        let id = test_machine_id();
        let state = ManagedHostState::Ready;
        hook.on_state_changed(&make_event(&id, &state));

        // Wait for publish to complete
        let (topic, payload) = receiver.recv().await.expect("should receive message");

        assert!(topic.starts_with("carbide/v1/machine/"));
        assert!(topic.ends_with("/state"));

        let parsed: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        let state_obj = parsed.get("managed_host_state").unwrap();
        assert_eq!(state_obj.get("state").unwrap(), "ready");
    }

    #[tokio::test]
    async fn test_publish_timeout() {
        let started = Arc::new(Barrier::new(2));
        let call_count = Arc::new(AtomicUsize::new(0));
        let complete_count = Arc::new(AtomicUsize::new(0));

        struct TimeoutPublisher {
            started: Arc<Barrier>,
            call_count: Arc<AtomicUsize>,
            complete_count: Arc<AtomicUsize>,
        }

        #[async_trait::async_trait]
        impl MqttPublisher for TimeoutPublisher {
            async fn publish(&self, _: &str, _: Vec<u8>) -> Result<(), MqtteaClientError> {
                self.call_count.fetch_add(1, Ordering::SeqCst);
                self.started.wait().await;
                // Block forever - timeout should cancel before we get here
                std::future::pending::<()>().await;
                self.complete_count.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        let publisher = TimeoutPublisher {
            started: started.clone(),
            call_count: call_count.clone(),
            complete_count: complete_count.clone(),
        };

        let hook = MqttStateChangeHook::new(publisher, Duration::from_millis(1), 16, &test_meter());

        let id = test_machine_id();
        let state = ManagedHostState::Ready;
        hook.on_state_changed(&make_event(&id, &state));

        // Wait for publish to start
        started.wait().await;

        // Publish was called but will never complete (blocked on pending)
        // Timeout should have cancelled it
        assert_eq!(call_count.load(Ordering::SeqCst), 1);
        assert_eq!(complete_count.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn test_queue_overflow_drops_events() {
        const QUEUE_SIZE: usize = 4;

        let (gate_tx, gate_rx) = tokio::sync::watch::channel(false);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();

        struct GatedPublisher {
            gate: tokio::sync::watch::Receiver<bool>,
            tx: tokio::sync::mpsc::UnboundedSender<()>,
        }

        #[async_trait::async_trait]
        impl MqttPublisher for GatedPublisher {
            async fn publish(&self, _: &str, _: Vec<u8>) -> Result<(), MqtteaClientError> {
                // Wait for gate to open
                let _ = self.gate.clone().wait_for(|&open| open).await;
                let _ = self.tx.send(());
                Ok(())
            }
        }

        let publisher = GatedPublisher { gate: gate_rx, tx };

        let hook = MqttStateChangeHook::new(
            publisher,
            Duration::from_secs(10),
            QUEUE_SIZE,
            &test_meter(),
        );

        let id = test_machine_id();
        let state = ManagedHostState::Ready;

        // Push more events than queue can hold
        for _ in 0..(QUEUE_SIZE + 10) {
            hook.on_state_changed(&make_event(&id, &state));
        }

        // Release the gate - processor will drain queue
        gate_tx.send(true).unwrap();

        // Drop hook to close sender
        drop(hook);

        // Count how many were actually published
        let mut count = 0;
        while rx.recv().await.is_some() {
            count += 1;
        }

        // Queue can hold QUEUE_SIZE events, so exactly that many should be processed
        assert_eq!(count, QUEUE_SIZE);
    }
}
