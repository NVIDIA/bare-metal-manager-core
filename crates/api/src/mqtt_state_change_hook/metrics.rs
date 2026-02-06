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

//! Metrics for the DSX Exchange Event Bus MQTT hook.

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Meter};
use tokio::sync::mpsc::WeakSender;

/// Metrics for the MQTT state change hook.
#[derive(Clone)]
pub struct MqttHookMetrics {
    /// Counter for publish attempts, with status label for success/error.
    publish_count: Counter<u64>,
}

impl MqttHookMetrics {
    /// Create new metrics instruments from the given meter.
    ///
    /// Uses a weak reference to the sender to observe queue depth without
    /// preventing shutdown (when the sender is dropped, queue depth reports 0).
    pub fn new<T: Send + 'static>(meter: &Meter, sender: WeakSender<T>) -> Self {
        // Get max_capacity once at construction (upgrade will succeed since sender still exists)
        let max_capacity = sender.upgrade().map(|s| s.max_capacity()).unwrap_or(0);

        // Register observable gauge for queue depth using sender's capacity
        meter
            .u64_observable_gauge("carbide_dsx_event_bus_queue_depth")
            .with_description(
                "Number of state change messages currently queued for MQTT publishing",
            )
            .with_callback(move |observer| {
                let depth = sender
                    .upgrade()
                    .map(|s| max_capacity - s.capacity())
                    .unwrap_or(0);
                observer.observe(depth as u64, &[]);
            })
            .build();

        let publish_count = meter
            .u64_counter("carbide_dsx_event_bus_publish_count")
            .with_description("Total number of MQTT publish attempts")
            .build();

        Self { publish_count }
    }

    /// Record a successful publish.
    pub fn record_success(&self) {
        self.publish_count.add(1, &[KeyValue::new("status", "ok")]);
    }

    /// Record that an event was dropped due to queue overflow.
    pub fn record_overflow(&self) {
        self.publish_count
            .add(1, &[KeyValue::new("status", "overflow")]);
    }

    /// Record a publish timeout.
    pub fn record_timeout(&self) {
        self.publish_count
            .add(1, &[KeyValue::new("status", "timeout")]);
    }

    /// Record an MQTT publish error.
    pub fn record_publish_error(&self) {
        self.publish_count
            .add(1, &[KeyValue::new("status", "publish_error")]);
    }

    /// Record a serialization failure.
    pub fn record_serialization_error(&self) {
        self.publish_count
            .add(1, &[KeyValue::new("status", "serialization_error")]);
    }
}
