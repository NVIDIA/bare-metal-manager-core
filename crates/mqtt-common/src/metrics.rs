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

use carbide_instrument::{Event, LabelValue};
use opentelemetry::KeyValue;
use opentelemetry::metrics::Meter;
use tokio::sync::mpsc::WeakSender;

/// The publishing path behind a DSX Exchange Event Bus publish, as the bounded
/// `component` metric label. Each variant renders to the exact value the
/// counter (and the queue-depth gauge) has always reported.
///
/// The set is closed: every construction site in the tree passes one of these
/// three, so the label is a framework `#[label]` rather than a free `&str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub enum PublishComponent {
    /// The BMS DSX Exchange publisher (`carbide-rack`).
    Bms,
    /// The change-driven managed-host state hook (`carbide-api-core`).
    ManagedHost,
    /// The periodic managed-host state republisher (`carbide-api-core`).
    ManagedHostRepublish,
}

/// The outcome of a publish attempt, as the bounded `status` metric label. Each
/// variant renders to the exact value the counter has always reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
enum PublishStatus {
    /// The message was published within its deadline.
    Ok,
    /// The bounded queue was full, so the message was dropped.
    Overflow,
    /// The publish did not complete before its deadline.
    Timeout,
    /// The broker rejected the publish.
    PublishError,
    /// The message could not be serialized.
    SerializationError,
}

/// A publish attempt against the DSX Exchange Event Bus, counted by publishing
/// path and outcome.
///
/// `name_unchecked` keeps the grandfathered exposed name byte-for-byte. The
/// counter has always registered `carbide_dsx_event_bus_publish_count` -- a
/// `_count` suffix, not the framework's conventional `_total` -- and the
/// OpenTelemetry Prometheus exporter appends its own `_total`, so `/metrics`
/// shows `carbide_dsx_event_bus_publish_count_total`. The framework strips a
/// trailing `_total` before registering; this name has none, so it registers
/// exactly the old instrument name and the exporter reproduces the exact
/// exposed series. The convention check would otherwise reject a counter name
/// that does not end in `_total`.
///
/// Metric-only (`log = off`): every emit sits beside the `tracing` line it has
/// always had, which is left untouched -- this event moves only the counter.
///
/// The `component =` attribute is the framework's owning-subsystem const, used
/// by tooling and never emitted as a label; the metric's own `component` label
/// is the per-path discriminator field below.
#[derive(Event)]
#[event(
    name = "carbide_dsx_event_bus_publish_count",
    name_unchecked,
    component = "nico-mqtt-common",
    log = off,
    metric = counter,
    describe = "Number of MQTT publish attempts"
)]
struct DsxEventBusPublish {
    #[label]
    component: PublishComponent,
    #[label]
    status: PublishStatus,
}

/// Metrics for the MQTT state change hook.
#[derive(Clone)]
pub struct MqttHookMetrics {
    component: PublishComponent,
}

impl MqttHookMetrics {
    /// Create new metrics instruments from the given meter.
    ///
    /// Uses a weak reference to the sender to observe queue depth without
    /// preventing shutdown (when the sender is dropped, queue depth reports 0).
    pub fn new<T: Send + 'static>(
        meter: &Meter,
        sender: WeakSender<T>,
        component: PublishComponent,
    ) -> Self {
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
                observer.observe(
                    depth as u64,
                    &[KeyValue::new("component", component.label_value())],
                );
            })
            .build();

        Self { component }
    }

    /// Create metrics for a publisher that does not buffer messages in a
    /// bounded queue, so no queue-depth gauge is registered. Used by the
    /// periodic state republisher, which publishes directly from its sweep.
    pub fn without_queue_depth(component: PublishComponent) -> Self {
        Self { component }
    }

    /// Count one publish attempt for this component with the given outcome.
    fn record(&self, status: PublishStatus) {
        carbide_instrument::emit(DsxEventBusPublish {
            component: self.component,
            status,
        });
    }

    /// Record a successful publish.
    pub fn record_success(&self) {
        self.record(PublishStatus::Ok);
    }

    /// Record that an event was dropped due to queue overflow.
    pub fn record_overflow(&self) {
        self.record(PublishStatus::Overflow);
    }

    /// Record a publish timeout.
    pub fn record_timeout(&self) {
        self.record(PublishStatus::Timeout);
    }

    /// Record an MQTT publish error.
    pub fn record_publish_error(&self) {
        self.record(PublishStatus::PublishError);
    }

    /// Record a serialization failure.
    pub fn record_serialization_error(&self) {
        self.record(PublishStatus::SerializationError);
    }
}

#[cfg(test)]
mod tests {
    use carbide_instrument::LabelValue;
    use carbide_instrument::testing::MetricsCapture;
    use carbide_test_support::{Check, check_values};

    use super::{DsxEventBusPublish, PublishComponent, PublishStatus};

    /// The `status` label values are the metric's contract: each variant renders
    /// to the exact string the publish counter has always reported.
    #[test]
    fn publish_status_renders_expected_label_values() {
        check_values(
            [
                Check {
                    scenario: "success",
                    input: PublishStatus::Ok,
                    expect: "ok".to_string(),
                },
                Check {
                    scenario: "queue overflow",
                    input: PublishStatus::Overflow,
                    expect: "overflow".to_string(),
                },
                Check {
                    scenario: "publish timeout",
                    input: PublishStatus::Timeout,
                    expect: "timeout".to_string(),
                },
                Check {
                    scenario: "publish error",
                    input: PublishStatus::PublishError,
                    expect: "publish_error".to_string(),
                },
                Check {
                    scenario: "serialization error",
                    input: PublishStatus::SerializationError,
                    expect: "serialization_error".to_string(),
                },
            ],
            |status| status.label_value().to_string(),
        );
    }

    /// The `component` label values are the metric's contract: each variant
    /// renders to the exact string the publish counter and queue-depth gauge
    /// have always reported.
    #[test]
    fn publish_component_renders_expected_label_values() {
        check_values(
            [
                Check {
                    scenario: "bms publisher",
                    input: PublishComponent::Bms,
                    expect: "bms".to_string(),
                },
                Check {
                    scenario: "change-driven managed host hook",
                    input: PublishComponent::ManagedHost,
                    expect: "managed_host".to_string(),
                },
                Check {
                    scenario: "periodic managed host republisher",
                    input: PublishComponent::ManagedHostRepublish,
                    expect: "managed_host_republish".to_string(),
                },
            ],
            |component| component.label_value().to_string(),
        );
    }

    /// The exposed series is the metric's contract. Emitting the event moves the
    /// grandfathered `carbide_dsx_event_bus_publish_count` counter, and the
    /// Prometheus exporter's appended `_total` makes the exposed name
    /// `carbide_dsx_event_bus_publish_count_total` -- byte-for-byte what the
    /// hand-rolled counter exported before the framework conversion, under the
    /// same `component` and `status` labels.
    #[test]
    fn publish_event_exposes_grandfathered_count_series() {
        let metrics = MetricsCapture::start();

        carbide_instrument::emit(DsxEventBusPublish {
            component: PublishComponent::ManagedHost,
            status: PublishStatus::PublishError,
        });

        assert_eq!(
            metrics.counter_delta(
                "carbide_dsx_event_bus_publish_count_total",
                &[("component", "managed_host"), ("status", "publish_error")],
            ),
            1.0,
        );
    }
}
