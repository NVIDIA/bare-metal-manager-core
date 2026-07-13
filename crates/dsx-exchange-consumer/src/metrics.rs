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

//! Metrics for the DSX Exchange Consumer service.

use std::hash::Hash;

use carbide_instrument::Event;
use moka::future::Cache;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Meter};

pub static METRICS_PREFIX: &str = "carbide_dsx_exchange_consumer";

/// Register a gauge for the metadata cache size.
///
/// Cloning the cache is cheap: moka caches are internally Arc'd.
pub fn register_metadata_cache_gauge<K, V>(meter: &Meter, cache: &Cache<K, V>)
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    let cache = cache.clone();
    meter
        .u64_observable_gauge(format!("{METRICS_PREFIX}_metadata_cache_size"))
        .with_description("Current number of entries in the metadata cache")
        .with_callback(move |observer| {
            observer.observe(cache.entry_count(), &[]);
        })
        .build();
}

/// Register a gauge for the value state cache size.
///
/// Cloning the cache is cheap: moka caches are internally Arc'd.
pub fn register_value_state_cache_gauge<K, V>(meter: &Meter, cache: &Cache<K, V>)
where
    K: Eq + Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    let cache = cache.clone();
    meter
        .u64_observable_gauge(format!("{METRICS_PREFIX}_value_state_cache_size"))
        .with_description("Current number of entries in the value state cache")
        .with_callback(move |observer| {
            observer.observe(cache.entry_count(), &[]);
        })
        .build();
}

// The four message counters are `carbide-instrument` events. Their exposed
// names are grandfathered, and `name_unchecked` keeps them byte-identical:
// the pre-framework counters registered names that already ended in `_total`,
// and the OpenTelemetry Prometheus exporter appends its own `_total` to every
// counter -- so `/metrics` has always shown a doubled `_total_total` suffix.
// The framework strips one `_total` before registering and the exporter
// re-appends it, reproducing the exact name every existing dashboard and alert
// already selects on.

/// An MQTT message reached a subscription handler, before any queueing.
#[derive(Event)]
#[event(
    name = "carbide_dsx_exchange_consumer_messages_received_total_total",
    name_unchecked,
    component = "nico-dsx-exchange-consumer",
    log = off,
    metric = counter,
    describe = "Total number of MQTT messages received"
)]
pub struct MessageReceived;

/// A message was correlated with its metadata and its rack health update
/// applied (or its alert cleared).
#[derive(Event)]
#[event(
    name = "carbide_dsx_exchange_consumer_messages_processed_total_total",
    name_unchecked,
    component = "nico-dsx-exchange-consumer",
    log = off,
    metric = counter,
    describe = "Total number of messages successfully processed"
)]
pub struct MessageProcessed;

/// The bounded internal queue was full, so an incoming message was dropped.
///
/// Metric-only: the `tracing::warn!` at each drop site is unchanged, so this
/// event only moves the counter beside it.
#[derive(Event)]
#[event(
    name = "carbide_dsx_exchange_consumer_messages_dropped_total_total",
    name_unchecked,
    component = "nico-dsx-exchange-consumer",
    log = off,
    metric = counter,
    describe = "Total number of messages dropped due to queue overflow"
)]
pub struct MessageDropped;

/// A value matched the state already cached for its point, so no API update
/// was sent.
///
/// Metric-only: the `tracing::trace!` at the dedup site is unchanged, so this
/// event only moves the counter beside it.
#[derive(Event)]
#[event(
    name = "carbide_dsx_exchange_consumer_dedup_skipped_total_total",
    name_unchecked,
    component = "nico-dsx-exchange-consumer",
    log = off,
    metric = counter,
    describe = "Total number of messages skipped due to deduplication"
)]
pub struct MessageDeduplicated;

/// Consumer metrics that remain hand-rolled OpenTelemetry counters.
///
/// Only `alerts_detected` stays here: its `point_type` label is a
/// caller-supplied string that needs a bounded mapping before it can become a
/// framework event, which is tracked separately. The message counters are the
/// `carbide-instrument` events above.
///
/// Cloning is cheap and correct: OpenTelemetry counters are internally Arc'd,
/// so clones share the same underlying metric instances.
#[derive(Clone)]
pub struct ConsumerMetrics {
    alerts_detected: Counter<u64>,
}

impl ConsumerMetrics {
    pub fn new(meter: &Meter) -> Self {
        Self {
            alerts_detected: meter
                .u64_counter(format!("{METRICS_PREFIX}_alerts_detected_total"))
                .with_description("Total number of leak alerts detected")
                .build(),
        }
    }

    pub fn record_alert_detected(&self, point_type: &str) {
        self.alerts_detected
            .add(1, &[KeyValue::new("point_type", point_type.to_string())]);
    }
}
