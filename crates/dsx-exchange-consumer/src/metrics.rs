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
use tokio::sync::mpsc;

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
        .with_description("Number of entries in the metadata cache")
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
        .with_description("Number of entries in the value state cache")
        .with_callback(move |observer| {
            observer.observe(cache.entry_count(), &[]);
        })
        .build();
}

/// Register a gauge for the number of messages queued in the processing
/// channel, so backpressure is visible before the drop counter starts moving.
///
/// Takes the sender by value and keeps only a weak handle for the meter's
/// (process) lifetime. A strong clone would pin the channel open and defeat
/// the consumer's shutdown, which completes only when the last real sender
/// drops and the receiver observes the close. The callback upgrades briefly to
/// read the depth and reports nothing once the senders are gone.
pub fn register_queue_pending_gauge<T>(meter: &Meter, tx: mpsc::Sender<T>)
where
    T: Send + 'static,
{
    let weak_tx = tx.downgrade();
    meter
        .u64_observable_gauge(format!("{METRICS_PREFIX}_queue_pending_messages"))
        .with_description(
            "Number of messages queued in the DSX exchange consumer's processing channel",
        )
        .with_callback(move |observer| {
            // Upgrade only for the read; a strong handle held between scrapes
            // would pin the channel open. Occupied slots = configured capacity
            // minus the free slots the sender currently reports.
            if let Some(tx) = weak_tx.upgrade() {
                let pending = tx.max_capacity().saturating_sub(tx.capacity());
                observer.observe(pending as u64, &[]);
            }
        })
        .build();
    // The moved-in strong sender drops here, leaving only `weak_tx`.
}

// The four message counters are `carbide-instrument` events. Each declares a
// name ending in a single `_total`: the framework strips one `_total` before
// registering the instrument and the OpenTelemetry Prometheus exporter appends
// its own `_total`, so `/metrics` exposes the name exactly as declared here.

/// An MQTT message reached a subscription handler, before any queueing.
#[derive(Event)]
#[event(
    name = "carbide_dsx_exchange_consumer_messages_received_total",
    component = "nico-dsx-exchange-consumer",
    log = off,
    metric = counter,
    describe = "Number of MQTT messages received"
)]
pub struct MessageReceived;

/// A message was correlated with its metadata and its rack health update
/// applied (or its alert cleared).
#[derive(Event)]
#[event(
    name = "carbide_dsx_exchange_consumer_messages_processed_total",
    component = "nico-dsx-exchange-consumer",
    log = off,
    metric = counter,
    describe = "Number of messages successfully processed"
)]
pub struct MessageProcessed;

/// The bounded internal queue was full, so an incoming message was dropped.
///
/// Metric-only: the `tracing::warn!` at each drop site is unchanged, so this
/// event only moves the counter beside it.
#[derive(Event)]
#[event(
    name = "carbide_dsx_exchange_consumer_messages_dropped_total",
    component = "nico-dsx-exchange-consumer",
    log = off,
    metric = counter,
    describe = "Number of messages dropped due to queue overflow"
)]
pub struct MessageDropped;

/// A value matched the state already cached for its point, so no API update
/// was sent.
///
/// Metric-only: the `tracing::trace!` at the dedup site is unchanged, so this
/// event only moves the counter beside it.
#[derive(Event)]
#[event(
    name = "carbide_dsx_exchange_consumer_dedup_skipped_total",
    component = "nico-dsx-exchange-consumer",
    log = off,
    metric = counter,
    describe = "Number of messages skipped due to deduplication"
)]
pub struct MessageDeduplicated;

/// How far behind the BMS event time we are when a value message reaches
/// processing: end-to-end consumer lag (MQTT transit plus time spent queued).
///
/// Metric-only histogram. The `_seconds` suffix declares the unit, and the
/// framework records the `Duration` observation in seconds.
#[derive(Event)]
#[event(
    name = "carbide_dsx_exchange_consumer_message_age_seconds",
    component = "nico-dsx-exchange-consumer",
    log = off,
    metric = histogram,
    describe = "Age of consumed BMS value messages at processing time (consumer lag), in seconds"
)]
pub struct MessageAge {
    #[observation]
    pub age: std::time::Duration,
}

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
            // The Prometheus exporter appends `_total`, so the registered name
            // omits it; that yields the single-`_total` exposed name, matching
            // the framework counters above (not a doubled `_total_total`).
            alerts_detected: meter
                .u64_counter(format!("{METRICS_PREFIX}_alerts_detected"))
                .with_description("Number of leak alerts detected")
                .build(),
        }
    }

    pub fn record_alert_detected(&self, point_type: &str) {
        self.alerts_detected
            .add(1, &[KeyValue::new("point_type", point_type.to_string())]);
    }
}
