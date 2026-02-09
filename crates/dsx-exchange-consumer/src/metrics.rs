/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Metrics for the DSX Exchange Consumer service.

use std::hash::Hash;

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

/// Consumer metrics using OpenTelemetry counters.
///
/// Cloning is cheap and correct: OpenTelemetry counters are internally Arc'd,
/// so clones share the same underlying metric instances.
#[derive(Clone)]
pub struct ConsumerMetrics {
    messages_received: Counter<u64>,
    messages_processed: Counter<u64>,
    messages_dropped: Counter<u64>,
    alerts_detected: Counter<u64>,
    dedup_skipped: Counter<u64>,
}

impl ConsumerMetrics {
    pub fn new(meter: &Meter) -> Self {
        Self {
            messages_received: meter
                .u64_counter(format!("{METRICS_PREFIX}_messages_received_total"))
                .with_description("Total number of MQTT messages received")
                .build(),
            messages_processed: meter
                .u64_counter(format!("{METRICS_PREFIX}_messages_processed_total"))
                .with_description("Total number of messages successfully processed")
                .build(),
            messages_dropped: meter
                .u64_counter(format!("{METRICS_PREFIX}_messages_dropped_total"))
                .with_description("Total number of messages dropped due to queue overflow")
                .build(),
            alerts_detected: meter
                .u64_counter(format!("{METRICS_PREFIX}_alerts_detected_total"))
                .with_description("Total number of leak alerts detected")
                .build(),
            dedup_skipped: meter
                .u64_counter(format!("{METRICS_PREFIX}_dedup_skipped_total"))
                .with_description("Total number of messages skipped due to deduplication")
                .build(),
        }
    }

    pub fn record_message_received(&self) {
        self.messages_received.add(1, &[]);
    }

    pub fn record_message_processed(&self) {
        self.messages_processed.add(1, &[]);
    }

    pub fn record_message_dropped(&self) {
        self.messages_dropped.add(1, &[]);
    }

    pub fn record_alert_detected(&self, point_type: &str) {
        self.alerts_detected
            .add(1, &[KeyValue::new("point_type", point_type.to_string())]);
    }

    pub fn record_dedup_skipped(&self) {
        self.dedup_skipped.add(1, &[]);
    }
}
