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

// src/mqttea/stats/publish.rs
// Publish statistics tracking for sent message performance monitoring.
//
// Provides thread-safe atomic counters for tracking message publishing
// success/failure rates and throughput metrics for sent messages.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

// PublishStats stores a snapshot of sent message statistics.
#[derive(Debug, Clone)]
pub struct PublishStats {
    // total_published is count of messages successfully sent
    // since startup/reset.
    pub total_published: usize,
    // total_failed is count of messages that failed to send
    // since startup/reset.
    pub total_failed: usize,
    // total_bytes_published is total size of messages
    // successfully sent (throughput metric).
    pub total_bytes_published: usize,
}

// PublishStatsTracker enables thread-safe updates to publish
// statistics using atomic operations. Lock-free design ensures
// statistics don't impact message sending performance.
#[derive(Debug)]
pub struct PublishStatsTracker {
    // published_count tracks total number of messages
    // successfully published.
    published_count: Arc<AtomicUsize>,
    // failed_count tracks total number of messages that
    // failed to publish.
    failed_count: Arc<AtomicUsize>,
    // published_bytes tracks total size of messages
    // successfully published.
    published_bytes: Arc<AtomicUsize>,
}

impl Default for PublishStatsTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl PublishStatsTracker {
    // new will create a PublishStatsTracker with all counters initialized to zero.
    // Creates atomic counters wrapped in Arc for safe sharing across async tasks.
    // (e.g. used during MqtteaClient initialization)
    pub fn new() -> Self {
        Self {
            published_count: Arc::new(AtomicUsize::new(0)),
            failed_count: Arc::new(AtomicUsize::new(0)),
            published_bytes: Arc::new(AtomicUsize::new(0)),
        }
    }

    // increment_published will record a successful message publish operation.
    // Called when the MQTT broker confirms receipt of published message.
    // (e.g. increment_published(512) for successful 512-byte message).
    // Thread-safe + lock-free.
    pub fn increment_published(&self, bytes: usize) {
        self.published_count.fetch_add(1, Ordering::Relaxed);
        self.published_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    // increment_failed will record a failed message publish operation.
    // Called when MQTT publish fails due to connection, authentication,
    // or broker issues. (e.g. network timeout, broker unavailable, QoS
    // negotiation failure)
    // Enables monitoring of publish success rates and connection health.
    pub fn increment_failed(&self) {
        self.failed_count.fetch_add(1, Ordering::Relaxed);
    }

    // reset_counters will clear all publish counters back to zero.
    // Useful for periodic reporting, testing, or monitoring system resets.
    // (e.g. reset hourly stats for sliding window metrics)
    pub fn reset_counters(&self) {
        self.published_count.store(0, Ordering::Relaxed);
        self.failed_count.store(0, Ordering::Relaxed);
        self.published_bytes.store(0, Ordering::Relaxed);
    }

    // to_stats will create an immutable snapshot of current publish
    // statistics. Safe to call frequently as it only reads atomic values
    // without locks. (e.g. called by client.publish_stats() for user
    // queries).
    // Returns PublishStats struct with current counter values.
    pub fn to_stats(&self) -> PublishStats {
        PublishStats {
            total_published: self.published_count.load(Ordering::Relaxed),
            total_failed: self.failed_count.load(Ordering::Relaxed),
            total_bytes_published: self.published_bytes.load(Ordering::Relaxed),
        }
    }
}
