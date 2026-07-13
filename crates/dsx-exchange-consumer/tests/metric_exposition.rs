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

//! Pins the exposed names of the four message-counter events byte-for-byte to
//! what the pre-framework hand-rolled counters served, so the conversion never
//! renames a metric a dashboard or alert selects on.
//!
//! One test in its own binary (its own process-global registry) keeps the
//! `counter_delta` measurements deterministic: the crate's other unit tests
//! emit these same events, but from a different test process.

use carbide_dsx_exchange_consumer::metrics::{
    MessageDeduplicated, MessageDropped, MessageProcessed, MessageReceived,
};
use carbide_instrument::emit;
use carbide_instrument::testing::{MetricsCapture, capture_logs};

/// Emitting each event once moves exactly its counter, under the doubled
/// `_total_total` name the OTel Prometheus exporter has always produced for
/// these counters (the register name already ended in `_total`, and the
/// exporter appends another). All four events are metric-only (`log = off`):
/// the WARN at each drop site and the TRACE at the dedup site are plain
/// `tracing` lines the reshape left untouched, so they stay at the call sites,
/// not on the events (the dedup line is exercised in `health_updater.rs`).
#[test]
fn message_events_preserve_names_and_are_metric_only() {
    let metrics = MetricsCapture::start();
    let logs = capture_logs(|| {
        emit(MessageReceived);
        emit(MessageProcessed);
        emit(MessageDropped);
        emit(MessageDeduplicated);
    });

    // Exposed names are byte-identical to the pre-conversion counters.
    for name in [
        "carbide_dsx_exchange_consumer_messages_received_total_total",
        "carbide_dsx_exchange_consumer_messages_processed_total_total",
        "carbide_dsx_exchange_consumer_messages_dropped_total_total",
        "carbide_dsx_exchange_consumer_dedup_skipped_total_total",
    ] {
        assert_eq!(
            metrics.counter_delta(name, &[]),
            1.0,
            "expected {name} to move by 1; exposition was:\n{}",
            metrics.render()
        );
    }

    // The single-`_total` name never appears -- that would be a rename.
    assert_eq!(
        metrics.counter_delta("carbide_dsx_exchange_consumer_messages_received_total", &[]),
        0.0
    );

    // Metric-only: the events build no log line, so the drop WARN and dedup
    // TRACE are never doubled -- only the untouched call-site `tracing` lines
    // remain.
    assert!(logs.is_empty(), "events must be metric-only: {logs:?}");
}
