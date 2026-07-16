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

//! Pins the exposed names of the four message-counter events to their single
//! `_total` form: the framework strips the declared name's `_total` before
//! registering and the OTel Prometheus exporter appends exactly one, so
//! `/metrics` shows one suffix, not the historical doubled `_total_total`.
//!
//! One test in its own binary (its own process-global registry) keeps the
//! `counter_delta` measurements deterministic: the crate's other unit tests
//! emit these same events, but from a different test process.

use carbide_dsx_exchange_consumer::metrics::{
    MessageDeduplicated, MessageDropped, MessageProcessed, MessageReceived,
};
use carbide_instrument::emit;
use carbide_instrument::testing::{MetricsCapture, capture_logs};

/// Emitting each event once moves exactly its counter, under the single
/// `_total` name the OTel Prometheus exporter produces (the framework strips
/// the declared name's `_total`, and the exporter appends exactly one). All
/// four events are metric-only (`log = off`): the WARN at each drop site and
/// the TRACE at the dedup site are plain `tracing` lines the reshape left
/// untouched, so they stay at the call sites, not on the events (the dedup
/// line is exercised in `health_updater.rs`).
#[test]
fn message_events_expose_single_total_names_and_are_metric_only() {
    let metrics = MetricsCapture::start();
    let logs = capture_logs(|| {
        emit(MessageReceived);
        emit(MessageProcessed);
        emit(MessageDropped);
        emit(MessageDeduplicated);
    });

    // Exposed names end in a single `_total`.
    for name in [
        "carbide_dsx_exchange_consumer_messages_received_total",
        "carbide_dsx_exchange_consumer_messages_processed_total",
        "carbide_dsx_exchange_consumer_messages_dropped_total",
        "carbide_dsx_exchange_consumer_dedup_skipped_total",
    ] {
        assert_eq!(
            metrics.counter_delta(name, &[]),
            1.0,
            "expected {name} to move by 1; exposition was:\n{}",
            metrics.render()
        );
    }

    // None of the historical doubled `_total_total` names appear -- this de-doubles them.
    let exposition = metrics.render();
    for doubled in [
        "carbide_dsx_exchange_consumer_messages_received_total_total",
        "carbide_dsx_exchange_consumer_messages_processed_total_total",
        "carbide_dsx_exchange_consumer_messages_dropped_total_total",
        "carbide_dsx_exchange_consumer_dedup_skipped_total_total",
    ] {
        assert!(
            !exposition.contains(doubled),
            "doubled name {doubled} must be gone; exposition was:\n{exposition}"
        );
    }

    // Metric-only: the events build no log line, so the drop WARN and dedup
    // TRACE are never doubled -- only the untouched call-site `tracing` lines
    // remain.
    assert!(logs.is_empty(), "events must be metric-only: {logs:?}");
}
