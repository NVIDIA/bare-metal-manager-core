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
//! These tests live in their own binary (its own process-global registry) to
//! keep the `counter_delta` measurements deterministic: the crate's other unit
//! tests emit these same events -- the message counters here, and the
//! health-report persist failure below -- but from a different test process, so
//! they cannot advance a shared counter between a test's baseline and delta.

use carbide_dsx_exchange_consumer::metrics::{
    HealthReportPersistFailed, MessageDeduplicated, MessageDropped, MessageProcessed,
    MessageReceived,
};
use carbide_instrument::emit;
use carbide_instrument::testing::{CapturedLog, MetricsCapture, capture_logs};

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

/// A persist failure writes the WARN line carrying the rack id and error, and
/// moves `carbide_dsx_exchange_consumer_health_report_persist_failures_total` once --
/// the "log it AND count it" the safety-relevant drop needs. Isolated here
/// because `health_updater`'s failure-path unit tests emit this same event
/// without a `MetricsCapture`; from a shared process they could advance the
/// zero-label counter between this test's baseline and delta.
#[test]
fn health_report_persist_failed_logs_warn_and_counts() {
    let metrics = MetricsCapture::start();
    let logs = capture_logs(|| {
        emit(HealthReportPersistFailed {
            rack_id: "rack-42".to_string(),
            error: "API call failed: deadline exceeded".to_string(),
        });
    });

    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].level, tracing::Level::WARN);
    assert_eq!(logs[0].message, "Failed to persist rack health report");
    fn field<'a>(log: &'a CapturedLog, name: &str) -> Option<&'a str> {
        log.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
    assert_eq!(field(&logs[0], "rack_id"), Some("rack-42"));
    assert_eq!(
        field(&logs[0], "error"),
        Some("API call failed: deadline exceeded")
    );

    assert_eq!(
        metrics.counter_delta(
            "carbide_dsx_exchange_consumer_health_report_persist_failures_total",
            &[],
        ),
        1.0
    );
}
