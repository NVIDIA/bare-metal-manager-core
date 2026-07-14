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

//! Pins the secrets timer's emit conditions -- which counter fires on success
//! versus failure, and that the duration records once on each path with no log
//! line -- while proving the exposed names are byte-identical to what the
//! pre-framework hand-rolled instruments served.
//!
//! Its own test binary on purpose: the crate's in-process `secrets::tests`
//! manager cases drive the same `OperationTimer`, so they emit these same
//! global `carbide_api_secrets_*` series. `MetricsCapture` only serializes
//! other capture users, so an exact-delta assertion would race a manager op
//! landing between its baseline and its delta. Alone in this process, these
//! two tests are the only emitters, and the `MetricsCapture` serial guard
//! orders them, so the `== 1` / `== 0` deltas are deterministic.

use carbide_api_core::secrets::{OperationTimer, SecretsOperation};
use carbide_instrument::testing::{MetricsCapture, capture_logs};

/// The success path counts the attempt, counts the success, and times the
/// operation once -- never touching the failure counter -- and builds no log
/// line, because the events are metric-only. The three counter deltas land
/// under the exact names the pre-framework instruments served.
#[test]
fn succeed_counts_attempt_success_and_duration_without_logging() {
    let metrics = MetricsCapture::start();
    let logs = capture_logs(|| {
        OperationTimer::start(SecretsOperation::Get).succeed();
    });

    assert!(
        logs.is_empty(),
        "log = off must not construct any log line, got {logs:?}"
    );
    assert_eq!(
        metrics.counter_delta(
            "carbide_api_secrets_requests_total",
            &[("operation", "get")]
        ),
        1.0,
        "the attempt counter must move once; exposition was:\n{}",
        metrics.render()
    );
    assert_eq!(
        metrics.counter_delta(
            "carbide_api_secrets_requests_succeeded_total",
            &[("operation", "get")],
        ),
        1.0,
        "the success counter must move once; exposition was:\n{}",
        metrics.render()
    );
    assert_eq!(
        metrics.counter_delta(
            "carbide_api_secrets_requests_failed_total",
            &[("operation", "get")],
        ),
        0.0,
        "the success path must not move the failure counter",
    );
    assert_eq!(
        metrics.histogram_count_delta(
            "carbide_api_secrets_request_duration_milliseconds",
            &[("operation", "get")],
        ),
        1,
        "the duration must record exactly once on the success path",
    );
}

/// Leaving the timer's scope without calling `succeed` -- as an early `?`
/// return would -- counts the attempt, counts a failure, and times the
/// operation once, without touching the success counter or logging.
#[test]
fn drop_without_succeed_counts_attempt_failure_and_duration() {
    let metrics = MetricsCapture::start();
    let logs = capture_logs(|| {
        let _timer = OperationTimer::start(SecretsOperation::Delete);
    });

    assert!(
        logs.is_empty(),
        "log = off must not construct any log line, got {logs:?}"
    );
    assert_eq!(
        metrics.counter_delta(
            "carbide_api_secrets_requests_total",
            &[("operation", "delete")],
        ),
        1.0,
        "the attempt counter must move once; exposition was:\n{}",
        metrics.render()
    );
    assert_eq!(
        metrics.counter_delta(
            "carbide_api_secrets_requests_failed_total",
            &[("operation", "delete")],
        ),
        1.0,
        "the failure counter must move once; exposition was:\n{}",
        metrics.render()
    );
    assert_eq!(
        metrics.counter_delta(
            "carbide_api_secrets_requests_succeeded_total",
            &[("operation", "delete")],
        ),
        0.0,
        "a dropped-as-failed timer must not move the success counter",
    );
    assert_eq!(
        metrics.histogram_count_delta(
            "carbide_api_secrets_request_duration_milliseconds",
            &[("operation", "delete")],
        ),
        1,
        "the duration must record exactly once on the failure path",
    );
}
