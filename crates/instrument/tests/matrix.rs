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

//! The log/metric matrix, end to end: every knob combination produces exactly
//! the declared outputs, with the same label values on both sides.

use std::time::Duration;

use carbide_instrument::testing::{MetricsCapture, capture_logs};
use carbide_instrument::{Event, LabelValue, LogAt, MetricKind, Outcome, emit};

#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
enum Stage {
    PreFlight,
    Apply,
}

fn field<'a>(log: &'a carbide_instrument::testing::CapturedLog, name: &str) -> Option<&'a str> {
    log.fields
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// log = warn, metric = counter: one emit writes the log line AND moves the
/// counter, with identical label values.
#[test]
fn both_sides_from_one_emit() {
    #[derive(Event)]
    #[event(
        name = "carbide_test_matrix_both_total",
        component = "matrix-test",
        log = warn,
        metric = counter,
        message = "matrix both fired"
    )]
    struct BothSides {
        #[label]
        stage: Stage,
        #[label]
        outcome: Outcome,
        #[context]
        machine: String,
    }

    let metrics = MetricsCapture::start();
    let logs = capture_logs(|| {
        emit(BothSides {
            stage: Stage::Apply,
            outcome: Outcome::Error,
            machine: "machine-1".to_string(),
        });
    });

    assert_eq!(logs.len(), 1);
    let log = &logs[0];
    assert_eq!(log.level, tracing::Level::WARN);
    assert_eq!(log.message, "matrix both fired");
    assert_eq!(field(log, "stage"), Some("apply"));
    assert_eq!(field(log, "outcome"), Some("error"));
    assert_eq!(field(log, "machine"), Some("machine-1"));

    assert_eq!(
        metrics.counter_delta(
            "carbide_test_matrix_both_total",
            &[("stage", "apply"), ("outcome", "error")],
        ),
        1.0
    );
}

/// log = off, metric = counter: the counter moves and no log line is built at
/// all (message is not even required).
#[test]
fn metric_only_writes_no_log() {
    #[derive(Event)]
    #[event(
        name = "carbide_test_matrix_quiet_total",
        component = "matrix-test",
        log = off,
        metric = counter
    )]
    struct Quiet {
        #[label]
        stage: Stage,
    }

    let metrics = MetricsCapture::start();
    let logs = capture_logs(|| {
        emit(Quiet {
            stage: Stage::PreFlight,
        });
        emit(Quiet {
            stage: Stage::PreFlight,
        });
    });

    assert!(logs.is_empty(), "log = off must not construct any log line");
    assert_eq!(
        metrics.counter_delta(
            "carbide_test_matrix_quiet_total",
            &[("stage", "pre_flight")]
        ),
        2.0
    );
}

/// metric = none: a plain structured log, and nothing appears on the registry.
#[test]
fn log_only_registers_no_metric() {
    #[derive(Event)]
    #[event(
        name = "carbide_test_matrix_logonly",
        component = "matrix-test",
        log = info,
        metric = none,
        message = "log only fired"
    )]
    struct LogOnly {
        #[context]
        detail: String,
    }

    let metrics = MetricsCapture::start();
    let logs = capture_logs(|| {
        emit(LogOnly {
            detail: "just words".to_string(),
        });
    });

    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].level, tracing::Level::INFO);
    assert_eq!(field(&logs[0], "detail"), Some("just words"));
    assert_eq!(
        metrics.counter_delta("carbide_test_matrix_logonly", &[]),
        0.0
    );
}

/// metric = histogram: the observation records in the unit the name declares
/// (a Duration converts), and the log still fires independently.
#[test]
fn histogram_records_the_observation_in_declared_units() {
    #[derive(Event)]
    #[event(
        name = "carbide_test_matrix_copy_duration_seconds",
        component = "matrix-test",
        log = info,
        metric = histogram,
        message = "copy finished"
    )]
    struct CopyFinished {
        #[label]
        outcome: Outcome,
        #[observation]
        took: Duration,
        #[context]
        host: String,
    }

    let metrics = MetricsCapture::start();
    let logs = capture_logs(|| {
        emit(CopyFinished {
            outcome: Outcome::Ok,
            took: Duration::from_millis(1500),
            host: "10.0.0.5".to_string(),
        });
    });

    assert_eq!(logs.len(), 1);
    assert_eq!(
        metrics.histogram_count_delta(
            "carbide_test_matrix_copy_duration_seconds",
            &[("outcome", "ok")],
        ),
        1
    );
    let sum = metrics.histogram_sum_delta(
        "carbide_test_matrix_copy_duration_seconds",
        &[("outcome", "ok")],
    );
    assert!(
        (sum - 1.5).abs() < 1e-9,
        "1500ms records as 1.5s, got {sum}"
    );
}

/// A unit struct works (zero labels), and the declared knob constants are
/// what the derive wrote.
#[test]
fn unit_struct_and_declared_knobs() {
    #[derive(Event)]
    #[event(
        name = "carbide_test_matrix_unit_total",
        component = "matrix-test",
        log = off,
        metric = counter
    )]
    struct Tick;

    assert_eq!(<Tick as Event>::LOG, LogAt::Off);
    assert_eq!(<Tick as Event>::METRIC, MetricKind::Counter);
    assert_eq!(<Tick as Event>::NAME, "carbide_test_matrix_unit_total");
    assert_eq!(<Tick as Event>::COMPONENT, "matrix-test");

    let metrics = MetricsCapture::start();
    emit(Tick);
    assert_eq!(
        metrics.counter_delta("carbide_test_matrix_unit_total", &[]),
        1.0
    );
}

/// A hand-written log_at override: failures log, successes are counted
/// silently -- the count-everything-log-only-failures idiom.
#[test]
fn per_instance_log_at_override() {
    #[derive(Event)]
    #[event(
        name = "carbide_test_matrix_calls_total",
        component = "matrix-test",
        log = warn,
        metric = counter,
        message = "call finished"
    )]
    struct CallFinished {
        #[label]
        outcome: Outcome,
    }

    // The derive keeps the trait's default log_at(); a wrapper type shows the
    // per-instance form until the derive grows dynamic support (the RED
    // helper issue).
    struct OnlyFailuresLog(CallFinished);
    impl Event for OnlyFailuresLog {
        const NAME: &'static str = <CallFinished as Event>::NAME;
        const COMPONENT: &'static str = <CallFinished as Event>::COMPONENT;
        const LOG: LogAt = <CallFinished as Event>::LOG;
        const METRIC: MetricKind = <CallFinished as Event>::METRIC;
        type Labels = <CallFinished as Event>::Labels;

        fn message(&self) -> &'static str {
            self.0.message()
        }
        fn labels(&self) -> Self::Labels {
            self.0.labels()
        }
        fn log_at(&self) -> LogAt {
            match self.0.outcome {
                Outcome::Error => LogAt::Level(tracing::Level::WARN),
                Outcome::Ok => LogAt::Off,
            }
        }
        fn __log(&self, level: tracing::Level) {
            self.0.__log(level);
        }
        fn __instrument(&self) -> &'static carbide_instrument::__private::CachedInstrument {
            self.0.__instrument()
        }
    }

    let metrics = MetricsCapture::start();
    let logs = capture_logs(|| {
        emit(OnlyFailuresLog(CallFinished {
            outcome: Outcome::Ok,
        }));
        emit(OnlyFailuresLog(CallFinished {
            outcome: Outcome::Error,
        }));
    });

    assert_eq!(logs.len(), 1, "only the failure logs");
    assert_eq!(logs[0].level, tracing::Level::WARN);
    assert_eq!(
        metrics.counter_delta("carbide_test_matrix_calls_total", &[("outcome", "ok")]),
        1.0
    );
    assert_eq!(
        metrics.counter_delta("carbide_test_matrix_calls_total", &[("outcome", "error")]),
        1.0
    );
}

/// Every supported histogram unit round-trips: the name in the attribute is
/// the exposed name, and the observation records in that unit.
#[test]
fn histogram_units_round_trip() {
    #[derive(Event)]
    #[event(
        name = "carbide_test_matrix_lag_duration_milliseconds",
        component = "matrix-test",
        log = off,
        metric = histogram
    )]
    struct LagSampled {
        #[observation]
        took: Duration,
    }

    #[derive(Event)]
    #[event(
        name = "carbide_test_matrix_poll_duration_microseconds",
        component = "matrix-test",
        log = off,
        metric = histogram
    )]
    struct PollSampled {
        #[observation]
        took: Duration,
    }

    #[derive(Event)]
    #[event(
        name = "carbide_test_matrix_payload_bytes",
        component = "matrix-test",
        log = off,
        metric = histogram
    )]
    struct PayloadSized {
        #[observation]
        size: u64,
    }

    let metrics = MetricsCapture::start();
    emit(LagSampled {
        took: Duration::from_millis(250),
    });
    emit(PollSampled {
        took: Duration::from_micros(1500),
    });
    emit(PayloadSized { size: 4096 });

    for (name, expected_sum) in [
        ("carbide_test_matrix_lag_duration_milliseconds", 250.0),
        ("carbide_test_matrix_poll_duration_microseconds", 1500.0),
        ("carbide_test_matrix_payload_bytes", 4096.0),
    ] {
        assert_eq!(metrics.histogram_count_delta(name, &[]), 1, "{name}");
        let sum = metrics.histogram_sum_delta(name, &[]);
        assert!(
            (sum - expected_sum).abs() < 1e-9,
            "{name}: expected sum {expected_sum}, got {sum}"
        );
    }
}
