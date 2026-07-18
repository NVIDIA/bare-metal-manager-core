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

//! One declaration per significant event: [`emit`] produces a structured log
//! line and/or a Prometheus metric from the same call, correlated by the
//! surrounding span, with metric cardinality bounded by the type system.
//!
//! Declare the event as a struct next to the code that emits it:
//!
//! ```
//! use carbide_instrument::{Event, LabelValue, Outcome, emit};
//!
//! #[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
//! enum Backend {
//!     Nsm,
//!     Psm,
//!     Rms,
//! }
//!
//! #[derive(Event)]
//! #[event(
//!     event_name  = "power_control_failed",       // stable event identity
//!     metric_name = "carbide_power_control_total", // exposed verbatim
//!     component = "component_manager",
//!     log       = warn,                          // error|warn|info|debug|trace|off
//!     metric    = counter,                       // counter | histogram | none
//!     describe  = "Number of power control operations that failed", // counter HELP text
//!     message   = "power control failed",
//! )]
//! struct PowerControlFailed {
//!     #[label]
//!     backend: Backend, // enum -> metric label backend="rms"
//!     #[label]
//!     outcome: Outcome, // enum -> metric label outcome="error"
//!     #[context]
//!     error: String, // high-cardinality -> the log line only
//! }
//!
//! emit(PowerControlFailed {
//!     backend: Backend::Rms,
//!     outcome: Outcome::Error,
//!     error: "deadline exceeded".to_string(),
//! });
//! ```
//!
//! The two knobs are independent: `log = off, metric = counter` counts a
//! hot-path event without building any log line at all, and `metric = none`
//! is a plain structured log. See `docs/observability/instrumentation.md`
//! for the standard (naming, cardinality rules, when to use which mode).
//!
//! # Cardinality is enforced by the types
//!
//! A `#[label]` field must implement [`LabelValue`], which is derivable only
//! for fieldless enums -- so a label's value set is closed by construction.
//! `String` does not implement it, and high-cardinality detail belongs in
//! `#[context]` fields, which appear on the log line only:
//!
//! ```compile_fail
//! #[derive(carbide_instrument::Event)]
//! #[event(event_name = "demo", metric_name = "carbide_demo_total",
//!         component = "demo", log = off, metric = counter,
//!         describe = "Number of demo events")]
//! struct Demo {
//!     #[label]
//!     machine_id: String, // ERROR: String is not a LabelValue
//! }
//! ```
//!
//! The metric name is validated at compile time -- the `carbide_` prefix, the
//! `_total` suffix for counters, a unit suffix for histograms:
//!
//! ```compile_fail
//! #[derive(carbide_instrument::Event)]
//! #[event(event_name = "power_control", metric_name = "power_control_total",
//!         component = "demo", log = off, metric = counter)]
//! struct Demo {} // ERROR: metric names use the `carbide_` prefix
//! ```
//!
//! ```compile_fail
//! #[derive(carbide_instrument::Event)]
//! #[event(event_name = "power_control", metric_name = "carbide_power_control",
//!         component = "demo", log = off, metric = counter)]
//! struct Demo {} // ERROR: counter names end in `_total`
//! ```
//!
//! And an event must produce something -- `log = off` with `metric = none`
//! would make `emit()` a silent no-op:
//!
//! ```compile_fail
//! #[derive(carbide_instrument::Event)]
//! #[event(event_name = "demo", component = "demo", log = off, metric = none)]
//! struct Demo {} // ERROR: declare at least one side
//! ```
//!
//! `unit` belongs to histograms (and only `metric_name_unchecked` ones -- a
//! standard histogram name already declares its unit as the suffix), and
//! `describe` documents a metric:
//!
//! ```compile_fail
//! #[derive(carbide_instrument::Event)]
//! #[event(event_name = "demo", metric_name = "carbide_demo_total",
//!         component = "demo", log = off, metric = counter, unit = "s")]
//! struct Demo {} // ERROR: `unit` is only valid for histogram metrics
//! ```
//!
//! ```compile_fail
//! #[derive(carbide_instrument::Event)]
//! #[event(event_name = "demo", component = "demo", message = "demo", describe = "demo")]
//! struct Demo {} // ERROR: `describe` documents a metric; this event has metric = none
//! ```
//!
//! A counter documents itself: `describe` is required and opens with
//! "Number of ..." (the tech-writer house rule, so the `core_metrics.md`
//! catalogue reads consistently):
//!
//! ```compile_fail
//! #[derive(carbide_instrument::Event)]
//! #[event(event_name = "demo", metric_name = "carbide_demo_total", component = "demo",
//!         log = off, metric = counter)]
//! struct Demo {} // ERROR: a counter must document itself with describe = "Number of ..."
//! ```
//!
//! ```compile_fail
//! #[derive(carbide_instrument::Event)]
//! #[event(event_name = "demo", metric_name = "carbide_demo_total", component = "demo",
//!         log = off, metric = counter, describe = "Total number of demos")]
//! struct Demo {} // ERROR: a counter's describe opens with "Number of ..."
//! ```
//!
//! A counter name ends in `_total` (Prometheus convention) but not
//! `_total_total` -- the framework strips one `_total` before registering and
//! the exporter appends it back, so a doubled suffix ships a `_total_total`
//! series:
//!
//! ```compile_fail
//! #[derive(carbide_instrument::Event)]
//! #[event(event_name = "demo", metric_name = "carbide_demo_total_total", component = "demo",
//!         log = off, metric = counter, describe = "Number of demos")]
//! struct Demo {} // ERROR: counter name ends in `_total_total`
//! ```
//!
//! Both checks have a greppable escape hatch for grandfathered metrics --
//! `describe_unchecked` for the text, `metric_name_unchecked` for the name:
//!
//! ```
//! #[derive(carbide_instrument::Event)]
//! #[event(event_name = "demo", metric_name = "carbide_demo_total_total", component = "demo",
//!         log = off, metric = counter, metric_name_unchecked,
//!         describe = "Total number of demos", describe_unchecked)]
//! struct Demo {}
//! ```

use std::time::Duration;

/// The derive macros: `#[derive(Event)]` and `#[derive(LabelValue)]`.
pub use carbide_instrument_macros::{Event, LabelValue};
use opentelemetry::{KeyValue, StringValue};

/// Whether (and at which level) an event writes a log line.
///
/// `Off` means no `tracing` event is constructed at all -- a metric-only
/// event has zero logging cost, not "logged then filtered".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogAt {
    /// No log line is ever constructed.
    Off,
    /// Log at this level (still subject to the subscriber's filters).
    Level(tracing::Level),
}

/// Which metric instrument an event updates, if any.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// A monotonic counter; the metric name must end in `_total`.
    Counter,
    /// A histogram of [`Event::observation`] values; the metric name must end
    /// in its unit (`_seconds`, `_milliseconds`, `_microseconds`, `_bytes`).
    Histogram {
        /// The OpenTelemetry unit string, derived from the name suffix.
        unit: &'static str,
    },
    /// No metric; the event is a structured log only.
    None,
}

/// A bounded metric label value.
///
/// Derivable only for fieldless enums -- that restriction is the cardinality
/// guarantee: a metric's series count is the product of its label domains,
/// and every derived domain is a closed set. For a value that is bounded but
/// not an enum (an RPC method name, a vendor), implement this by hand on a
/// newtype; the manual impl is the deliberate, greppable escape hatch and the
/// place to justify boundedness at review. `String` never implements it.
pub trait LabelValue {
    /// The value as it appears on both the metric label and the log line.
    fn label_value(&self) -> StringValue;
}

/// A value a histogram event records, converted to the unit the metric name
/// declares (`Duration` converts; plain numbers record as-is).
pub trait Observation {
    /// The value in the metric's declared unit.
    fn observe_as(&self, unit: &'static str) -> f64;
}

impl Observation for Duration {
    fn observe_as(&self, unit: &'static str) -> f64 {
        match unit {
            "ms" => self.as_secs_f64() * 1_000.0,
            "us" => self.as_secs_f64() * 1_000_000.0,
            // Seconds, and the sensible default for anything else.
            _ => self.as_secs_f64(),
        }
    }
}

impl Observation for f64 {
    fn observe_as(&self, _unit: &'static str) -> f64 {
        *self
    }
}

macro_rules! lossless_observation {
    ($($ty:ty),*) => {
        $(
            impl Observation for $ty {
                fn observe_as(&self, _unit: &'static str) -> f64 {
                    f64::from(*self)
                }
            }
        )*
    };
}
lossless_observation!(f32, u32, i32);

macro_rules! wide_observation {
    ($($ty:ty),*) => {
        $(
            impl Observation for $ty {
                fn observe_as(&self, _unit: &'static str) -> f64 {
                    // Counts and sizes; precision loss starts beyond 2^53.
                    *self as f64
                }
            }
        )*
    };
}
wide_observation!(u64, usize, i64);

/// A significant occurrence, declared once as a type.
///
/// Implemented with `#[derive(Event)]` (see the crate docs). Production hand
/// implementations are unsupported because they bypass identity validation
/// and the workspace uniqueness check. Emitting an event produces a log line
/// and/or a metric per the [`LogAt`] and [`MetricKind`] knobs -- each side
/// independently optional.
pub trait Event {
    /// Stable semantic identity for this event, rendered as `event_name` on
    /// Event-generated log lines.
    const EVENT_NAME: &'static str;
    /// The exposed metric name, verbatim and derive-validated. Exactly `Some`
    /// when [`Self::METRIC`] records a metric; `None` for a typed log with
    /// `metric = none`.
    const METRIC_NAME: Option<&'static str>;
    /// The owning subsystem, for tooling and test assertions. The logfmt
    /// `component` key on log lines continues to come from the subscriber
    /// configuration and span attributes, as everywhere else.
    const COMPONENT: &'static str;
    /// The metric's description: the Prometheus HELP text, and the row the
    /// `core_metrics.md` catalogue picks up. Empty for log-only events.
    const DESCRIBE: &'static str = "";
    /// The declared log side. Default: log at INFO.
    const LOG: LogAt = LogAt::Level(tracing::Level::INFO);
    /// The declared metric side. Default: no metric.
    const METRIC: MetricKind = MetricKind::None;
    /// The label array, sized by the derive -- no heap allocation on emit.
    type Labels: AsRef<[KeyValue]>;

    /// The constant, human-readable message for the log line.
    fn message(&self) -> &'static str;
    /// The bounded labels, attached to both the metric and the log line.
    fn labels(&self) -> Self::Labels;
    /// High-cardinality detail, attached to the log line only.
    ///
    /// Introspection for tests and tooling: [`emit`] does not read it. The
    /// derive renders context fields inline in the generated log call
    /// instead, so the log path keeps static field names and allocates
    /// nothing for them.
    fn context(&self) -> Vec<KeyValue> {
        Vec::new()
    }
    /// The value a histogram records; counters ignore it.
    fn observation(&self) -> f64 {
        1.0
    }
    /// Per-instance log control (e.g. log failures, count successes
    /// silently). Defaults to the declared [`Self::LOG`].
    fn log_at(&self) -> LogAt {
        Self::LOG
    }

    #[doc(hidden)]
    fn __log(&self, level: tracing::Level);
    #[doc(hidden)]
    fn __instrument(&self) -> &'static __private::CachedInstrument;
}

/// Emits an event: a log line and/or a metric, per the event's knobs.
///
/// Never panics. The metric side resolves its instrument once per event type
/// (a `OnceLock`) from the global OpenTelemetry meter -- install the meter
/// provider at startup, before the first emit, as every NICo binary already
/// does for its existing metrics.
pub fn emit<E: Event>(event: E) {
    if let LogAt::Level(level) = event.log_at() {
        event.__log(level);
    }
    match event.__instrument() {
        __private::CachedInstrument::Counter(counter) => {
            counter.add(1, event.labels().as_ref());
        }
        __private::CachedInstrument::Histogram(histogram) => {
            histogram.record(event.observation(), event.labels().as_ref());
        }
        __private::CachedInstrument::None => {}
    }
}

/// The success-or-failure of an operation, as a bounded label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The operation succeeded.
    Ok,
    /// The operation failed.
    Error,
}

impl LabelValue for Outcome {
    fn label_value(&self) -> StringValue {
        StringValue::from(match self {
            Outcome::Ok => "ok",
            Outcome::Error => "error",
        })
    }
}

impl<T, E> From<&Result<T, E>> for Outcome {
    fn from(result: &Result<T, E>) -> Self {
        match result {
            Ok(_) => Outcome::Ok,
            Err(_) => Outcome::Error,
        }
    }
}

pub mod log_events;
pub use log_events::LogEventsMetric;
pub mod red;

#[cfg(feature = "test-support")]
pub mod testing;

#[doc(hidden)]
pub mod __private {
    //! Support for the derive-generated code; not a public API.

    pub use opentelemetry;
    pub use tracing;

    /// The per-event-type instrument, resolved once and cached in a
    /// `OnceLock` by the generated `__instrument()`.
    pub enum CachedInstrument {
        Counter(opentelemetry::metrics::Counter<u64>),
        Histogram(opentelemetry::metrics::Histogram<f64>),
        None,
    }

    /// Builds the instrument an event type declares, from the global meter.
    ///
    /// `Event::METRIC_NAME` is the *exposed* name, verbatim. The Prometheus
    /// exporter appends the conventional suffix itself (`_total` for
    /// counters, the unit for histograms), so the instrument registers under
    /// the name with that suffix stripped -- what lands on `/metrics` is
    /// exactly `METRIC_NAME`.
    pub fn new_instrument<E: crate::Event>() -> CachedInstrument {
        let meter = opentelemetry::global::meter("carbide-instrument");
        let Some(metric_name) = E::METRIC_NAME else {
            return CachedInstrument::None;
        };
        match E::METRIC {
            crate::MetricKind::Counter => {
                let name = metric_name.strip_suffix("_total").unwrap_or(metric_name);
                let mut builder = meter.u64_counter(name);
                if !E::DESCRIBE.is_empty() {
                    builder = builder.with_description(E::DESCRIBE);
                }
                CachedInstrument::Counter(builder.build())
            }
            crate::MetricKind::Histogram { unit } => {
                let suffix = match unit {
                    "s" => "_seconds",
                    "ms" => "_milliseconds",
                    "us" => "_microseconds",
                    "By" => "_bytes",
                    _ => "",
                };
                let name = if suffix.is_empty() {
                    metric_name
                } else {
                    metric_name.strip_suffix(suffix).unwrap_or(metric_name)
                };
                let mut builder = meter.f64_histogram(name);
                if !unit.is_empty() {
                    builder = builder.with_unit(unit);
                }
                if !E::DESCRIBE.is_empty() {
                    builder = builder.with_description(E::DESCRIBE);
                }
                CachedInstrument::Histogram(builder.build())
            }
            crate::MetricKind::None => CachedInstrument::None,
        }
    }
}

/// Per-instance log-level selection for `log = dynamic` events: implement
/// this (the derive routes `Event::log_at` through it) to choose the level --
/// or [`LogAt::Off`] -- from the event's own fields. The idiom: count every
/// outcome, log only the failures.
pub trait DynamicLog {
    /// Where (and whether) this instance logs.
    fn log_at(&self) -> LogAt;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(carbide_instrument::Event)]
    #[event(
        event_name = "metric_only_reserved_labels",
        metric_name = "carbide_metric_only_reserved_labels_total",
        component = "instrument_test",
        log = off,
        metric = counter,
        describe = "Number of metric-only reserved-label test events",
    )]
    struct MetricOnlyReservedLabels {
        #[label]
        component: carbide_instrument::Outcome,
        #[label]
        event_name: carbide_instrument::Outcome,
        #[label]
        metric_name: carbide_instrument::Outcome,
    }

    #[test]
    fn outcome_from_result() {
        let ok: Result<(), &str> = Ok(());
        let err: Result<(), &str> = Err("nope");
        assert_eq!(Outcome::from(&ok), Outcome::Ok);
        assert_eq!(Outcome::from(&err), Outcome::Error);
    }

    #[test]
    fn duration_observation_converts_to_the_declared_unit() {
        use carbide_test_support::{Check, check_values};

        check_values(
            [
                Check {
                    scenario: "seconds",
                    input: "s",
                    expect: 1.5,
                },
                Check {
                    scenario: "milliseconds",
                    input: "ms",
                    expect: 1500.0,
                },
                Check {
                    scenario: "microseconds",
                    input: "us",
                    expect: 1_500_000.0,
                },
                Check {
                    scenario: "unknown units fall back to seconds",
                    input: "By",
                    expect: 1.5,
                },
            ],
            |unit| Duration::from_millis(1500).observe_as(unit),
        );
    }

    #[test]
    fn numeric_observations_ignore_the_unit() {
        assert!((42u64.observe_as("ms") - 42.0).abs() < f64::EPSILON);
        assert!((2.5f64.observe_as("s") - 2.5).abs() < f64::EPSILON);
    }

    #[test]
    fn metric_only_reserved_labels_have_no_log_surface() {
        let event = MetricOnlyReservedLabels {
            component: carbide_instrument::Outcome::Ok,
            event_name: carbide_instrument::Outcome::Ok,
            metric_name: carbide_instrument::Outcome::Ok,
        };

        assert_eq!(carbide_instrument::Event::labels(&event).len(), 3);
        assert_eq!(
            carbide_instrument::Event::log_at(&event),
            carbide_instrument::LogAt::Off
        );
    }
}
