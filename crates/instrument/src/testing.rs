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

//! Capture helpers for asserting, in plain unit tests, that an event logged
//! at the expected level *and* moved the expected metric -- the coherency
//! guarantee is itself testable.
//!
//! ```
//! use carbide_instrument::testing::{MetricsCapture, capture_logs};
//! use carbide_instrument::{Event, emit};
//!
//! #[derive(Event)]
//! #[event(event_name = "doc_demo", metric_name = "carbide_doc_demo_total", component = "demo",
//!         log = warn, metric = counter, message = "demo fired",
//!         describe = "Number of demo events fired")]
//! struct Demo {}
//!
//! let metrics = MetricsCapture::start();
//! let logs = capture_logs(|| emit(Demo {}));
//!
//! assert_eq!(logs.len(), 1);
//! assert_eq!(logs[0].level, tracing::Level::WARN);
//! assert_eq!(logs[0].message, "demo fired");
//! assert_eq!(metrics.counter_delta("carbide_doc_demo_total", &[]), 1.0);
//! ```

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use tracing_subscriber::layer::{Context, SubscriberExt};

/// One captured log event: its level, message, and rendered fields.
#[derive(Debug, Clone)]
pub struct CapturedLog {
    /// The event's stable `tracing` metadata name.
    pub metadata_name: String,
    pub level: tracing::Level,
    /// The event's `tracing` target (usually the emitting module path).
    pub target: String,
    pub message: String,
    /// Field name/value pairs as strings, in emission order.
    pub fields: Vec<(String, String)>,
}

impl CapturedLog {
    /// Returns the rendered value of the first field named `name`.
    pub fn field(&self, name: &str) -> Option<&str> {
        self.fields
            .iter()
            .find_map(|(field_name, value)| (field_name == name).then_some(value.as_str()))
    }
}

/// Runs `f` under a capturing subscriber (this thread only) and returns every
/// log event it emitted, at any level.
pub fn capture_logs(f: impl FnOnce()) -> Vec<CapturedLog> {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let layer = CaptureLayer {
        captured: captured.clone(),
    };
    let subscriber = tracing_subscriber::registry().with(layer);
    tracing::subscriber::with_default(subscriber, f);
    let logs = captured.lock().unwrap_or_else(|p| p.into_inner());
    logs.clone()
}

struct CaptureLayer {
    captured: Arc<Mutex<Vec<CapturedLog>>>,
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for CaptureLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        // The OpenTelemetry crates emit their own internal diagnostics through
        // `tracing`; they are not the events under test.
        if event.metadata().target().starts_with("opentelemetry") {
            return;
        }
        let mut visitor = CaptureVisitor {
            message: String::new(),
            fields: Vec::new(),
        };
        event.record(&mut visitor);
        self.captured
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(CapturedLog {
                metadata_name: event.metadata().name().to_string(),
                level: *event.metadata().level(),
                target: event.metadata().target().to_string(),
                message: visitor.message,
                fields: visitor.fields,
            });
    }
}

struct CaptureVisitor {
    message: String,
    fields: Vec<(String, String)>,
}

impl tracing::field::Visit for CaptureVisitor {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.fields
            .push((field.name().to_string(), value.to_string()));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        // `%display` fields and the message both arrive here; their Debug
        // rendering forwards to Display, so this is the raw string.
        let rendered = format!("{value:?}");
        if field.name() == "message" {
            self.message = rendered;
        } else {
            self.fields.push((field.name().to_string(), rendered));
        }
    }
}

/// A serialized window onto the process-global test meter.
///
/// The first capture installs a Prometheus-backed meter provider as the
/// global OpenTelemetry meter (instruments are cached per event type, so
/// tests share one provider for the whole process); the mutex serializes
/// metric-asserting tests, and deltas are measured against the snapshot taken
/// at [`MetricsCapture::start`].
pub struct MetricsCapture {
    _serialized: MutexGuard<'static, ()>,
    baseline: Snapshot,
}

impl MetricsCapture {
    /// Locks the test-metrics window and snapshots current values.
    pub fn start() -> Self {
        static SERIAL: Mutex<()> = Mutex::new(());
        let guard = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        let registry = test_registry();
        Self {
            _serialized: guard,
            baseline: snapshot(registry),
        }
    }

    /// How much the named counter (with exactly these label pairs) moved
    /// since [`MetricsCapture::start`]. Zero if it never appeared.
    pub fn counter_delta(&self, name: &str, labels: &[(&str, &str)]) -> f64 {
        let now = snapshot(test_registry());
        now.value(name, labels) - self.baseline.value(name, labels)
    }

    /// How many observations the named histogram (with exactly these label
    /// pairs) recorded since [`MetricsCapture::start`].
    pub fn histogram_count_delta(&self, name: &str, labels: &[(&str, &str)]) -> u64 {
        self.counter_delta(&format!("{name}#count"), labels) as u64
    }

    /// The sum the named histogram accumulated since [`MetricsCapture::start`].
    pub fn histogram_sum_delta(&self, name: &str, labels: &[(&str, &str)]) -> f64 {
        self.counter_delta(&format!("{name}#sum"), labels)
    }

    /// The current registry contents in Prometheus text exposition format --
    /// handy for eyeballing exact rendered names and labels in a failing test.
    pub fn render(&self) -> String {
        use prometheus::Encoder as _;
        let mut buffer = Vec::new();
        prometheus::TextEncoder::new()
            .encode(&test_registry().gather(), &mut buffer)
            .expect("encode test registry");
        String::from_utf8(buffer).expect("prometheus text is utf-8")
    }
}

/// `(metric name, sorted labels) -> value`; histograms store `name#count`
/// and `name#sum` entries.
struct Snapshot(BTreeMap<(String, BTreeMap<String, String>), f64>);

impl Snapshot {
    fn value(&self, name: &str, labels: &[(&str, &str)]) -> f64 {
        let labels: BTreeMap<String, String> = labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        self.0
            .get(&(name.to_string(), labels))
            .copied()
            .unwrap_or_default()
    }
}

fn snapshot(registry: &prometheus::Registry) -> Snapshot {
    let mut values = BTreeMap::new();
    for family in registry.gather() {
        for metric in family.get_metric() {
            let labels: BTreeMap<String, String> = metric
                .get_label()
                .iter()
                .map(|pair| (pair.name().to_string(), pair.value().to_string()))
                .collect();
            match family.get_field_type() {
                prometheus::proto::MetricType::COUNTER => {
                    values.insert(
                        (family.name().to_string(), labels),
                        metric.get_counter().value(),
                    );
                }
                prometheus::proto::MetricType::HISTOGRAM => {
                    let histogram = metric.get_histogram();
                    values.insert(
                        (format!("{}#count", family.name()), labels.clone()),
                        histogram.get_sample_count() as f64,
                    );
                    values.insert(
                        (format!("{}#sum", family.name()), labels),
                        histogram.get_sample_sum(),
                    );
                }
                _ => {}
            }
        }
    }
    Snapshot(values)
}

/// Installs the test meter at test-binary load, before any test (and so any
/// `emit()`) runs. Instruments are cached per event type on first emit, so a
/// test that emits without a `MetricsCapture` must still find the real
/// provider installed -- otherwise that event type would bind to the no-op
/// global meter and later counter assertions would sit at zero.
#[ctor::ctor(unsafe)]
fn install_test_meter_eagerly() {
    let _ = test_registry();
}

/// The process-global test registry, installing the global meter provider on
/// first use.
fn test_registry() -> &'static prometheus::Registry {
    static REGISTRY: OnceLock<prometheus::Registry> = OnceLock::new();
    REGISTRY.get_or_init(|| {
        let registry = prometheus::Registry::new();
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .without_scope_info()
            .without_target_info()
            .build()
            .expect("test meter provider");
        let provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_reader(exporter)
            .build();
        opentelemetry::global::set_meter_provider(provider);
        registry
    })
}
