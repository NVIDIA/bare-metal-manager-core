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

//! Cross-controller registry backing per-object metrics.
//!
//! Per-object series (one or more per object id) are emitted from shared
//! gauges rather than a type-prefixed metric per controller, so metric names
//! stay stable as observability generalizes across object types. Writers
//! obtain a [`PerObjectGauge`] via [`PerObjectMetricsRegistry::gauge`] and
//! replace an object's series with [`PerObjectGauge::set`]/[`set_all`]/
//! [`clear`]; each gauge's series exist only while the fact they state is
//! true, and entries not refreshed within the registry's hold period are
//! evicted lazily on read.
//!
//! The per-object health classification metric predates this generalization
//! and keeps its dedicated [`PerObjectMetricsRegistry::record`]/
//! [`PerObjectMetricsRegistry::register`] API (opt-in per classification to
//! bound cardinality), implemented on the first gauge handle.
//!
//! [`set_all`]: PerObjectGauge::set_all
//! [`clear`]: PerObjectGauge::clear

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use health_report::HealthAlertClassification;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Meter;
use prometheus::core::{Collector, Desc};
use prometheus::proto;

const UNHEALTHY_BY_CLASSIFICATION_METRIC: &str = "carbide_object_unhealthy_by_classification_count";

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct ObjectKey {
    /// `machine`, `switch`, `rack`, `power_shelf`, ...
    object_type: &'static str,
    object_id: String,
}

impl ObjectKey {
    fn new(object_type: &'static str, object_id: &str) -> Self {
        Self {
            object_type,
            object_id: object_id.to_string(),
        }
    }
}

/// The series one object currently exposes on one gauge. The series set is
/// shared via `Arc` so scrape callbacks can snapshot it and observe outside
/// the gauge lock.
#[derive(Debug)]
struct SeriesEntry {
    /// `(value, labels)` per series.
    series: Arc<Vec<(f64, Vec<KeyValue>)>>,
    /// Prometheus encoding of `series`, built once outside the gauge lock on
    /// first collection (the series are immutable after insert) so scrapes
    /// clone instead of re-encode.
    prometheus_metrics: Arc<OnceLock<Vec<proto::Metric>>>,
    updated_at: Instant,
}

/// Writer handle for one per-object gauge. Cheap to clone; all clones share
/// the same series store. The `(object_type, object_id)` key controls only
/// series lifecycle (replace/evict) — labels are emitted exactly as supplied,
/// so metrics that need `object_type`/`object_id` labels must include them.
#[derive(Clone, Debug)]
pub struct PerObjectGauge(Arc<GaugeState>);

#[derive(Debug)]
struct GaugeState {
    hold_period: Duration,
    entries: Mutex<HashMap<ObjectKey, SeriesEntry>>,
}

impl PerObjectGauge {
    fn new(hold_period: Duration) -> Self {
        Self(Arc::new(GaugeState {
            hold_period,
            entries: Mutex::new(HashMap::new()),
        }))
    }

    /// Replaces the object's series with a single one.
    pub fn set(&self, object_type: &'static str, object_id: &str, value: f64, labels: Vec<KeyValue>) {
        self.set_all(object_type, object_id, vec![(value, labels)]);
    }

    /// Replaces all of the object's series on this gauge; an empty set removes
    /// the object so its series stop being emitted.
    pub fn set_all(
        &self,
        object_type: &'static str,
        object_id: &str,
        series: Vec<(f64, Vec<KeyValue>)>,
    ) {
        let key = ObjectKey::new(object_type, object_id);
        let mut entries = self.0.entries.lock().expect("per-object gauge mutex poisoned");
        if series.is_empty() {
            entries.remove(&key);
        } else if let Some(entry) = entries.get_mut(&key).filter(|entry| *entry.series == series) {
            // Unchanged series (the common case: controllers re-record every
            // iteration): keep the entry — and its cached Prometheus encoding
            // — and only extend the eviction deadline.
            entry.updated_at = Instant::now();
        } else {
            entries.insert(
                key,
                SeriesEntry {
                    series: Arc::new(series),
                    prometheus_metrics: Arc::new(OnceLock::new()),
                    updated_at: Instant::now(),
                },
            );
        }
    }

    /// Removes all of the object's series on this gauge.
    pub fn clear(&self, object_type: &'static str, object_id: &str) {
        self.set_all(object_type, object_id, Vec::new());
    }

    /// Refreshes the object's eviction deadline without changing its series;
    /// a no-op if the object has none. For writers that cannot determine the
    /// current value this iteration but know the existing series must not be
    /// evicted meanwhile.
    pub fn touch(&self, object_type: &'static str, object_id: &str) {
        let key = ObjectKey::new(object_type, object_id);
        let mut entries = self.0.entries.lock().expect("per-object gauge mutex poisoned");
        if let Some(entry) = entries.get_mut(&key) {
            entry.updated_at = Instant::now();
        }
    }

    /// Like [`Self::touch`], but only while every series still carries all of
    /// `required_labels`; otherwise the entry is removed — the recorded fact
    /// no longer describes the object's current state, so keeping it alive
    /// would publish contradictory labels.
    pub fn touch_if_labels(
        &self,
        object_type: &'static str,
        object_id: &str,
        required_labels: &[KeyValue],
    ) {
        let key = ObjectKey::new(object_type, object_id);
        let mut entries = self.0.entries.lock().expect("per-object gauge mutex poisoned");
        if let Some(entry) = entries.get_mut(&key) {
            let still_current = entry.series.iter().all(|(_, labels)| {
                required_labels
                    .iter()
                    .all(|required| labels.contains(required))
            });
            if still_current {
                entry.updated_at = Instant::now();
            } else {
                entries.remove(&key);
            }
        }
    }

    /// Registers this gauge as a u64 OpenTelemetry instrument (the
    /// pre-existing classification metric's exposition type; changing it
    /// would fork the series for typed OTLP consumers).
    fn register_on(&self, meter: &Meter, name: &'static str, description: &'static str) {
        let state = self.clone();
        meter
            .u64_observable_gauge(name)
            .with_description(description)
            .with_callback(move |observer| {
                // Snapshot under the lock (cheap Arc clones), observe outside
                // it, so a large scrape doesn't stall writers.
                let mut snapshots = Vec::new();
                state.for_each_live(|_, entry| snapshots.push(entry.series.clone()));
                for (value, labels) in snapshots.iter().flat_map(|series| series.iter()) {
                    observer.observe(*value as u64, labels);
                }
            })
            .build();
    }

    /// Locks the gauge, evicts stale entries, and visits the survivors.
    fn for_each_live(&self, mut visit: impl FnMut(&ObjectKey, &SeriesEntry)) {
        let now = Instant::now();
        let mut entries = self.0.entries.lock().expect("per-object gauge mutex poisoned");
        entries
            .retain(|_, entry| now.saturating_duration_since(entry.updated_at) <= self.0.hold_period);
        for (key, entry) in entries.iter() {
            visit(key, entry);
        }
    }
}

/// Exports one [`PerObjectGauge`] as a native Prometheus metric family.
#[derive(Debug)]
struct GaugeCollector {
    gauge: PerObjectGauge,
    name: &'static str,
    help: &'static str,
    desc: Desc,
}

impl GaugeCollector {
    fn new(
        gauge: PerObjectGauge,
        name: &'static str,
        help: &'static str,
        label_names: &[&str],
    ) -> prometheus::Result<Self> {
        let desc = Desc::new(
            name.to_string(),
            help.to_string(),
            label_names.iter().map(|label| label.to_string()).collect(),
            HashMap::new(),
        )?;
        Ok(Self {
            gauge,
            name,
            help,
            desc,
        })
    }
}

impl Collector for GaugeCollector {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.desc]
    }

    fn collect(&self) -> Vec<proto::MetricFamily> {
        // Snapshot under the gauge lock (cheap Arc clones), then encode
        // outside it so a large scrape doesn't stall writers. The encoding is
        // cached per entry, and unchanged re-records keep the entry, so
        // steady-state scrapes only clone.
        let mut snapshots = Vec::new();
        self.gauge.for_each_live(|_, entry| {
            snapshots.push((entry.series.clone(), entry.prometheus_metrics.clone()));
        });
        let metrics: Vec<proto::Metric> = snapshots
            .iter()
            .flat_map(|(series, encoded)| {
                encoded
                    .get_or_init(|| series.iter().map(prometheus_metric).collect())
                    .iter()
                    .cloned()
            })
            .collect();
        if metrics.is_empty() {
            return Vec::new();
        }
        let mut family = proto::MetricFamily::default();
        family.set_name(self.name.to_string());
        family.set_help(self.help.to_string());
        family.set_field_type(proto::MetricType::GAUGE);
        family.set_metric(metrics);
        vec![family]
    }
}

fn prometheus_metric((value, labels): &(f64, Vec<KeyValue>)) -> proto::Metric {
    let mut labels: Vec<_> = labels
        .iter()
        .map(|key_value| {
            let mut label = proto::LabelPair::default();
            label.set_name(key_value.key.as_str().to_string());
            label.set_value(key_value.value.to_string());
            label
        })
        .collect();
    labels.sort_by(|left, right| left.name().cmp(right.name()));

    let mut gauge = proto::Gauge::default();
    gauge.set_value(*value);
    let mut metric = proto::Metric::from_gauge(gauge);
    metric.set_label(labels);
    metric
}

/// Shared factory for per-object gauges, plus the per-object health
/// classification metric. Stale entries (not refreshed within `hold_period`)
/// are evicted lazily on read, mirroring the controllers' `metric_hold_time`.
#[derive(Debug)]
pub struct PerObjectMetricsRegistry {
    emit_for_classifications: HashSet<HealthAlertClassification>,
    classification: PerObjectGauge,
    /// Every gauge created through this registry (including the
    /// classification gauge), so [`Self::clear_object`] can sweep all series
    /// of a deleted object.
    gauges: Mutex<Vec<PerObjectGauge>>,
}

impl PerObjectMetricsRegistry {
    /// Emits per-object classification series only for
    /// `emit_for_classifications`; an empty set disables that metric entirely
    /// (gauges created via [`Self::gauge`] are unaffected). `hold_period`
    /// governs the classification gauge and should match (or slightly
    /// exceed) the feeding controllers' `metric_hold_time`.
    pub fn new(
        emit_for_classifications: impl IntoIterator<Item = HealthAlertClassification>,
        hold_period: Duration,
    ) -> Arc<Self> {
        let classification = PerObjectGauge::new(hold_period);
        Arc::new(Self {
            emit_for_classifications: emit_for_classifications.into_iter().collect(),
            classification: classification.clone(),
            gauges: Mutex::new(vec![classification]),
        })
    }

    /// Creates a per-object gauge with its own `hold_period` (an object's
    /// series is only refreshed when its controller processes it, so the hold
    /// must cover the slowest feeder's refresh interval), exported as a
    /// native Prometheus collector on `registry` (typically the dedicated
    /// per-object endpoint's registry). Native collection deliberately
    /// bypasses OpenTelemetry instruments, whose per-stream cardinality limit
    /// (2000 series by default) a per-object fleet vastly exceeds.
    pub fn gauge(
        &self,
        registry: &prometheus::Registry,
        name: &'static str,
        help: &'static str,
        label_names: &[&str],
        hold_period: Duration,
    ) -> prometheus::Result<PerObjectGauge> {
        let gauge = PerObjectGauge::new(hold_period);
        registry.register(Box::new(GaugeCollector::new(
            gauge.clone(),
            name,
            help,
            label_names,
        )?))?;
        self.gauges
            .lock()
            .expect("per-object registry mutex poisoned")
            .push(gauge.clone());
        Ok(gauge)
    }

    /// Removes every series of the object across all gauges created through
    /// this registry, e.g. when the object was deleted. (Gauge locks nest
    /// inside the registry lock; no path takes them in the other order.)
    pub fn clear_object(&self, object_type: &'static str, object_id: &str) {
        for gauge in self
            .gauges
            .lock()
            .expect("per-object registry mutex poisoned")
            .iter()
        {
            gauge.clear(object_type, object_id);
        }
    }

    /// Refreshes the eviction deadline of every series of the object across
    /// all gauges created through this registry, without changing them. For
    /// iterations that could not determine the object's state at all (e.g. a
    /// load failure): neither the state series nor the info/association
    /// series recorded by handlers that never ran may evict mid-incident.
    pub fn touch_object(&self, object_type: &'static str, object_id: &str) {
        for gauge in self
            .gauges
            .lock()
            .expect("per-object registry mutex poisoned")
            .iter()
        {
            gauge.touch(object_type, object_id);
        }
    }

    /// Records the object's current classifications, retaining only those opted
    /// in for emission. An object left with no opted-in classification (e.g. it
    /// became healthy) is removed so its series stop being emitted.
    pub fn record<'a>(
        &self,
        object_type: &'static str,
        object_id: &str,
        classifications: impl IntoIterator<Item = &'a HealthAlertClassification>,
        extra_labels: Vec<KeyValue>,
    ) {
        // When disabled the map is always empty, so skip the key alloc and lock.
        if self.emit_for_classifications.is_empty() {
            return;
        }

        let series: Vec<(f64, Vec<KeyValue>)> = classifications
            .into_iter()
            .filter(|c| self.emit_for_classifications.contains(*c))
            .map(|c| {
                let mut labels = vec![
                    KeyValue::new("object_type", object_type),
                    KeyValue::new("object_id", object_id.to_string()),
                    KeyValue::new("classification", c.to_string()),
                ];
                labels.extend(extra_labels.iter().cloned());
                (1.0, labels)
            })
            .collect();
        self.classification.set_all(object_type, object_id, series);
    }

    /// Registers the per-object classification gauge. Call once per process;
    /// with no opted-in classifications nothing is registered.
    pub fn register(self: &Arc<Self>, meter: &Meter) {
        if self.emit_for_classifications.is_empty() {
            return;
        }
        self.classification.register_on(
            meter,
            UNHEALTHY_BY_CLASSIFICATION_METRIC,
            "Per-object indication that an object (host, switch, rack, ...) is marked with a \
             health alert classification due to being unhealthy. Labeled with object_type and \
             object_id. Only classifications configured via \
             observability.per_object_metrics_for_classifications are emitted, bounding \
             metric cardinality.",
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifications(values: &[&str]) -> Vec<HealthAlertClassification> {
        values.iter().map(|v| v.parse().unwrap()).collect()
    }

    /// `(object_type, object_id, sorted (value, sorted labels) per series)`.
    type GaugeRow = (String, String, Vec<(f64, Vec<(String, String)>)>);

    fn gauge_snapshot(gauge: &PerObjectGauge) -> Vec<GaugeRow> {
        let mut rows = Vec::new();
        gauge.for_each_live(|key, entry| {
            let mut series: Vec<(f64, Vec<(String, String)>)> = entry
                .series
                .iter()
                .map(|(value, labels)| {
                    let mut labels: Vec<(String, String)> = labels
                        .iter()
                        .map(|kv| (kv.key.to_string(), kv.value.to_string()))
                        .collect();
                    labels.sort();
                    (*value, labels)
                })
                .collect();
            series.sort_by(|a, b| a.partial_cmp(b).unwrap());
            rows.push((key.object_type.to_string(), key.object_id.clone(), series));
        });
        rows.sort_by(|a, b| a.partial_cmp(b).unwrap());
        rows
    }

    /// `(object_type, object_id, sorted classifications, sorted labels)`.
    type SnapshotRow = (String, String, Vec<String>, Vec<(String, String)>);

    fn snapshot(registry: &PerObjectMetricsRegistry) -> Vec<SnapshotRow> {
        let mut rows = Vec::new();
        registry.classification.for_each_live(|key, entry| {
            let mut classifications = Vec::new();
            let mut labels = Vec::new();
            for (value, series_labels) in entry.series.iter() {
                assert!((*value - 1.0).abs() < f64::EPSILON);
                for kv in series_labels {
                    match kv.key.as_str() {
                        "object_type" | "object_id" => {}
                        "classification" => classifications.push(kv.value.to_string()),
                        _ => labels.push((kv.key.to_string(), kv.value.to_string())),
                    }
                }
            }
            classifications.sort();
            labels.sort();
            labels.dedup();
            rows.push((
                key.object_type.to_string(),
                key.object_id.clone(),
                classifications,
                labels,
            ));
        });
        rows.sort();
        rows
    }

    #[test]
    fn disabled_registry_records_nothing() {
        let registry = PerObjectMetricsRegistry::new(Vec::new(), Duration::from_secs(60));
        registry.record(
            "machine",
            "machine-a",
            &classifications(&["Hardware"]),
            vec![],
        );
        assert!(snapshot(&registry).is_empty());
    }

    #[test]
    fn record_retains_only_opted_in_classifications_and_labels() {
        let registry =
            PerObjectMetricsRegistry::new(classifications(&["Hardware"]), Duration::from_secs(60));

        registry.record(
            "machine",
            "machine-a",
            &classifications(&["Hardware", "PreventAllocations"]),
            vec![KeyValue::new("in_use", "true")],
        );

        assert_eq!(
            snapshot(&registry),
            vec![(
                "machine".to_string(),
                "machine-a".to_string(),
                vec!["Hardware".to_string()],
                vec![("in_use".to_string(), "true".to_string())],
            )]
        );
    }

    #[test]
    fn record_without_opted_in_classification_removes_existing_entry() {
        let registry =
            PerObjectMetricsRegistry::new(classifications(&["Hardware"]), Duration::from_secs(60));

        registry.record(
            "machine",
            "machine-a",
            &classifications(&["Hardware"]),
            vec![],
        );
        assert_eq!(snapshot(&registry).len(), 1);

        // The object now carries only non-opted-in classifications: its series
        // must stop being emitted, and extra labels alone must not keep it alive.
        registry.record(
            "machine",
            "machine-a",
            &classifications(&["PreventAllocations"]),
            vec![KeyValue::new("in_use", "false")],
        );
        assert!(snapshot(&registry).is_empty());
    }

    #[test]
    fn distinct_object_types_and_ids_are_independent() {
        let registry =
            PerObjectMetricsRegistry::new(classifications(&["Hardware"]), Duration::from_secs(60));

        registry.record(
            "machine",
            "shared-id",
            &classifications(&["Hardware"]),
            vec![],
        );
        registry.record(
            "switch",
            "shared-id",
            &classifications(&["Hardware"]),
            vec![],
        );

        assert_eq!(snapshot(&registry).len(), 2);
    }

    #[test]
    fn stale_entries_are_evicted_on_read() {
        let registry =
            PerObjectMetricsRegistry::new(classifications(&["Hardware"]), Duration::from_millis(0));

        registry.record(
            "machine",
            "machine-a",
            &classifications(&["Hardware"]),
            vec![],
        );

        // With a zero hold period the entry is immediately stale on the next read.
        std::thread::sleep(Duration::from_millis(5));
        assert!(snapshot(&registry).is_empty());
    }

    #[test]
    fn gauge_set_replaces_the_objects_series() {
        let gauge = PerObjectGauge::new(Duration::from_secs(60));

        gauge.set(
            "machine",
            "machine-a",
            1.0,
            vec![KeyValue::new("state", "provisioning")],
        );
        gauge.set(
            "machine",
            "machine-a",
            2.0,
            vec![KeyValue::new("state", "ready")],
        );

        assert_eq!(
            gauge_snapshot(&gauge),
            vec![(
                "machine".to_string(),
                "machine-a".to_string(),
                vec![(2.0, vec![("state".to_string(), "ready".to_string())])],
            )]
        );
    }

    #[test]
    fn gauge_set_all_emits_one_series_per_entry_and_empty_removes() {
        let gauge = PerObjectGauge::new(Duration::from_secs(60));

        gauge.set_all(
            "machine",
            "machine-a",
            vec![
                (1.0, vec![KeyValue::new("dpu_id", "dpu-1")]),
                (1.0, vec![KeyValue::new("dpu_id", "dpu-2")]),
            ],
        );
        assert_eq!(gauge_snapshot(&gauge)[0].2.len(), 2);

        gauge.set_all("machine", "machine-a", vec![]);
        assert!(gauge_snapshot(&gauge).is_empty());
    }

    #[test]
    fn gauge_clear_removes_only_the_given_object() {
        let gauge = PerObjectGauge::new(Duration::from_secs(60));

        gauge.set("machine", "machine-a", 1.0, vec![]);
        gauge.set("switch", "switch-a", 1.0, vec![]);

        gauge.clear("machine", "machine-a");

        let rows = gauge_snapshot(&gauge);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].0, "switch");
    }

    #[test]
    fn prometheus_collector_exports_more_than_otel_default_cardinality() {
        // Native collection must not inherit OpenTelemetry's default
        // per-stream cardinality limit (2000 series per instrument).
        let registry = PerObjectMetricsRegistry::new(Vec::new(), Duration::from_secs(60));
        let prometheus_registry = prometheus::Registry::new();
        let gauge = registry
            .gauge(
                &prometheus_registry,
                "test_per_object_gauge",
                "test gauge",
                &["object_type", "object_id"],
                Duration::from_secs(60),
            )
            .unwrap();

        for i in 0..2100 {
            gauge.set(
                "machine",
                &format!("machine-{i}"),
                1.0,
                vec![
                    KeyValue::new("object_type", "machine"),
                    KeyValue::new("object_id", format!("machine-{i}")),
                ],
            );
        }

        let families = prometheus_registry.gather();
        assert_eq!(families.len(), 1);
        assert_eq!(families[0].get_metric().len(), 2100);
    }

    #[test]
    fn clear_object_sweeps_all_registry_gauges() {
        let registry = PerObjectMetricsRegistry::new(
            classifications(&["Hardware"]),
            Duration::from_secs(60),
        );
        let prometheus_registry = prometheus::Registry::new();
        let gauge_a = registry
            .gauge(
                &prometheus_registry,
                "test_gauge_a",
                "a",
                &[],
                Duration::from_secs(60),
            )
            .unwrap();
        let gauge_b = registry
            .gauge(
                &prometheus_registry,
                "test_gauge_b",
                "b",
                &[],
                Duration::from_secs(60),
            )
            .unwrap();

        registry.record(
            "machine",
            "machine-a",
            &classifications(&["Hardware"]),
            vec![],
        );
        gauge_a.set("machine", "machine-a", 1.0, vec![]);
        gauge_b.set("machine", "machine-a", 1.0, vec![]);
        gauge_a.set("machine", "machine-b", 1.0, vec![]);

        registry.clear_object("machine", "machine-a");

        assert!(snapshot(&registry).is_empty());
        let rows = gauge_snapshot(&gauge_a);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].1, "machine-b");
        assert!(gauge_snapshot(&gauge_b).is_empty());
    }

    #[test]
    fn touch_if_labels_clears_series_with_stale_labels() {
        let gauge = PerObjectGauge::new(Duration::from_secs(60));
        gauge.set(
            "machine",
            "machine-a",
            1.0,
            vec![KeyValue::new("state", "failed")],
        );

        // The fact still matches the object's state: kept alive.
        gauge.touch_if_labels("machine", "machine-a", &[KeyValue::new("state", "failed")]);
        assert_eq!(gauge_snapshot(&gauge).len(), 1);

        // The object's state moved on: the stale fact is removed rather than
        // kept publishing contradictory labels.
        gauge.touch_if_labels(
            "machine",
            "machine-a",
            &[KeyValue::new("state", "provisioning")],
        );
        assert!(gauge_snapshot(&gauge).is_empty());
    }

    #[test]
    fn gauge_stale_entries_are_evicted_on_read() {
        let gauge = PerObjectGauge::new(Duration::from_millis(0));

        gauge.set("machine", "machine-a", 1.0, vec![]);

        std::thread::sleep(Duration::from_millis(5));
        assert!(gauge_snapshot(&gauge).is_empty());
    }
}
