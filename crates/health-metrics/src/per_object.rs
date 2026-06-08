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

//! Cross-controller registry backing the generic per-object health metrics.
//!
//! Per-object series (one per object id) are emitted from a single shared
//! registry rather than a type-prefixed metric per controller, so the metric
//! name stays stable as observability generalizes across object types. Each
//! object keeps one [`ObjectObservability`] record; [`Self::register`] wires up
//! one observable instrument per dimension, all labeled with `object_type` and
//! `object_id`. Emission is opt-in per dimension to bound cardinality.
//!
//! To add a per-object metric: add a field to [`ObjectObservability`], a setter
//! to [`ObjectObservationBuilder`], and an instrument in
//! [`PerObjectMetricsRegistry::register`]. Counters (e.g. transition counts) do
//! not belong here; this registry only snapshots point-in-time gauges.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use health_report::HealthAlertClassification;
use opentelemetry::metrics::Meter;
use opentelemetry::{KeyValue, Value};

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct ObjectKey {
    /// `machine`, `switch`, `rack`, `power_shelf`, ...
    object_type: &'static str,
    object_id: String,
}

/// One object's per-object signals; each metric-bearing field backs a distinct
/// instrument registered by [`PerObjectMetricsRegistry::register`].
#[derive(Debug, Default, Clone)]
struct ObjectObservability {
    /// Opted-in classifications present on the object. Backs
    /// `carbide_object_unhealthy_by_classification_count`.
    classifications: Vec<String>,
    /// Extra labels (e.g. `in_use`) applied to every series; not a metric, so
    /// they do not by themselves keep an entry alive.
    extra_labels: Vec<KeyValue>,
}

impl ObjectObservability {
    /// An empty record (e.g. the object became healthy) is evicted. Extend as
    /// metric-bearing dimensions are added.
    fn is_empty(&self) -> bool {
        self.classifications.is_empty()
    }
}

#[derive(Debug)]
struct ObjectEntry {
    observability: ObjectObservability,
    updated_at: Instant,
}

/// Shared registry backing the generic per-object health metrics. Controllers
/// record signals via [`Self::observe`]; instruments registered once via
/// [`Self::register`] emit them. Stale entries (not refreshed within
/// `hold_period`) are evicted lazily on read, mirroring the controllers'
/// `metric_hold_time`.
#[derive(Debug)]
pub struct PerObjectMetricsRegistry {
    emit_for_classifications: HashSet<HealthAlertClassification>,
    hold_period: Duration,
    entries: Mutex<HashMap<ObjectKey, ObjectEntry>>,
}

impl PerObjectMetricsRegistry {
    /// Name of the per-object "unhealthy by classification" gauge.
    pub const UNHEALTHY_BY_CLASSIFICATION_METRIC: &'static str =
        "carbide_object_unhealthy_by_classification_count";

    /// Emits per-object classification series only for `emit_for_classifications`;
    /// an empty set disables per-object emission entirely. `hold_period` should
    /// match (or slightly exceed) the controllers' `metric_hold_time`.
    pub fn new(
        emit_for_classifications: impl IntoIterator<Item = HealthAlertClassification>,
        hold_period: Duration,
    ) -> Arc<Self> {
        Arc::new(Self {
            emit_for_classifications: emit_for_classifications.into_iter().collect(),
            hold_period,
            entries: Mutex::new(HashMap::new()),
        })
    }

    /// Whether any per-object dimension is enabled.
    pub fn is_enabled(&self) -> bool {
        !self.emit_for_classifications.is_empty()
    }

    /// Begins recording observations for one object. Chain dimension setters and
    /// finish with [`ObjectObservationBuilder::commit`]; the full set of signals
    /// must be provided each call, and an object whose record ends up empty is
    /// evicted.
    pub fn observe<'a>(
        &'a self,
        object_type: &'static str,
        object_id: &'a str,
    ) -> ObjectObservationBuilder<'a> {
        ObjectObservationBuilder {
            registry: self,
            object_type,
            object_id,
            record: ObjectObservability::default(),
        }
    }

    /// Registers one observable instrument per enabled dimension. Call exactly
    /// once per process (instruments are shared across object types); disabled
    /// dimensions register nothing.
    pub fn register(self: &Arc<Self>, meter: &Meter) {
        if !self.emit_for_classifications.is_empty() {
            self.register_unhealthy_by_classification(meter);
        }
    }

    fn register_unhealthy_by_classification(self: &Arc<Self>, meter: &Meter) {
        let registry = self.clone();
        meter
            .u64_observable_gauge(Self::UNHEALTHY_BY_CLASSIFICATION_METRIC)
            .with_description(
                "Per-object indication that an object (host, switch, rack, ...) is marked with a \
                 health alert classification due to being unhealthy. Labeled with object_type and \
                 object_id. Only classifications configured via \
                 observability.per_object_metrics_for_classifications are emitted, bounding \
                 metric cardinality.",
            )
            .with_callback(move |observer| {
                registry.for_each_live(|key, record| {
                    for classification in &record.classifications {
                        let mut labels = Vec::with_capacity(3 + record.extra_labels.len());
                        labels.push(KeyValue::new("object_type", key.object_type));
                        labels.push(KeyValue::new("object_id", key.object_id.clone()));
                        labels.push(KeyValue::new("classification", classification.clone()));
                        labels.extend(record.extra_labels.iter().cloned());
                        observer.observe(1, &labels);
                    }
                });
            })
            .build();
    }

    /// Runs `f` over all live entries, lazily evicting stale ones first.
    fn for_each_live(&self, mut f: impl FnMut(&ObjectKey, &ObjectObservability)) {
        let mut entries = self.entries.lock().expect("registry mutex poisoned");
        let hold_period = self.hold_period;
        entries.retain(|_, entry| entry.updated_at.elapsed() <= hold_period);
        for (key, entry) in entries.iter() {
            f(key, &entry.observability);
        }
    }

    fn store(&self, object_type: &'static str, object_id: &str, record: ObjectObservability) {
        // When disabled the map is always empty, so skip the key alloc and lock.
        if record.is_empty() && !self.is_enabled() {
            return;
        }

        let key = ObjectKey {
            object_type,
            object_id: object_id.to_string(),
        };

        let mut entries = self.entries.lock().expect("registry mutex poisoned");
        if record.is_empty() {
            entries.remove(&key);
        } else {
            entries.insert(
                key,
                ObjectEntry {
                    observability: record,
                    updated_at: Instant::now(),
                },
            );
        }
    }
}

/// Builder for a single object's per-object observations.
///
/// Created via [`PerObjectMetricsRegistry::observe`]; finish with
/// [`Self::commit`].
#[must_use = "observations are only recorded when `commit` is called"]
pub struct ObjectObservationBuilder<'a> {
    registry: &'a PerObjectMetricsRegistry,
    object_type: &'static str,
    object_id: &'a str,
    record: ObjectObservability,
}

impl<'a> ObjectObservationBuilder<'a> {
    /// Records the object's classifications; only those opted in for emission
    /// are retained.
    pub fn classifications<'c>(
        mut self,
        classifications: impl IntoIterator<Item = &'c HealthAlertClassification>,
    ) -> Self {
        self.record.classifications = classifications
            .into_iter()
            .filter(|classification| {
                self.registry
                    .emit_for_classifications
                    .contains(*classification)
            })
            .map(|classification| classification.to_string())
            .collect();
        self
    }

    /// Adds an extra per-object label applied to every series this object emits.
    pub fn label(mut self, key: &'static str, value: impl Into<Value>) -> Self {
        self.record.extra_labels.push(KeyValue::new(key, value));
        self
    }

    /// Stores the observation, replacing any previous record for this object.
    pub fn commit(self) {
        self.registry
            .store(self.object_type, self.object_id, self.record);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn classification(value: &str) -> HealthAlertClassification {
        value.parse().expect("valid classification")
    }

    fn classifications(values: &[&str]) -> Vec<HealthAlertClassification> {
        values.iter().map(|v| classification(v)).collect()
    }

    fn snapshot(
        registry: &PerObjectMetricsRegistry,
    ) -> Vec<(String, String, Vec<String>, Vec<(String, String)>)> {
        let mut rows = Vec::new();
        registry.for_each_live(|key, record| {
            let mut classifications = record.classifications.clone();
            classifications.sort();
            let mut labels: Vec<(String, String)> = record
                .extra_labels
                .iter()
                .map(|kv| (kv.key.to_string(), kv.value.to_string()))
                .collect();
            labels.sort();
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
        assert!(!registry.is_enabled());

        registry
            .observe("machine", "machine-a")
            .classifications(&classifications(&["Hardware"]))
            .commit();

        assert!(snapshot(&registry).is_empty());
    }

    #[test]
    fn observe_retains_only_opted_in_classifications_and_labels() {
        let registry =
            PerObjectMetricsRegistry::new([classification("Hardware")], Duration::from_secs(60));

        registry
            .observe("machine", "machine-a")
            .classifications(&classifications(&["Hardware", "PreventAllocations"]))
            .label("in_use", "true")
            .commit();

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
    fn observe_without_opted_in_classification_removes_existing_entry() {
        let registry =
            PerObjectMetricsRegistry::new([classification("Hardware")], Duration::from_secs(60));

        registry
            .observe("machine", "machine-a")
            .classifications(&classifications(&["Hardware"]))
            .commit();
        assert_eq!(snapshot(&registry).len(), 1);

        // The object became healthy (or only carries non-opted-in
        // classifications): its series must stop being emitted, and extra labels
        // alone must not keep the entry alive.
        registry
            .observe("machine", "machine-a")
            .classifications(&classifications(&["PreventAllocations"]))
            .label("in_use", "false")
            .commit();
        assert!(snapshot(&registry).is_empty());
    }

    #[test]
    fn distinct_object_types_and_ids_are_independent() {
        let registry =
            PerObjectMetricsRegistry::new([classification("Hardware")], Duration::from_secs(60));

        registry
            .observe("machine", "shared-id")
            .classifications(&classifications(&["Hardware"]))
            .commit();
        registry
            .observe("switch", "shared-id")
            .classifications(&classifications(&["Hardware"]))
            .commit();

        assert_eq!(snapshot(&registry).len(), 2);
    }

    #[test]
    fn stale_entries_are_evicted_on_read() {
        let registry =
            PerObjectMetricsRegistry::new([classification("Hardware")], Duration::from_millis(0));

        registry
            .observe("machine", "machine-a")
            .classifications(&classifications(&["Hardware"]))
            .commit();

        // With a zero hold period the entry is immediately stale on the next read.
        std::thread::sleep(Duration::from_millis(5));
        assert!(snapshot(&registry).is_empty());
    }
}
