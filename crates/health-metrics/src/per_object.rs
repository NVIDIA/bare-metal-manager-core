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

//! Cross-controller registry backing the per-object health metrics.
//!
//! Per-object series (one per object id) are emitted from a single shared
//! registry rather than a type-prefixed metric per controller, so the metric
//! name stays stable as observability generalizes across object types. Each
//! state controller records its objects via [`PerObjectMetricsRegistry::record`];
//! the gauge registered once via [`PerObjectMetricsRegistry::register`] reads the
//! entries, labeling each series with `object_type` and `object_id`. Emission is
//! opt-in per classification to bound cardinality.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use health_report::HealthAlertClassification;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Meter;

const UNHEALTHY_BY_CLASSIFICATION_METRIC: &str = "carbide_object_unhealthy_by_classification_count";

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
struct ObjectKey {
    /// `machine`, `switch`, `rack`, `power_shelf`, ...
    object_type: &'static str,
    object_id: String,
}

#[derive(Debug)]
struct ObjectEntry {
    /// Opted-in classifications currently present on the object.
    classifications: Vec<String>,
    /// Extra labels (e.g. `in_use`) added to every series for this object.
    extra_labels: Vec<KeyValue>,
    updated_at: Instant,
}

/// Shared registry backing the per-object health metrics. Controllers write via
/// [`Self::record`]; the gauge registered once via [`Self::register`] emits the
/// entries. Stale entries (not refreshed within `hold_period`) are evicted
/// lazily on read, mirroring the controllers' `metric_hold_time`.
#[derive(Debug)]
pub struct PerObjectMetricsRegistry {
    emit_for_classifications: HashSet<HealthAlertClassification>,
    hold_period: Duration,
    entries: Mutex<HashMap<ObjectKey, ObjectEntry>>,
}

impl PerObjectMetricsRegistry {
    /// Emits per-object series only for `emit_for_classifications`; an empty set
    /// disables per-object emission entirely. `hold_period` should match (or
    /// slightly exceed) the controllers' `metric_hold_time`.
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

        let classifications: Vec<String> = classifications
            .into_iter()
            .filter(|c| self.emit_for_classifications.contains(*c))
            .map(ToString::to_string)
            .collect();

        let key = ObjectKey {
            object_type,
            object_id: object_id.to_string(),
        };
        let mut entries = self.entries.lock().expect("registry mutex poisoned");
        if classifications.is_empty() {
            entries.remove(&key);
        } else {
            entries.insert(
                key,
                ObjectEntry {
                    classifications,
                    extra_labels,
                    updated_at: Instant::now(),
                },
            );
        }
    }

    /// Registers the per-object gauge. Call once per process; with no opted-in
    /// classifications nothing is registered.
    pub fn register(self: &Arc<Self>, meter: &Meter) {
        if self.emit_for_classifications.is_empty() {
            return;
        }

        let registry = self.clone();
        meter
            .u64_observable_gauge(UNHEALTHY_BY_CLASSIFICATION_METRIC)
            .with_description(
                "Per-object indication that an object (host, switch, rack, ...) is marked with a \
                 health alert classification due to being unhealthy. Labeled with object_type and \
                 object_id. Only classifications configured via \
                 observability.per_object_metrics_for_classifications are emitted, bounding \
                 metric cardinality.",
            )
            .with_callback(move |observer| {
                registry.for_each_live(|key, entry| {
                    for classification in &entry.classifications {
                        let mut labels = vec![
                            KeyValue::new("object_type", key.object_type),
                            KeyValue::new("object_id", key.object_id.clone()),
                            KeyValue::new("classification", classification.clone()),
                        ];
                        labels.extend(entry.extra_labels.iter().cloned());
                        observer.observe(1, &labels);
                    }
                });
            })
            .build();
    }

    /// Locks the registry, evicts stale entries, and visits the survivors.
    fn for_each_live(&self, mut visit: impl FnMut(&ObjectKey, &ObjectEntry)) {
        let mut entries = self.entries.lock().expect("registry mutex poisoned");
        entries.retain(|_, entry| entry.updated_at.elapsed() <= self.hold_period);
        for (key, entry) in entries.iter() {
            visit(key, entry);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classifications(values: &[&str]) -> Vec<HealthAlertClassification> {
        values.iter().map(|v| v.parse().unwrap()).collect()
    }

    /// `(object_type, object_id, sorted classifications, sorted labels)`.
    type SnapshotRow = (String, String, Vec<String>, Vec<(String, String)>);

    fn snapshot(registry: &PerObjectMetricsRegistry) -> Vec<SnapshotRow> {
        let mut rows = Vec::new();
        registry.for_each_live(|key, entry| {
            let mut classifications = entry.classifications.clone();
            classifications.sort();
            let mut labels: Vec<(String, String)> = entry
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
}
