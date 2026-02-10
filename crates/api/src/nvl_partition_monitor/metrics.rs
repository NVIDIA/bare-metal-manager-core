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

use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use serde::Serialize;

use crate::logging::metrics_utils::SharedMetricsHolder;
use crate::nvl_partition_monitor::NmxmPartitionOperationType;

/// Metrics that are gathered in a single nvl partition monitor run
#[derive(Clone, Debug)]
pub struct NvlPartitionMonitorMetrics {
    /// Start time of metrics gathering
    pub recording_started_at: std::time::Instant,
    pub nmxm: NmxmMetrics,
    pub num_machines_scanned: usize,
    pub num_instances_scanned: usize,
    pub num_gpus_scanned: usize,
    /// Number of machines where NVLink status observation got updated
    pub num_machine_nvl_status_updates: usize,
    /// Number of logical partitions
    pub num_logical_partitions: usize,
    /// Number of physical partitions
    pub num_physical_partitions: usize,
    /// Number of completed operations in this run
    pub num_completed_operations: usize,
    /// Number of NvLink GPU nmx_m_id mismatches between DB and NMX-M
    pub num_nvlink_info_mismatches: usize,
    /// Number of stale partitions deleted from DB (not found in NMX-M)
    pub num_stale_partitions_deleted: usize,
    pub applied_changes: HashMap<AppliedChange, usize>,
    pub operation_latencies: HashMap<AppliedChange, Vec<Duration>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NmxmPartitionOperations {
    Create,
    Remove,
    RemoveDefaultPartition,
    Update,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NmxmPartitionOperationStatus {
    Completed,
    Failed,
    Timedout,
    Cancelled,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AppliedChange {
    /// The operation that has been issued
    pub operation: NmxmPartitionOperations,
    /// Whether the operation succeeded or failed
    pub status: NmxmPartitionOperationStatus,
}

/// Metrics collected for nmx-m data
#[derive(Clone, Debug, Default, Serialize)]
pub struct NmxmMetrics {
    /// The endpoint that we use to interact with nmx-m
    pub endpoint: String,
    /// connection errors
    pub connect_error: String,
    /// Version of nmxm
    pub version: String,
    /// Number of partitions visible at NMX-M
    pub num_partitions: usize,
    /// Number of gpus visible at NMX-M
    pub num_gpus: usize,
}

impl NvlPartitionMonitorMetrics {
    pub fn new() -> Self {
        Self {
            recording_started_at: std::time::Instant::now(),
            num_machines_scanned: 0,
            num_instances_scanned: 0,
            num_machine_nvl_status_updates: 0,
            num_logical_partitions: 0,
            num_physical_partitions: 0,
            num_gpus_scanned: 0,
            num_completed_operations: 0,
            num_nvlink_info_mismatches: 0,
            num_stale_partitions_deleted: 0,
            applied_changes: HashMap::new(),
            operation_latencies: HashMap::new(),
            nmxm: NmxmMetrics {
                endpoint: String::new(),
                connect_error: String::new(),
                version: String::new(),
                num_partitions: 0,
                num_gpus: 0,
            },
        }
    }
}

impl Display for NvlPartitionMonitorMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ machines_scanned: {}, instances_scanned: {}, nvl_status_updates: {}, num_logical_partitions: {}, num_physical_partitions:{}, num_gpus_scanned: {}, nvlink_info_mismatches: {}, stale_partitions_deleted: {}, applied_changes: {}, nmxm_connect_err: {}, nmxm_num_partitions: {}, nmxm_num_gpus: {}, completed_operations: {}, duration: {} }}",
            self.num_machines_scanned,
            self.num_instances_scanned,
            self.num_machine_nvl_status_updates,
            self.num_logical_partitions,
            self.num_physical_partitions,
            self.num_gpus_scanned,
            self.num_nvlink_info_mismatches,
            self.num_stale_partitions_deleted,
            self.applied_changes.len(),
            self.nmxm.connect_error,
            self.nmxm.num_partitions,
            self.nmxm.num_gpus,
            self.num_completed_operations,
            self.recording_started_at.elapsed().as_millis(),
        )
    }
}

/// Instruments that are used by pub struct NvlPartitionMonitor
pub struct NvlPartitionMonitorInstruments {
    pub iteration_latency: Histogram<f64>,
    pub nmxm_changes_applied: Counter<u64>,
    pub operations_latency: Histogram<f64>,
}

impl NvlPartitionMonitorInstruments {
    pub fn new(
        meter: Meter,
        shared_metrics: SharedMetricsHolder<NvlPartitionMonitorMetrics>,
    ) -> Self {
        let iteration_latency = meter
            .f64_histogram("carbide_nvlink_partition_monitor_iteration_latency")
            .with_description("Time consumed for one monitor iteration")
            .with_unit("ms")
            .build();

        let operations_latency = meter
            .f64_histogram("carbide_nvlink_partition_monitor_nmxm_op_latency")
            .with_description("Time consumed for one nmxm operations")
            .with_unit("ms")
            .build();

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge(
                    "carbide_nvlink_partition_monitor_machine_status_updates_count",
                )
                .with_description("Number of machines nvlink_status_observation got updated")
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        o.observe(metrics.num_machine_nvl_status_updates as u64, attrs);
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_nvlink_partition_monitor_num_logical_partitions")
                .with_description("Number of logical partitions that were monitored")
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        o.observe(metrics.num_logical_partitions as u64, attrs);
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_nvlink_partition_monitor_num_physical_partitions")
                .with_description("Number of physical partitions that were monitored")
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        o.observe(metrics.num_physical_partitions as u64, attrs);
                    })
                })
                .build();
        }

        let nmxm_changes_applied = meter
            .u64_counter("carbide_nvlink_partition_monitor_nmxm_changes_applied")
            .with_description("Number of changes requested to Nmx-M")
            .build();

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_nvlink_partition_monitor_nmxm_connect_error_count")
                .with_description("The errors encountered while checking NMX-M")
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        if !metrics.nmxm.connect_error.is_empty() {
                            o.observe(
                                1,
                                &[
                                    attrs,
                                    &[KeyValue::new(
                                        "error",
                                        truncate_error_for_metric_label(
                                            metrics.nmxm.connect_error.clone(),
                                        ),
                                    )],
                                ]
                                .concat(),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_nvlink_partition_monitor_nmxm_partition_count")
                .with_description("Number of partitions NMX-M is reporting")
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        o.observe(metrics.nmxm.num_partitions as u64, attrs);
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_nvlink_partition_monitor_nmxm_gpu_count")
                .with_description("Number of GPUs NMX-M is reporting")
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        o.observe(metrics.nmxm.num_partitions as u64, attrs);
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_nvlink_partition_monitor_nvlink_info_mismatches")
                .with_description("Number of NvLink GPU nmx_m_id mismatches between DB and NMX-M")
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        o.observe(metrics.num_nvlink_info_mismatches as u64, attrs);
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics;
            meter
                .u64_observable_gauge("carbide_nvlink_partition_monitor_stale_partitions_deleted")
                .with_description("Number of stale partitions deleted from DB (not found in NMX-M)")
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        o.observe(metrics.num_stale_partitions_deleted as u64, attrs);
                    })
                })
                .build();
        }

        Self {
            iteration_latency,
            nmxm_changes_applied,
            operations_latency,
        }
    }

    fn emit_counters_and_histograms(&self, metrics: &NvlPartitionMonitorMetrics) {
        self.iteration_latency.record(
            1000.0 * metrics.recording_started_at.elapsed().as_secs_f64(),
            &[],
        );

        for (change, &count) in metrics.applied_changes.iter() {
            self.nmxm_changes_applied.add(
                count as u64,
                &[
                    KeyValue::new("operation", change.operation),
                    KeyValue::new("status", change.status),
                ],
            );
        }

        for (change, latencies) in metrics.operation_latencies.iter() {
            for latency in latencies {
                self.operations_latency.record(
                    1000.0 * latency.as_secs_f64(), // latency in milliseconds
                    &[
                        KeyValue::new("operation", change.operation),
                        KeyValue::new("status", change.status),
                    ],
                );
            }
        }
    }

    fn init_counters_and_histograms(&self) {
        for status in [false, true] {
            for operation in NmxmPartitionOperations::values() {
                self.nmxm_changes_applied.add(
                    0u64,
                    &[
                        KeyValue::new("operation", operation),
                        KeyValue::new("status", status),
                    ],
                );
            }
        }
    }
}

impl NmxmPartitionOperations {
    pub fn values() -> impl Iterator<Item = Self> {
        [Self::Create, Self::Update, Self::Pending, Self::Remove].into_iter()
    }
}

impl From<NmxmPartitionOperations> for opentelemetry::Value {
    fn from(value: NmxmPartitionOperations) -> Self {
        let str_value = match value {
            NmxmPartitionOperations::Create => "create",
            NmxmPartitionOperations::Update => "update",
            NmxmPartitionOperations::Remove => "remove",
            NmxmPartitionOperations::Pending => "pending",
            NmxmPartitionOperations::RemoveDefaultPartition => "remove_default_partition",
        };

        Self::from(str_value)
    }
}

impl From<NmxmPartitionOperationType> for NmxmPartitionOperations {
    fn from(value: NmxmPartitionOperationType) -> NmxmPartitionOperations {
        match value {
            NmxmPartitionOperationType::Create => NmxmPartitionOperations::Create,
            NmxmPartitionOperationType::Remove(_) => NmxmPartitionOperations::Remove,
            NmxmPartitionOperationType::RemoveDefaultPartition(_) => {
                NmxmPartitionOperations::RemoveDefaultPartition
            }
            NmxmPartitionOperationType::Update(_) => NmxmPartitionOperations::Update,
            NmxmPartitionOperationType::Pending(_) => NmxmPartitionOperations::Pending,
        }
    }
}

impl NmxmPartitionOperationStatus {
    pub fn values() -> impl Iterator<Item = Self> {
        [Self::Completed, Self::Failed, Self::Timedout].into_iter()
    }
}

impl From<NmxmPartitionOperationStatus> for opentelemetry::Value {
    fn from(value: NmxmPartitionOperationStatus) -> Self {
        let str_value = match value {
            NmxmPartitionOperationStatus::Completed => "completed",
            NmxmPartitionOperationStatus::Failed => "failed",
            NmxmPartitionOperationStatus::Timedout => "timedout",
            NmxmPartitionOperationStatus::Cancelled => "cancelled",
        };

        Self::from(str_value)
    }
}

/// Stores Metric data shared between the nvl partition monitor and the OpenTelemetry background task
pub struct MetricHolder {
    instruments: NvlPartitionMonitorInstruments,
    last_iteration_metrics: SharedMetricsHolder<NvlPartitionMonitorMetrics>,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: Duration) -> Self {
        let last_iteration_metrics = SharedMetricsHolder::with_hold_period(hold_period);
        let instruments =
            NvlPartitionMonitorInstruments::new(meter, last_iteration_metrics.clone());
        instruments.init_counters_and_histograms();
        Self {
            instruments,
            last_iteration_metrics,
        }
    }

    /// Updates the most recent metrics
    pub fn update_metrics(&self, metrics: NvlPartitionMonitorMetrics) {
        // Emit the last recent latency metrics
        self.instruments.emit_counters_and_histograms(&metrics);
        self.last_iteration_metrics.update(metrics);
    }
}

/// Truncates an error message in order to use it as label
/// Borrowed this from IbFabricMonitor code
fn truncate_error_for_metric_label(mut error: String) -> String {
    const MAX_LEN: usize = 32;

    let upto = error
        .char_indices()
        .map(|(i, _)| i)
        .nth(MAX_LEN)
        .unwrap_or(error.len());
    error.truncate(upto);
    error
}
