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

use std::fmt;
use std::fmt::Display;
use std::time::Duration;

use ::carbide_utils::metrics::SharedMetricsHolder;
use opentelemetry::metrics::{Counter, Histogram, Meter};

/// Metrics that are gathered in a single dpa monitor run
#[derive(Clone, Debug)]
pub struct DpaMonitorMetrics {
    /// Start time of metrics gathering
    pub recording_started_at: std::time::Instant,
    pub num_machines_scanned: usize,
    pub num_instances_scanned: usize,
    pub num_dpa_interfaces_scanned: usize,
    pub num_heartbeats_sent: usize,
    pub num_creates: usize,
    pub num_deletes: usize,
}

impl DpaMonitorMetrics {
    pub fn new() -> Self {
        Self {
            recording_started_at: std::time::Instant::now(),
            num_machines_scanned: 0,
            num_instances_scanned: 0,
            num_dpa_interfaces_scanned: 0,
            num_heartbeats_sent: 0,
            num_creates: 0,
            num_deletes: 0,
        }
    }
}

impl Display for DpaMonitorMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{{ machines_scanned: {}, instances_scanned: {}, duration: {} }}",
            self.num_machines_scanned,
            self.num_instances_scanned,
            self.recording_started_at.elapsed().as_millis(),
        )
    }
}

/// Stores Metric data shared between the dpa monitor and the OpenTelemetry background task
pub struct MetricHolder {
    instruments: DpaMonitorInstruments,
    last_iteration_metrics: SharedMetricsHolder<DpaMonitorMetrics>,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: Duration) -> Self {
        let last_iteration_metrics = SharedMetricsHolder::with_hold_period(hold_period);
        let instruments = DpaMonitorInstruments::new(meter, last_iteration_metrics.clone());
        instruments.init_counters_and_histograms();
        Self {
            instruments,
            last_iteration_metrics,
        }
    }

    /// Updates the most recent metrics
    pub fn update_metrics(&self, metrics: DpaMonitorMetrics) {
        // Emit the last recent latency metrics
        self.instruments.emit_counters_and_histograms(&metrics);
        self.last_iteration_metrics.update(metrics);
    }
}

/// Instruments that are used by pub struct DpaMonitor
#[allow(dead_code)]
pub struct DpaMonitorInstruments {
    pub iteration_latency: Histogram<f64>,
    pub operations_latency: Histogram<f64>,
    pub dpa_config_apply_latency: Histogram<f64>,
    pub heartbeats_sent: Counter<u64>,
    pub creates: Counter<u64>,
    pub deletes: Counter<u64>,
}

impl DpaMonitorInstruments {
    pub fn new(meter: Meter, shared_metrics: SharedMetricsHolder<DpaMonitorMetrics>) -> Self {
        let iteration_latency = meter
            .f64_histogram("carbide_dpa_monitor_iteration_latency")
            .with_description("Time consumed for one monitor iteration")
            .with_unit("ms")
            .build();
        let dpa_config_apply_latency = meter
            .f64_histogram("carbide_dpa_monitor_dpa_config_apply_latency")
            .with_description("Time since dpa config was requested for this instance")
            .with_unit("ms")
            .build();
        let operations_latency = meter
            .f64_histogram("carbide_dpa_monitor_operations_latency")
            .with_description("Time consumed for one operations")
            .with_unit("ms")
            .build();
        let heartbeats_sent = meter
            .u64_counter("carbide_dpa_monitor_heartbeats_sent")
            .with_description("Number of heartbeats sent to DPA interfaces")
            .build();
        let creates = meter
            .u64_counter("carbide_dpa_monitor_creates")
            .with_description("Number of DPA interfaces created")
            .build();
        let deletes = meter
            .u64_counter("carbide_dpa_monitor_deletes")
            .with_description("Number of DPA interfaces deleted")
            .build();

        meter
            .u64_observable_gauge("carbide_dpa_monitor_interfaces_scanned_count")
            .with_description("Number of DPA interfaces scanned in the last monitor iteration")
            .with_callback(move |o| {
                shared_metrics.if_available(|metrics, attrs| {
                    o.observe(metrics.num_dpa_interfaces_scanned as u64, attrs);
                })
            })
            .build();

        Self {
            iteration_latency,
            dpa_config_apply_latency,
            operations_latency,
            heartbeats_sent,
            creates,
            deletes,
        }
    }

    fn init_counters_and_histograms(&self) {
        self.heartbeats_sent.add(0, &[]);
        self.creates.add(0, &[]);
        self.deletes.add(0, &[]);
    }

    fn emit_counters_and_histograms(&self, metrics: &DpaMonitorMetrics) {
        self.iteration_latency.record(
            1000.0 * metrics.recording_started_at.elapsed().as_secs_f64(),
            &[],
        );
        self.heartbeats_sent
            .add(metrics.num_heartbeats_sent as u64, &[]);
        self.creates.add(metrics.num_creates as u64, &[]);
        self.deletes.add(metrics.num_deletes as u64, &[]);
    }
}
