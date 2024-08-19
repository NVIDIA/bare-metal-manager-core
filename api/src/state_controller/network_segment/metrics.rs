/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! Defines custom metrics that are collected and emitted by the Machine State Controller

// use std::backtrace::Backtrace;
use std::collections::HashMap;

use opentelemetry::{
    metrics::{self, Meter, ObservableGauge},
    KeyValue,
};

use crate::state_controller::metrics::MetricsEmitter;

#[derive(Debug, Default, Clone)]
pub struct NetworkSegmentMetrics {
    // These are the stats for a particular segment
    pub available_ips: usize,
    pub reserved_ips: usize,
    pub total_ips: usize,
    // These are the attributes of that segment
    pub seg_name: String,
    pub prefix: String,
    pub seg_type: String,
    pub seg_id: String,
}

#[derive(Debug, Default)]
pub struct NetworkSegmentStateControllerIterationMetrics {
    // Hash key is segment uuid string; value is the metrics of that segment
    seg_stats: HashMap<String, NetworkSegmentMetrics>,
}

#[derive(Debug)]
pub struct NetworkSegmentMetricsEmitter {
    available_ips_gauge: ObservableGauge<u64>,
    reserved_ips_gauge: ObservableGauge<u64>,
    total_ips_gauge: ObservableGauge<u64>,
}

impl NetworkSegmentStateControllerIterationMetrics {}

impl MetricsEmitter for NetworkSegmentMetricsEmitter {
    type ObjectMetrics = NetworkSegmentMetrics;
    type IterationMetrics = NetworkSegmentStateControllerIterationMetrics;

    fn new(_object_type: &str, meter: &Meter) -> Self {
        let available_ips_gauge = meter
            .u64_observable_gauge("forge_available_ips_count")
            .with_description("The total number of available ips in the Forge site")
            .init();
        let reserved_ips_gauge = meter
            .u64_observable_gauge("forge_reserved_ips_count")
            .with_description("The total number of reserved ips in the Forge site")
            .init();
        let total_ips_gauge = meter
            .u64_observable_gauge("forge_total_ips_count")
            .with_description("The total number of ips in the Forge site")
            .init();
        Self {
            available_ips_gauge,
            reserved_ips_gauge,
            total_ips_gauge,
        }
    }

    fn instruments(&self) -> Vec<std::sync::Arc<dyn std::any::Any>> {
        vec![
            self.available_ips_gauge.as_any(),
            self.total_ips_gauge.as_any(),
            self.reserved_ips_gauge.as_any(),
        ]
    }

    // This routine is called in the context of a single thread.
    // The statecontroller launches multiple threads (upto max_concurrency)
    // Each thread works on one object and records the metrics for that object.
    // Once all the tasks are done, the original thread calls merge object_handling_metrics.
    // No need for mutex when manipulating the seg_stats HashMap.
    fn merge_object_handling_metrics(
        iteration_metrics: &mut Self::IterationMetrics,
        object_metrics: &Self::ObjectMetrics,
    ) {
        let this_seg_id = object_metrics.seg_id.clone();
        if this_seg_id.is_empty() {
            // If the segment state is not READY, the metrics would not
            // have been populated. So there are no stats to include for
            // such a segment.
            return;
        }
        iteration_metrics
            .seg_stats
            .insert(this_seg_id, (*object_metrics).clone());
    }

    fn emit_gauges(
        &self,
        observer: &dyn metrics::Observer,
        iteration_metrics: &Self::IterationMetrics,
        attributes: &[KeyValue],
    ) {
        let iteration_seg_stats = iteration_metrics.seg_stats.clone();
        for (_seg_id, seg_stats) in iteration_seg_stats {
            let mut seg_attrs = attributes.to_vec();
            seg_attrs.push(KeyValue::new("name", seg_stats.seg_name));
            seg_attrs.push(KeyValue::new("type", seg_stats.seg_type));
            seg_attrs.push(KeyValue::new("prefix", seg_stats.prefix));
            observer.observe_u64(
                &self.available_ips_gauge,
                seg_stats.available_ips as u64,
                &seg_attrs,
            );
            observer.observe_u64(
                &self.reserved_ips_gauge,
                seg_stats.reserved_ips as u64,
                &seg_attrs,
            );
            observer.observe_u64(
                &self.total_ips_gauge,
                seg_stats.total_ips as u64,
                &seg_attrs,
            );
        }
    }

    fn emit_counters_and_histograms(&self, _iteration_metrics: &Self::IterationMetrics) {}
}
