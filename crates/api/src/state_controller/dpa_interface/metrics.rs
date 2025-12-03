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

use opentelemetry::metrics::Meter;

use crate::logging::metrics_utils::SharedMetricsHolder;
use crate::state_controller::metrics::MetricsEmitter;

#[derive(Debug, Default, Clone)]
pub struct DpaInterfaceMetrics {}

#[derive(Debug, Default)]
pub struct DpaInterfaceStateControllerIterationMetrics {}

#[derive(Debug)]
pub struct DpaInterfaceMetricsEmitter {}

impl DpaInterfaceStateControllerIterationMetrics {}

impl MetricsEmitter for DpaInterfaceMetricsEmitter {
    type ObjectMetrics = DpaInterfaceMetrics;
    type IterationMetrics = DpaInterfaceStateControllerIterationMetrics;

    fn new(
        _object_type: &str,
        _meter: &Meter,
        _shared_metrics: SharedMetricsHolder<Self::IterationMetrics>,
    ) -> Self {
        Self {}
    }

    // This routine is called in the context of a single thread.
    // The statecontroller launches multiple threads (upto max_concurrency)
    // Each thread works on one object and records the metrics for that object.
    // Once all the tasks are done, the original thread calls merge object_handling_metrics.
    // No need for mutex when manipulating the seg_stats HashMap.
    fn merge_object_handling_metrics(
        _iteration_metrics: &mut Self::IterationMetrics,
        _object_metrics: &Self::ObjectMetrics,
    ) {
    }

    fn emit_object_counters_and_histograms(&self, _object_metrics: &Self::ObjectMetrics) {}
}
