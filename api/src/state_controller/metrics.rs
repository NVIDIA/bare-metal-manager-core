/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{collections::HashMap, time::Duration};

use opentelemetry::{
    metrics::{Histogram, Meter, ObservableGauge, Unit},
    Context, KeyValue,
};

use crate::state_controller::{controller::StateControllerIO, state_handler::StateHandlerError};

/// The result of the state handler processing the state of a single object
pub struct ObjectHandlerMetrics<IO: StateControllerIO> {
    /// The state the object was in after the iteration ended
    pub state: Option<IO::ControllerState>,
    /// The time the object was in the this state
    pub time_in_state: Duration,
    /// How long we took to execute the state handler
    pub handler_latency: Duration,
    /// If state handling fails, this contains the error
    pub error: Option<StateHandlerError>,
}

/// Metrics that are produced by a state controller iteration
#[derive(Debug)]
pub struct IterationMetrics {
    /// When the metrics have been recorded
    pub recorded_at: std::time::Instant,
    /// Aggregated metrics per state
    pub state_metrics: HashMap<(&'static str, &'static str), StateMetrics>,
}

impl Default for IterationMetrics {
    fn default() -> Self {
        Self {
            recorded_at: std::time::Instant::now(),
            state_metrics: HashMap::new(),
        }
    }
}

impl IterationMetrics {
    pub fn merge_object_handling_metrics<IO: StateControllerIO>(
        &mut self,
        object_metrics: &ObjectHandlerMetrics<IO>,
    ) {
        // The `unknown` state can occur if loading the current object state fails
        // or if the state is not deserializable
        let (state, substate) = object_metrics
            .state
            .as_ref()
            .map(IO::metric_state_names)
            .unwrap_or(("unknown", ""));

        let state_metrics = self.state_metrics.entry((state, substate)).or_default();

        state_metrics.num_objects += 1;
        state_metrics
            .time_in_state
            .push(object_metrics.time_in_state);
        state_metrics
            .handler_latencies
            .push(object_metrics.handler_latency);

        if let Some(error) = &object_metrics.error {
            let error_label = error.metric_label();
            *state_metrics
                .handling_errors_per_type
                .entry(error_label)
                .or_default() += 1;
        }
    }
}

/// Metrics for each state of an object
#[derive(Debug, Clone, Default)]
pub struct StateMetrics {
    /// Amount of objects in the state
    pub num_objects: usize,
    /// The time the objects had been in that state
    pub time_in_state: Vec<Duration>,
    /// How long we took to execute state handlers in this state
    pub handler_latencies: Vec<Duration>,
    /// Counts the errors per error type in this state
    pub handling_errors_per_type: HashMap<&'static str, usize>,
}

/// Holds the OpenTelemetry datastructures that are used to submit
/// state handling related metrics
pub struct StateControllerMetricEmitter {
    _meter: Meter,
    total_objects_gauge: ObservableGauge<u64>,
    objects_per_state_gauge: ObservableGauge<u64>,
    errors_per_state_gauge: ObservableGauge<u64>,
    time_in_state_histogram: Histogram<f64>,
    handler_latency_in_state_histogram: Histogram<f64>,
}

impl StateControllerMetricEmitter {
    pub fn new(object_type: &str, meter: Meter) -> Self {
        let total_objects_gauge = meter
            .u64_observable_gauge(format!("{}_total", object_type))
            .with_description(format!("The total amount of {} in the system", object_type))
            .init();
        let objects_per_state_gauge: ObservableGauge<u64> = meter
            .u64_observable_gauge(format!("{}_per_state", object_type))
            .with_description(format!(
                "The amount of {} in the system with a given state",
                object_type
            ))
            .init();
        let errors_per_state_gauge = meter
            .u64_observable_gauge(format!(
                "{}_with_state_handling_errors_per_state",
                object_type
            ))
            .with_description(format!(
                "The amount of {} in the system with a given state that failed state handling",
                object_type
            ))
            .init();
        let time_in_state_histogram = meter
            .f64_histogram(format!("{}_time_in_state", object_type))
            .with_unit(Unit::new("s"))
            .init();
        let handler_latency_in_state_histogram = meter
            .f64_histogram(format!("{}_handler_latency_in_state", object_type))
            .with_unit(Unit::new("ms"))
            .init();

        Self {
            objects_per_state_gauge,
            total_objects_gauge,
            errors_per_state_gauge,
            handler_latency_in_state_histogram,
            time_in_state_histogram,
            _meter: meter,
        }
    }

    /// Emites the latency metrics that are captured during a single state handler
    /// iteration. Those are emitted immediately as histograms, whereas the
    /// amount of objects in states is emitted as gauges.
    pub fn emit_latency_metrics(&self, iteration_metrics: &IterationMetrics) {
        let cx = opentelemetry::Context::current();

        for ((state, substate), m) in iteration_metrics.state_metrics.iter() {
            let state_attr = KeyValue::new("state", state.to_string());
            let substate_attr = KeyValue::new("substate", substate.to_string());
            let attrs = &[state_attr.clone(), substate_attr.clone()];

            for time_in_state in m.time_in_state.iter() {
                self.time_in_state_histogram
                    .record(&cx, time_in_state.as_secs_f64(), attrs);
            }
            for handler_latency in m.handler_latencies.iter() {
                self.handler_latency_in_state_histogram.record(
                    &cx,
                    1000.0 * handler_latency.as_secs_f64(),
                    attrs,
                );
            }
        }
    }

    pub fn emit_gauges(&self, iteration_metrics: &IterationMetrics, otel_cx: &Context) {
        // This attributes defines whether we captured the metrics recently,
        // where recently here means in the last Minute. in the case multiple
        // state controllers run in a 3 control plane cluster, this will help
        // differentiating the metrics from a node which has recently acted on
        // objects from metrics that are more outdated
        const MAX_FRESH_DURATION: Duration = Duration::from_secs(60);
        let fresh_attr = KeyValue::new(
            "fresh",
            iteration_metrics.recorded_at.elapsed() <= MAX_FRESH_DURATION,
        );

        let mut total_objects = 0;
        for ((state, substate), m) in iteration_metrics.state_metrics.iter() {
            total_objects += m.num_objects;

            let state_attr = KeyValue::new("state", state.to_string());
            let substate_attr = KeyValue::new("substate", substate.to_string());
            let attrs = &[
                fresh_attr.clone(),
                state_attr.clone(),
                substate_attr.clone(),
            ];

            self.objects_per_state_gauge
                .observe(otel_cx, m.num_objects as u64, attrs);

            let mut total_errs = 0;
            for (error, &count) in m.handling_errors_per_type.iter() {
                total_errs += count;
                let err_attr = KeyValue::new("error", error.to_string());
                let attrs = &[
                    fresh_attr.clone(),
                    state_attr.clone(),
                    substate_attr.clone(),
                    err_attr,
                ];
                self.errors_per_state_gauge
                    .observe(otel_cx, count as u64, attrs);
            }

            let err_attr = KeyValue::new("error", "any".to_string());
            let attrs = &[
                fresh_attr.clone(),
                state_attr.clone(),
                substate_attr.clone(),
                err_attr,
            ];
            self.errors_per_state_gauge
                .observe(otel_cx, total_errs as u64, attrs);
        }

        self.total_objects_gauge
            .observe(otel_cx, total_objects as u64, &[fresh_attr]);
    }
}
