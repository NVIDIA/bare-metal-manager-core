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

use crate::{
    logging::sqlx_query_tracing,
    state_controller::{controller::StateControllerIO, state_handler::StateHandlerError},
};

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
    /// Returns the time that has elapsed since `IterationMetrics` has been
    /// constructed.
    pub fn elapsed(&self) -> std::time::Duration {
        self.recorded_at.elapsed()
    }

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
#[derive(Debug, Clone, Default, serde::Serialize)]
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
    controller_iteration_latency: Histogram<f64>,
    total_objects_gauge: ObservableGauge<u64>,
    objects_per_state_gauge: ObservableGauge<u64>,
    errors_per_state_gauge: ObservableGauge<u64>,
    time_in_state_histogram: Histogram<f64>,
    handler_latency_in_state_histogram: Histogram<f64>,
    db: sqlx_query_tracing::DatabaseMetricEmitters,
}

impl StateControllerMetricEmitter {
    pub fn new(object_type: &str, meter: Meter) -> Self {
        let controller_iteration_latency = meter
            .f64_histogram(format!("{}_iteration_latency", object_type))
            .with_description(format!(
                "The overall time it took to handle state for all {} in the system",
                object_type
            ))
            .with_unit(Unit::new("ms"))
            .init();
        let total_objects_gauge = meter
            .u64_observable_gauge(format!("{}_total", object_type))
            .with_description(format!("The total number of {} in the system", object_type))
            .init();
        let objects_per_state_gauge: ObservableGauge<u64> = meter
            .u64_observable_gauge(format!("{}_per_state", object_type))
            .with_description(format!(
                "The number of {} in the system with a given state",
                object_type
            ))
            .init();
        let errors_per_state_gauge = meter
            .u64_observable_gauge(format!(
                "{}_with_state_handling_errors_per_state",
                object_type
            ))
            .with_description(format!(
                "The number of {} in the system with a given state that failed state handling",
                object_type
            ))
            .init();
        let time_in_state_histogram = meter
            .f64_histogram(format!("{}_time_in_state", object_type))
            .with_description(format!(
                "The amount of time objects of type {} have spent in a certain state",
                object_type
            ))
            .with_unit(Unit::new("s"))
            .init();
        let handler_latency_in_state_histogram = meter
            .f64_histogram(format!("{}_handler_latency_in_state", object_type))
            .with_description(format!(
                "The amount of time it took to invoke the state handler for objects of type {} in a certain state",
                object_type
            ))
            .with_unit(Unit::new("ms"))
            .init();

        let db = sqlx_query_tracing::DatabaseMetricEmitters::new(&meter);

        Self {
            controller_iteration_latency,
            objects_per_state_gauge,
            total_objects_gauge,
            errors_per_state_gauge,
            handler_latency_in_state_histogram,
            time_in_state_histogram,
            db,
            _meter: meter,
        }
    }

    /// Emites the latency metrics that are captured during a single state handler
    /// iteration. Those are emitted immediately as histograms, whereas the
    /// amount of objects in states is emitted as gauges.
    pub fn emit_latency_metrics(
        &self,
        log_span_name: &str,
        iteration_metrics: &IterationMetrics,
        db_metrics: &sqlx_query_tracing::SqlxQueryDataAggregation,
    ) {
        let cx = opentelemetry::Context::current();

        self.controller_iteration_latency.record(
            &cx,
            1000.0 * iteration_metrics.recorded_at.elapsed().as_secs_f64(),
            &[],
        );

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

        // We use an attribute to distinguish the query counter from the
        // ones that are used for other state controller and for gRPC requests
        let attrs = &[KeyValue::new("operation", log_span_name.to_string())];
        self.db.emit(db_metrics, &cx, attrs);
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

    /// Emits the metrics that had been collected during a state controller iteration
    /// as attributes on the tracing/OpenTelemetry span.
    ///
    /// This is different from the metrics being emitted as gauges since the span
    /// will be emitted immediately after the iteration finishes. It will provide
    /// exact information for the single run. However the information can not
    /// be retrieved at any later time. The values for gauges are however cached
    /// and can be consumed until the next iteration.
    pub fn set_iteration_span_attributes(
        &self,
        span: &tracing::Span,
        iteration_metrics: &IterationMetrics,
    ) {
        let mut total_objects = 0;
        let mut total_errors = 0;
        let mut states: HashMap<String, usize> = HashMap::new();
        let mut error_types: HashMap<String, HashMap<String, usize>> = HashMap::new();
        let mut times_in_state: HashMap<String, LatencyStats> = HashMap::new();
        let mut handler_latencies: HashMap<String, LatencyStats> = HashMap::new();

        for ((state, substate), m) in iteration_metrics.state_metrics.iter() {
            total_objects += m.num_objects;

            let state_name = if !substate.is_empty() {
                format!("{}.{}", state, substate)
            } else {
                state.to_string()
            };

            times_in_state.insert(
                state_name.clone(),
                LatencyStats::from_latencies(&m.time_in_state, Duration::as_secs),
            );
            handler_latencies.insert(
                state_name.clone(),
                LatencyStats::from_latencies(&m.handler_latencies, |duration| {
                    duration.as_micros().min(u64::MAX as u128) as u64
                }),
            );

            for (error, &count) in m.handling_errors_per_type.iter() {
                total_errors += count;
                *error_types
                    .entry(state_name.clone())
                    .or_default()
                    .entry(error.to_string())
                    .or_default() += count;
            }

            states.insert(state_name.clone(), m.num_objects);
        }

        span.record("objects_total", total_objects);
        span.record("errors_total", total_errors);
        span.record(
            "states",
            serde_json::to_string(&states).unwrap_or_else(|_| "{}".to_string()),
        );
        if !error_types.is_empty() {
            span.record(
                "error_types",
                serde_json::to_string(&error_types).unwrap_or_else(|_| "{}".to_string()),
            );
        }
        if !times_in_state.is_empty() {
            span.record(
                "times_in_state_s",
                serde_json::to_string(&times_in_state).unwrap_or_else(|_| "{}".to_string()),
            );
        }
        if !handler_latencies.is_empty() {
            span.record(
                "handler_latencies_us",
                serde_json::to_string(&handler_latencies).unwrap_or_else(|_| "{}".to_string()),
            );
        }
    }
}

/// Stores statistics for the invocation latencies of state handler that will
/// get emitted as part of controller span attributes
#[derive(Debug, serde::Serialize, Clone)]
struct LatencyStats {
    pub min: u64,
    pub max: u64,
    pub avg: u64,
}

impl LatencyStats {
    pub fn from_latencies(latencies: &[Duration], convert_duration: fn(&Duration) -> u64) -> Self {
        let mut max_latency = 0u64;
        let mut min_latency = u64::MAX;
        let mut total_latency = 0u64;

        for latency in latencies.iter() {
            let l = convert_duration(latency);
            total_latency = total_latency.saturating_add(l);
            min_latency = min_latency.min(l);
            max_latency = max_latency.max(l);
        }
        min_latency = min_latency.min(max_latency);
        let avg_latency = total_latency / latencies.len() as u64;

        Self {
            min: min_latency,
            max: max_latency,
            avg: avg_latency,
        }
    }
}
