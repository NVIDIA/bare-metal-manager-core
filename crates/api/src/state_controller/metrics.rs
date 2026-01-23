/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter};

use crate::logging::metrics_utils::SharedMetricsHolder;
use crate::logging::sqlx_query_tracing;
use crate::state_controller::controller::ControllerIterationId;
use crate::state_controller::io::StateControllerIO;
use crate::state_controller::state_handler::StateHandlerError;

#[derive(Debug, Hash, PartialEq, Eq, serde::Serialize, Clone)]
pub(crate) struct FullState {
    state: &'static str,
    substate: &'static str,
}

// This attributes defines whether we captured the metrics recently,
// where recently here means in the last Minute. in the case multiple
// state controllers run in a 3 control plane cluster, this will help
// differentiating the metrics from a node which has recently acted on
// objects from metrics that are more outdated
const MAX_FRESH_DURATION: Duration = Duration::from_secs(60);

/// The result of the state handler processing the state of a single object
///
/// These metrics are emitted for all types of state controllers
#[derive(Debug)]
pub struct CommonObjectHandlerMetrics<IO: StateControllerIO> {
    /// The state the object was in when the iteration started
    pub initial_state: Option<IO::ControllerState>,
    /// When a state transition occured and `initial_state` was exited during state handling,
    /// this field tracks the next state
    pub next_state: Option<IO::ControllerState>,
    /// The time the object was in `initial_state` at the start of the iteration
    pub time_in_state: Duration,
    /// Whether the object was in `initial_state` for longer than allowed by the SLA
    pub time_in_state_above_sla: bool,
    /// How long we took to execute the state handler
    pub handler_latency: Duration,
    /// If state handling fails, this contains the error
    pub error: Option<StateHandlerError>,
}

impl<IO: StateControllerIO> Default for CommonObjectHandlerMetrics<IO> {
    fn default() -> Self {
        Self {
            initial_state: None,
            next_state: None,
            handler_latency: Duration::from_secs(0),
            time_in_state: Duration::from_secs(0),
            time_in_state_above_sla: false,
            error: None,
        }
    }
}

/// The result of the state handler processing the state of a single object
#[derive(Debug)]
pub struct ObjectHandlerMetrics<IO: StateControllerIO> {
    /// Metrics that are emitted for all types of state controllers
    pub common: CommonObjectHandlerMetrics<IO>,
    /// Metrics that are specific to the type of object this state handler is processing
    pub specific: <IO::MetricsEmitter as MetricsEmitter>::ObjectMetrics,
}

impl<IO: StateControllerIO> Default for ObjectHandlerMetrics<IO> {
    fn default() -> Self {
        Self {
            common: Default::default(),
            specific: Default::default(),
        }
    }
}

/// Metrics that are produced by a state controller iteration
#[derive(Debug)]
pub struct CommonIterationMetrics {
    /// When we started recording these metrics
    pub recording_started_at: std::time::Instant,
    /// When we finished recording the metrics
    pub recording_finished_at: std::time::Instant,
    /// The iteration ID
    pub iteration_id: Option<ControllerIterationId>,
    /// The amount of objects which have been enqueued in this run
    pub num_enqueued_objects: usize,
    /// Aggregated metrics per state, with optional next state information
    /// Key: FullState containing current_state, current_substate before the transition
    pub state_metrics: HashMap<FullState, StateMetrics>,
}

impl Default for CommonIterationMetrics {
    fn default() -> Self {
        Self {
            recording_started_at: std::time::Instant::now(),
            recording_finished_at: std::time::Instant::now(),
            iteration_id: None,
            num_enqueued_objects: 0,
            state_metrics: Default::default(),
        }
    }
}

impl CommonIterationMetrics {
    pub fn merge_object_handling_metrics<IO: StateControllerIO>(
        &mut self,
        object_metrics: &CommonObjectHandlerMetrics<IO>,
    ) {
        // The `unknown` state can occur if loading the current object state fails
        // or if the state is not deserializable
        let (state_name, substate_name) = object_metrics
            .initial_state
            .as_ref()
            .map(IO::metric_state_names)
            .unwrap_or(("unknown", ""));

        let state_metrics = self
            .state_metrics
            .entry(FullState {
                state: state_name,
                substate: substate_name,
            })
            .or_default();

        // The first set of metrics is always related to the initial state
        if let Some(error) = &object_metrics.error {
            let error_label = error.metric_label();
            *state_metrics
                .handling_errors_per_type
                .entry(error_label)
                .or_default() += 1;
        }

        // If the object is still in the current state, track its presence there
        // If the object has moved into a next state, record it there
        if object_metrics.next_state.is_none() {
            state_metrics.num_objects += 1;
            if object_metrics.time_in_state_above_sla {
                state_metrics.num_objects_above_sla += 1;
            }
        }

        // If a follow-up state is defined, we exited the state and entered the next state
        if let Some(next_state) = object_metrics.next_state.as_ref() {
            // Get the metric names for the next state
            let (next_state_name, next_substate_name) = IO::metric_state_names(next_state);

            // We have to emit additional metrics for the next state
            let next_state_metrics = self
                .state_metrics
                .entry(FullState {
                    state: next_state_name,
                    substate: next_substate_name,
                })
                .or_default();
            next_state_metrics.num_objects += 1;
            // The object will never be above sla in the new state,
            // given it just entered this state
        }
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct StateTransitionRecord {
    pub time_in_state: Duration,
    pub target_state: FullState,
}

/// Metrics for each state of an object
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct StateMetrics {
    /// Amount of objects in the state
    pub num_objects: usize,
    /// Amount of objects that have been in the state for more than the SLA allows
    pub num_objects_above_sla: usize,
    /// Counts the errors per error type in this state
    pub handling_errors_per_type: HashMap<&'static str, usize>,
}

/// Iteration Metrics that are produced by a state controller iteration
#[derive(Debug)]
pub struct IterationMetrics<IO: StateControllerIO> {
    /// Metrics that are emitted for all types of state controllers
    pub common: CommonIterationMetrics,
    /// Metrics that are specific to the type of object this state handler is processing
    pub specific: <IO::MetricsEmitter as MetricsEmitter>::IterationMetrics,
}

impl<IO: StateControllerIO> Default for IterationMetrics<IO> {
    fn default() -> Self {
        Self {
            common: CommonIterationMetrics::default(),
            specific: <IO::MetricsEmitter as MetricsEmitter>::IterationMetrics::default(),
        }
    }
}

impl<IO: StateControllerIO> IterationMetrics<IO> {
    pub fn merge_object_handling_metrics(&mut self, object_metrics: &ObjectHandlerMetrics<IO>) {
        self.common
            .merge_object_handling_metrics(&object_metrics.common);

        // Merge metrics that are specific to the object
        <IO::MetricsEmitter as MetricsEmitter>::merge_object_handling_metrics(
            &mut self.specific,
            &object_metrics.specific,
        );
    }
}

/// A trait that defines how custom metrics are handled for a particular object type
///
/// The emitter itself holds the OpenTelemetry data structures (Gauges) that are
/// required to submit the collected metrics in periodic intervals.
///
/// The metrics themselves are captured in a 2 step process:
/// 1. When the state handler acts on an object, it collects `ObjectMetrics` from it.
/// 2. The metrics for all objects are merged into an overall set of `IterationMetrics`
///    via the user-defined `merge_object_handling_metrics` function.
///
/// The `IterationMetrics` are then cached and will be submitted to the metrics system
/// as required.
pub trait MetricsEmitter: std::fmt::Debug + Send + Sync + 'static {
    /// The type that can hold metrics specific to a single object.
    ///
    /// These metrics can be produced by code inside the state handler by writing
    /// them to `ObjectMetrics`.
    /// After state has been processed for all all objects, the various metrics
    /// are merged into an `IterationMetrics` object.
    type ObjectMetrics: std::fmt::Debug + Default + Send + Sync + 'static;
    /// The type that can hold custom metrics for a full state handler iteration.
    /// These metrics will also be cached inside the state controller for the
    /// case where the metrics framework wants to access them between iterations.
    type IterationMetrics: std::fmt::Debug + Default + Send + Sync + 'static;

    /// Initializes a custom metric emitters that are required for this state controller
    fn new(
        object_type: &str,
        meter: &Meter,
        metrics: SharedMetricsHolder<Self::IterationMetrics>,
    ) -> Self;

    /// Merges the `ObjectMetrics` metrics that are produced by the state handler action on a single
    /// object into the aggregate `IterationMetrics` object that tracks metrics
    /// for all objects that the handler has iterated on.
    fn merge_object_handling_metrics(
        iteration_metrics: &mut Self::IterationMetrics,
        object_metrics: &Self::ObjectMetrics,
    );

    /// This function is called on `ObjectMetrics` in every state controller
    /// iteration to emit captured counters and histograms
    fn emit_object_counters_and_histograms(&self, object_metrics: &Self::ObjectMetrics);
}

/// A [MetricsEmitter] that can be used if no custom metrics are required.
///
/// This emitter will emit no additional metrics
#[derive(Debug, Default)]
pub struct NoopMetricsEmitter {}

impl MetricsEmitter for NoopMetricsEmitter {
    type ObjectMetrics = ();

    type IterationMetrics = ();

    fn merge_object_handling_metrics(
        _iteration_metrics: &mut Self::IterationMetrics,
        _object_metrics: &Self::ObjectMetrics,
    ) {
    }

    fn new(
        _object_type: &str,
        _meter: &Meter,
        _metrics: SharedMetricsHolder<Self::IterationMetrics>,
    ) -> Self {
        Self {}
    }

    fn emit_object_counters_and_histograms(&self, _object_metrics: &Self::ObjectMetrics) {}
}

/// Holds the OpenTelemetry data structures that are used to submit
/// state handling related metrics that are used within all state controllers.
#[derive(Debug)]
pub struct CommonMetricsEmitter<IO> {
    controller_iteration_latency: Histogram<f64>,
    state_entered_counter: Counter<u64>,
    state_exited_counter: Counter<u64>,
    time_in_state_histogram: Histogram<f64>,
    handler_latency_in_state_histogram: Histogram<f64>,
    _phantom_io: PhantomData<IO>,
}

impl<IO: StateControllerIO> MetricsEmitter for CommonMetricsEmitter<IO> {
    type ObjectMetrics = CommonObjectHandlerMetrics<IO>;
    type IterationMetrics = CommonIterationMetrics;

    fn new(
        object_type: &str,
        meter: &Meter,
        shared_metrics_holder: SharedMetricsHolder<Self::IterationMetrics>,
    ) -> Self {
        let controller_iteration_latency = meter
            .f64_histogram(format!("{object_type}_iteration_latency"))
            .with_description(format!(
                "The overall time it took to handle state for all {object_type} in the system"
            ))
            .with_unit("ms")
            .build();
        {
            // The code below is what creates counters like forge_network_segments_total
            let metrics = shared_metrics_holder.clone();
            meter
                .u64_observable_gauge(format!("{object_type}_total"))
                .with_description(format!("The total number of {object_type} in the system"))
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        let num_objects = metrics
                            .state_metrics
                            .values()
                            .map(|m| m.num_objects)
                            .reduce(|a, b| a + b)
                            .unwrap_or_default();
                        observer.observe(num_objects as u64, attrs);
                    });
                })
                .build()
        };
        {
            let metrics = shared_metrics_holder.clone();
            meter
                .u64_observable_gauge(format!("{object_type}_per_state"))
                .with_description(format!(
                    "The number of {object_type} in the system with a given state"
                ))
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for (full_state, state_metrics) in metrics.state_metrics.iter() {
                            observer.observe(
                                state_metrics.num_objects as u64,
                                &[
                                    attrs,
                                    &[
                                        KeyValue::new("state", full_state.state.to_string()),
                                        KeyValue::new("substate", full_state.substate.to_string()),
                                    ],
                                ]
                                .concat(),
                            );
                        }
                    })
                })
                .build()
        };

        {
            let metrics = shared_metrics_holder.clone();
            meter
                .u64_observable_gauge(format!("{object_type}_per_state_above_sla"))
                .with_description(format!(
                    "The number of {object_type} in the system which had been longer in a state than allowed per SLA"
                ))
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for (full_state, state_metrics) in metrics.state_metrics.iter() {
                            observer.observe(
                                state_metrics.num_objects_above_sla as u64,
                                [
                                    attrs,
                                    &[
                                        KeyValue::new("state", full_state.state.to_string()),
                                        KeyValue::new("substate", full_state.substate.to_string()),
                                    ],
                                ]
                                    .concat().as_slice(),
                            );
                        }
                    })
                })
                .build()
        };

        {
            let metrics = shared_metrics_holder;
            meter
                .u64_observable_gauge(format!(
                    "{object_type}_with_state_handling_errors_per_state"
                ))
                .with_description(format!(
                    "The number of {object_type} in the system with a given state that failed state handling"
                ))
                .with_callback(move |observer| {
                                        metrics.if_available(|metrics, attrs| {
                        for (full_state, state_metrics) in metrics.state_metrics.iter() {
                            let mut total_errs = 0;
                            for (error, &count) in state_metrics.handling_errors_per_type.iter() {
                                total_errs += count;
                                observer.observe(
                                    count as u64,
                                    &[
                                        attrs,
                                        &[
                                            KeyValue::new("state", full_state.state.to_string()),
                                            KeyValue::new("substate", full_state.substate.to_string()),
                                            KeyValue::new("error", error.to_string()),
                                        ],
                                    ]
                                    .concat(),
                                );
                            }

                            observer.observe(
                                total_errs as u64,
                                &[
                                    attrs,
                                    &[
                                        KeyValue::new("state", full_state.state.to_string()),
                                        KeyValue::new("substate", full_state.substate.to_string()),
                                        KeyValue::new("error", "any".to_string()),
                                    ],
                                ]
                                .concat(),
                            );
                        }
                    })
                })
                .build()
        };

        let state_entered_counter = meter
            .u64_counter(format!("{object_type}_state_entered"))
            .with_description(format!(
                "The amount of types that objects of type {object_type} have entered a certain state"
            ))
            .build();
        let state_exited_counter = meter
            .u64_counter(format!("{object_type}_state_exited"))
            .with_description(format!(
                "The amount of types that objects of type {object_type} have exited a certain state"
            ))
            .build();
        let time_in_state_histogram = meter
            .f64_histogram(format!("{object_type}_time_in_state"))
            .with_description(format!(
                "The amount of time objects of type {object_type} have spent in a certain state"
            ))
            .with_unit("s")
            .build();
        let handler_latency_in_state_histogram = meter
            .f64_histogram(format!("{object_type}_handler_latency_in_state"))
            .with_description(format!(
                "The amount of time it took to invoke the state handler for objects of type {object_type} in a certain state"
            ))
            .with_unit("ms")
            .build();

        Self {
            controller_iteration_latency,
            state_entered_counter,
            state_exited_counter,
            handler_latency_in_state_histogram,
            time_in_state_histogram,
            _phantom_io: PhantomData,
        }
    }

    fn merge_object_handling_metrics(
        iteration_metrics: &mut Self::IterationMetrics,
        object_metrics: &Self::ObjectMetrics,
    ) {
        iteration_metrics.merge_object_handling_metrics(object_metrics)
    }

    fn emit_object_counters_and_histograms(&self, object_metrics: &Self::ObjectMetrics) {
        let (initial_state_name, initial_substate_name) = object_metrics
            .initial_state
            .as_ref()
            .map(IO::metric_state_names)
            .unwrap_or(("unknown", ""));

        let initial_state_attr = KeyValue::new("state", initial_state_name.to_string());
        let initial_substate_attr = KeyValue::new("substate", initial_substate_name.to_string());

        // If a follow-up state is defined, emit metrics for exiting and leaving the state
        if let Some(next_state) = object_metrics.next_state.as_ref() {
            let (next_state_name, next_substate_name) = IO::metric_state_names(next_state);

            let attrs = &[initial_state_attr.clone(), initial_substate_attr.clone()];
            self.state_exited_counter.add(1, attrs);
            let next_state_attr = KeyValue::new("state", next_state_name.to_string());
            let next_substate_attr = KeyValue::new("substate", next_substate_name.to_string());
            let attrs = &[next_state_attr, next_substate_attr];
            self.state_entered_counter.add(1, attrs);

            let transition_record = StateTransitionRecord {
                time_in_state: object_metrics.time_in_state,
                target_state: FullState {
                    state: next_state_name,
                    substate: next_substate_name,
                },
            };

            // Record time_in_state histogram with next_state information
            let attrs_with_next_state = &[
                initial_state_attr.clone(),
                initial_substate_attr.clone(),
                KeyValue::new(
                    "next_state",
                    transition_record.target_state.state.to_string(),
                ),
                KeyValue::new(
                    "next_substate",
                    transition_record.target_state.substate.to_string(),
                ),
            ];
            self.time_in_state_histogram.record(
                transition_record.time_in_state.as_secs_f64(),
                attrs_with_next_state,
            );
        }

        let attrs = &[initial_state_attr, initial_substate_attr];
        self.handler_latency_in_state_histogram
            .record(1000.0 * object_metrics.handler_latency.as_secs_f64(), attrs);
    }
}

impl<IO: StateControllerIO> CommonMetricsEmitter<IO> {
    /// Emits iteration related counters and histograms
    fn emit_iteration_counters_and_histograms(&self, iteration_metrics: &IterationMetrics<IO>) {
        self.controller_iteration_latency.record(
            1000.0
                * iteration_metrics
                    .common
                    .recording_started_at
                    .elapsed()
                    .as_secs_f64(),
            &[],
        );
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
        iteration_metrics: &IterationMetrics<IO>,
    ) {
        let mut total_objects = 0;
        let mut total_errors = 0;
        let mut states: HashMap<String, usize> = HashMap::new();
        let mut states_above_sla: HashMap<String, usize> = HashMap::new();
        let mut error_types: HashMap<String, HashMap<String, usize>> = HashMap::new();

        span.record(
            "num_enqueued_objects",
            iteration_metrics.common.num_enqueued_objects,
        );
        if let Some(iteration_id) = iteration_metrics.common.iteration_id.as_ref() {
            span.record("iteration_id", iteration_id.0);
        }

        for (full_state, state_metrics) in iteration_metrics.common.state_metrics.iter() {
            total_objects += state_metrics.num_objects;

            let full_state_name = if !full_state.substate.is_empty() {
                format!("{}.{}", full_state.state, full_state.substate)
            } else {
                full_state.state.to_string()
            };

            for (error, &count) in state_metrics.handling_errors_per_type.iter() {
                total_errors += count;
                *error_types
                    .entry(full_state_name.clone())
                    .or_default()
                    .entry(error.to_string())
                    .or_default() += count;
            }

            states.insert(full_state_name.clone(), state_metrics.num_objects);
            if state_metrics.num_objects_above_sla > 0 {
                states_above_sla
                    .insert(full_state_name.clone(), state_metrics.num_objects_above_sla);
            }
        }

        span.record("objects_total", total_objects);
        span.record("errors_total", total_errors);
        span.record(
            "states",
            serde_json::to_string(&states).unwrap_or_else(|_| "{}".to_string()),
        );
        span.record(
            "states_above_sla",
            serde_json::to_string(&states_above_sla).unwrap_or_else(|_| "{}".to_string()),
        );
        if !error_types.is_empty() {
            span.record(
                "error_types",
                serde_json::to_string(&error_types).unwrap_or_else(|_| "{}".to_string()),
            );
        }
    }
}

/// Holds the OpenTelemetry data structures that are used to submit
/// state handling related metrics
pub struct StateControllerMetricEmitter<IO: StateControllerIO> {
    _meter: Meter,
    common: CommonMetricsEmitter<IO>,
    db: sqlx_query_tracing::DatabaseMetricEmitters,
    specific: IO::MetricsEmitter,
}

impl<IO: StateControllerIO> StateControllerMetricEmitter<IO> {
    pub fn new(
        object_type: &str,
        meter: Meter,
        common_iteration_metrics: SharedMetricsHolder<CommonIterationMetrics>,
        specific_iteration_metrics: SharedMetricsHolder<
            <IO::MetricsEmitter as MetricsEmitter>::IterationMetrics,
        >,
    ) -> Self {
        let common = CommonMetricsEmitter::new(object_type, &meter, common_iteration_metrics);
        let db = sqlx_query_tracing::DatabaseMetricEmitters::new(&meter);
        let specific = IO::MetricsEmitter::new(object_type, &meter, specific_iteration_metrics);

        Self {
            common,
            db,
            specific,
            _meter: meter,
        }
    }

    /// Emits counters and histogram metrics that are captured during a single
    /// object handling iteration.
    pub fn emit_object_counters_and_histograms(&self, object_metrics: &ObjectHandlerMetrics<IO>) {
        self.common
            .emit_object_counters_and_histograms(&object_metrics.common);
        self.specific
            .emit_object_counters_and_histograms(&object_metrics.specific);
    }

    /// Emits counters and histogram metrics that are captured during a single state handler
    /// iteration. Those are emitted immediately, whereas the values of gauges
    /// is cached and emitted when queried.
    pub fn emit_iteration_counters_and_histograms(
        &self,
        log_span_name: &str,
        iteration_metrics: &IterationMetrics<IO>,
        db_metrics: &sqlx_query_tracing::SqlxQueryDataAggregation,
    ) {
        self.common
            .emit_iteration_counters_and_histograms(iteration_metrics);

        // We use an attribute to distinguish the query counter from the
        // ones that are used for other state controller and for gRPC requests
        let attrs = &[KeyValue::new("operation", log_span_name.to_string())];
        self.db.emit(db_metrics, attrs);
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
        iteration_metrics: &IterationMetrics<IO>,
    ) {
        self.common
            .set_iteration_span_attributes(span, iteration_metrics)
    }
}

/// Stores Metric data shared between the Controller and the OpenTelemetry background task
pub struct MetricHolder<IO: StateControllerIO> {
    pub emitter: Option<Arc<StateControllerMetricEmitter<IO>>>,
    pub last_iteration_common_metrics: SharedMetricsHolder<CommonIterationMetrics>,
    pub last_iteration_specific_metrics:
        SharedMetricsHolder<<IO::MetricsEmitter as MetricsEmitter>::IterationMetrics>,
}

impl<IO: StateControllerIO> MetricHolder<IO> {
    pub fn new(meter: Option<Meter>, object_type_for_metrics: &str) -> Self {
        let last_iteration_common_metrics =
            SharedMetricsHolder::<CommonIterationMetrics>::with_fresh_period(MAX_FRESH_DURATION);
        let last_iteration_specific_metrics = SharedMetricsHolder::<
            <IO::MetricsEmitter as MetricsEmitter>::IterationMetrics,
        >::with_fresh_period(MAX_FRESH_DURATION);

        let emitter = meter.as_ref().map(|meter| {
            Arc::new(StateControllerMetricEmitter::new(
                object_type_for_metrics,
                meter.clone(),
                last_iteration_common_metrics.clone(),
                last_iteration_specific_metrics.clone(),
            ))
        });

        Self {
            emitter,
            last_iteration_common_metrics,
            last_iteration_specific_metrics,
        }
    }
}
