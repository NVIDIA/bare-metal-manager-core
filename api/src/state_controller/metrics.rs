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

use std::{collections::HashMap, marker::PhantomData, time::Duration};

use arc_swap::ArcSwapOption;
use opentelemetry::{
    metrics::{self, Histogram, Meter, ObservableGauge, Unit},
    KeyValue,
};

use crate::{
    logging::sqlx_query_tracing,
    state_controller::{io::StateControllerIO, state_handler::StateHandlerError},
};

/// The result of the state handler processing the state of a single object
///
/// These metrics are emitted for all types of state controllers
#[derive(Debug)]
pub struct CommonObjectHandlerMetrics<IO: StateControllerIO> {
    /// The state the object was in after the iteration ended
    pub state: Option<IO::ControllerState>,
    /// The time the object was in the this state
    pub time_in_state: Duration,
    /// Whether the object was in the state for longer than allowed by the SLA
    pub time_in_state_above_sla: bool,
    /// How long we took to execute the state handler
    pub handler_latency: Duration,
    /// If state handling fails, this contains the error
    pub error: Option<StateHandlerError>,
}

impl<IO: StateControllerIO> Default for CommonObjectHandlerMetrics<IO> {
    fn default() -> Self {
        Self {
            state: None,
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
#[derive(Debug, Default)]
pub struct CommonIterationMetrics {
    /// Aggregated metrics per state
    pub state_metrics: HashMap<(&'static str, &'static str), StateMetrics>,
}

impl CommonIterationMetrics {
    pub fn merge_object_handling_metrics<IO: StateControllerIO>(
        &mut self,
        object_metrics: &CommonObjectHandlerMetrics<IO>,
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
        if object_metrics.time_in_state_above_sla {
            state_metrics.num_objects_above_sla += 1;
        }

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
    /// Amount of objects that have been in the state for more than the SLA allows
    pub num_objects_above_sla: usize,
    /// The time the objects had been in that state
    pub time_in_state: Vec<Duration>,
    /// How long we took to execute state handlers in this state
    pub handler_latencies: Vec<Duration>,
    /// Counts the errors per error type in this state
    pub handling_errors_per_type: HashMap<&'static str, usize>,
}

/// Metrics that are produced by a state controller iteration
#[derive(Debug)]
pub struct IterationMetrics<IO: StateControllerIO> {
    /// When the metrics have been recorded
    pub recorded_at: std::time::Instant,
    /// Metrics that are emitted for all types of state controllers
    pub common: CommonIterationMetrics,
    /// Metrics that are specific to the type of object this state handler is processing
    pub specific: <IO::MetricsEmitter as MetricsEmitter>::IterationMetrics,
}

impl<IO: StateControllerIO> Default for IterationMetrics<IO> {
    fn default() -> Self {
        Self {
            recorded_at: std::time::Instant::now(),
            common: CommonIterationMetrics::default(),
            specific: <IO::MetricsEmitter as MetricsEmitter>::IterationMetrics::default(),
        }
    }
}

impl<IO: StateControllerIO> IterationMetrics<IO> {
    /// Returns the time that has elapsed since `IterationMetrics` has been
    /// constructed.
    pub fn elapsed(&self) -> std::time::Duration {
        self.recorded_at.elapsed()
    }

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
    fn new(object_type: &str, meter: &Meter) -> Self;

    /// Merges the `ObjectMetrics` metrics that are produced by the state handler action on a single
    /// object into the aggregate `IterationMetrics` object that tracks metrics
    /// for all objects that the handler has iterated on.
    fn merge_object_handling_metrics(
        iteration_metrics: &mut Self::IterationMetrics,
        object_metrics: &Self::ObjectMetrics,
    );

    /// Emit the value of gauges whose values had been captured in [IterationMetrics]
    ///
    /// This method will be called as a callback whenever OpenTelemetry requires
    /// the latest version of metrics. The `iteration_metrics` that are passed
    /// are cached values that had been collected on the last controller iteration.
    ///
    /// The `attributes` parameters lists additional attributes/labels that should
    /// be added to each emitted gauge.
    fn emit_gauges(
        &self,
        observer: &dyn metrics::Observer,
        iteration_metrics: &Self::IterationMetrics,
        attributes: &[KeyValue],
    );

    /// Returns the list of instruments that are used by this emitter.
    /// Used for opentelemetry callback registration
    fn instruments(&self) -> Vec<std::sync::Arc<dyn std::any::Any>>;

    /// Once IterationMetrics are merged, call this to record these values into histograms.
    fn update_histograms(&self, iteration_metrics: &Self::IterationMetrics);
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

    fn new(_object_type: &str, _meter: &Meter) -> Self {
        Self {}
    }

    fn emit_gauges(
        &self,
        _observer: &dyn metrics::Observer,
        _iteration_metrics: &Self::IterationMetrics,
        _attributes: &[KeyValue],
    ) {
    }

    fn instruments(&self) -> Vec<std::sync::Arc<dyn std::any::Any>> {
        Vec::new()
    }

    fn update_histograms(&self, _iteration_metrics: &Self::IterationMetrics) {}
}

/// Holds the OpenTelemetry data structures that are used to submit
/// state handling related metrics that are used within all state controllers.
#[derive(Debug)]
pub struct CommonMetricsEmitter<IO> {
    controller_iteration_latency: Histogram<f64>,
    total_objects_gauge: ObservableGauge<u64>,
    objects_per_state_gauge: ObservableGauge<u64>,
    objects_per_state_above_sla_gauge: ObservableGauge<u64>,
    errors_per_state_gauge: ObservableGauge<u64>,
    time_in_state_histogram: Histogram<f64>,
    handler_latency_in_state_histogram: Histogram<f64>,
    _phantom_io: PhantomData<IO>,
}

impl<IO: StateControllerIO> MetricsEmitter for CommonMetricsEmitter<IO> {
    type ObjectMetrics = CommonObjectHandlerMetrics<IO>;
    type IterationMetrics = CommonIterationMetrics;

    fn new(object_type: &str, meter: &Meter) -> Self {
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
        let objects_per_state_above_sla_gauge: ObservableGauge<u64> = meter
            .u64_observable_gauge(format!("{}_per_state_above_sla", object_type))
            .with_description(format!(
                "The number of {} in the system which had been longer in a state than allowed per SLA",
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

        Self {
            controller_iteration_latency,
            objects_per_state_gauge,
            objects_per_state_above_sla_gauge,
            total_objects_gauge,
            errors_per_state_gauge,
            handler_latency_in_state_histogram,
            time_in_state_histogram,
            _phantom_io: PhantomData,
        }
    }

    fn instruments(&self) -> Vec<std::sync::Arc<dyn std::any::Any>> {
        vec![
            self.objects_per_state_gauge.as_any(),
            self.objects_per_state_above_sla_gauge.as_any(),
            self.total_objects_gauge.as_any(),
            self.errors_per_state_gauge.as_any(),
        ]
    }

    fn merge_object_handling_metrics(
        iteration_metrics: &mut Self::IterationMetrics,
        object_metrics: &Self::ObjectMetrics,
    ) {
        iteration_metrics.merge_object_handling_metrics(object_metrics)
    }

    fn emit_gauges(
        &self,
        observer: &dyn metrics::Observer,
        iteration_metrics: &Self::IterationMetrics,
        attributes: &[KeyValue],
    ) {
        let mut total_objects = 0;

        for ((state, substate), m) in iteration_metrics.state_metrics.iter() {
            total_objects += m.num_objects;

            let mut attrs: Vec<KeyValue> = attributes.to_vec();
            let state_attr = KeyValue::new("state", state.to_string());
            let substate_attr = KeyValue::new("substate", substate.to_string());
            attrs.push(state_attr.clone());
            attrs.push(substate_attr.clone());

            observer.observe_u64(&self.objects_per_state_gauge, m.num_objects as u64, &attrs);
            observer.observe_u64(
                &self.objects_per_state_above_sla_gauge,
                m.num_objects_above_sla as u64,
                &attrs,
            );

            // Placeholder attribute that we will mutate for each error via .last_mut()
            attrs.push(KeyValue::new("error", "".to_string()));

            let mut total_errs = 0;
            for (error, &count) in m.handling_errors_per_type.iter() {
                total_errs += count;
                attrs.last_mut().unwrap().value = error.to_string().into();
                observer.observe_u64(&self.errors_per_state_gauge, count as u64, &attrs);
            }

            attrs.last_mut().unwrap().value = "any".to_string().into();
            observer.observe_u64(&self.errors_per_state_gauge, total_errs as u64, &attrs);
        }

        observer.observe_u64(&self.total_objects_gauge, total_objects as u64, attributes);
    }

    fn update_histograms(&self, _iteration_metrics: &Self::IterationMetrics) {}
}

impl<IO: StateControllerIO> CommonMetricsEmitter<IO> {
    /// Emits the latency metrics that are captured during a single state handler
    /// iteration. Those are emitted immediately as histograms, whereas the
    /// amount of objects in states is emitted as gauges.
    pub fn emit_latency_metrics(&self, iteration_metrics: &IterationMetrics<IO>) {
        self.controller_iteration_latency.record(
            1000.0 * iteration_metrics.recorded_at.elapsed().as_secs_f64(),
            &[],
        );

        for ((state, substate), m) in iteration_metrics.common.state_metrics.iter() {
            let state_attr = KeyValue::new("state", state.to_string());
            let substate_attr = KeyValue::new("substate", substate.to_string());
            let attrs = &[state_attr.clone(), substate_attr.clone()];

            for time_in_state in m.time_in_state.iter() {
                self.time_in_state_histogram
                    .record(time_in_state.as_secs_f64(), attrs);
            }
            for handler_latency in m.handler_latencies.iter() {
                self.handler_latency_in_state_histogram
                    .record(1000.0 * handler_latency.as_secs_f64(), attrs);
            }
        }
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
        let mut times_in_state: HashMap<String, LatencyStats> = HashMap::new();
        let mut handler_latencies: HashMap<String, LatencyStats> = HashMap::new();

        for ((state, substate), m) in iteration_metrics.common.state_metrics.iter() {
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
            if m.num_objects_above_sla > 0 {
                states_above_sla.insert(state_name.clone(), m.num_objects_above_sla);
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

/// Holds the OpenTelemetry data structures that are used to submit
/// state handling related metrics
pub struct StateControllerMetricEmitter<IO: StateControllerIO> {
    _meter: Meter,
    common: CommonMetricsEmitter<IO>,
    db: sqlx_query_tracing::DatabaseMetricEmitters,
    specific: IO::MetricsEmitter,
}

impl<IO: StateControllerIO> StateControllerMetricEmitter<IO> {
    pub fn new(object_type: &str, meter: Meter) -> Self {
        let common = CommonMetricsEmitter::new(object_type, &meter);
        let db = sqlx_query_tracing::DatabaseMetricEmitters::new(&meter);
        let specific = IO::MetricsEmitter::new(object_type, &meter);

        Self {
            common,
            db,
            specific,
            _meter: meter,
        }
    }

    /// Returns the list of instruments that are used by this emitter.
    /// Used for opentelemetry callback registration
    pub fn instruments(&self) -> Vec<std::sync::Arc<dyn std::any::Any>> {
        // db metrics don't have to be inserted here, since there are not Observable
        // and are therefore not queried in callbacks
        let mut instruments = self.common.instruments();
        instruments.extend(self.specific.instruments());
        instruments
    }

    /// Emits the latency metrics that are captured during a single state handler
    /// iteration. Those are emitted immediately as histograms, whereas the
    /// amount of objects in states is emitted as gauges.
    pub fn emit_latency_metrics(
        &self,
        log_span_name: &str,
        iteration_metrics: &IterationMetrics<IO>,
        db_metrics: &sqlx_query_tracing::SqlxQueryDataAggregation,
    ) {
        self.common.emit_latency_metrics(iteration_metrics);

        // We use an attribute to distinguish the query counter from the
        // ones that are used for other state controller and for gRPC requests
        let attrs = &[KeyValue::new("operation", log_span_name.to_string())];
        self.db.emit(db_metrics, attrs);
    }

    pub fn emit_gauges(
        &self,
        observer: &dyn metrics::Observer,
        iteration_metrics: &IterationMetrics<IO>,
    ) {
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

        let attributes = &[fresh_attr];
        self.common
            .emit_gauges(observer, &iteration_metrics.common, attributes);
        self.specific
            .emit_gauges(observer, &iteration_metrics.specific, attributes);
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

    /// Update histograms
    pub fn update_histograms(&self, iteration_metrics: &IterationMetrics<IO>) {
        self.specific.update_histograms(&iteration_metrics.specific);
    }
}

/// Stores Metric data shared between the Controller and the OpenTelemetry background task
pub struct MetricHolder<IO: StateControllerIO> {
    pub emitter: Option<StateControllerMetricEmitter<IO>>,
    pub last_iteration_metrics: ArcSwapOption<IterationMetrics<IO>>,
}

impl<IO: StateControllerIO> MetricHolder<IO> {
    pub fn new(meter: Option<Meter>, object_type_for_metrics: &str) -> Self {
        let emitter = meter
            .as_ref()
            .map(|meter| StateControllerMetricEmitter::new(object_type_for_metrics, meter.clone()));

        Self {
            emitter,
            last_iteration_metrics: ArcSwapOption::const_empty(),
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
