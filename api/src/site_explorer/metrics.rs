use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use opentelemetry_api::{
    metrics::{Counter, Histogram, Meter, Unit},
    KeyValue,
};

use crate::model::site_explorer::EndpointExplorationError;

/// Metrics that are gathered in one site exploration run
#[derive(Clone, Debug)]
pub struct SiteExplorationMetrics {
    /// When the exploration started
    pub start_time: Instant,
    /// Total amount of endpoint exploration attempts that has been attempted
    pub endpoint_explorations: usize,
    /// Successful endpoint explorations
    pub endpoint_explorations_success: usize,
    /// Endpoint exploration failures by type
    pub endpoint_explorations_failures_by_type: HashMap<String, usize>,
    /// The time it took to explore endpoints
    pub endpoint_exploration_duration: Vec<Duration>,
}

impl SiteExplorationMetrics {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            endpoint_explorations: 0,
            endpoint_explorations_success: 0,
            endpoint_explorations_failures_by_type: HashMap::new(),
            endpoint_exploration_duration: Vec::new(),
        }
    }
}

/// Instruments that are used by the Site Explorer
pub struct SiteExplorerInstruments {
    pub explorations_counter: Counter<u64>,
    pub exploration_success_counter: Counter<u64>,
    pub exploration_failures_counter: Counter<u64>,
    pub exploration_durations: Histogram<f64>,
}

impl SiteExplorerInstruments {
    pub fn new(meter: &Meter) -> Self {
        SiteExplorerInstruments {
            explorations_counter: meter
                .u64_counter("forge_endpoint_explorations")
                .with_description("The amount of endpoint explorations that have been attempted")
                .init(),
            exploration_success_counter: meter
                .u64_counter("forge_endpoint_exploration_success")
                .with_description("The amount of endpoint explorations that have been successful")
                .init(),
            exploration_failures_counter: meter
                .u64_counter("forge_endpoint_exploration_failures")
                .with_description("The amount of endpoint explorations that have failed by error")
                .init(),
            exploration_durations: meter
                .f64_histogram("forge_endpoint_exploration_duration")
                .with_description("The time it took to explore an endpoint")
                .with_unit(Unit::new("ms"))
                .init(),
        }
    }

    /// Emits the metrics for one site exploration run
    pub fn emit(
        &self,
        metrics: &SiteExplorationMetrics,
        attributes: &[opentelemetry_api::KeyValue],
    ) {
        self.explorations_counter
            .add(metrics.endpoint_explorations as u64, attributes);
        self.exploration_success_counter
            .add(metrics.endpoint_explorations_success as u64, attributes);

        for duration in metrics.endpoint_exploration_duration.iter() {
            self.exploration_durations
                .record(duration.as_secs_f64() * 1000.0, attributes);
        }

        let mut error_attributes = attributes.to_vec();
        // Placeholder that is replaced in the loop in order not having to reallocate the Vec each time
        error_attributes.push(KeyValue::new("failure", "".to_string()));
        for (error, &count) in metrics.endpoint_explorations_failures_by_type.iter() {
            error_attributes.last_mut().unwrap().value = error.to_string().into();
            self.exploration_failures_counter
                .add(count as u64, attributes);
        }
    }
}

/// Converts an endpoint exploration error into a concise label for metrics
///
/// Since we want to keep the amount of dimensions in metrics down, only the top
/// level error information is copied and details are omitted.
pub fn exploration_error_to_metric_label(error: &EndpointExplorationError) -> String {
    match error {
        EndpointExplorationError::Unreachable => "unreachable",
        EndpointExplorationError::RedfishError { .. } => "redfish_error",
        EndpointExplorationError::Unauthorized { .. } => "unauthorized",
        EndpointExplorationError::MissingCredentials => "missing_credentials",
        EndpointExplorationError::Other { .. } => "other",
    }
    .to_string()
}
