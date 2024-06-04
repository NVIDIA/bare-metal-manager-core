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

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use arc_swap::ArcSwapOption;
use opentelemetry::{
    metrics::{self, Histogram, Meter, ObservableGauge, Unit},
    KeyValue,
};

use crate::model::site_explorer::EndpointExplorationError;

/// Metrics that are gathered in one site exploration run
#[derive(Clone, Debug)]
pub struct SiteExplorationMetrics {
    /// When the exploration started
    pub recorded_at: Instant,
    /// Total amount of endpoint exploration attempts that has been attempted
    pub endpoint_explorations: usize,
    /// Successful endpoint explorations
    pub endpoint_explorations_success: usize,
    /// Endpoint exploration failures by type
    pub endpoint_explorations_failures_by_type: HashMap<String, usize>,
    /// The time it took to explore endpoints
    pub endpoint_exploration_duration: Vec<Duration>,
    /// Total amount of managedhosts that has been identified via Site Exploration
    pub exploration_identified_managed_hosts: usize,
    /// The amount of Machine pairs (Host + DPU) that have been created by Site Explorer
    pub created_machines: usize,
}

impl SiteExplorationMetrics {
    pub fn new() -> Self {
        Self {
            recorded_at: Instant::now(),
            endpoint_explorations: 0,
            endpoint_explorations_success: 0,
            endpoint_explorations_failures_by_type: HashMap::new(),
            endpoint_exploration_duration: Vec::new(),
            exploration_identified_managed_hosts: 0,
            created_machines: 0,
        }
    }
}

/// Instruments that are used by the Site Explorer
pub struct SiteExplorerInstruments {
    pub meter: Meter,
    pub endpoint_explorations_count: ObservableGauge<u64>,
    pub endpoint_exploration_success_count: ObservableGauge<u64>,
    pub endpoint_exploration_failures_count: ObservableGauge<u64>,
    pub endpoint_exploration_duration: Histogram<f64>,
    pub site_exploration_identified_managed_hosts_count: ObservableGauge<u64>,
    pub site_explorer_created_machines_count: ObservableGauge<u64>,
}

impl SiteExplorerInstruments {
    pub fn new(meter: Meter) -> Self {
        SiteExplorerInstruments {
            meter: meter.clone(),
            endpoint_explorations_count: meter
                .u64_observable_gauge("forge_endpoint_explorations_count")
                .with_description("The amount of endpoint explorations that have been attempted")
                .init(),
            endpoint_exploration_success_count: meter
                .u64_observable_gauge("forge_endpoint_exploration_success_count")
                .with_description("The amount of endpoint explorations that have been successful")
                .init(),
            endpoint_exploration_failures_count: meter
                .u64_observable_gauge("forge_endpoint_exploration_failures_count")
                .with_description("The amount of endpoint explorations that have failed by error")
                .init(),
            endpoint_exploration_duration: meter
                .f64_histogram("forge_endpoint_exploration_duration")
                .with_description("The time it took to explore an endpoint")
                .with_unit(Unit::new("ms"))
                .init(),
            site_exploration_identified_managed_hosts_count: meter
                .u64_observable_gauge("forge_site_exploration_identified_managed_hosts_count")
                .with_description("The amount of Host+DPU pairs that has been identified in the last SiteExplorer run")
                .init(),
            site_explorer_created_machines_count: meter
                .u64_observable_gauge("forge_site_explorer_created_machines_count")
                .with_description("The amount of Machine pairs that had been created by Site Explorer after being identified")
                .init(),
        }
    }

    /// Returns the list of instruments that are used by this emitter.
    /// Used for opentelemetry callback registration
    pub fn instruments(&self) -> Vec<std::sync::Arc<dyn std::any::Any>> {
        vec![
            self.endpoint_explorations_count.as_any(),
            self.endpoint_exploration_success_count.as_any(),
            self.endpoint_exploration_failures_count.as_any(),
            self.site_exploration_identified_managed_hosts_count
                .as_any(),
            self.site_explorer_created_machines_count.as_any(),
        ]
    }

    /// Emit the value of gauges whose values had been captured in [SiteExplorationMetrics]
    ///
    /// This method will be called as a callback whenever OpenTelemetry requires
    /// the latest version of metrics. The `metrics` that are passed
    /// are cached values that had been collected on the last explorer iteration.
    ///
    /// The `attributes` parameters lists additional attributes/labels that should
    /// be added to each emitted gauge.
    pub fn emit_gauges(
        &self,
        observer: &dyn metrics::Observer,
        metrics: &SiteExplorationMetrics,
        attributes: &[opentelemetry::KeyValue],
    ) {
        observer.observe_u64(
            &self.site_exploration_identified_managed_hosts_count,
            metrics.exploration_identified_managed_hosts as u64,
            attributes,
        );

        observer.observe_u64(
            &self.site_explorer_created_machines_count,
            metrics.created_machines as u64,
            attributes,
        );

        observer.observe_u64(
            &self.endpoint_explorations_count,
            metrics.endpoint_explorations as u64,
            attributes,
        );
        observer.observe_u64(
            &self.endpoint_exploration_success_count,
            metrics.endpoint_explorations_success as u64,
            attributes,
        );

        let mut error_attributes = attributes.to_vec();
        // Placeholder that is replaced in the loop in order not having to reallocate the Vec each time
        error_attributes.push(KeyValue::new("failure", "".to_string()));
        for (error, &count) in metrics.endpoint_explorations_failures_by_type.iter() {
            error_attributes.last_mut().unwrap().value = error.to_string().into();
            observer.observe_u64(
                &self.endpoint_exploration_failures_count,
                count as u64,
                &error_attributes,
            );
        }
    }

    /// Emits the latency metrics that are captured during a single site explorer
    /// iteration. Those are emitted immediately as histograms, whereas the
    /// amount of objects in states is emitted as gauges.
    pub fn emit_latency_metrics(
        &self,
        metrics: &SiteExplorationMetrics,
        attributes: &[opentelemetry::KeyValue],
    ) {
        for duration in metrics.endpoint_exploration_duration.iter() {
            self.endpoint_exploration_duration
                .record(duration.as_secs_f64() * 1000.0, attributes);
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
        EndpointExplorationError::UnsupportedVendor(_) => "unsupported_vendor",
        EndpointExplorationError::RedfishError { .. } => "redfish_error",
        EndpointExplorationError::Unauthorized { .. } => "unauthorized",
        EndpointExplorationError::MissingCredentials => "missing_credentials",
        EndpointExplorationError::InvalidCredentials { .. } => "invalid_credentials",
        EndpointExplorationError::MissingRedfish => "missing_redfish",
        EndpointExplorationError::MissingVendor => "missing_vendor",
        EndpointExplorationError::Other { .. } => "other",
    }
    .to_string()
}

/// Stores Metric data shared between SiteExplorer and the OpenTelemetry background task
pub struct MetricHolder {
    instruments: SiteExplorerInstruments,
    last_iteration_metrics: ArcSwapOption<SiteExplorationMetrics>,
    /// The maximum time the stored metrics will be treated as up to date and valid.
    /// This will avoid to emit metrics that are outdated in case new metric
    /// collection is stuck.
    hold_period: std::time::Duration,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: std::time::Duration) -> Self {
        let instruments = SiteExplorerInstruments::new(meter);
        Self {
            instruments,
            last_iteration_metrics: ArcSwapOption::const_empty(),
            hold_period,
        }
    }

    /// Registers a callback to OpenTelemetry which will lead to emitting the latest
    /// stored metrics
    pub fn register_callback(self: &Arc<Self>) {
        let self_clone = self.clone();
        if let Err(e) = self.instruments.meter.register_callback(
            &self.instruments.instruments(),
            move |observer| {
                if let Some(metrics) = self_clone.last_iteration_metrics.load_full() {
                    let elapsed = metrics.recorded_at.elapsed();
                    if elapsed > self_clone.hold_period {
                        return;
                    }

                    self_clone.instruments.emit_gauges(observer, &metrics, &[]);
                }
            },
        ) {
            tracing::error!("Failed to register SiteExplorer metrics: {e}");
        };
    }

    /// Updates the most recent metrics
    pub fn update_metrics(&self, mut metrics: SiteExplorationMetrics) {
        // Emit the last recent latency metrics
        self.instruments.emit_latency_metrics(&metrics, &[]);
        // We don't need to store the latency metrics anymore
        metrics.endpoint_exploration_duration.clear();
        // And store the remaining metrics
        self.last_iteration_metrics.store(Some(Arc::new(metrics)));
    }
}
