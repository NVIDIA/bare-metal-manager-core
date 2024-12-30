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
    metrics::{self, Histogram, Meter, ObservableGauge},
    KeyValue,
};

use crate::model::site_explorer::{EndpointExplorationError, MachineExpectation};
use forge_uuid::machine::MachineType;

/// Metrics that are gathered in one site exploration run
#[derive(Clone, Debug)]
pub struct SiteExplorationMetrics {
    /// When we started recording these metrics
    pub recording_started_at: std::time::Instant,
    /// When we finished recording the metrics
    pub recording_finished_at: std::time::Instant,
    /// Total amount of endpoint exploration attempts that has been attempted
    pub endpoint_explorations: usize,
    /// Successful endpoint explorations
    pub endpoint_explorations_success: usize,
    /// Endpoint exploration failures by type
    pub endpoint_explorations_failures_by_type: HashMap<String, usize>,
    /// Total amount of endpoint exploration failures by failure type
    pub endpoint_explorations_failures_overall_count: HashMap<String, usize>,
    /// Total number of machines that have not completed preingestion,
    /// by expected/unexpected and machine type
    pub endpoint_explorations_preingestions_incomplete_overall_count:
        HashMap<(MachineExpectation, MachineType), usize>,
    /// Total amount of expected machines where actual serial doesn't
    /// match expected serial, by machine type.
    pub endpoint_explorations_expected_serial_number_mismatches_overall_count:
        HashMap<MachineType, usize>,
    /// Total number of expected machines that have been explored,
    /// by expected/unexpected and machine type
    pub endpoint_explorations_machines_explored_overall_count:
        HashMap<(MachineExpectation, MachineType), usize>,
    /// Total number of managed hosts have been successfully constructed,
    /// by expected/unexpected.
    pub endpoint_explorations_identified_managed_hosts_overall_count:
        HashMap<MachineExpectation, usize>,
    /// Total number of expected managed hosts that were not successfully constructed.
    pub endpoint_explorations_expected_machines_missing_overall_count: usize,
    /// The time it took to explore endpoints
    pub endpoint_exploration_duration: Vec<Duration>,
    /// Total amount of managedhosts that has been identified via Site Exploration
    pub exploration_identified_managed_hosts: usize,
    /// The amount of Machine pairs (Host + DPU) that have been created by Site Explorer
    pub created_machines: usize,
    /// The time it took to create machines
    pub create_machines_latency: Option<Duration>,
    /// Total amount of BMC resets
    pub bmc_reset_count: usize,
    /// Total amount of BMC reboots
    pub bmc_reboot_count: usize,
}

impl Default for SiteExplorationMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl SiteExplorationMetrics {
    pub fn new() -> Self {
        Self {
            recording_started_at: Instant::now(),
            recording_finished_at: Instant::now(),
            endpoint_explorations: 0,
            endpoint_explorations_success: 0,
            endpoint_explorations_failures_by_type: HashMap::new(),
            endpoint_explorations_failures_overall_count: HashMap::new(),
            endpoint_explorations_preingestions_incomplete_overall_count: HashMap::new(),
            endpoint_explorations_expected_serial_number_mismatches_overall_count: HashMap::new(),
            endpoint_explorations_machines_explored_overall_count: HashMap::new(),
            endpoint_explorations_identified_managed_hosts_overall_count: HashMap::new(),
            endpoint_explorations_expected_machines_missing_overall_count: 0,
            endpoint_exploration_duration: Vec::new(),
            exploration_identified_managed_hosts: 0,
            created_machines: 0,
            create_machines_latency: None,
            bmc_reset_count: 0,
            bmc_reboot_count: 0,
        }
    }

    fn increment_endpoint_explorations_failures(&mut self, failure_type: String) {
        *self
            .endpoint_explorations_failures_by_type
            .entry(failure_type)
            .or_default() += 1;
    }

    pub fn increment_credential_missing(&mut self, credential_key: String) {
        self.increment_endpoint_explorations_failures(format!(
            "credentials_missing_{credential_key}"
        ))
    }

    pub fn increment_endpoint_explorations_failures_overall_count(&mut self, failure_type: String) {
        *self
            .endpoint_explorations_failures_overall_count
            .entry(failure_type)
            .or_default() += 1;
    }

    pub fn increment_endpoint_explorations_preingestions_incomplete_overall_count(
        &mut self,
        expected: MachineExpectation,
        machine_type: MachineType,
    ) {
        *self
            .endpoint_explorations_preingestions_incomplete_overall_count
            .entry((expected, machine_type))
            .or_default() += 1;
    }

    pub fn increment_endpoint_explorations_expected_serial_number_mismatches_overall_count(
        &mut self,
        machine_type: MachineType,
    ) {
        *self
            .endpoint_explorations_expected_serial_number_mismatches_overall_count
            .entry(machine_type)
            .or_default() += 1;
    }

    pub fn increment_endpoint_explorations_machines_explored_overall_count(
        &mut self,
        expected: MachineExpectation,
        machine_type: MachineType,
    ) {
        *self
            .endpoint_explorations_machines_explored_overall_count
            .entry((expected, machine_type))
            .or_default() += 1;
    }

    pub fn increment_endpoint_explorations_identified_managed_hosts_overall_count(
        &mut self,
        expected: MachineExpectation,
    ) {
        *self
            .endpoint_explorations_identified_managed_hosts_overall_count
            .entry(expected)
            .or_default() += 1;
    }
}

/// Instruments that are used by the Site Explorer
pub struct SiteExplorerInstruments {
    pub meter: Meter,
    pub endpoint_explorations_count: ObservableGauge<u64>,
    pub endpoint_exploration_success_count: ObservableGauge<u64>,
    pub endpoint_exploration_failures_count: ObservableGauge<u64>,
    pub endpoint_exploration_duration: Histogram<f64>,

    pub endpoint_exploration_failures_overall_count: ObservableGauge<u64>,
    pub endpoint_exploration_preingestions_incomplete_overall_count: ObservableGauge<u64>,
    pub endpoint_exploration_expected_serial_number_mismatches_overall_count: ObservableGauge<u64>,
    pub endpoint_exploration_machines_explored_overall_count: ObservableGauge<u64>,
    pub endpoint_exploration_identified_managed_hosts_overall_count: ObservableGauge<u64>,
    pub endpoint_exploration_expected_machines_missing_overall_count: ObservableGauge<u64>,

    pub site_explorer_iteration_latency: Histogram<f64>,
    pub site_explorer_create_machines_latency: Histogram<f64>,
    pub site_exploration_identified_managed_hosts_count: ObservableGauge<u64>,
    pub site_explorer_created_machines_count: ObservableGauge<u64>,
    pub site_explorer_bmc_reset_count: ObservableGauge<u64>,
    pub site_explorer_bmc_reboot_count: ObservableGauge<u64>,
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
            endpoint_exploration_failures_overall_count: meter
                .u64_observable_gauge("forge_endpoint_exploration_failures_overall_count")
                .with_description("The total number of endpoint explorations that have failed by error")
                .init(),
            endpoint_exploration_preingestions_incomplete_overall_count: meter
                .u64_observable_gauge("forge_endpoint_exploration_preingestions_incomplete_overall_count")
                .with_description("The total number of machines in a preingestion state by expectation and machine type")
                .init(),
            endpoint_exploration_expected_serial_number_mismatches_overall_count: meter
                .u64_observable_gauge("forge_endpoint_exploration_expected_serial_number_mismatches_overall_count")
                .with_description("The total number of found expected machines by machine type where the observed and expected serial numbers do not match")
                .init(),
            endpoint_exploration_machines_explored_overall_count: meter
                .u64_observable_gauge("forge_endpoint_exploration_machines_explored_overall_count")
                .with_description("The total number of machines explored by machine type")
                .init(),
            endpoint_exploration_identified_managed_hosts_overall_count: meter
                .u64_observable_gauge("forge_endpoint_exploration_identified_managed_hosts_overall_count")
                .with_description("The total number of managed hosts identified by expectation")
                .init(),
            endpoint_exploration_expected_machines_missing_overall_count: meter
                .u64_observable_gauge("forge_endpoint_exploration_expected_machines_missing_overall_count")
                .with_description("The total number of machines that were expected but not identified")
                .init(),
            endpoint_exploration_duration: meter
                .f64_histogram("forge_endpoint_exploration_duration")
                .with_description("The time it took to explore an endpoint")
                .with_unit("ms")
                .init(),
            site_explorer_iteration_latency: meter
                .f64_histogram("forge_site_explorer_iteration_latency")
                .with_description("The time it took to perform one site explorer iteration")
                .with_unit("ms")
                .init(),
            site_explorer_create_machines_latency: meter
                .f64_histogram("forge_site_explorer_create_machines_latency")
                .with_description("The time it to perform create_machines inside site-explorer")
                .with_unit("ms")
                .init(),
            site_exploration_identified_managed_hosts_count: meter
                .u64_observable_gauge("forge_site_exploration_identified_managed_hosts_count")
                .with_description("The amount of Host+DPU pairs that has been identified in the last SiteExplorer run")
                .init(),
            site_explorer_created_machines_count: meter
                .u64_observable_gauge("forge_site_explorer_created_machines_count")
                .with_description("The amount of Machine pairs that had been created by Site Explorer after being identified")
                .init(),
            site_explorer_bmc_reset_count: meter
                .u64_observable_gauge("forge_site_explorer_bmc_reset_count")
                .with_description("The amount of BMC resets initiated in the last SiteExplorer run")
                .init(),
            site_explorer_bmc_reboot_count: meter
                .u64_observable_gauge("forge_site_explorer_bmc_reboot_count")
                .with_description("The amount of BMC reboots initiated in the last SiteExplorer run")
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
            self.endpoint_exploration_failures_overall_count.as_any(),
            self.site_exploration_identified_managed_hosts_count
                .as_any(),
            self.site_explorer_created_machines_count.as_any(),
            self.site_explorer_bmc_reset_count.as_any(),
            self.site_explorer_bmc_reboot_count.as_any(),
            self.endpoint_exploration_preingestions_incomplete_overall_count
                .as_any(),
            self.endpoint_exploration_expected_serial_number_mismatches_overall_count
                .as_any(),
            self.endpoint_exploration_machines_explored_overall_count
                .as_any(),
            self.endpoint_exploration_identified_managed_hosts_overall_count
                .as_any(),
            self.endpoint_exploration_expected_machines_missing_overall_count
                .as_any(),
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
            &self.site_explorer_bmc_reboot_count,
            metrics.bmc_reboot_count as u64,
            attributes,
        );

        observer.observe_u64(
            &self.site_explorer_bmc_reset_count,
            metrics.bmc_reset_count as u64,
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

        observer.observe_u64(
            &self.endpoint_exploration_expected_machines_missing_overall_count,
            metrics.endpoint_explorations_expected_machines_missing_overall_count as u64,
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

        for (error, &count) in metrics.endpoint_explorations_failures_overall_count.iter() {
            error_attributes.last_mut().unwrap().value = error.to_string().into();
            observer.observe_u64(
                &self.endpoint_exploration_failures_overall_count,
                count as u64,
                &error_attributes,
            );
        }

        let attrs_len = attributes.len();
        let mut additional_attributes = attributes.to_vec();
        additional_attributes.push(KeyValue::new("expectation", "".to_string()));
        additional_attributes.push(KeyValue::new("machine_type", "".to_string()));

        for ((ref expected, machine_type), &count) in metrics
            .endpoint_explorations_preingestions_incomplete_overall_count
            .iter()
        {
            additional_attributes[attrs_len].value = expected.to_string().into();

            additional_attributes[attrs_len + 1].value =
                machine_type.to_string().to_lowercase().into();

            observer.observe_u64(
                &self.endpoint_exploration_preingestions_incomplete_overall_count,
                count as u64,
                &additional_attributes,
            );
        }

        for ((ref expected, machine_type), &count) in metrics
            .endpoint_explorations_machines_explored_overall_count
            .iter()
        {
            additional_attributes[attrs_len].value = expected.to_string().into();

            additional_attributes[attrs_len + 1].value =
                machine_type.to_string().to_lowercase().into();

            observer.observe_u64(
                &self.endpoint_exploration_machines_explored_overall_count,
                count as u64,
                &additional_attributes,
            );
        }

        let mut additional_attributes = attributes.to_vec();
        additional_attributes.push(KeyValue::new("machine_type", "".to_string()));

        for (machine_type, &count) in metrics
            .endpoint_explorations_expected_serial_number_mismatches_overall_count
            .iter()
        {
            additional_attributes.last_mut().unwrap().value =
                machine_type.to_string().to_lowercase().into();

            observer.observe_u64(
                &self.endpoint_exploration_expected_serial_number_mismatches_overall_count,
                count as u64,
                &additional_attributes,
            );
        }

        additional_attributes.last_mut().unwrap().key = "expectation".into();
        for (ref expected, &count) in metrics
            .endpoint_explorations_identified_managed_hosts_overall_count
            .iter()
        {
            additional_attributes.last_mut().unwrap().value = expected.to_string().into();

            observer.observe_u64(
                &self.endpoint_exploration_identified_managed_hosts_overall_count,
                count as u64,
                &additional_attributes,
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
        self.site_explorer_iteration_latency.record(
            1000.0 * metrics.recording_started_at.elapsed().as_secs_f64(),
            &[],
        );

        if let Some(latency) = metrics.create_machines_latency {
            self.site_explorer_create_machines_latency
                .record(1000.0 * latency.as_secs_f64(), &[]);
        }

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
        EndpointExplorationError::Unreachable { .. } => "unreachable",
        EndpointExplorationError::UnsupportedVendor(_) => "unsupported_vendor",
        EndpointExplorationError::RedfishError { .. } => "redfish_error",
        EndpointExplorationError::Unauthorized { .. } => "unauthorized",
        EndpointExplorationError::MissingCredentials { .. } => "missing_credentials",
        EndpointExplorationError::SetCredentials { .. } => "set_credentials",
        EndpointExplorationError::MissingRedfish { .. } => "missing_redfish",
        EndpointExplorationError::MissingVendor => "missing_vendor",
        EndpointExplorationError::AvoidLockout => "avoid_lockout",
        EndpointExplorationError::Other { .. } => "other",
        EndpointExplorationError::InvalidDpuRedfishBiosResponse { .. } => {
            "invalid_dpu_redfish_bios_response"
        }
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
                    let elapsed = metrics.recording_finished_at.elapsed();
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
        metrics.recording_finished_at = std::time::Instant::now();
        // Emit the last recent latency metrics
        self.instruments.emit_latency_metrics(&metrics, &[]);
        // We don't need to store the latency metrics anymore
        metrics.endpoint_exploration_duration.clear();
        // And store the remaining metrics
        self.last_iteration_metrics.store(Some(Arc::new(metrics)));
    }
}
