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

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::time::{Duration, Instant};

use carbide_uuid::machine::MachineType;
use model::site_explorer::{EndpointExplorationError, MachineExpectation};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Histogram, Meter};

use crate::logging::metrics_utils::SharedMetricsHolder;

/// Reasons why a host fails to pair with its DPU(s).
/// These are issues that require manual intervention.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PairingBlockerReason {
    /// Non-Dell host needs power cycle after DPU mode change
    ManualPowerCycleRequired,
    /// Viking CPLDMB_0 version too old, needs data center power cycle
    VikingCpldVersionIssue,
    /// Cannot determine DPU's NIC/DPU mode (likely BMC firmware too old)
    DpuNicModeUnknown,
    /// Cannot retrieve DPU's pf0 MAC address
    DpuPf0MacMissing,
    /// Cannot get system info from host BMC
    HostSystemReportMissing,
    /// Host's boot MAC not found in any discovered DPU
    BootInterfaceMacMismatch,
    /// Host BMC did not report any DPUs in its PCIE device list
    NoDpuReportedByHost,
}

impl Display for PairingBlockerReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::ManualPowerCycleRequired => "manual_power_cycle_required",
            Self::VikingCpldVersionIssue => "viking_cpld_version_issue",
            Self::DpuNicModeUnknown => "dpu_nic_mode_unknown",
            Self::DpuPf0MacMissing => "dpu_pf0_mac_missing",
            Self::HostSystemReportMissing => "host_system_report_missing",
            Self::BootInterfaceMacMismatch => "boot_interface_mac_mismatch",
            Self::NoDpuReportedByHost => "no_dpu_reported_by_host",
        };
        write!(f, "{s}")
    }
}

/// Metrics that are gathered in one site exploration run
#[derive(Clone, Debug)]
pub struct SiteExplorationMetrics {
    /// When we started recording these metrics
    pub recording_started_at: std::time::Instant,
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
    // TODO(chet): Track down Jira created and/or implement Rack metrics
    // also. Currently on Vinod to make a Jira, but leaving this here.
    /// The amount of Power Shelves that have been created by Site Explorer
    pub created_power_shelves_count: usize,
    /// The number of Switches that have been created by Site Explorer
    pub created_switches_count: usize,
    /// The time it took to create power shelves
    pub create_power_shelves_latency: Option<Duration>,
    /// The time it took to create switches
    pub create_switches_latency: Option<Duration>,
    /// Total amount of BMC resets
    pub bmc_reset_count: usize,
    /// Total amount of BMC reboots
    pub bmc_reboot_count: usize,
    /// Total number of expected power shelves that were not successfully identified.
    // TODO(chet): Track down Jira and/or implement similar
    // counter for Switch as well.
    pub endpoint_explorations_expected_power_shelves_missing_overall_count: usize,
    /// Total count of expected machines by SKU ID and device type
    pub expected_machines_sku_count: HashMap<(String, String), usize>, // (sku_id, device_type)
    /// Total count of host+dpu pairing blockers by reason.
    /// These are issues that prevent a host from being paired with its dpu(s)
    /// and require manual intervention.
    pub host_dpu_pairing_blockers: HashMap<String, usize>,
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
            created_power_shelves_count: 0,
            create_power_shelves_latency: None,
            created_switches_count: 0,
            create_switches_latency: None,
            bmc_reset_count: 0,
            bmc_reboot_count: 0,
            endpoint_explorations_expected_power_shelves_missing_overall_count: 0,
            expected_machines_sku_count: HashMap::new(),
            host_dpu_pairing_blockers: HashMap::new(),
        }
    }

    fn increment_endpoint_explorations_failures(&mut self, failure_type: String) {
        *self
            .endpoint_explorations_failures_by_type
            .entry(failure_type)
            .or_default() += 1;
    }

    pub fn increment_credential_missing(&mut self, credential_key: &str) {
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

    pub fn increment_expected_machines_sku_count(
        &mut self,
        sku_id: Option<&str>,
        device_type: Option<&str>,
    ) {
        let sku_id_key = sku_id.unwrap_or("unknown").to_string();
        let device_type_key = device_type.unwrap_or("unknown").to_string();
        *self
            .expected_machines_sku_count
            .entry((sku_id_key, device_type_key))
            .or_default() += 1;
    }

    /// Increment the count of host+dpu pairing blockers for a given reason.
    pub fn increment_host_dpu_pairing_blocker(&mut self, reason: PairingBlockerReason) {
        *self
            .host_dpu_pairing_blockers
            .entry(reason.to_string())
            .or_default() += 1;
    }
}

/// Instruments that are used by the Site Explorer
pub struct SiteExplorerInstruments {
    pub endpoint_exploration_duration: Histogram<f64>,
    pub site_explorer_iteration_latency: Histogram<f64>,
    pub site_explorer_create_machines_latency: Histogram<f64>,
    pub site_explorer_create_power_shelves_latency: Histogram<f64>,
    pub site_explorer_create_switches_latency: Histogram<f64>,
}

impl SiteExplorerInstruments {
    pub fn new(meter: Meter, shared_metrics: SharedMetricsHolder<SiteExplorationMetrics>) -> Self {
        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_endpoint_explorations_count")
                .with_description("The amount of endpoint explorations that have been attempted")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        observer.observe(metrics.endpoint_explorations as u64, attrs);
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_endpoint_exploration_success_count")
                .with_description("The amount of endpoint explorations that have been successful")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        observer.observe(metrics.endpoint_explorations_success as u64, attrs);
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_endpoint_exploration_failures_count")
                .with_description("The amount of endpoint explorations that have failed by error")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for (error, &count) in metrics.endpoint_explorations_failures_by_type.iter()
                        {
                            observer.observe(
                                count as u64,
                                &[attrs, &[KeyValue::new("failure", error.to_string())]].concat(),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_endpoint_exploration_failures_overall_count")
                .with_description(
                    "The total number of endpoint explorations that have failed by error",
                )
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for (error, &count) in
                            metrics.endpoint_explorations_failures_overall_count.iter()
                        {
                            observer.observe(
                                count as u64,
                                &[attrs, &[KeyValue::new("failure", error.to_string())]].concat(),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_endpoint_exploration_preingestions_incomplete_overall_count")
                .with_description("The total number of machines in a preingestion state by expectation and machine type")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for ((expected, machine_type), &count) in metrics
                            .endpoint_explorations_preingestions_incomplete_overall_count
                            .iter()
                        {
                            observer.observe(
                                count as u64,
                                &[
                                    attrs,
                                    &[
                                        KeyValue::new("expectation", expected.to_string()),
                                        KeyValue::new("machine_type", machine_type.metrics_value()),
                                    ]
                                ].concat()
                            );
                        }

                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_endpoint_exploration_expected_serial_number_mismatches_overall_count")
                .with_description("The total number of found expected machines by machine type where the observed and expected serial numbers do not match")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for (machine_type, &count) in metrics
                            .endpoint_explorations_expected_serial_number_mismatches_overall_count
                            .iter()
                        {
                            observer.observe(
                                count as u64,
                                &[
                                    attrs,
                                    &[KeyValue::new("machine_type", machine_type.metrics_value())],
                                ].concat(),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge(
                    "carbide_endpoint_exploration_machines_explored_overall_count",
                )
                .with_description("The total number of machines explored by machine type")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for ((expected, machine_type), &count) in metrics
                            .endpoint_explorations_machines_explored_overall_count
                            .iter()
                        {
                            observer.observe(
                                count as u64,
                                &[
                                    attrs,
                                    &[
                                        KeyValue::new("expectation", expected.to_string()),
                                        KeyValue::new("machine_type", machine_type.metrics_value()),
                                    ],
                                ]
                                .concat(),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge(
                    "carbide_endpoint_exploration_identified_managed_hosts_overall_count",
                )
                .with_description("The total number of managed hosts identified by expectation")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for (expected, &count) in metrics
                            .endpoint_explorations_identified_managed_hosts_overall_count
                            .iter()
                        {
                            observer.observe(
                                count as u64,
                                &[attrs, &[KeyValue::new("expectation", expected.to_string())]]
                                    .concat(),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge(
                    "carbide_endpoint_exploration_expected_machines_missing_overall_count",
                )
                .with_description(
                    "The total number of machines that were expected but not identified",
                )
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        observer.observe(
                            metrics.endpoint_explorations_expected_machines_missing_overall_count
                                as u64,
                            attrs,
                        );
                    })
                })
                .build();
        }

        let endpoint_exploration_duration = meter
            .f64_histogram("carbide_endpoint_exploration_duration")
            .with_description("The time it took to explore an endpoint")
            .with_unit("ms")
            .build();

        let site_explorer_iteration_latency = meter
            .f64_histogram("carbide_site_explorer_iteration_latency")
            .with_description("The time it took to perform one site explorer iteration")
            .with_unit("ms")
            .build();

        let site_explorer_create_machines_latency = meter
            .f64_histogram("carbide_site_explorer_create_machines_latency")
            .with_description("The time it to perform create_machines inside site-explorer")
            .with_unit("ms")
            .build();

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_site_exploration_identified_managed_hosts_count")
                .with_description("The amount of Host+DPU pairs that has been identified in the last SiteExplorer run")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        observer.observe(
                            metrics.exploration_identified_managed_hosts as u64,
                            attrs,
                        );
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_site_explorer_created_machines_count")
                .with_description("The amount of Machine pairs that had been created by Site Explorer after being identified")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        observer.observe(
                            metrics.created_machines as u64,
                            attrs,
                        );
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_site_explorer_bmc_reset_count")
                .with_description("The amount of BMC resets initiated in the last SiteExplorer run")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        observer.observe(metrics.bmc_reset_count as u64, attrs);
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge(
                    "carbide_endpoint_exploration_expected_power_shelves_missing_overall_count",
                )
                .with_description(
                    "The total number of power shelves that were expected but not identified",
                )
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        observer.observe(
                            metrics
                                .endpoint_explorations_expected_power_shelves_missing_overall_count
                                as u64,
                            attrs,
                        );
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_site_exploration_expected_machines_sku_count")
                .with_description("The total count of expected machines by SKU ID and device type")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for ((sku_id, device_type), &count) in
                            metrics.expected_machines_sku_count.iter()
                        {
                            observer.observe(
                                count as u64,
                                &[
                                    attrs,
                                    &[
                                        KeyValue::new("sku_id", sku_id.clone()),
                                        KeyValue::new("device_type", device_type.clone()),
                                    ],
                                ]
                                .concat(),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_host_dpu_pairing_blockers_count")
                .with_description(
                    "Count of host+dpu pairing blockers by reason. These are issues that prevent \
                     a host from being paired with its dpu(s) and require manual intervention.",
                )
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        for (reason, &count) in metrics.host_dpu_pairing_blockers.iter() {
                            observer.observe(
                                count as u64,
                                &[attrs, &[KeyValue::new("reason", reason.clone())]].concat(),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge(
                    "carbide_endpoint_exploration_expected_power_shelves_missing_overall_count",
                )
                .with_description(
                    "The total number of power shelves that were expected but not identified",
                )
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        observer.observe(
                            metrics
                                .endpoint_explorations_expected_power_shelves_missing_overall_count
                                as u64,
                            attrs,
                        );
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics;
            meter
                .u64_observable_gauge("carbide_site_explorer_created_power_shelves_count")
                .with_description("The amount of Power Shelves that had been created by Site Explorer after being identified")
                .with_callback(move |observer| {
                    metrics.if_available(|metrics, attrs| {
                        observer.observe(
                            metrics.created_power_shelves_count as u64,
                            attrs,
                        );
                    })
                })
                .build();
        }

        let site_explorer_create_power_shelves_latency = meter
            .f64_histogram("site_explorer_create_power_shelves_latency")
            .with_description("Duration of power shelf creation")
            .with_unit("s")
            .build();

        let site_explorer_create_switches_latency = meter
            .f64_histogram("site_explorer_create_switches_latency")
            .with_description("Duration of switch creation")
            .with_unit("s")
            .build();

        SiteExplorerInstruments {
            endpoint_exploration_duration,
            site_explorer_iteration_latency,
            site_explorer_create_machines_latency,
            site_explorer_create_power_shelves_latency,
            site_explorer_create_switches_latency,
        }
    }

    /// Emits the latency metrics that are captured during a single site explorer
    /// iteration. Those are emitted immediately as histograms, whereas the
    /// amount of objects in states is emitted as gauges.
    pub fn emit_latency_metrics(&self, metrics: &SiteExplorationMetrics) {
        self.site_explorer_iteration_latency.record(
            1000.0 * metrics.recording_started_at.elapsed().as_secs_f64(),
            &[],
        );

        if let Some(latency) = metrics.create_machines_latency {
            self.site_explorer_create_machines_latency
                .record(1000.0 * latency.as_secs_f64(), &[]);
        }

        if let Some(latency) = metrics.create_power_shelves_latency {
            self.site_explorer_create_power_shelves_latency
                .record(1000.0 * latency.as_secs_f64(), &[]);
        }

        if let Some(latency) = metrics.create_switches_latency {
            self.site_explorer_create_switches_latency
                .record(1000.0 * latency.as_secs_f64(), &[]);
        }

        for duration in metrics.endpoint_exploration_duration.iter() {
            self.endpoint_exploration_duration
                .record(duration.as_secs_f64() * 1000.0, &[]);
        }
    }
}

/// Converts an endpoint exploration error into a concise label for metrics
///
/// Since we want to keep the amount of dimensions in metrics down, only the top
/// level error information is copied and details are omitted.
pub fn exploration_error_to_metric_label(error: &EndpointExplorationError) -> String {
    match error {
        EndpointExplorationError::ConnectionRefused { .. } => "connection_refused",
        EndpointExplorationError::ConnectionTimeout { .. } => "connection_timeout",
        EndpointExplorationError::Unreachable { .. } => "unreachable",
        EndpointExplorationError::UnsupportedVendor { .. } => "unsupported_vendor",
        EndpointExplorationError::RedfishError { .. } => "redfish_error",
        EndpointExplorationError::Unauthorized { .. } => "unauthorized",
        EndpointExplorationError::MissingCredentials { .. } => "missing_credentials",
        EndpointExplorationError::SetCredentials { .. } => "set_credentials",
        EndpointExplorationError::MissingRedfish { .. } => "missing_redfish",
        EndpointExplorationError::MissingVendor => "missing_vendor",
        EndpointExplorationError::AvoidLockout => "avoid_lockout",
        EndpointExplorationError::Other { .. } => "other",
        EndpointExplorationError::VikingFWInventoryForbiddenError { .. } => {
            "viking_fw_inventory_forbidden"
        }
        EndpointExplorationError::InvalidDpuRedfishBiosResponse { .. } => {
            "invalid_dpu_redfish_bios_response"
        }
        EndpointExplorationError::SecretsEngineError { .. } => "secrets_engine",
        EndpointExplorationError::IntermittentUnauthorized { .. } => "intermittent_unauthorized",
    }
    .to_string()
}

/// Stores Metric data shared between SiteExplorer and the OpenTelemetry background task
pub struct MetricHolder {
    instruments: SiteExplorerInstruments,
    last_iteration_metrics: SharedMetricsHolder<SiteExplorationMetrics>,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: std::time::Duration) -> Self {
        let last_iteration_metrics = SharedMetricsHolder::with_hold_period(hold_period);
        let instruments = SiteExplorerInstruments::new(meter, last_iteration_metrics.clone());
        Self {
            instruments,
            last_iteration_metrics,
        }
    }

    /// Updates the most recent metrics
    pub fn update_metrics(&self, mut metrics: SiteExplorationMetrics) {
        // Emit the last recent latency metrics
        self.instruments.emit_latency_metrics(&metrics);
        // We don't need to store the latency metrics anymore
        metrics.endpoint_exploration_duration.clear();
        // And store the remaining metrics
        self.last_iteration_metrics.update(metrics);
    }
}
