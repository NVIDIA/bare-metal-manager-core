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
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter};
use serde::Serialize;

use crate::logging::metrics_utils::SharedMetricsHolder;

/// Metrics that are gathered in one a single `IbFabricMonitor` run
#[derive(Clone, Debug)]
pub struct IbFabricMonitorMetrics {
    /// When we started recording these metrics
    pub recording_started_at: std::time::Instant,
    /// The amount of fabrics that are monitored
    pub num_fabrics: usize,
    /// Per fabric metrics
    pub fabrics: HashMap<String, FabricMetrics>,
    /// The amount of Machines where the IB status observation got updated
    pub num_machine_ib_status_updates: usize,
    /// The amount of Machines with a certain port state
    /// Key: Tuple of total and active amount of IB ports on the Machines
    /// Value: Amount of Machines with that amount of total and active ports
    pub num_machines_by_port_states: HashMap<(usize, usize), usize>,
    /// The amount of Machines with a certain amount of associated partitions
    /// Key: The amount of associated partitions
    /// Value: Amount of Machines with that amount of associated partitions
    pub num_machines_by_ports_with_partitions: HashMap<usize, usize>,
    /// The amount of machines where at least one port is not assigned to the
    /// expected pkey on UFM
    pub num_machines_with_missing_pkeys: usize,
    /// The amount of machines where at least one port is assigned to an unexpected
    /// pkey on UFM
    pub num_machines_with_unexpected_pkeys: usize,
    /// The amount of machines where at least one port is assigned to a pkey value
    /// that is not associated with any partition ID
    pub num_machines_with_unknown_pkeys: usize,
    /// The amount of changes that IBFabricMonitor performed,
    /// keyed by the type of change and outcome
    pub applied_changes: HashMap<AppliedChange, usize>,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub struct AppliedChange {
    /// The fabric the operation has been applied against
    pub fabric: String,
    /// The operation that has been performed
    pub operation: UfmOperation,
    /// Whether the operation succeeded or failed
    pub status: UfmOperationStatus,
}

/// Metrics collected for a single fabric
#[derive(Clone, Debug, Default, Serialize)]
pub struct FabricMetrics {
    /// The endpoint that we use to interact with the fabric
    pub endpoints: Vec<String>,
    /// Error when trying to connect to the fabric
    pub fabric_error: String,
    /// UFM version
    pub ufm_version: String,
    /// The subnet_prefix of UFM
    pub subnet_prefix: String,
    /// The m_key of UFM
    pub m_key: String,
    /// The sm_key of UFM
    pub sm_key: String,
    /// The sa_key of UFM
    pub sa_key: String,
    /// The m_key_per_port of UFM
    pub m_key_per_port: bool,
    /// Default partition membership
    pub default_partition_membership: Option<String>,
    /// The amount of partitions visible at UFM
    pub num_partitions: Option<usize>,
    /// The amount of ports visible at UFM - indexed by state
    pub ports_by_state: Option<HashMap<String, usize>>,
    /// Whether the fabric not configured to protect tenants and infrastructure
    pub insecure_fabric_configuration: bool,
    /// Whether an insecure fabric configuration is allowed
    pub allow_insecure_fabric_configuration: bool,
}

impl IbFabricMonitorMetrics {
    pub fn new() -> Self {
        Self {
            recording_started_at: std::time::Instant::now(),
            num_fabrics: 0,
            fabrics: HashMap::new(),
            num_machine_ib_status_updates: 0,
            num_machines_by_port_states: HashMap::new(),
            num_machines_by_ports_with_partitions: HashMap::new(),
            num_machines_with_missing_pkeys: 0,
            num_machines_with_unexpected_pkeys: 0,
            num_machines_with_unknown_pkeys: 0,
            applied_changes: HashMap::new(),
        }
    }
}

/// Instruments that are used by pub struct IbFabricMonitor
pub struct IbFabricMonitorInstruments {
    pub iteration_latency: Histogram<f64>,
    pub ufm_changes_applied: Counter<u64>,
}

impl IbFabricMonitorInstruments {
    pub fn new(meter: Meter, shared_metrics: SharedMetricsHolder<IbFabricMonitorMetrics>) -> Self {
        let iteration_latency = meter
            .f64_histogram("carbide_ib_monitor_iteration_latency")
            .with_description("The time it took to perform one IB fabric monitor iteration")
            .with_unit("ms")
            .build();

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_ib_monitor_fabrics_count")
                .with_description("The amount of InfiniBand fabrics that are monitored")
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        o.observe(metrics.num_fabrics as u64, attrs);
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_ib_monitor_machine_ib_status_updates_count")
                .with_description(
                    "The amount of Machines where the infiniband_status_observation got updated",
                )
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        o.observe(metrics.num_machine_ib_status_updates as u64, attrs);
                    })
                })
                .build();
        }

        let ufm_changes_applied = meter
            .u64_counter("carbide_ib_monitor_ufm_changes_applied")
            .with_description("The amount of changes that have been performed at UFM")
            .build();

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_ib_monitor_machines_by_port_state_count")
                .with_description(
                    "The amount of Machines where the amount of total and active ports matches the values in attributes",
                )
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        for (&(total_ports, active_ports), &num_machines) in metrics.num_machines_by_port_states.iter() {
                            o.observe(
                                num_machines as u64,
                                &[
                                    attrs,
                                    &[
                                        KeyValue::new("total_ports", total_ports as i64),
                                        KeyValue::new("active_ports", active_ports as i64),
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
                .u64_observable_gauge("carbide_ib_monitor_machines_by_ports_with_partitions_count")
                .with_description(
                    "The amount of Machines where a certain amount of ports is associated with at least one partition",
                )
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        for (&ports_with_partitions, &num_machines) in metrics.num_machines_by_ports_with_partitions.iter() {
                            o.observe(
                                num_machines as u64,
                                &[
                                    attrs,
                                    &[
                                        KeyValue::new("ports_with_partitions", ports_with_partitions as i64),
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
                .u64_observable_gauge("carbide_ib_monitor_machines_with_missing_pkeys_count")
                .with_description(
                    "The amount of machines where at least one port is not assigned to the expected pkey on UFM",
                )
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        o.observe(metrics.num_machines_with_missing_pkeys as u64, attrs);
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_ib_monitor_machines_with_unexpected_pkeys_count")
                .with_description(
                    "The amount of machines where at least one port is assigned to an unexpected pkey on UFM",
                )
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        o.observe(metrics.num_machines_with_unexpected_pkeys as u64, attrs);
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_ib_monitor_machines_with_unknown_pkeys_count")
                .with_description(
                    "The amount of machines where at least one port is assigned to a pkey value that is not associated with any partition ID",
                )
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        o.observe(metrics.num_machines_with_unknown_pkeys as u64, attrs);
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_ib_monitor_ufm_version_count")
                .with_description("The amount of UFM deployments per version")
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        for (fabric, metrics) in metrics.fabrics.iter() {
                            let ufm_version = match &metrics.ufm_version {
                                version if !version.is_empty() => version.clone(),
                                _ => "unknown".to_string(),
                            };
                            o.observe(
                                1,
                                &[
                                    attrs,
                                    &[
                                        KeyValue::new("fabric", fabric.to_string()),
                                        KeyValue::new("version", ufm_version),
                                    ],
                                ]
                                .concat(),
                            );
                        }
                    });
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_ib_monitor_fabric_error_count")
                .with_description("The errors encountered while checking fabric states")
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        for (fabric, metrics) in metrics.fabrics.iter() {
                            if !metrics.fabric_error.is_empty() {
                                o.observe(
                                    1,
                                    &[
                                        attrs,
                                        &[
                                            KeyValue::new("fabric", fabric.to_string()),
                                            KeyValue::new(
                                                "error",
                                                truncate_error_for_metric_label(
                                                    metrics.fabric_error.clone(),
                                                ),
                                            ),
                                        ],
                                    ]
                                    .concat(),
                                );
                            }
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_ib_monitor_insecure_fabric_configuration_count")
                .with_description(
                    "The amount of InfiniBand fabrics that are not configured securely",
                )
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        for (fabric, metrics) in metrics.fabrics.iter() {
                            o.observe(
                                if metrics.insecure_fabric_configuration {
                                    1
                                } else {
                                    0
                                },
                                &[attrs, &[KeyValue::new("fabric", fabric.to_string())]].concat(),
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
                    "carbide_ib_monitor_allow_insecure_fabric_configuration_count",
                )
                .with_description(
                    "The amount of InfiniBand fabrics that are not configured securely",
                )
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        for (fabric, metrics) in metrics.fabrics.iter() {
                            o.observe(
                                if metrics.allow_insecure_fabric_configuration {
                                    1
                                } else {
                                    0
                                },
                                &[attrs, &[KeyValue::new("fabric", fabric.to_string())]].concat(),
                            );
                        }
                    })
                })
                .build();
        }

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_ib_monitor_ufm_partitions_count")
                .with_description(
                    "The amount partitions registered at UFM in total (incl non Forge partitions)",
                )
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        for (fabric, metrics) in metrics.fabrics.iter() {
                            if let Some(num_partitions) = metrics.num_partitions {
                                o.observe(
                                    num_partitions as u64,
                                    &[attrs, &[KeyValue::new("fabric", fabric.to_string())]]
                                        .concat(),
                                );
                            }
                        }
                    });
                })
                .build();
        }

        {
            let metrics = shared_metrics;
            meter
                .u64_observable_gauge("carbide_ib_monitor_ufm_ports_by_state_count")
                .with_description(
                    "Total number of ports reported by UFM (incl non Forge managed ports)",
                )
                .with_callback(move |o| {
                    metrics.if_available(|metrics, attrs| {
                        for (fabric, metrics) in metrics.fabrics.iter() {
                            if let Some(num_ports_by_state) = metrics.ports_by_state.as_ref() {
                                for (state, &count) in num_ports_by_state.iter() {
                                    o.observe(
                                        count as u64,
                                        &[
                                            attrs,
                                            &[
                                                KeyValue::new("fabric", fabric.to_string()),
                                                KeyValue::new("port_state", state.to_string()),
                                            ],
                                        ]
                                        .concat(),
                                    );
                                }
                            }
                        }
                    })
                })
                .build();
        }

        Self {
            iteration_latency,
            ufm_changes_applied,
        }
    }

    fn emit_counters_and_histograms(&self, metrics: &IbFabricMonitorMetrics) {
        self.iteration_latency.record(
            1000.0 * metrics.recording_started_at.elapsed().as_secs_f64(),
            &[],
        );

        for (change, &count) in metrics.applied_changes.iter() {
            self.ufm_changes_applied.add(
                count as u64,
                &[
                    KeyValue::new("fabric", change.fabric.clone()),
                    KeyValue::new("operation", change.operation),
                    KeyValue::new("status", change.status),
                ],
            );
        }
    }

    fn init_counters_and_histograms(&self, fabric_ids: &[&str]) {
        for fabric_id in fabric_ids.iter() {
            for status in UfmOperationStatus::values() {
                for operation in UfmOperation::values() {
                    self.ufm_changes_applied.add(
                        0u64,
                        &[
                            KeyValue::new("fabric", fabric_id.to_string()),
                            KeyValue::new("operation", operation),
                            KeyValue::new("status", status),
                        ],
                    );
                }
            }
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[allow(clippy::enum_variant_names)]
pub enum UfmOperation {
    BindGuidToPkey,
    UnbindGuidFromPkey,
    // If you add anything here, adjust the values function below
}

impl UfmOperation {
    pub fn values() -> impl Iterator<Item = Self> {
        [Self::BindGuidToPkey, Self::UnbindGuidFromPkey].into_iter()
    }
}

impl From<UfmOperation> for opentelemetry::Value {
    fn from(value: UfmOperation) -> Self {
        let str_value = match value {
            UfmOperation::BindGuidToPkey => "bind_guid_to_pkey",
            UfmOperation::UnbindGuidFromPkey => "unbind_guid_from_pkey",
        };

        Self::from(str_value)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum UfmOperationStatus {
    Ok,
    Error,
    // If you add anything here, adjust the values function below
}

impl UfmOperationStatus {
    pub fn values() -> impl Iterator<Item = Self> {
        [Self::Ok, Self::Error].into_iter()
    }
}

impl From<UfmOperationStatus> for opentelemetry::Value {
    fn from(value: UfmOperationStatus) -> Self {
        let str_value = match value {
            UfmOperationStatus::Ok => "ok",
            UfmOperationStatus::Error => "error",
        };

        Self::from(str_value)
    }
}

/// Stores Metric data shared between the Fabric Monitor and the OpenTelemetry background task
pub struct MetricHolder {
    instruments: IbFabricMonitorInstruments,
    last_iteration_metrics: SharedMetricsHolder<IbFabricMonitorMetrics>,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: Duration, fabric_ids: &[&str]) -> Self {
        let last_iteration_metrics = SharedMetricsHolder::with_hold_period(hold_period);
        let instruments = IbFabricMonitorInstruments::new(meter, last_iteration_metrics.clone());
        instruments.init_counters_and_histograms(fabric_ids);
        Self {
            instruments,
            last_iteration_metrics,
        }
    }

    /// Updates the most recent metrics
    pub fn update_metrics(&self, metrics: IbFabricMonitorMetrics) {
        // Emit the last recent latency metrics
        self.instruments.emit_counters_and_histograms(&metrics);
        self.last_iteration_metrics.update(metrics);
    }
}

/// Truncates an error message in order to use it as label
/// TODO: This is not a preferred approach, since it will lead to a set of non-descriptive
/// labels. We should rather get better Error Codes from the IB/UFM library
fn truncate_error_for_metric_label(mut error: String) -> String {
    const MAX_LEN: usize = 32;

    let upto = error
        .char_indices()
        .map(|(i, _)| i)
        .nth(MAX_LEN)
        .unwrap_or(error.len());
    error.truncate(upto);
    error
}
