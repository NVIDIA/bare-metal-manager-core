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

use crate::logging::metrics_utils::SharedMetricsHolder;
use opentelemetry::{
    KeyValue,
    metrics::{Histogram, Meter},
};
use serde::Serialize;
use std::{collections::HashMap, time::Duration};

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
        }
    }
}

/// Instruments that are used by pub struct IbFabricMonitor
pub struct IbFabricMonitorInstruments {
    pub iteration_latency: Histogram<f64>,
}

impl IbFabricMonitorInstruments {
    pub fn new(meter: Meter, shared_metrics: SharedMetricsHolder<IbFabricMonitorMetrics>) -> Self {
        let iteration_latency = meter
            .f64_histogram("forge_ib_monitor_iteration_latency")
            .with_description("The time it took to perform one IB fabric monitor iteration")
            .with_unit("ms")
            .build();

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("forge_ib_monitor_fabrics_count")
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
                .u64_observable_gauge("forge_ib_monitor_machine_ib_status_updates_count")
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

        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("forge_ib_monitor_machines_by_port_state_count")
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
                .u64_observable_gauge("forge_ib_monitor_ufm_version_count")
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
                .u64_observable_gauge("forge_ib_monitor_fabric_error_count")
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
                .u64_observable_gauge("forge_ib_monitor_insecure_fabric_configuration_count")
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
                .u64_observable_gauge("forge_ib_monitor_allow_insecure_fabric_configuration_count")
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
                .u64_observable_gauge("forge_ib_monitor_ufm_partitions_count")
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
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("forge_ib_monitor_ufm_ports_by_state_count")
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

        Self { iteration_latency }
    }

    fn emit_counters_and_histograms(&self, metrics: &IbFabricMonitorMetrics) {
        self.iteration_latency.record(
            1000.0 * metrics.recording_started_at.elapsed().as_secs_f64(),
            &[],
        );
    }
}

/// Stores Metric data shared between the Fabric Monitor and the OpenTelemetry background task
pub struct MetricHolder {
    instruments: IbFabricMonitorInstruments,
    last_iteration_metrics: SharedMetricsHolder<IbFabricMonitorMetrics>,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: Duration) -> Self {
        let last_iteration_metrics = SharedMetricsHolder::with_hold_period(hold_period);
        let instruments = IbFabricMonitorInstruments::new(meter, last_iteration_metrics.clone());
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
