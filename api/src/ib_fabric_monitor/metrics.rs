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

use crate::metrics_utils::SharedMetricsHolder;
use opentelemetry::{metrics::Meter, KeyValue};
use serde::Serialize;
use std::{collections::HashMap, time::Duration};

/// Metrics that are gathered in one a single `IbFabricMonitor` run
#[derive(Clone, Debug)]
pub struct IbFabricMonitorMetrics {
    /// The amount of fabrics that are monitored
    pub num_fabrics: usize,
    /// Per fabric metrics
    pub fabrics: HashMap<String, FabricMetrics>,
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
}

impl IbFabricMonitorMetrics {
    pub fn new() -> Self {
        Self {
            num_fabrics: 0,
            fabrics: HashMap::new(),
        }
    }
}

fn hydrate_meter(meter: Meter, shared_metrics: SharedMetricsHolder<IbFabricMonitorMetrics>) {
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
                                &[attrs, &[KeyValue::new("fabric", fabric.to_string())]].concat(),
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
}

/// Stores Metric data shared between the Fabric Monitor and the OpenTelemetry background task
pub struct MetricHolder {
    last_iteration_metrics: SharedMetricsHolder<IbFabricMonitorMetrics>,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: Duration) -> Self {
        let last_iteration_metrics = SharedMetricsHolder::with_hold_period(hold_period);
        hydrate_meter(meter, last_iteration_metrics.clone());
        Self {
            last_iteration_metrics,
        }
    }

    /// Updates the most recent metrics
    pub fn update_metrics(&self, metrics: IbFabricMonitorMetrics) {
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
