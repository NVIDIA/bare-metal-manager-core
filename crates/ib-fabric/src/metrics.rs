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

use ::carbide_utils::metrics::SharedMetricsHolder;
use carbide_instrument::{
    DynamicLog, DynamicMessage, Event, LabelValue, LogAt, emit, initialize_counter_series,
};
use model::ib_partition::PartitionKey;
use opentelemetry::metrics::Meter;
use opentelemetry::{KeyValue, StringValue};
use serde::Serialize;

use crate::errors::IbResult;

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
        }
    }
}

/// Closes a monitor pass after the work lock is acquired. Every emission
/// records the existing label-free latency histogram; failures also retain the
/// historical `ERROR` diagnostic.
#[derive(Event)]
#[event(
    event_name = "ib_monitor_iteration_finished",
    metric_name = "carbide_ib_monitor_iteration_latency_milliseconds",
    component = "ib-fabric-monitor",
    log = dynamic,
    metric = histogram,
    message = "IB fabric monitor run failed",
    describe = "The time it took to perform one IB fabric monitor iteration"
)]
pub(crate) struct IbMonitorIterationFinished {
    #[observation]
    pub latency: Duration,
    /// An empty value keeps successful passes log-silent without skipping the
    /// latency observation.
    #[context]
    pub error: String,
}

impl DynamicLog for IbMonitorIterationFinished {
    fn log_at(&self) -> LogAt {
        if self.error.is_empty() {
            LogAt::Off
        } else {
            LogAt::Level(tracing::Level::ERROR)
        }
    }
}

/// Registers the observable instruments used by `IbFabricMonitor`.
struct IbFabricMonitorInstruments;

impl IbFabricMonitorInstruments {
    fn new(meter: Meter, shared_metrics: SharedMetricsHolder<IbFabricMonitorMetrics>) -> Self {
        {
            let metrics = shared_metrics.clone();
            meter
                .u64_observable_gauge("carbide_ib_monitor_fabrics_count")
                .with_description("Number of monitored InfiniBand fabrics")
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
                    "Number of Machines whose InfiniBand status observation was updated",
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
                .u64_observable_gauge("carbide_ib_monitor_machines_by_port_state_count")
                .with_description(
                    "Number of machines whose total and active port counts match the attribute values",
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
                    "Number of machines where a certain number of ports is associated with at least one partition",
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
                    "Number of machines where at least one port is not assigned to the expected pkey on UFM",
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
                    "Number of machines where at least one port is assigned to an unexpected pkey on UFM",
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
                    "Number of machines where at least one port is assigned to a pkey value not associated with any partition ID",
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
                .with_description("Number of UFM deployments per version")
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
                .with_description("Number of InfiniBand fabrics not configured securely")
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
                    "Number of InfiniBand fabrics allowed to use insecure configuration",
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
                    "Number of partitions registered at UFM per fabric (including non-Forge partitions)",
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
                    "Number of ports reported by UFM in each port state (including non-Forge-managed ports)",
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

        Self
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, LabelValue)]
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

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, LabelValue)]
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

/// `ConfiguredFabric` is the reviewed escape hatch for the existing `fabric`
/// label. Values come from `IbFabricMonitor`'s startup configuration, and the
/// same finite set is used to initialize the counter series below.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ConfiguredFabric(String);

impl LabelValue for ConfiguredFabric {
    fn label_value(&self) -> StringValue {
        StringValue::from(self.0.clone())
    }
}

/// One GUID/pkey bind or unbind finished at UFM. Every call updates the
/// existing counter; successful calls stay quiet, while failures retain the
/// historical `ERROR` record and its operation-specific message.
#[derive(Event)]
#[event(
    event_name = "ib_ufm_guid_pkey_change_finished",
    metric_name = "carbide_ib_monitor_ufm_changes_applied_total",
    component = "ib-fabric-monitor",
    log = dynamic,
    metric = counter,
    message = dynamic,
    describe = "Number of changes performed at UFM"
)]
pub(crate) struct UfmGuidPkeyChangeFinished {
    #[label]
    fabric: ConfiguredFabric,
    #[label]
    operation: UfmOperation,
    #[label]
    status: UfmOperationStatus,
    #[context]
    guid: String,
    #[context]
    pkey: String,
    #[context]
    error: String,
}

impl UfmGuidPkeyChangeFinished {
    pub(crate) fn emit(
        fabric: &str,
        operation: UfmOperation,
        guid: &str,
        pkey: PartitionKey,
        result: &IbResult<()>,
    ) {
        emit(Self {
            fabric: ConfiguredFabric(fabric.to_string()),
            operation,
            status: if result.is_ok() {
                UfmOperationStatus::Ok
            } else {
                UfmOperationStatus::Error
            },
            guid: guid.to_string(),
            pkey: pkey.to_string(),
            error: result
                .as_ref()
                .err()
                .map(ToString::to_string)
                .unwrap_or_default(),
        });
    }

    fn initialize_counter_series(fabric_ids: &[&str]) {
        for &fabric in fabric_ids {
            for operation in UfmOperation::values() {
                for status in UfmOperationStatus::values() {
                    // `initialize_counter_series` only reads labels. These
                    // empty context values therefore never reach a log line.
                    let event = Self {
                        fabric: ConfiguredFabric(fabric.to_string()),
                        operation,
                        status,
                        guid: String::new(),
                        pkey: String::new(),
                        error: String::new(),
                    };
                    let initialized = initialize_counter_series(&event);
                    debug_assert!(initialized, "UFM change Event must remain a counter");
                }
            }
        }
    }
}

impl DynamicLog for UfmGuidPkeyChangeFinished {
    fn log_at(&self) -> LogAt {
        match self.status {
            UfmOperationStatus::Ok => LogAt::Off,
            UfmOperationStatus::Error => LogAt::Level(tracing::Level::ERROR),
        }
    }
}

impl DynamicMessage for UfmGuidPkeyChangeFinished {
    fn message(&self) -> &'static str {
        match self.operation {
            UfmOperation::BindGuidToPkey => "Failed to bind GUID to pkey",
            UfmOperation::UnbindGuidFromPkey => "Failed to unbind GUID from pkey",
        }
    }
}

/// Stores Metric data shared between the Fabric Monitor and the OpenTelemetry background task
pub struct MetricHolder {
    _instruments: IbFabricMonitorInstruments,
    last_iteration_metrics: SharedMetricsHolder<IbFabricMonitorMetrics>,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: Duration, fabric_ids: &[&str]) -> Self {
        let last_iteration_metrics = SharedMetricsHolder::with_hold_period(hold_period);
        let instruments = IbFabricMonitorInstruments::new(meter, last_iteration_metrics.clone());
        UfmGuidPkeyChangeFinished::initialize_counter_series(fabric_ids);
        Self {
            _instruments: instruments,
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

#[cfg(test)]
mod tests {
    use carbide_instrument::emit;
    use carbide_instrument::testing::{MetricsCapture, capture_logs};
    use carbide_test_support::{Check, check_values};

    use super::*;

    #[test]
    fn ib_monitor_iteration_outcomes_pair_latency_with_failure_log() {
        const EXPOSED_METRIC: &str = "carbide_ib_monitor_iteration_latency_milliseconds";

        struct IterationCase {
            latency: Duration,
            error: &'static str,
        }

        #[derive(Debug, PartialEq)]
        struct LogObservation {
            level: tracing::Level,
            metadata_name: String,
            message: String,
            event_name: Option<String>,
            metric_name: Option<String>,
            error: Option<String>,
        }

        #[derive(Debug, PartialEq)]
        struct Observation {
            log_count: usize,
            log: Option<LogObservation>,
            histogram_count_delta: u64,
            histogram_sum_delta: f64,
        }

        let failure = r#"Internal { message: "simulated iteration failure" }"#;
        check_values(
            [
                Check {
                    scenario: "successful iteration",
                    input: IterationCase {
                        latency: Duration::from_millis(125),
                        error: "",
                    },
                    expect: Observation {
                        log_count: 0,
                        log: None,
                        histogram_count_delta: 1,
                        histogram_sum_delta: 125.0,
                    },
                },
                Check {
                    scenario: "fractional milliseconds remain precise",
                    input: IterationCase {
                        latency: Duration::from_micros(125_500),
                        error: "",
                    },
                    expect: Observation {
                        log_count: 0,
                        log: None,
                        histogram_count_delta: 1,
                        histogram_sum_delta: 125.5,
                    },
                },
                Check {
                    scenario: "failed iteration",
                    input: IterationCase {
                        latency: Duration::from_millis(375),
                        error: failure,
                    },
                    expect: Observation {
                        log_count: 1,
                        log: Some(LogObservation {
                            level: tracing::Level::ERROR,
                            metadata_name: "ib_monitor_iteration_finished".to_string(),
                            message: "IB fabric monitor run failed".to_string(),
                            event_name: Some("ib_monitor_iteration_finished".to_string()),
                            metric_name: Some(EXPOSED_METRIC.to_string()),
                            error: Some(failure.to_string()),
                        }),
                        histogram_count_delta: 1,
                        histogram_sum_delta: 375.0,
                    },
                },
            ],
            |IterationCase { latency, error }| {
                let metrics = MetricsCapture::start();
                let logs = capture_logs(|| {
                    emit(IbMonitorIterationFinished {
                        latency,
                        error: error.to_string(),
                    });
                });
                let log = logs.first().map(|log| LogObservation {
                    level: log.level,
                    metadata_name: log.metadata_name.clone(),
                    message: log.message.clone(),
                    event_name: log.field("event_name").map(str::to_string),
                    metric_name: log.field("metric_name").map(str::to_string),
                    error: log.field("error").map(str::to_string),
                });

                Observation {
                    log_count: logs.len(),
                    log,
                    histogram_count_delta: metrics.histogram_count_delta(EXPOSED_METRIC, &[]),
                    histogram_sum_delta: metrics.histogram_sum_delta(EXPOSED_METRIC, &[]),
                }
            },
        );
    }

    #[test]
    fn ib_monitor_iteration_histogram_exposition_stays_stable() {
        const EXPOSED_METRIC: &str = "carbide_ib_monitor_iteration_latency_milliseconds";

        let metrics = MetricsCapture::start();
        emit(IbMonitorIterationFinished {
            latency: Duration::from_millis(125),
            error: String::new(),
        });

        let encoded = metrics.render();
        assert!(
            encoded.contains(&format!(
                "# HELP {EXPOSED_METRIC} The time it took to perform one IB fabric monitor iteration\n"
            )),
            "description or exposed family changed:\n{encoded}"
        );
        assert!(
            encoded.contains(&format!("# TYPE {EXPOSED_METRIC} histogram\n")),
            "expected the millisecond family to remain a histogram:\n{encoded}"
        );
        assert!(
            !encoded.contains("carbide_ib_monitor_iteration_latency_milliseconds_milliseconds"),
            "the unit suffix must be applied exactly once:\n{encoded}"
        );
        for suffix in ["count", "sum"] {
            let prefix = format!("{EXPOSED_METRIC}_{suffix} ");
            let sample = encoded
                .lines()
                .find(|line| line.starts_with(&prefix))
                .unwrap_or_else(|| panic!("missing {prefix} sample:\n{encoded}"));
            assert!(
                !sample.contains('{'),
                "iteration latency must remain label-free: {sample}"
            );
        }
    }

    #[test]
    fn ufm_guid_pkey_change_pairs_the_counter_with_failure_logs() {
        const EXPOSED_METRIC: &str = "carbide_ib_monitor_ufm_changes_applied_total";
        const FABRIC: &str = "event-test-fabric";
        const GUID: &str = "guid-1";

        struct ChangeCase {
            operation: UfmOperation,
            error: Option<&'static str>,
        }

        #[derive(Debug, PartialEq)]
        struct LogObservation {
            level: tracing::Level,
            metadata_name: String,
            message: String,
            event_name: Option<String>,
            metric_name: Option<String>,
            fabric: Option<String>,
            operation: Option<String>,
            status: Option<String>,
            guid: Option<String>,
            pkey: Option<String>,
            error: Option<String>,
        }

        #[derive(Debug, PartialEq)]
        struct Observation {
            log_count: usize,
            log: Option<LogObservation>,
            counter_delta: f64,
        }

        let fabric_error = "failed to call IBFabricManager: simulated UFM failure";
        check_values(
            [
                Check {
                    scenario: "successful bind",
                    input: ChangeCase {
                        operation: UfmOperation::BindGuidToPkey,
                        error: None,
                    },
                    expect: Observation {
                        log_count: 0,
                        log: None,
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "failed bind",
                    input: ChangeCase {
                        operation: UfmOperation::BindGuidToPkey,
                        error: Some("simulated UFM failure"),
                    },
                    expect: Observation {
                        log_count: 1,
                        log: Some(LogObservation {
                            level: tracing::Level::ERROR,
                            metadata_name: "ib_ufm_guid_pkey_change_finished".to_string(),
                            message: "Failed to bind GUID to pkey".to_string(),
                            event_name: Some("ib_ufm_guid_pkey_change_finished".to_string()),
                            metric_name: Some(EXPOSED_METRIC.to_string()),
                            fabric: Some(FABRIC.to_string()),
                            operation: Some("bind_guid_to_pkey".to_string()),
                            status: Some("error".to_string()),
                            guid: Some(GUID.to_string()),
                            pkey: Some("0x101".to_string()),
                            error: Some(fabric_error.to_string()),
                        }),
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "successful unbind",
                    input: ChangeCase {
                        operation: UfmOperation::UnbindGuidFromPkey,
                        error: None,
                    },
                    expect: Observation {
                        log_count: 0,
                        log: None,
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "failed unbind",
                    input: ChangeCase {
                        operation: UfmOperation::UnbindGuidFromPkey,
                        error: Some("simulated UFM failure"),
                    },
                    expect: Observation {
                        log_count: 1,
                        log: Some(LogObservation {
                            level: tracing::Level::ERROR,
                            metadata_name: "ib_ufm_guid_pkey_change_finished".to_string(),
                            message: "Failed to unbind GUID from pkey".to_string(),
                            event_name: Some("ib_ufm_guid_pkey_change_finished".to_string()),
                            metric_name: Some(EXPOSED_METRIC.to_string()),
                            fabric: Some(FABRIC.to_string()),
                            operation: Some("unbind_guid_from_pkey".to_string()),
                            status: Some("error".to_string()),
                            guid: Some(GUID.to_string()),
                            pkey: Some("0x101".to_string()),
                            error: Some(fabric_error.to_string()),
                        }),
                        counter_delta: 1.0,
                    },
                },
            ],
            |ChangeCase { operation, error }| {
                let pkey = PartitionKey::try_from(0x101).expect("valid pkey");
                let result = error.map_or(Ok(()), |error| {
                    Err(crate::errors::IbError::IBFabricError(error.to_string()))
                });
                let operation_label = match operation {
                    UfmOperation::BindGuidToPkey => "bind_guid_to_pkey",
                    UfmOperation::UnbindGuidFromPkey => "unbind_guid_from_pkey",
                };
                let status_label = if result.is_ok() { "ok" } else { "error" };
                let metrics = MetricsCapture::start();
                let logs = capture_logs(|| {
                    UfmGuidPkeyChangeFinished::emit(FABRIC, operation, GUID, pkey, &result);
                });
                let log = logs.first().map(|log| LogObservation {
                    level: log.level,
                    metadata_name: log.metadata_name.clone(),
                    message: log.message.clone(),
                    event_name: log.field("event_name").map(str::to_string),
                    metric_name: log.field("metric_name").map(str::to_string),
                    fabric: log.field("fabric").map(str::to_string),
                    operation: log.field("operation").map(str::to_string),
                    status: log.field("status").map(str::to_string),
                    guid: log.field("guid").map(str::to_string),
                    pkey: log.field("pkey").map(str::to_string),
                    error: log.field("error").map(str::to_string),
                });

                Observation {
                    log_count: logs.len(),
                    log,
                    counter_delta: metrics.counter_delta(
                        EXPOSED_METRIC,
                        &[
                            ("fabric", FABRIC),
                            ("operation", operation_label),
                            ("status", status_label),
                        ],
                    ),
                }
            },
        );
    }

    #[test]
    fn initializes_every_ufm_change_series_without_logging() {
        const EXPOSED_METRIC: &str = "carbide_ib_monitor_ufm_changes_applied_total";
        const FABRIC: &str = "zero-series-fabric";

        let metrics = MetricsCapture::start();
        let logs = capture_logs(|| {
            UfmGuidPkeyChangeFinished::initialize_counter_series(&[FABRIC]);
        });

        assert!(logs.is_empty());
        let encoded = metrics.render();
        assert!(
            encoded.contains(&format!(
                "# HELP {EXPOSED_METRIC} Number of changes performed at UFM\n"
            )),
            "description or exposed family changed:\n{encoded}"
        );
        assert!(
            encoded.contains(&format!("# TYPE {EXPOSED_METRIC} counter\n")),
            "expected the UFM change family to remain a counter:\n{encoded}"
        );
        assert!(
            !encoded.contains("carbide_ib_monitor_ufm_changes_applied_total_total"),
            "the counter suffix must be applied exactly once:\n{encoded}"
        );
        for operation in ["bind_guid_to_pkey", "unbind_guid_from_pkey"] {
            for status in ["ok", "error"] {
                let sample = format!(
                    "{EXPOSED_METRIC}{{fabric=\"{FABRIC}\",operation=\"{operation}\",status=\"{status}\"}} 0"
                );
                assert!(
                    encoded.lines().any(|line| line == sample),
                    "missing initialized series {sample}:\n{encoded}"
                );
            }
        }
    }

    #[test]
    fn enumerates_ufm_operations_and_statuses() {
        assert_eq!(
            UfmOperation::values().collect::<Vec<_>>(),
            vec![
                UfmOperation::BindGuidToPkey,
                UfmOperation::UnbindGuidFromPkey
            ]
        );
        assert_eq!(
            UfmOperationStatus::values().collect::<Vec<_>>(),
            vec![UfmOperationStatus::Ok, UfmOperationStatus::Error]
        );
    }

    #[test]
    fn creates_empty_monitor_metrics() {
        let metrics = IbFabricMonitorMetrics::new();

        assert_eq!(metrics.num_fabrics, 0);
        assert!(metrics.fabrics.is_empty());
        assert_eq!(metrics.num_machine_ib_status_updates, 0);
        assert!(metrics.num_machines_by_port_states.is_empty());
        assert!(metrics.num_machines_by_ports_with_partitions.is_empty());
        assert_eq!(metrics.num_machines_with_missing_pkeys, 0);
        assert_eq!(metrics.num_machines_with_unexpected_pkeys, 0);
        assert_eq!(metrics.num_machines_with_unknown_pkeys, 0);
    }
}
