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

use std::{collections::HashMap, sync::Arc, time::Instant};

use arc_swap::ArcSwapOption;
use opentelemetry::{
    metrics::{self, Meter, ObservableGauge},
    KeyValue,
};
use serde::Serialize;

/// Metrics that are gathered in one a single `IbFabricMonitor` run
#[derive(Clone, Debug)]
pub struct IbFabricMonitorMetrics {
    /// When we finished recording the metrics
    pub recording_finished_at: std::time::Instant,
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
            recording_finished_at: Instant::now(),
            num_fabrics: 0,
            fabrics: HashMap::new(),
        }
    }
}

/// Instruments that are used by IbFabricMonitor
pub struct IbFabricMonitorInstruments {
    pub meter: Meter,
    pub num_fabrics: ObservableGauge<u64>,
    pub ufm_versions: ObservableGauge<u64>,
    pub fabric_errors: ObservableGauge<u64>,
    pub num_partitions: ObservableGauge<u64>,
    pub ports_by_state: ObservableGauge<u64>,
}

impl IbFabricMonitorInstruments {
    pub fn new(meter: Meter) -> Self {
        IbFabricMonitorInstruments {
            meter: meter.clone(),
            num_fabrics: meter
                .u64_observable_gauge("forge_ib_monitor_fabrics_count")
                .with_description("The amount of InfiniBand fabrics that are monitored")
                .init(),
            ufm_versions: meter
                .u64_observable_gauge("forge_ib_monitor_ufm_version_count")
                .with_description("The amount of UFM deployments per version")
                .init(),
            fabric_errors: meter
                .u64_observable_gauge("forge_ib_monitor_fabric_error_count")
                .with_description("The errors encountered while checking fabric states")
                .init(),
            num_partitions: meter
                .u64_observable_gauge("forge_ib_monitor_ufm_partitions_count")
                .with_description(
                    "The amount partitions registered at UFM in total (incl non Forge partitions)",
                )
                .init(),
            ports_by_state: meter
                .u64_observable_gauge("forge_ib_monitor_ufm_ports_by_state_count")
                .with_description(
                    "Total number of ports reported by UFM (incl non Forge managed ports)",
                )
                .init(),
        }
    }

    /// Returns the list of instruments that are used by this emitter.
    /// Used for opentelemetry callback registration
    pub fn instruments(&self) -> Vec<std::sync::Arc<dyn std::any::Any>> {
        vec![
            self.num_fabrics.as_any(),
            self.ufm_versions.as_any(),
            self.fabric_errors.as_any(),
            self.num_partitions.as_any(),
            self.ports_by_state.as_any(),
        ]
    }

    /// Emit the value of gauges whose values had been captured in [IbFabricMonitorMetrics]
    ///
    /// This method will be called as a callback whenever OpenTelemetry requires
    /// the latest version of metrics. The `metrics` that are passed
    /// are cached values that had been collected on the last monitor iteration.
    ///
    /// The `attributes` parameters lists additional attributes/labels that should
    /// be added to each emitted gauge.
    pub fn emit_gauges(
        &self,
        observer: &dyn metrics::Observer,
        metrics: &IbFabricMonitorMetrics,
        attributes: &[opentelemetry::KeyValue],
    ) {
        observer.observe_u64(&self.num_fabrics, metrics.num_fabrics as u64, attributes);

        for (fabric, metrics) in metrics.fabrics.iter() {
            let mut attrs: Vec<KeyValue> = attributes.to_vec();
            let fabric_attr = KeyValue::new("fabric", fabric.to_string());
            attrs.push(fabric_attr);

            let ufm_version = match &metrics.ufm_version {
                version if !version.is_empty() => version.clone(),
                _ => "unknown".to_string(),
            };
            let ufm_version_attr = KeyValue::new("version", ufm_version);
            attrs.push(ufm_version_attr);
            observer.observe_u64(&self.ufm_versions, 1, &attrs);
            attrs.pop();

            if !metrics.fabric_error.is_empty() {
                let error_attr = KeyValue::new(
                    "error",
                    truncate_error_for_metric_label(metrics.fabric_error.clone()),
                );
                attrs.push(error_attr);
                observer.observe_u64(&self.fabric_errors, 1, &attrs);
                attrs.pop();
            }

            if let Some(num_partitions) = metrics.num_partitions {
                observer.observe_u64(&self.num_partitions, num_partitions as u64, &attrs);
            }
            if let Some(num_ports_by_state) = metrics.ports_by_state.as_ref() {
                let state_attr = KeyValue::new("port_state", "".to_string());
                attrs.push(state_attr);
                for (state, &count) in num_ports_by_state.iter() {
                    attrs.last_mut().unwrap().value = state.clone().into();
                    observer.observe_u64(&self.ports_by_state, count as u64, &attrs);
                }
                attrs.pop();
            }
        }
    }
}

/// Stores Metric data shared between the Fabric Monitor and the OpenTelemetry background task
pub struct MetricHolder {
    instruments: IbFabricMonitorInstruments,
    last_iteration_metrics: ArcSwapOption<IbFabricMonitorMetrics>,
    /// The maximum time the stored metrics will be treated as up to date and valid.
    /// This will avoid to emit metrics that are outdated in case new metric
    /// collection is stuck.
    hold_period: std::time::Duration,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: std::time::Duration) -> Self {
        let instruments = IbFabricMonitorInstruments::new(meter);
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
            tracing::error!("Failed to register IbFabricMonitor metrics: {e}");
        };
    }

    /// Updates the most recent metrics
    pub fn update_metrics(&self, mut metrics: IbFabricMonitorMetrics) {
        metrics.recording_finished_at = std::time::Instant::now();
        self.last_iteration_metrics.store(Some(Arc::new(metrics)));
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
