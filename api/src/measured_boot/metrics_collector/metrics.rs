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

use crate::measured_boot::dto::{
    keys::{MeasurementBundleId, MeasurementSystemProfileId},
    records::{MeasurementBundleState, MeasurementMachineState},
};
use std::{collections::HashMap, sync::Arc, time::Instant};

use arc_swap::ArcSwapOption;
use opentelemetry::{
    metrics::{self, Meter, ObservableGauge},
    KeyValue,
};

/// MeasuredBootMetricsCollectorMetrics stores metrics that are gathered in
/// one a single `MeasuredBootMetricsCollector` run. These metrics are then
/// emitted into opentelemetry.
#[derive(Clone, Debug)]
pub struct MeasuredBootMetricsCollectorMetrics {
    // When we finished recording the metrics.
    pub recording_finished_at: std::time::Instant,
    // The number of measured boot profiles.
    pub num_profiles: usize,
    // The number of measured boot bundles.
    pub num_bundles: usize,
    // The number of machines which have reported measurements,
    // which should be <= the number of machines in the site.
    pub num_machines: usize,
    // The number of machines per profile.
    pub num_machines_per_profile: HashMap<MeasurementSystemProfileId, usize>,
    // The number of machines per bundle.
    pub num_machines_per_bundle: HashMap<MeasurementBundleId, usize>,
    // The number of machines per bundle state.
    pub num_machines_per_bundle_state: HashMap<MeasurementBundleState, usize>,
    // The number of machines per machine state.
    pub num_machines_per_machine_state: HashMap<MeasurementMachineState, usize>,
}

impl MeasuredBootMetricsCollectorMetrics {
    pub fn new() -> Self {
        Self {
            recording_finished_at: Instant::now(),
            num_profiles: 0,
            num_bundles: 0,
            num_machines: 0,
            num_machines_per_profile: HashMap::new(),
            num_machines_per_bundle: HashMap::new(),
            num_machines_per_bundle_state: HashMap::new(),
            num_machines_per_machine_state: HashMap::new(),
        }
    }
}

/// MeasuredBootMetricsCollectorInstruments are instruments which get
/// fed into opentelemetry.
pub struct MeasuredBootMetricsCollectorInstruments {
    pub meter: Meter,
    pub num_profiles_total: ObservableGauge<u64>,
    pub num_bundles_total: ObservableGauge<u64>,
    pub num_machines_total: ObservableGauge<u64>,
    pub num_machines_per_profile_total: ObservableGauge<u64>,
    pub num_machines_per_bundle_total: ObservableGauge<u64>,
    pub num_machines_per_bundle_state_total: ObservableGauge<u64>,
    pub num_machines_per_machine_state_total: ObservableGauge<u64>,
}

impl MeasuredBootMetricsCollectorInstruments {
    pub fn new(meter: Meter) -> Self {
        Self {
            meter: meter.clone(),
            num_profiles_total: meter
                .u64_observable_gauge("forge_measured_boot_profiles_total")
                .with_description("The total number of measured boot profiles.")
                .init(),
            num_bundles_total: meter
                .u64_observable_gauge("forge_measured_boot_bundles_total")
                .with_description("The total number of measured boot bundles.")
                .init(),
            num_machines_total: meter
                .u64_observable_gauge("forge_measured_boot_machines_total")
                .with_description("The total number of machines reporting measurements.")
                .init(),
            num_machines_per_profile_total: meter
                .u64_observable_gauge("forge_measured_boot_machines_per_profile_total")
                .with_description("The total number of machines per measured boot system profile.")
                .init(),
            num_machines_per_bundle_total: meter
                .u64_observable_gauge("forge_measured_boot_machines_per_bundle_total")
                .with_description("The total number of machines per measured boot bundle.")
                .init(),
            num_machines_per_bundle_state_total: meter
                .u64_observable_gauge("forge_measured_boot_machines_per_bundle_state_total")
                .with_description(
                    "The total number of machines per a given measured boot bundle state.",
                )
                .init(),
            num_machines_per_machine_state_total: meter
                .u64_observable_gauge("forge_measured_boot_machines_per_machine_state_total")
                .with_description(
                    "The total number of machines per a given measured boot machine state.",
                )
                .init(),
        }
    }

    /// Returns the list of instruments that are used by this emitter.
    /// Used for opentelemetry callback registration.
    pub fn instruments(&self) -> Vec<std::sync::Arc<dyn std::any::Any>> {
        vec![
            self.num_profiles_total.as_any(),
            self.num_bundles_total.as_any(),
            self.num_machines_total.as_any(),
            self.num_machines_per_profile_total.as_any(),
            self.num_machines_per_bundle_total.as_any(),
            self.num_machines_per_bundle_state_total.as_any(),
            self.num_machines_per_machine_state_total.as_any(),
        ]
    }

    /// Emit the value of gauges whose values had been captured
    /// in [MeasuredBootMetricsCollectorMetrics].
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
        metrics: &MeasuredBootMetricsCollectorMetrics,
        attributes: &[opentelemetry::KeyValue],
    ) {
        observer.observe_u64(
            &self.num_profiles_total,
            metrics.num_profiles as u64,
            attributes,
        );
        observer.observe_u64(
            &self.num_bundles_total,
            metrics.num_bundles as u64,
            attributes,
        );

        for (profile_id, total) in metrics.num_machines_per_profile.iter() {
            let mut attrs: Vec<KeyValue> = attributes.to_vec();
            let profile_id_attr = KeyValue::new("profile_id", profile_id.to_string());
            attrs.push(profile_id_attr);
            observer.observe_u64(&self.num_machines_per_profile_total, *total as u64, &attrs);
        }

        for (bundle_id, total) in metrics.num_machines_per_bundle.iter() {
            let mut attrs: Vec<KeyValue> = attributes.to_vec();
            let bundle_id_attr = KeyValue::new("bundle_id", bundle_id.to_string());
            attrs.push(bundle_id_attr);
            observer.observe_u64(&self.num_machines_per_bundle_total, *total as u64, &attrs);
        }

        for (bundle_state, total) in metrics.num_machines_per_bundle_state.iter() {
            let mut attrs: Vec<KeyValue> = attributes.to_vec();
            let bundle_state_attr = KeyValue::new("bundle_state", bundle_state.to_string());
            attrs.push(bundle_state_attr);
            observer.observe_u64(
                &self.num_machines_per_bundle_state_total,
                *total as u64,
                &attrs,
            );
        }

        for (machine_state, total) in metrics.num_machines_per_machine_state.iter() {
            let mut attrs: Vec<KeyValue> = attributes.to_vec();
            let machine_state_attr = KeyValue::new("machine_state", machine_state.to_string());
            attrs.push(machine_state_attr);
            observer.observe_u64(
                &self.num_machines_per_machine_state_total,
                *total as u64,
                &attrs,
            );
        }
    }
}

/// Stores Metric data shared between the Fabric Monitor and the OpenTelemetry background task
pub struct MetricHolder {
    instruments: MeasuredBootMetricsCollectorInstruments,
    last_iteration_metrics: ArcSwapOption<MeasuredBootMetricsCollectorMetrics>,
    /// The maximum time the stored metrics will be treated as up to date and valid.
    /// This will avoid to emit metrics that are outdated in case new metric
    /// collection is stuck.
    hold_period: std::time::Duration,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: std::time::Duration) -> Self {
        let instruments = MeasuredBootMetricsCollectorInstruments::new(meter);
        Self {
            instruments,
            last_iteration_metrics: ArcSwapOption::const_empty(),
            hold_period,
        }
    }

    /// Registers a callback to OpenTelemetry which will lead to
    /// emitting the latest stored metrics.
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
            tracing::error!("Failed to register MeasuredBootMetricsCollector metrics: {e}");
        };
    }

    /// Updates the most recent metrics
    pub fn update_metrics(&self, mut metrics: MeasuredBootMetricsCollectorMetrics) {
        metrics.recording_finished_at = std::time::Instant::now();
        self.last_iteration_metrics.store(Some(Arc::new(metrics)));
    }
}
