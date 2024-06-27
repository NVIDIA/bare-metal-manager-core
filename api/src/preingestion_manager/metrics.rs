/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use arc_swap::ArcSwapOption;
use opentelemetry::{
    metrics::{self, Meter, ObservableGauge},
    KeyValue,
};
use std::{sync::Arc, time::Instant};

#[derive(Clone, Debug)]
pub struct PreingestionMetrics {
    /// When the exploration started
    recorded_at: Instant,

    pub machines_in_preingestion: usize,
    pub waiting_for_installation: usize,
    pub delayed_uploading: u64,
}

impl PreingestionMetrics {
    pub fn new() -> Self {
        Self {
            recorded_at: Instant::now(),
            machines_in_preingestion: 0,
            waiting_for_installation: 0,
            delayed_uploading: 0,
        }
    }
}
pub struct PreingestionInstruments {
    meter: Meter,
    pub machines_in_preingestion: ObservableGauge<u64>,
    pub waiting_for_installation: ObservableGauge<u64>,
    pub delayed_uploading: ObservableGauge<u64>,
}
impl PreingestionInstruments {
    pub fn new(meter: Meter) -> Self {
        Self {
            meter: meter.clone(),
            machines_in_preingestion: meter
                .u64_observable_gauge("forge_preingestion_total")
                .with_description(
                    "The amount of known machines currently being evaluated prior to ingestion",
                )
                .init(),
            waiting_for_installation: meter
                .u64_observable_gauge("forge_preingestion_waiting_installation")
                .with_description(
                    "The amount of machines which have had firmware uploaded to them and are currently in the process of installing that firmware"
                ).init(),
            delayed_uploading: meter
                .u64_observable_gauge("forge_preingestion_waiting_download")
                .with_description("The amount of machines that are waiting for firmware downloads on other machines to complete before doing thier own")
                .init(),
        }
    }

    pub fn instruments(&self) -> Vec<std::sync::Arc<dyn std::any::Any>> {
        vec![
            self.machines_in_preingestion.as_any(),
            self.waiting_for_installation.as_any(),
            self.delayed_uploading.as_any(),
        ]
    }
    pub fn emit_gauges(
        &self,
        observer: &dyn metrics::Observer,
        metrics: &PreingestionMetrics,
        attributes: &[KeyValue],
    ) {
        observer.observe_u64(
            &self.machines_in_preingestion,
            metrics.machines_in_preingestion as u64,
            attributes,
        );
        observer.observe_u64(
            &self.waiting_for_installation,
            metrics.waiting_for_installation as u64,
            attributes,
        );
        observer.observe_u64(
            &self.delayed_uploading,
            metrics.delayed_uploading,
            attributes,
        );
    }
}

pub struct MetricHolder {
    pub instruments: PreingestionInstruments,
    last_iteration_metrics: ArcSwapOption<PreingestionMetrics>,
    /// The maximum time the stored metrics will be treated as up to date and valid.
    /// This will avoid to emit metrics that are outdated in case new metric
    /// collection is stuck.
    hold_period: std::time::Duration,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: std::time::Duration) -> Self {
        let instruments = PreingestionInstruments::new(meter);
        Self {
            instruments,
            last_iteration_metrics: ArcSwapOption::const_empty(),
            hold_period,
        }
    }

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
            tracing::error!("Failed to register PreingestionManager metrics: {e}");
        };
    }

    /// Updates the most recent metrics
    pub fn update_metrics(&self, metrics: PreingestionMetrics) {
        // And store the remaining metrics
        self.last_iteration_metrics.store(Some(Arc::new(metrics)));
    }
}
