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

use opentelemetry::metrics::Meter;

use crate::logging::metrics_utils::SharedMetricsHolder;

#[derive(Clone, Debug)]
pub struct PreingestionMetrics {
    pub machines_in_preingestion: usize,
    pub waiting_for_installation: usize,
    pub delayed_uploading: u64,
}

impl PreingestionMetrics {
    pub fn new() -> Self {
        Self {
            machines_in_preingestion: 0,
            waiting_for_installation: 0,
            delayed_uploading: 0,
        }
    }
}
fn hydrate_meter(meter: Meter, shared_metrics: SharedMetricsHolder<PreingestionMetrics>) {
    {
        let metrics = shared_metrics.clone();
        meter
            .u64_observable_gauge("carbide_preingestion_total")
            .with_description(
                "The amount of known machines currently being evaluated prior to ingestion",
            )
            .with_callback(move |observer| {
                metrics.if_available(|metrics, attrs| {
                    observer.observe(metrics.machines_in_preingestion as u64, attrs);
                });
            })
            .build();
    }

    {
        let metrics = shared_metrics.clone();
        meter
                .u64_observable_gauge("carbide_preingestion_waiting_installation")
                .with_description(
                    "The amount of machines which have had firmware uploaded to them and are currently in the process of installing that firmware"
                ).with_callback(move |observer| {
                metrics.if_available(|metrics, attrs| {
                    observer.observe(metrics.waiting_for_installation as u64, attrs)
                });
            }).build();
    }

    {
        let metrics = shared_metrics;
        meter
            .u64_observable_gauge("carbide_preingestion_waiting_download")
            .with_description("The amount of machines that are waiting for firmware downloads on other machines to complete before doing thier own")
            .with_callback(move |observer| {
                metrics.if_available(|metrics, attrs| {
                    observer.observe(
                        metrics.delayed_uploading,
                        attrs,
                    );
                });
            })
            .build();
    }
}

pub struct MetricHolder {
    last_iteration_metrics: SharedMetricsHolder<PreingestionMetrics>,
}

impl MetricHolder {
    pub fn new(meter: Meter, hold_period: std::time::Duration) -> Self {
        let last_iteration_metrics = SharedMetricsHolder::with_hold_period(hold_period);
        hydrate_meter(meter, last_iteration_metrics.clone());
        Self {
            last_iteration_metrics,
        }
    }

    /// Updates the most recent metrics
    pub fn update_metrics(&self, metrics: PreingestionMetrics) {
        self.last_iteration_metrics.update(metrics);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use prometheus_text_parser::ParsedPrometheusMetrics;

    use super::*;
    use crate::preingestion_manager::metrics::PreingestionMetrics;
    use crate::tests::common::test_meter::TestMeter;

    #[test]
    fn test_metrics_collector() {
        let mut metrics = PreingestionMetrics::new();
        metrics.delayed_uploading = 10;
        metrics.waiting_for_installation = 15;
        metrics.machines_in_preingestion = 20;
        let test_meter = TestMeter::default();

        let metric_holder = Arc::new(MetricHolder::new(test_meter.meter(), Duration::MAX));
        metric_holder.update_metrics(metrics);

        assert_eq!(
            test_meter
                .export_metrics()
                .parse::<ParsedPrometheusMetrics>()
                .unwrap(),
            include_str!("fixtures/test_metrics_collector.txt")
                .parse::<ParsedPrometheusMetrics>()
                .unwrap()
        );
    }
}
