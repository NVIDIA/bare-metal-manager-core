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

use opentelemetry::metrics::Meter;
use opentelemetry::metrics::MeterProvider;
use prometheus::Encoder;
use prometheus::TextEncoder;

pub struct TestMeter {
    meter: Meter,
    registry: prometheus::Registry,
}

impl TestMeter {
    /// Returns the latest accumulated metrics in prometheus format
    pub fn export_metrics(&self) -> String {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }

    pub fn meter(&self) -> Meter {
        self.meter.clone()
    }

    /// Returns the value of a single metric with a given name
    pub fn formatted_metric(&self, metric_name: &str) -> Option<String> {
        let mut metrics = self.formatted_metrics(metric_name);
        match metrics.len() {
            0 => None,
            1 => metrics.pop(),
            n => panic!("Expected to find a single metric with name \"{metric_name}\", but found {n}. Full metrics:\n{:?}", metrics),
        }
    }

    /// Returns the value of multiple metrics with the given name
    /// This can be used if the metric is duplicated due to attributes
    pub fn formatted_metrics(&self, metric_name: &str) -> Vec<String> {
        let formatted = self.export_metrics();
        let mut result = Vec::new();
        for line in formatted.lines() {
            // Metrics look like "metric_name $value" if without attributes
            // and "metric_name{$attrs} value" if with attributes
            if !line.starts_with(metric_name) {
                continue;
            }
            let line = line.trim_start_matches(metric_name);
            if line.starts_with('{') {
                result.push(line.to_string());
            } else {
                result.push(line.strip_prefix(' ').unwrap_or(line).to_string());
            }
        }
        result
    }
}

impl Default for TestMeter {
    /// Builds an OpenTelemetry `Meter` for unit-testing purposes
    fn default() -> Self {
        // Note: This configures metrics bucket between 5.0 and 10000.0, which are best suited
        // for tracking milliseconds
        // See https://github.com/open-telemetry/opentelemetry-rust/blob/495330f63576cfaec2d48946928f3dc3332ba058/opentelemetry-sdk/src/metrics/reader.rs#L155-L158
        let prometheus_registry = prometheus::Registry::new();
        let metrics_exporter = opentelemetry_prometheus::exporter()
            .with_registry(prometheus_registry.clone())
            .without_scope_info()
            .without_target_info()
            .build()
            .unwrap();
        let meter_provider = opentelemetry_sdk::metrics::MeterProvider::builder()
            .with_reader(metrics_exporter)
            .build();

        TestMeter {
            meter: meter_provider.meter("carbide-api"),
            registry: prometheus_registry,
        }
    }
}
