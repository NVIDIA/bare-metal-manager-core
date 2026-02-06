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

use model::machine_validation::MachineValidationTest;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Meter;

use crate::logging::metrics_utils::SharedMetricsHolder;

#[derive(Clone, Debug)]
pub struct MachineValidationMetrics {
    pub completed_validation: usize,
    pub failed_validation: usize,
    pub in_progress_validation: usize,
    pub tests: Vec<MachineValidationTest>,
}

impl MachineValidationMetrics {
    pub fn new() -> Self {
        Self {
            completed_validation: 0,
            failed_validation: 0,
            in_progress_validation: 0,
            tests: Vec::new(),
        }
    }
}
fn hydrate_meter(meter: Meter, shared_metrics: SharedMetricsHolder<MachineValidationMetrics>) {
    {
        let metrics = shared_metrics.clone();
        meter
            .u64_observable_gauge("carbide_machine_validation_completed")
            .with_description("Count of machine validation that have completed successfully")
            .with_callback(move |observer| {
                metrics.if_available(|metrics, attrs| {
                    observer.observe(metrics.completed_validation as u64, attrs);
                });
            })
            .build();
    }

    {
        let metrics = shared_metrics.clone();
        meter
            .u64_observable_gauge("carbide_machine_validation_failed")
            .with_description("Count of machine validation that have failed")
            .with_callback(move |observer| {
                metrics.if_available(|metrics, attrs| {
                    observer.observe(metrics.failed_validation as u64, attrs);
                });
            })
            .build();
    }

    {
        let metrics = shared_metrics.clone();
        meter
            .u64_observable_gauge("carbide_machine_validation_in_progress")
            .with_description("Count of machine validation that are in progress")
            .with_callback(move |observer| {
                metrics.if_available(|metrics, attrs| {
                    observer.observe(metrics.in_progress_validation as u64, attrs);
                });
            })
            .build();
    }
    {
        let metrics = shared_metrics;
        meter
            .u64_observable_gauge("carbide_machine_validation_tests")
            .with_description("The details of machine validation tests")
            .with_callback(move |observer| {
                metrics.if_available(|metrics, attrs| {
                    for test in metrics.tests.iter() {
                        observer.observe(
                            if test.is_enabled { 1 } else { 0 },
                            &[
                                attrs,
                                &[
                                    KeyValue::new("TestId", test.test_id.clone()),
                                    KeyValue::new("isVerified", test.verified),
                                ],
                            ]
                            .concat(),
                        );
                    }
                });
            })
            .build();
    }
}

pub struct MetricHolder {
    last_iteration_metrics: SharedMetricsHolder<MachineValidationMetrics>,
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
    pub fn update_metrics(&self, metrics: MachineValidationMetrics) {
        self.last_iteration_metrics.update(metrics);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use chrono::Utc;
    use config_version::ConfigVersion;
    use prometheus_text_parser::ParsedPrometheusMetrics;

    use super::*;
    use crate::machine_validation::metrics::MachineValidationMetrics;
    use crate::tests::common::test_meter::TestMeter;

    #[test]
    fn test_metrics_collector() {
        let mut metrics = MachineValidationMetrics::new();
        metrics.completed_validation = 10;
        metrics.failed_validation = 15;
        metrics.in_progress_validation = 20;
        metrics.tests = vec![MachineValidationTest {
            test_id: "forge_Test1".to_string(),
            name: "test1".to_string(),
            description: Some("description".to_string()),
            contexts: vec!["OnDemand".to_string(), "Discovery".to_string()],
            img_name: None,
            execute_in_host: Some(false),
            container_arg: None,
            command: "".to_string(),
            args: "".to_string(),
            extra_output_file: None,
            extra_err_file: None,
            external_config_file: None,
            pre_condition: None,
            timeout: None,
            version: ConfigVersion::initial(),
            supported_platforms: vec![],
            modified_by: "User".to_string(),
            verified: true,
            read_only: false,
            custom_tags: None,
            components: vec![],
            last_modified_at: Utc::now(),
            is_enabled: true,
        }];
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
