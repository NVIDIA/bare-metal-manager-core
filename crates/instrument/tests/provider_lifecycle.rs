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

use std::process::Command;

use carbide_instrument::testing::capture_logs;
use carbide_instrument::{Event, emit, initialize_counter_series};
use opentelemetry_sdk::metrics::SdkMeterProvider;

const CHILD_PROCESS_ENV: &str = "CARBIDE_INSTRUMENT_PROVIDER_LIFECYCLE_CHILD";
const DISABLE_EAGER_TEST_METER_ENV: &str = "CARBIDE_INSTRUMENT_DISABLE_EAGER_TEST_METER";

#[derive(Event)]
#[event(
    event_name = "provider_lifecycle_counter_test",
    metric_name = "carbide_provider_lifecycle_counter_test_total",
    component = "instrument-test",
    log = warn,
    metric = counter,
    describe = "Number of provider lifecycle counter test events",
    message = "provider lifecycle counter observed",
)]
struct ProviderCounter;

#[derive(Event)]
#[event(
    event_name = "provider_lifecycle_histogram_test",
    metric_name = "carbide_provider_lifecycle_test_milliseconds",
    component = "instrument-test",
    log = off,
    metric = histogram,
    describe = "Provider lifecycle test duration",
)]
struct ProviderHistogram {
    #[observation]
    elapsed_ms: f64,
}

#[derive(Event)]
#[event(
    event_name = "provider_lifecycle_initialization_test",
    metric_name = "carbide_provider_lifecycle_initialization_test_total",
    component = "instrument-test",
    log = off,
    metric = counter,
    describe = "Number of initialized provider lifecycle test events",
)]
struct ProviderInitialization;

#[test]
fn cached_metric_handles_follow_provider_changes() {
    if std::env::var_os(CHILD_PROCESS_ENV).is_some() {
        run_provider_lifecycle_assertions();
        return;
    }

    // `carbide-instrument` normally installs its test provider in a ctor. Run
    // this contract in a new copy of the test binary so generation zero is a
    // real no-provider state rather than an ordering assumption between tests.
    let output = Command::new(std::env::current_exe().expect("current test executable"))
        .args([
            "--exact",
            "cached_metric_handles_follow_provider_changes",
            "--nocapture",
        ])
        .env(CHILD_PROCESS_ENV, "1")
        .env(DISABLE_EAGER_TEST_METER_ENV, "1")
        .output()
        .expect("run provider lifecycle test child");

    assert!(
        output.status.success(),
        "provider lifecycle child failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn run_provider_lifecycle_assertions() {
    let logs = capture_logs(|| emit(ProviderCounter));
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].message, "provider lifecycle counter observed");

    emit(ProviderHistogram { elapsed_ms: 5.0 });
    assert!(initialize_counter_series(&ProviderInitialization));
    carbide_instrument::red::record("lifecycle-test", "first", "ok", 5.0);

    let first = TestMetrics::install();
    emit(ProviderCounter);
    emit(ProviderHistogram { elapsed_ms: 12.5 });
    assert!(initialize_counter_series(&ProviderInitialization));
    carbide_instrument::red::record("lifecycle-test", "first", "ok", 20.0);

    assert_eq!(
        first.counter("carbide_provider_lifecycle_counter_test_total"),
        Some(1.0)
    );
    assert_eq!(
        first.counter("carbide_provider_lifecycle_initialization_test_total"),
        Some(0.0)
    );
    assert_eq!(
        first.histogram("carbide_provider_lifecycle_test_milliseconds"),
        Some((1, 12.5))
    );
    assert_eq!(
        first.histogram("carbide_external_call_duration_milliseconds"),
        Some((1, 20.0))
    );

    let second = TestMetrics::install();
    emit(ProviderCounter);
    emit(ProviderHistogram { elapsed_ms: 7.5 });
    assert!(initialize_counter_series(&ProviderInitialization));
    carbide_instrument::red::record("lifecycle-test", "second", "ok", 30.0);

    // Provider replacement does not replay or redirect earlier observations.
    assert_eq!(
        first.counter("carbide_provider_lifecycle_counter_test_total"),
        Some(1.0)
    );
    assert_eq!(
        first.histogram("carbide_provider_lifecycle_test_milliseconds"),
        Some((1, 12.5))
    );
    assert_eq!(
        first.histogram("carbide_external_call_duration_milliseconds"),
        Some((1, 20.0))
    );

    assert_eq!(
        second.counter("carbide_provider_lifecycle_counter_test_total"),
        Some(1.0)
    );
    assert_eq!(
        second.counter("carbide_provider_lifecycle_initialization_test_total"),
        Some(0.0)
    );
    assert_eq!(
        second.histogram("carbide_provider_lifecycle_test_milliseconds"),
        Some((1, 7.5))
    );
    assert_eq!(
        second.histogram("carbide_external_call_duration_milliseconds"),
        Some((1, 30.0))
    );
}

struct TestMetrics {
    registry: prometheus::Registry,
    _provider: SdkMeterProvider,
}

impl TestMetrics {
    fn install() -> Self {
        let registry = prometheus::Registry::new();
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .without_scope_info()
            .without_target_info()
            .build()
            .expect("test metrics exporter");
        let provider = SdkMeterProvider::builder().with_reader(exporter).build();
        carbide_instrument::set_meter_provider(provider.clone());

        Self {
            registry,
            _provider: provider,
        }
    }

    fn counter(&self, name: &str) -> Option<f64> {
        self.registry
            .gather()
            .into_iter()
            .find(|family| family.name() == name)
            .and_then(|family| {
                family
                    .get_metric()
                    .first()
                    .map(|metric| metric.get_counter().value())
            })
    }

    fn histogram(&self, name: &str) -> Option<(u64, f64)> {
        self.registry
            .gather()
            .into_iter()
            .find(|family| family.name() == name)
            .and_then(|family| {
                family.get_metric().first().map(|metric| {
                    let histogram = metric.get_histogram();
                    (histogram.get_sample_count(), histogram.get_sample_sum())
                })
            })
    }
}
