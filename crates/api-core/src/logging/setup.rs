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
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use carbide_metrics_utils::OtelView;
use opentelemetry::metrics::{Meter, MeterProvider};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_semantic_conventions as semcov;
use spancounter::SpanCountReader;
use tracing_subscriber::filter::EnvFilter;

use super::level_filter::ActiveLevel;
use super::stream::LogStream;
use crate::api::metrics::ApiMetricsEmitter;

#[derive(Debug, Clone, Default)]
pub struct Logging {
    pub filter: Arc<ActiveLevel>,
    pub tracing_enabled: Arc<AtomicBool>,
    pub spancount_reader: Option<spancounter::SpanCountReader>,
    /// Log stream used to feed the admin web UI. Only fed when the admin UI is
    /// enabled (`enable_admin_ui`); otherwise no [`LogStreamLayer`] is
    /// installed and the stream stays empty.
    pub log_stream: LogStream,
}

#[derive(Debug, Clone)]
pub struct Metrics {
    pub registry: prometheus::Registry,
    pub meter: Meter,
    // Need to retain this, if it's dropped, metrics are not held
    pub _meter_provider: SdkMeterProvider,
}

pub fn dep_log_filter(env_filter: EnvFilter) -> EnvFilter {
    const DEPS: &str = "sqlxmq::runner=warn,sqlx::query=warn,\
        sqlx::extract_query_data=warn,rustify=off,hyper=error,\
        rustls=warn,tokio_util::codec=warn,vaultrs=error,h2=warn";

    let user = env_filter.to_string();
    let combined = if user.is_empty() {
        DEPS.to_string()
    } else {
        format!("{DEPS},{user}")
    };

    EnvFilter::builder()
        .parse(&combined)
        .unwrap_or_else(|err| panic!("could not reparse combined filter '{combined}': {err}"))
}

pub fn create_metrics() -> eyre::Result<Metrics> {
    // This sets the global meter provider
    // Note: This configures metrics bucket between 5.0 and 10000.0, which are best suited
    // for tracking milliseconds
    // See https://github.com/open-telemetry/opentelemetry-rust/blob/495330f63576cfaec2d48946928f3dc3332ba058/opentelemetry-sdk/src/metrics/reader.rs#L155-L158
    use opentelemetry::KeyValue;
    let service_telemetry_attributes = opentelemetry_sdk::Resource::builder()
        .with_attributes(vec![
            KeyValue::new(semcov::resource::SERVICE_NAME, "carbide-api"),
            KeyValue::new(semcov::resource::SERVICE_NAMESPACE, "forge-system"),
        ])
        .build();
    let prometheus_registry = prometheus::Registry::new();
    let metrics_exporter = opentelemetry_prometheus::exporter()
        .with_registry(prometheus_registry.clone())
        .without_scope_info()
        .without_target_info()
        .build()?;
    let meter_provider = opentelemetry_sdk::metrics::MeterProviderBuilder::default()
        .with_reader(metrics_exporter)
        .with_resource(service_telemetry_attributes)
        .with_view(create_metric_view_for_retry_histograms("*_attempts_*")?)
        .with_view(create_metric_view_for_retry_histograms("*_retries_*")?)
        .with_view(ApiMetricsEmitter::machine_reboot_duration_view()?)
        .with_view(carbide_site_explorer::site_explorer_latency_histogram_view(
            "carbide_site_explorer_*_latency",
        )?)
        .with_view(carbide_site_explorer::site_explorer_latency_histogram_view(
            "carbide_endpoint_exploration_duration",
        )?)
        .build();
    // After this call `global::meter()` will be available
    opentelemetry::global::set_meter_provider(meter_provider.clone());
    let meter = meter_provider.meter("carbide-api");

    Ok(Metrics {
        registry: prometheus_registry,
        meter,
        _meter_provider: meter_provider,
    })
}

/// Configures a View for Histograms that describe retries or attempts for operations
/// The view reconfigures the histogram to use a small set of buckets that track
/// the exact amount of retry attempts up to 3, and 2 additional buckets up to 10.
/// This is more useful than the default histogram range where the lowest sets of
/// buckets are 0, 5, 10, 25
fn create_metric_view_for_retry_histograms(
    name_filter: &'static str,
) -> carbide_metrics_utils::Result<OtelView> {
    carbide_metrics_utils::new_view(
        name_filter,
        Some(opentelemetry_sdk::metrics::InstrumentKind::Histogram),
        opentelemetry_sdk::metrics::Aggregation::ExplicitBucketHistogram {
            boundaries: vec![0.0, 1.0, 2.0, 3.0, 5.0, 10.0],
            record_min_max: true,
        },
    )
}

pub fn create_metric_for_spancount_reader(
    meter: &Meter,
    spancount_reader: Option<SpanCountReader>,
) {
    meter
        .u64_observable_gauge("carbide_api_tracing_spans_open")
        .with_description("Number of open logging/tracing spans")
        .with_callback(move |observer| {
            let open_spans = if let Some(spancount_reader) = &spancount_reader {
                spancount_reader.open_spans()
            } else {
                0
            };
            observer.observe(open_spans as u64, &[]);
        })
        .build();
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use opentelemetry::KeyValue;
    use opentelemetry_sdk::metrics;
    use prometheus::{Encoder, TextEncoder};

    use super::*;

    /// This test mostly mimics the test setup above and checks whether
    /// the prometheus opentelemetry stack will only report the most recent
    /// values for gauges and not cached values that are not important anymore
    #[test]
    fn test_gauge_aggregation() {
        let prometheus_registry = prometheus::Registry::new();
        let metrics_exporter = opentelemetry_prometheus::exporter()
            .with_registry(prometheus_registry.clone())
            .without_scope_info()
            .without_target_info()
            .build()
            .unwrap();

        let meter_provider = metrics::MeterProviderBuilder::default()
            .with_reader(metrics_exporter)
            .with_view(create_metric_view_for_retry_histograms("*_attempts_*").unwrap())
            .with_view(create_metric_view_for_retry_histograms("*_retries_*").unwrap())
            .with_view(ApiMetricsEmitter::machine_reboot_duration_view().unwrap())
            .with_view(
                carbide_site_explorer::site_explorer_latency_histogram_view(
                    "carbide_site_explorer_*_latency",
                )
                .unwrap(),
            )
            .with_view(
                carbide_site_explorer::site_explorer_latency_histogram_view(
                    "carbide_endpoint_exploration_duration",
                )
                .unwrap(),
            )
            .build();

        let state = KeyValue::new("state", "mystate");
        let p1 = vec![state.clone(), KeyValue::new("error", "ErrA")];
        let p2 = vec![state.clone(), KeyValue::new("error", "ErrB")];
        let p3 = vec![state, KeyValue::new("error", "ErrC")];

        let counter = std::sync::Arc::new(AtomicUsize::new(0));

        meter_provider
            .meter("myservice")
            .u64_observable_gauge("mygauge")
            .with_callback(move |observer| {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                println!("Collection {count}");
                if count.is_multiple_of(2) {
                    observer.observe(1, &p1);
                } else {
                    observer.observe(1, &p2);
                }
                if count % 3 == 1 {
                    observer.observe(1, &p3);
                }
            })
            .build();

        for i in 0..10 {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = prometheus_registry.gather();
            encoder.encode(&metric_families, &mut buffer).unwrap();
            let encoded = String::from_utf8(buffer).unwrap();

            if i % 2 == 0 {
                assert!(encoded.contains(r#"mygauge{error="ErrA",state="mystate"} 1"#));
                assert!(!encoded.contains(r#"mygauge{error="ErrB",state="mystate"} 1"#));
            } else {
                assert!(encoded.contains(r#"mygauge{error="ErrB",state="mystate"} 1"#));
                assert!(!encoded.contains(r#"mygauge{error="ErrA",state="mystate"} 1"#));
            }
            if i % 3 == 1 {
                assert!(encoded.contains(r#"mygauge{error="ErrC",state="mystate"} 1"#));
            } else {
                assert!(!encoded.contains(r#"mygauge{error="ErrC",state="mystate"} 1"#));
            }
        }
    }
}
