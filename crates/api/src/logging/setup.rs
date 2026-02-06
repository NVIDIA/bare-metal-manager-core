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
use std::fmt::Debug;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use eyre::WrapErr;
use opentelemetry::metrics::{Meter, MeterProvider};
use opentelemetry::trace::{Link, SamplingDecision, SamplingResult, SpanKind, TracerProvider};
use opentelemetry::{Context, KeyValue, TraceId, Value};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::trace::{Sampler, ShouldSample};
use opentelemetry_semantic_conventions as semcov;
use spancounter::SpanCountReader;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::prelude::*;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{Layer, filter, reload};

use super::level_filter::ActiveLevel;
use crate::logging::level_filter::ReloadableFilter;
use crate::logging::sqlx_query_tracing;

#[derive(Debug, Clone, Default)]
pub struct Logging {
    pub filter: Arc<ActiveLevel>,
    pub tracing_enabled: Arc<AtomicBool>,
    pub spancount_reader: Option<spancounter::SpanCountReader>,
}

#[derive(Debug, Clone)]
pub struct Metrics {
    pub registry: prometheus::Registry,
    pub meter: Meter,
    // Need to retain this, if it's dropped, metrics are not held
    pub _meter_provider: SdkMeterProvider,
}

pub fn dep_log_filter(env_filter: EnvFilter) -> EnvFilter {
    [
        "sqlxmq::runner=warn",
        "sqlx::query=warn",
        "sqlx::extract_query_data=warn",
        "rustify=off",
        "hyper=error",
        "rustls=warn",
        "tokio_util::codec=warn",
        "vaultrs=error",
        "h2=warn",
    ]
    .iter()
    .fold(env_filter, |f, filter_str| {
        f.add_directive(
            filter_str
                .parse()
                .unwrap_or_else(|err| panic!("{filter_str} must be parsed; error: {err}")),
        )
    })
}

pub fn setup_logging(
    debug: u8,
    extra_logfmt_event_fields: Vec<String>,
    override_logging_subscriber: Option<impl SubscriberInitExt>,
) -> eyre::Result<Logging> {
    // This configures emission of logs in LogFmt syntax
    // and emission of metrics
    let log_level = match debug {
        0 => LevelFilter::INFO,
        1 => {
            // command line overrides config file
            LevelFilter::DEBUG
        }
        _ => LevelFilter::TRACE,
    };

    // We set up some global filtering using `tracing`s `EnvFilter` framework
    // The global filter will apply to all `Layer`s that are added to the
    // `logging_subscriber` later on. This means it applies for both logging to
    // stdout as well as for OpenTelemetry integration.
    // We ignore a lot of spans and events from 3rd party frameworks
    let initial_log_filter = EnvFilter::builder()
        .with_default_directive(log_level.into())
        .from_env()?;
    let initial_log_filter = dep_log_filter(initial_log_filter);

    let (logfmt_stdout_filter, logfmt_stdout_reload_handle) =
        reload::Layer::new(initial_log_filter.clone());
    let logfmt_stdout_formatter = logfmt::layer().with_event_fields(extra_logfmt_event_fields);
    let spancount_layer = spancounter::layer();
    let spancount_reader = spancount_layer.reader();

    // == Dynamic filter for tracing enabled/disabled ==
    // This doesn't track levels but instead just enabled/disabled (when we want tracing enabled, we
    // typically want a high level of verbosity.) Enabled by default if debug is enabled.
    let tracing_enabled = Arc::new(AtomicBool::new(debug == 1));
    let trace_sampler = CarbideSpanSampler::new(tracing_enabled.clone());
    let trace_filter =
        filter::filter_fn(should_accept_span_or_event).with_max_level_hint(log_level);

    if let Some(logging_subscriber) = override_logging_subscriber {
        logging_subscriber
            .try_init()
            .wrap_err("logging_subscriber.try_init()")?;
    } else {
        let maybe_otel_tracing_layer =
            match std::env::var(opentelemetry_otlp::OTEL_EXPORTER_OTLP_TRACES_ENDPOINT) {
                Err(_) => None,
                Ok(_) => {
                    // Exporter reads from OTEL_EXPORTER_OTLP_TRACES_ENDPOINT env var for endpoint
                    let otlp_exporter = opentelemetry_otlp::SpanExporter::builder()
                        .with_tonic()
                        .with_protocol(opentelemetry_otlp::Protocol::Grpc)
                        .build()?;

                    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                        // CarbideSpanSampler selects spans that begin from our crate
                        .with_sampler(trace_sampler.into_sampler())
                        .with_batch_exporter(otlp_exporter)
                        .with_resource(
                            Resource::builder()
                                .with_attributes([KeyValue::new("service.name", "carbide-api")])
                                .build(),
                        )
                        .build();
                    Some(
                        tracing_opentelemetry::layer()
                            .with_tracer(tracer_provider.tracer("carbide"))
                            .with_filter(trace_filter),
                    )
                }
            };

        tracing_subscriber::registry()
            .with(spancount_layer.with_filter(log_level))
            .with(maybe_otel_tracing_layer)
            .with(logfmt_stdout_formatter.with_filter(logfmt_stdout_filter))
            .with(sqlx_query_tracing::create_sqlx_query_tracing_layer())
            .try_init()
            .wrap_err("new tracing subscriber try_init()")?;
    };

    if LevelFilter::current() != log_level {
        Err(eyre::eyre!(
            "not expected current log level {} when expected: {log_level}",
            LevelFilter::current()
        ))
    } else {
        tracing::info!("current log level: {}", LevelFilter::current());
        Ok(Logging {
            filter: ActiveLevel::new(
                initial_log_filter,
                Some(Box::new(ReloadableFilter::new(logfmt_stdout_reload_handle))),
            )
            .into(),
            tracing_enabled,
            spancount_reader: Some(spancount_reader),
        })
    }
}

pub fn create_metrics() -> Result<Metrics, opentelemetry_sdk::metrics::MetricError> {
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
    name_filter: &str,
) -> Result<Box<dyn opentelemetry_sdk::metrics::View>, opentelemetry_sdk::metrics::MetricError> {
    let mut criteria = opentelemetry_sdk::metrics::Instrument::new().name(name_filter.to_string());
    criteria.kind = Some(opentelemetry_sdk::metrics::InstrumentKind::Histogram);
    let mask = opentelemetry_sdk::metrics::Stream::new().aggregation(
        opentelemetry_sdk::metrics::Aggregation::ExplicitBucketHistogram {
            boundaries: vec![0.0, 1.0, 2.0, 3.0, 5.0, 10.0],
            record_min_max: true,
        },
    );
    opentelemetry_sdk::metrics::new_view(criteria, mask)
}

#[derive(Debug, Clone)]
struct CarbideSpanSampler(Arc<AtomicBool>);

impl CarbideSpanSampler {
    fn new(enabled: Arc<AtomicBool>) -> Self {
        Self(enabled)
    }

    /// Construct a new Sampler that samples spans originating from the carbide crate
    fn into_sampler(self) -> Sampler {
        Sampler::ParentBased(Box::new(self))
    }
}

/// Predicate to check if a child span or event should be accepted. This is distinct from
/// CarbideSpanSampler, which chooses which *root* spans to accept (ie. just ours). This predicate
/// checks if any span or event should be accepted, even within a root span.
///
/// Currently discards tokio spans: tokio seems to have an issue where it creates spans without
/// closing them, which results in us running out of memory quickly.
fn should_accept_span_or_event(metadata: &tracing::Metadata<'_>) -> bool {
    let is_tokio = metadata
        .module_path()
        .is_some_and(|p| p.starts_with("tokio"));

    !is_tokio
}

impl ShouldSample for CarbideSpanSampler {
    fn should_sample(
        &self,
        _parent_context: Option<&Context>,
        _trace_id: TraceId,
        _name: &str,
        _span_kind: &SpanKind,
        attributes: &[KeyValue],
        _links: &[Link],
    ) -> SamplingResult {
        let enabled = self.0.load(Ordering::Relaxed);

        // We want this to short-circuit if enabled is false, because we want to skip iterating
        // through all attributes. (This could be a simple && expression but it should be really
        // clear from reading the code here.)
        let should_sample = if !enabled {
            false
        } else {
            attributes
                .iter()
                .find(|kv| kv.key.as_str() == "code.namespace")
                .and_then(|v| match &v.value {
                    Value::String(str) => Some(str.as_str()),
                    _ => None,
                })
                .is_some_and(|s| s.starts_with("carbide::"))
        };

        SamplingResult {
            decision: if should_sample {
                SamplingDecision::RecordAndSample
            } else {
                SamplingDecision::Drop
            },
            attributes: vec![],
            trace_state: Default::default(),
        }
    }
}

pub fn create_metric_for_spancount_reader(
    meter: &Meter,
    spancount_reader: Option<SpanCountReader>,
) {
    meter
        .u64_observable_gauge("carbide_api_tracing_spans_open")
        .with_description("Whether the Forge Site Controller API is running")
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
