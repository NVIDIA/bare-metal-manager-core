/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::sync::Arc;

use eyre::WrapErr;
use opentelemetry::metrics::Meter;
use opentelemetry::{metrics::MeterProvider, trace::TracerProvider};
use opentelemetry_otlp::{SpanExporterBuilder, WithExportConfig};
use opentelemetry_sdk::trace;
use opentelemetry_semantic_conventions as semcov;
use tracing_subscriber::{
    filter::EnvFilter, filter::LevelFilter, fmt, prelude::*, util::SubscriberInitExt,
};

use crate::{
    cfg::CarbideConfig,
    logging::{otel_stdout_exporter::OtelStdoutExporter, sqlx_query_tracing},
};

pub async fn setup_telemetry(
    debug: u8,
    carbide_config: Arc<CarbideConfig>,
    logging_subscriber: Option<impl SubscriberInitExt>,
) -> eyre::Result<(prometheus::Registry, Meter)> {
    // This configures the tracing framework

    // We set up some global filtering using `tracing`s `EnvFilter` framework
    // The global filter will apply to all `Layer`s that are added to the
    // `logging_subscriber` later on. This means it applies for both logging to
    // stdout as well as for OpenTelemetry integration.
    // We ignore a lot of spans and events from 3rd party frameworks
    let mut global_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    if debug != 0 {
        global_filter = global_filter.add_directive(
            match debug {
                1 => {
                    // command line overrides config file
                    LevelFilter::DEBUG
                }
                _ => LevelFilter::TRACE,
            }
            .into(),
        );
    }
    global_filter = global_filter
        .add_directive("sqlxmq::runner=warn".parse()?)
        .add_directive("sqlx::query=warn".parse()?)
        .add_directive("sqlx::extract_query_data=warn".parse()?)
        .add_directive("rustify=off".parse()?)
        .add_directive("hyper=error".parse()?)
        .add_directive("rustls=warn".parse()?)
        .add_directive("tokio_util::codec=warn".parse()?)
        .add_directive("vaultrs=error".parse()?)
        .add_directive("h2=warn".parse()?);

    // This defines attributes that are set on the exported logs **and** metrics
    let service_telemetry_attributes = opentelemetry_sdk::Resource::new(vec![
        semcov::resource::SERVICE_NAME.string("carbide-api"),
        semcov::resource::SERVICE_NAMESPACE.string("forge-system"),
    ]);

    // Set up an OpenTelemetry tracer with an exporter to either StdOut only
    // or to StdOut and a OTLP endpoint - depending on the config
    //
    // Note: This doesn't yet make any logs get pushed to the OpenTelemetry library
    // The binding happens later once we initialize tracing_opentelemetry and configure
    // it to forward log events from the `tracing` framework.
    // The application internally only uses `tracing` events.
    let tracer: opentelemetry_sdk::trace::Tracer = {
        use opentelemetry_sdk::trace::TracerProvider as SdkTracerProvider;

        let trace_config =
            opentelemetry_sdk::trace::config().with_resource(service_telemetry_attributes.clone());
        let mut provider_builder = SdkTracerProvider::builder().with_config(trace_config);

        // Always export to stdout
        let stdout_exporter = OtelStdoutExporter::new(std::io::stdout());
        provider_builder = provider_builder.with_simple_exporter(stdout_exporter);

        // If OTEL is configured, also export there
        // Note that .with_simple_exporter, .with_batch_exporter and .with_span_processor
        // can be multiple times. And each call will add an additional log link
        if let Some(otel_endpoint) = &carbide_config.as_ref().otlp_endpoint {
            tracing::info!(
                "Starting OTLP tracer. Sending tracing data to: {}",
                otel_endpoint
            );
            let tonic_exporter_builder = opentelemetry_otlp::new_exporter()
                .tonic()
                .with_endpoint(otel_endpoint);
            let tonic_exporter =
                SpanExporterBuilder::from(tonic_exporter_builder).build_span_exporter()?;
            let batch_processor = trace::BatchSpanProcessor::builder(
                tonic_exporter,
                opentelemetry_sdk::runtime::Tokio,
            )
            .build();
            provider_builder = provider_builder.with_span_processor(batch_processor);
        }

        let provider = provider_builder.build();
        let tracer = provider.tracer("carbide-api");
        let _ = opentelemetry::global::set_tracer_provider(provider);
        tracer
    };

    // tracing-opentelemetry integration
    // This will lead to tracing events being forwarded into the specified `tracer`.
    // A `tracing` `span` will create an opentelemetry span, and tracing `event`s (like `info!`)
    // will create OTEL events.
    let opentelemetry_layer = tracing_opentelemetry::layer()
        .with_error_fields_to_exceptions(true)
        .with_threads(false)
        .with_tracer(tracer);

    let logfmt_er = utils::logfmt::LogFmtFormatter {};
    let stdout_formatter = fmt::Layer::default()
        .with_ansi(false)
        .event_format(logfmt_er);

    if let Some(logging_subscriber) = logging_subscriber {
        logging_subscriber
            .try_init()
            .wrap_err("logging_subscriber.try_init()")?;
    } else {
        // Start tokio-console server. Returns a tracing-subscriber Layer.
        let tokio_console_layer = console_subscriber::ConsoleLayer::builder()
            .with_default_env()
            .server_addr(([0, 0, 0, 0], console_subscriber::Server::DEFAULT_PORT))
            .spawn();
        // tokio-console wants "runtime=trace,tokio=trace"
        let tokio_console_filter = tracing_subscriber::filter::Targets::new()
            .with_default(LevelFilter::ERROR)
            .with_target("runtime", LevelFilter::TRACE)
            .with_target("tokio", LevelFilter::TRACE);

        let global_filter_clone = EnvFilter::from(&global_filter.to_string());

        // Set up the tracing subscriber
        tracing_subscriber::registry()
            .with(stdout_formatter.with_filter(global_filter))
            .with(opentelemetry_layer.with_filter(global_filter_clone))
            .with(tokio_console_layer.with_filter(tokio_console_filter))
            .with(sqlx_query_tracing::create_sqlx_query_tracing_layer())
            .try_init()
            .wrap_err("new tracing subscriber try_init()")?;
    };

    // This sets the global meter provider
    // Note: This configures metrics bucket between 5.0 and 10000.0, which are best suited
    // for tracking milliseconds
    // See https://github.com/open-telemetry/opentelemetry-rust/blob/495330f63576cfaec2d48946928f3dc3332ba058/opentelemetry-sdk/src/metrics/reader.rs#L155-L158
    let prometheus_registry = prometheus::Registry::new();
    let metrics_exporter = opentelemetry_prometheus::exporter()
        .with_registry(prometheus_registry.clone())
        .without_scope_info()
        .without_target_info()
        .build()?;
    let meter_provider = opentelemetry_sdk::metrics::MeterProvider::builder()
        .with_reader(metrics_exporter)
        .with_resource(service_telemetry_attributes)
        .with_view(create_metric_view_for_retry_histograms("*_attempts_*")?)
        .with_view(create_metric_view_for_retry_histograms("*_retries_*")?)
        .build();
    // After this call `global::meter()` will be available
    opentelemetry::global::set_meter_provider(meter_provider.clone());

    let meter = meter_provider.meter("carbide-api");
    Ok((prometheus_registry, meter))
}

/// Configures a View for Histograms that describe retries or attempts for operations
/// The view reconfigures the histogram to use a small set of buckets that track
/// the exact amount of retry attempts up to 3, and 2 additional buckets up to 10.
/// This is more useful than the default histogram range where the lowest sets of
/// buckets are 0, 5, 10, 25
fn create_metric_view_for_retry_histograms(
    name_filter: &str,
) -> Result<Box<dyn opentelemetry_sdk::metrics::View>, opentelemetry::metrics::MetricsError> {
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

        let meter_provider = metrics::MeterProvider::builder()
            .with_reader(metrics_exporter)
            .with_view(create_metric_view_for_retry_histograms("*_attempts_*").unwrap())
            .with_view(create_metric_view_for_retry_histograms("*_retries_*").unwrap())
            .build();

        let meter = meter_provider.meter("myservice");
        let x = meter.u64_observable_gauge("mygauge").init();

        let state = KeyValue::new("state", "mystate");
        let p1 = vec![state.clone(), KeyValue::new("error", "ErrA")];
        let p2 = vec![state.clone(), KeyValue::new("error", "ErrB")];
        let p3 = vec![state.clone(), KeyValue::new("error", "ErrC")];

        let counter = Arc::new(AtomicUsize::new(0));

        meter
            .register_callback(&[x.as_any()], move |observer| {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                println!("Collection {}", count);
                if count % 2 == 0 {
                    observer.observe_u64(&x, 1, &p1);
                } else {
                    observer.observe_u64(&x, 1, &p2);
                }
                if count % 3 == 1 {
                    observer.observe_u64(&x, 1, &p3);
                }
            })
            .unwrap();

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
