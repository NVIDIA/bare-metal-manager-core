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
use std::{net::SocketAddr, sync::Arc};

use bytes::Bytes;
use http_body_util::Full;
use hyper::{
    body,
    header::{CONTENT_LENGTH, CONTENT_TYPE},
    service::service_fn,
    Method, Request, Response,
};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
};
use opentelemetry::{
    metrics::{Meter, MeterProvider},
    KeyValue,
};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_semantic_conventions as semconv;
use prometheus::{Encoder, TextEncoder};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
pub struct MetricsSetup {
    pub registry: prometheus::Registry,
    pub meter: Meter,
    // Need to retain this, if it's dropped, metrics are not held
    pub meter_provider: SdkMeterProvider,
}

/// The shared state between HTTP requests
struct MetricsHandlerState {
    registry: prometheus::Registry,
}

/// Configuration for the metrics endpoint
pub struct MetricsEndpointConfig {
    pub address: SocketAddr,
    pub registry: prometheus::Registry,
}

pub fn new_metrics_setup(
    service_name: &'static str,
    service_namespace: &'static str,
) -> eyre::Result<MetricsSetup> {
    // This defines attributes that are set on the exported metrics
    let service_telemetry_attributes = opentelemetry_sdk::Resource::new(vec![
        KeyValue::new(semconv::resource::SERVICE_NAME, service_name),
        KeyValue::new(semconv::resource::SERVICE_NAMESPACE, service_namespace),
    ]);

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
    let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
        .with_reader(metrics_exporter)
        .with_resource(service_telemetry_attributes)
        .with_view(create_metric_view_for_retry_histograms("*_attempts_*")?)
        .with_view(create_metric_view_for_retry_histograms("*_retries_*")?)
        .build();
    // After this call `global::meter()` will be available
    opentelemetry::global::set_meter_provider(meter_provider.clone());

    Ok(MetricsSetup {
        registry: prometheus_registry,
        meter: meter_provider.meter(service_name),
        meter_provider,
    })
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

/// Start a HTTP endpoint which exposes metrics using the provided configuration
pub async fn run_metrics_endpoint(config: &MetricsEndpointConfig) -> Result<(), std::io::Error> {
    let handler_state = Arc::new(MetricsHandlerState {
        registry: config.registry.clone(),
    });

    let listener = TcpListener::bind(&config.address).await?;

    tracing::info!(
        address = config.address.to_string(),
        "Starting metrics listener"
    );

    loop {
        let (stream, _) = listener.accept().await?;

        let io = TokioIo::new(stream);

        let handler_state = handler_state.clone();

        tokio::task::spawn(async move {
            let handler_state = handler_state.clone();
            if let Err(err) = Builder::new(TokioExecutor::new())
                .serve_connection(
                    io,
                    service_fn(move |req: Request<body::Incoming>| {
                        handle_metrics_request(req, handler_state.clone())
                    }),
                )
                .await
            {
                tracing::warn!(error = err, "Error serving connection for metrics listener");
            }
        });
    }
}

/// Metrics request handler
async fn handle_metrics_request(
    req: Request<body::Incoming>,
    state: Arc<MetricsHandlerState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = state.registry.gather();
            encoder.encode(&metric_families, &mut buffer).unwrap();

            Response::builder()
                .status(200)
                .header(CONTENT_TYPE, encoder.format_type())
                .header(CONTENT_LENGTH, buffer.len())
                .body(Full::new(Bytes::from(buffer)))
                .unwrap()
        }
        (&Method::GET, "/") => Response::builder()
            .status(200)
            .body(Full::new(Bytes::from(
                "Metrics are exposed via /metrics. There is nothing else to see here",
            )))
            .unwrap(),
        _ => Response::builder()
            .status(404)
            .body(Full::new(Bytes::from("Invalid URL")))
            .unwrap(),
    };

    Ok(response)
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

        let meter = meter_provider.meter("myservice");

        let state = KeyValue::new("state", "mystate");
        let p1 = vec![state.clone(), KeyValue::new("error", "ErrA")];
        let p2 = vec![state.clone(), KeyValue::new("error", "ErrB")];
        let p3 = vec![state.clone(), KeyValue::new("error", "ErrC")];

        let counter = Arc::new(AtomicUsize::new(0));

        meter
            .u64_observable_gauge("mygauge")
            .with_callback(move |observer| {
                let count = counter.fetch_add(1, Ordering::SeqCst);
                println!("Collection {}", count);
                if count % 2 == 0 {
                    observer.observe(1, &p1);
                } else {
                    observer.observe(1, &p2);
                }
                if count % 3 == 1 {
                    observer.observe(1, &p3);
                }
            })
            .init();

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
