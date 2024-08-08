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
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server};
use opentelemetry::metrics::{Meter, MeterProvider};
use opentelemetry_semantic_conventions as semconv;
use prometheus::{Encoder, TextEncoder};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct MetricsSetup {
    pub registry: prometheus::Registry,
    pub meter: Meter,
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
    service_name: &str,
    service_namespace: &str,
) -> eyre::Result<MetricsSetup> {
    // This defines attributes that are set on the exported metrics
    let service_telemetry_attributes = opentelemetry_sdk::Resource::new(vec![
        semconv::resource::SERVICE_NAME.string(service_name.to_string()),
        semconv::resource::SERVICE_NAMESPACE.string(service_namespace.to_string()),
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
    let meter_provider = opentelemetry_sdk::metrics::MeterProvider::builder()
        .with_reader(metrics_exporter)
        .with_resource(service_telemetry_attributes)
        .with_view(create_metric_view_for_retry_histograms("*_attempts_*")?)
        .with_view(create_metric_view_for_retry_histograms("*_retries_*")?)
        .build();
    // After this call `global::meter()` will be available
    opentelemetry::global::set_meter_provider(meter_provider.clone());

    Ok(MetricsSetup {
        registry: prometheus_registry,
        meter: meter_provider.meter(service_name.to_string()),
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
pub async fn run_metrics_endpoint(config: &MetricsEndpointConfig) -> Result<(), hyper::Error> {
    let handler_state = Arc::new(MetricsHandlerState {
        registry: config.registry.clone(),
    });

    // `connection_handler` defines the closure that will be called at the start of every TCP connection attempt to this server.
    // There can be multiple requests on the same connection
    let connection_handler = make_service_fn(move |_conn| {
        let handler_state = handler_state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                // this is the function that will be called for every request on the connection
                handle_metrics_request(req, handler_state.clone())
            }))
        }
    });

    tracing::info!(
        address = config.address.to_string(),
        "Starting metrics listener"
    );

    // TODO: We need timeouts for this listener
    let server = Server::bind(&config.address).serve(connection_handler);
    // This will block until the server is shut down
    server.await?;

    Ok(())
}

/// Metrics request handler
async fn handle_metrics_request(
    req: Request<Body>,
    state: Arc<MetricsHandlerState>,
) -> Result<Response<Body>, hyper::Error> {
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
                .body(Body::from(buffer))
                .unwrap()
        }
        (&Method::GET, "/") => Response::builder()
            .status(200)
            .body(Body::from(
                "Metrics are exposed via /metrics. There is nothing else to see here",
            ))
            .unwrap(),
        _ => Response::builder()
            .status(404)
            .body(Body::from("Invalid URL"))
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

        let counter = std::sync::Arc::new(AtomicUsize::new(0));

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
