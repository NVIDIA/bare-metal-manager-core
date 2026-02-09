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
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, body};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Meter, MeterProvider};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_semantic_conventions as semconv;
use prometheus::{Encoder, TextEncoder};
use tokio::net::TcpListener;

/// Health and readiness controller
#[derive(Debug, Clone)]
pub struct HealthController {
    ready: Arc<AtomicBool>,
    healthy: Arc<AtomicBool>,
}

impl Default for HealthController {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthController {
    pub fn new() -> Self {
        // Ready and healthy by default
        Self {
            ready: Arc::new(AtomicBool::new(true)),
            healthy: Arc::new(AtomicBool::new(true)),
        }
    }

    pub fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Relaxed);
    }

    pub fn set_healthy(&self, healthy: bool) {
        self.healthy.store(healthy, Ordering::Relaxed);
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Relaxed)
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone)]
pub struct MetricsSetup {
    pub registry: prometheus::Registry,
    pub meter: Meter,
    // Need to retain this, if it's dropped, metrics are not held
    pub meter_provider: SdkMeterProvider,
    pub health_controller: HealthController,
}

/// The shared state between HTTP requests
struct MetricsHandlerState {
    registry: prometheus::Registry,
    health_controller: HealthController,
}

/// Configuration for the metrics endpoint
pub struct MetricsEndpointConfig {
    pub address: SocketAddr,
    pub registry: prometheus::Registry,
    pub health_controller: Option<HealthController>,
}

pub fn new_metrics_setup(
    service_name: &'static str,
    service_namespace: &'static str,
    set_global_meter: bool,
) -> eyre::Result<MetricsSetup> {
    // This defines attributes that are set on the exported metrics
    let service_telemetry_attributes = opentelemetry_sdk::Resource::builder()
        .with_attributes(vec![
            KeyValue::new(semconv::resource::SERVICE_NAME, service_name),
            KeyValue::new(semconv::resource::SERVICE_NAMESPACE, service_namespace),
        ])
        .build();

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

    if set_global_meter {
        // After this call `global::meter()` will be available
        opentelemetry::global::set_meter_provider(meter_provider.clone());
    }

    Ok(MetricsSetup {
        registry: prometheus_registry,
        meter: meter_provider.meter(service_name),
        meter_provider,
        health_controller: HealthController::new(),
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

/// Start a HTTP endpoint which exposes metrics using the provided configuration
pub async fn run_metrics_endpoint(config: &MetricsEndpointConfig) -> Result<(), std::io::Error> {
    let handler_state = Arc::new(MetricsHandlerState {
        registry: config.registry.clone(),
        health_controller: config.health_controller.clone().unwrap_or_default(),
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
                        let handler_state = handler_state.clone();
                        async move { handle_metrics_request(req, handler_state) }
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
fn handle_metrics_request(
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
        (&Method::GET, "/health") if state.health_controller.is_healthy() => Response::builder()
            .status(200)
            .body(Full::new(Bytes::from("Healthy")))
            .unwrap(),
        (&Method::GET, "/health") => Response::builder()
            .status(503)
            .body(Full::new(Bytes::from("Unhealthy")))
            .unwrap(),
        (&Method::GET, "/ready") if state.health_controller.is_ready() => Response::builder()
            .status(200)
            .body(Full::new(Bytes::from("Ready")))
            .unwrap(),
        (&Method::GET, "/ready") => Response::builder()
            .status(503)
            .body(Full::new(Bytes::from("Unavailable")))
            .unwrap(),
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
        let p3 = vec![state, KeyValue::new("error", "ErrC")];

        let counter = Arc::new(AtomicUsize::new(0));

        meter
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

    #[test]
    fn test_health_controller_state_changes() {
        let controller = HealthController::new();

        // Defaults are true
        assert!(controller.is_ready());
        assert!(controller.is_healthy());

        controller.set_ready(false);
        assert!(!controller.is_ready());

        controller.set_healthy(false);
        assert!(!controller.is_healthy());
        assert!(!controller.is_ready());

        controller.set_ready(true);
        controller.set_healthy(true);
        assert!(controller.is_ready());
        assert!(controller.is_healthy());
    }
}
