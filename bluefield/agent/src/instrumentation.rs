use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::routing::get;
use axum::Router;
use http_body::combinators::UnsyncBoxBody;
use hyper::{Body, Request, Response};
use opentelemetry::metrics::{Counter, Histogram, Meter, Unit};
use tower::ServiceBuilder;
use tracing::Span;

use prometheus::{Encoder, TextEncoder};

pub struct MetricsState {
    http_counter: Counter<u64>,
    http_req_latency_histogram: Histogram<f64>,
}

pub fn create_metrics(meter: Meter) -> Arc<MetricsState> {
    let http_counter = meter
        .u64_counter("http_requests_total")
        .with_description("Total number of HTTP requests made.")
        .init();
    let http_req_latency_histogram = meter
        .f64_histogram("request_latency")
        .with_description("HTTP request latency")
        .with_unit(Unit::new("ms"))
        .init();

    Arc::new(MetricsState {
        http_counter,
        http_req_latency_histogram,
    })
}

pub fn get_metrics_router(registry: prometheus::Registry) -> Router {
    Router::new()
        .route("/", get(export_metrics))
        .with_state(registry)
}

async fn export_metrics(State(registry): State<prometheus::Registry>) -> Response<Body> {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = registry.gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .header(CONTENT_LENGTH, buffer.len())
        .body(Body::from(buffer))
        .unwrap()
}
pub trait WithTracingLayer {
    fn with_tracing_layer(self, metrics: Arc<MetricsState>) -> Router;
}

impl WithTracingLayer for Router {
    fn with_tracing_layer(self, metrics: Arc<MetricsState>) -> Router {
        let metrics_copy = metrics.clone();
        let layer = tower_http::trace::TraceLayer::new_for_http()
            .on_request(move |request: &Request<Body>, _span: &Span| {
                metrics.http_counter.add(1, &[]);
                tracing::info!("started {} {}", request.method(), request.uri().path())
            })
            .on_response(
                move |_response: &Response<
                    UnsyncBoxBody<opentelemetry_http::Bytes, axum::Error>,
                >,
                      latency: Duration,
                      _span: &Span| {
                    // TODO revisit time units
                    metrics_copy
                        .http_req_latency_histogram
                        .record(latency.as_secs_f64() * 1000.0, &[]);

                    tracing::info!("response generated in {:?}", latency)
                },
            );

        self.layer(ServiceBuilder::new().layer(layer))
    }
}
