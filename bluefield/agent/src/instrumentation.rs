use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::routing::get;
use axum::Router;
use http_body::combinators::UnsyncBoxBody;
use hyper::{Body, Request, Response};
use opentelemetry::metrics::{Counter, Histogram, Meter, Unit};
use opentelemetry::Context;
use opentelemetry_prometheus::PrometheusExporter;
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
        .with_unit(Unit::new("s"))
        .init();

    Arc::new(MetricsState {
        http_counter,
        http_req_latency_histogram,
    })
}

pub fn get_metrics_router(exporter: Arc<PrometheusExporter>) -> Router {
    Router::new()
        .route("/", get(export_metrics))
        .with_state(exporter)
}

async fn export_metrics(State(exporter): State<Arc<PrometheusExporter>>) -> Response<Body> {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = exporter.registry().gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    Response::builder()
        .status(200)
        .header(CONTENT_TYPE, encoder.format_type())
        .header(CONTENT_LENGTH, buffer.len())
        .body(Body::from(buffer))
        .unwrap()
}
pub trait WithTracingLayer {
    fn with_tracing_layer(self, metrics: Arc<MetricsState>, context: Context) -> Router;
}

impl WithTracingLayer for Router {
    fn with_tracing_layer(self, metrics: Arc<MetricsState>, context: Context) -> Router {
        let metrics_copy = metrics.clone();
        let context_copy = context.clone();
        let layer = tower_http::trace::TraceLayer::new_for_http()
            .on_request(move |request: &Request<Body>, _span: &Span| {
                metrics.http_counter.add(&context, 1, &[]);
                tracing::info!("started {} {}", request.method(), request.uri().path())
            })
            .on_response(
                move |_response: &Response<
                    UnsyncBoxBody<opentelemetry_http::Bytes, axum::Error>,
                >,
                      latency: Duration,
                      _span: &Span| {
                    // TODO revisit time units
                    metrics_copy.http_req_latency_histogram.record(
                        &context_copy,
                        latency.as_secs_f64(),
                        &[],
                    );

                    tracing::info!("response generated in {:?}", latency)
                },
            );

        self.layer(ServiceBuilder::new().layer(layer))
    }
}
