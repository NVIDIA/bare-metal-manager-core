// use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::routing::get;
use axum::Router;
use http_body::combinators::UnsyncBoxBody;
use hyper::{Body, Request, Response};
use opentelemetry::metrics::{Counter, Histogram, Meter, Unit};
use opentelemetry::KeyValue;
use tower::ServiceBuilder;
use tracing::Span;

use prometheus::{Encoder, TextEncoder};

pub struct MetricsState {
    http_counter: Counter<u64>,
    http_req_latency_histogram: Histogram<f64>,
    network_reachable: Histogram<u64>,
    network_latency: Histogram<f64>,
    network_loss_percent: Histogram<f64>,
}

impl MetricsState {
    pub fn record_metrics(
        &self,
        machine_id: String,
        dpu_id: String,
        duration: Option<Duration>,
        reachable: bool,
        loss_percent: f64,
    ) {
        // @TODO(Felicity): Reduce number of metrics getting eliminated
        let attributes = [
            KeyValue::new("source_dpu_id", machine_id),
            KeyValue::new("dest_dpu_id", dpu_id),
        ];
        let reachability = if reachable { 1 } else { 0 };

        if let Some(latency) = duration {
            self.network_latency
                .record(latency.as_secs_f64(), &attributes);
        }
        self.network_reachable.record(reachability, &attributes);
        self.network_loss_percent.record(loss_percent, &attributes);
    }
}

pub fn create_metrics(meter: Meter) -> Arc<MetricsState> {
    let http_counter = meter
        .u64_counter("http_requests")
        .with_description("Total number of HTTP requests made.")
        .init();
    let http_req_latency_histogram: Histogram<f64> = meter
        .f64_histogram("request_latency")
        .with_description("HTTP request latency")
        .with_unit(Unit::new("ms"))
        .init();

    let network_reachable = meter
        .u64_histogram("network_reachable")
        .with_description("Network reachability status (1 for reachable, 0 for unreachable)")
        .init();
    let network_latency = meter
        .f64_histogram("network_latency")
        .with_description("Network latency in seconds")
        .init();
    let network_loss_percent = meter
        .f64_histogram("network_loss_percentage")
        .with_description("Percentage of failed pings out of total 5 pings")
        .init();

    Arc::new(MetricsState {
        http_counter,
        http_req_latency_histogram,
        network_reachable,
        network_latency,
        network_loss_percent,
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
