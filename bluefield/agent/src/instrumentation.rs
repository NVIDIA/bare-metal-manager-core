use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwapOption;
use axum::extract::State;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::routing::get;
use axum::Router;
use http_body::combinators::UnsyncBoxBody;
use hyper::{Body, Request, Response};
use opentelemetry::metrics::{Counter, Histogram, Meter, ObservableGauge, Unit};
use opentelemetry::KeyValue;
use tower::ServiceBuilder;
use tracing::Span;

use prometheus::{Encoder, TextEncoder};

pub struct MetricsState {
    meter: Meter,

    http_counter: Counter<u64>,
    http_req_latency_histogram: Histogram<f64>,

    // Metrics for network monitoring
    network_reachable: ObservableGauge<u64>,
    network_latency: Histogram<f64>,
    network_loss_percent: Histogram<f64>,
    network_monitor_error: Counter<u64>,
    network_communication_error: Counter<u64>,

    // Fields used for network_reachable observatioins
    network_reachable_map: ArcSwapOption<HashMap<String, bool>>,
    machine_id: String,
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
        let attributes = [
            KeyValue::new("source_dpu_id", machine_id),
            KeyValue::new("dest_dpu_id", dpu_id.clone()),
        ];

        // Update the network_reachable_map
        let new_map = {
            let current_map = self.network_reachable_map.load();
            let mut map = match current_map.as_ref() {
                Some(m) => m.as_ref().clone(),
                None => HashMap::new(),
            };
            map.insert(dpu_id.clone(), reachable);
            Arc::new(map)
        };
        self.network_reachable_map.store(Some(new_map));

        if let Some(latency) = duration {
            self.network_latency
                .record(latency.as_secs_f64() * 1000.0, &attributes);
        }
        self.network_loss_percent.record(loss_percent, &attributes);
    }

    pub fn record_communication_error(
        &self,
        machine_id: String,
        dpu_id: String,
        error_type: String,
    ) {
        let attributes = [
            KeyValue::new("source_dpu_id", machine_id),
            KeyValue::new("dest_dpu_id", dpu_id.clone()),
            KeyValue::new("error_type", error_type),
        ];
        self.network_communication_error.add(1, &attributes);
    }

    pub fn record_monitor_error(&self, machine_id: String, error_type: String) {
        let attributes = [
            KeyValue::new("dpu_id", machine_id),
            KeyValue::new("error_type", error_type),
        ];
        self.network_monitor_error.add(1, &attributes);
    }

    pub fn register_callback(self: &Arc<Self>) {
        let self_clone = self.clone();
        if let Err(e) =
            self.meter
                .register_callback(&[self.network_reachable.as_any()], move |observer| {
                    let network_reachable_map = self_clone.network_reachable_map.load();
                    if let Some(map) = network_reachable_map.as_ref() {
                        for (dpu_id, reachable) in map.iter() {
                            let reachability = if *reachable { 1 } else { 0 };
                            let attributes = [
                                KeyValue::new("source_dpu_id", self_clone.machine_id.clone()),
                                KeyValue::new("dest_dpu_id", dpu_id.clone()),
                            ];
                            observer.observe_u64(
                                &self_clone.network_reachable,
                                reachability,
                                &attributes,
                            );
                        }
                    }
                })
        {
            tracing::error!("Failed to register network reachable metric: {e}");
        };
    }
}

pub fn create_metrics(meter: Meter, machine_id: String) -> Arc<MetricsState> {
    let http_counter = meter
        .u64_counter("http_requests")
        .with_description("Total number of HTTP requests made.")
        .init();
    let http_req_latency_histogram: Histogram<f64> = meter
        .f64_histogram("request_latency")
        .with_description("HTTP request latency")
        .with_unit(Unit::new("ms"))
        .init();

    let network_reachable: ObservableGauge<u64> = meter
        .u64_observable_gauge("forge_dpu_agent_network_reachable")
        .with_description("Network reachability status (1 for reachable, 0 for unreachable)")
        .init();
    let network_latency = meter
        .f64_histogram("forge_dpu_agent_network_latency")
        .with_unit(Unit::new("ms"))
        .init();
    let network_loss_percent = meter
        .f64_histogram("forge_dpu_agent_network_loss_percentage")
        .with_description("Percentage of failed pings out of total 5 pings")
        .init();
    let network_monitor_error = meter
        .u64_counter("forge_dpu_agent_network_monitor_error")
        .with_description("Network monitor errors which are unrelated to network connectivity")
        .init();

    let network_communication_error = meter
        .u64_counter("forge_dpu_agent_network_communication_error")
        .with_description("Network monitor errors related to ping dpu")
        .init();

    Arc::new(MetricsState {
        meter: meter.clone(),
        network_reachable_map: ArcSwapOption::const_empty(),
        http_counter,
        http_req_latency_histogram,
        machine_id,

        network_reachable,
        network_latency,
        network_loss_percent,
        network_monitor_error,
        network_communication_error,
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
