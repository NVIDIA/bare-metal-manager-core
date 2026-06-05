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
use std::time::Duration;

use axum::Router;
use axum::extract::State;
use axum::http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use axum::routing::get;
use eyre::WrapErr;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider};
use opentelemetry_prometheus::ExporterBuilder;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_semantic_conventions::resource::{SERVICE_NAME, SERVICE_NAMESPACE};
use prometheus::{Encoder, Registry, TextEncoder};
use tonic::service::AxumBody;
use tower::ServiceBuilder;
use tower_http::trace::TraceLayer;
use tracing::Span;

/// Prometheus scrape + HTTP instrumentation matching forge-dpu-agent embedded FMDS (`http_requests`, `request_latency`).
pub struct HttpRequestMetrics {
    http_counter: Counter<u64>,
    http_req_latency_histogram: Histogram<f64>,
}

impl HttpRequestMetrics {
    fn new(meter: &Meter) -> Self {
        let http_counter = meter
            .u64_counter("http_requests")
            .with_description("Total number of HTTP requests made.")
            .build();
        let http_req_latency_histogram = meter
            .f64_histogram("request_latency")
            .with_description("HTTP request latency")
            .with_unit("ms")
            .build();

        Self {
            http_counter,
            http_req_latency_histogram,
        }
    }
}

/// Registers a Prometheus reader and global meter provider; returns the scrape registry and HTTP metrics state.
pub fn init() -> eyre::Result<(Registry, HttpRequestMetrics)> {
    let prometheus_registry = Registry::new();
    let exporter = ExporterBuilder::default()
        .with_registry(prometheus_registry.clone())
        .without_scope_info()
        .without_target_info()
        .build()
        .wrap_err("Could not build Prometheus exporter")?;

    let resource_attributes = opentelemetry_sdk::Resource::builder()
        .with_attributes([
            KeyValue::new(SERVICE_NAME, "carbide-fmds"),
            KeyValue::new(SERVICE_NAMESPACE, "forge-system"),
        ])
        .build();

    let meter_provider = SdkMeterProvider::builder()
        .with_reader(exporter)
        .with_resource(resource_attributes)
        .build();

    let meter = meter_provider.meter("carbide-fmds");
    let http_metrics = HttpRequestMetrics::new(&meter);
    opentelemetry::global::set_meter_provider(meter_provider);

    Ok((prometheus_registry, http_metrics))
}

pub fn metrics_router(registry: Registry) -> Router {
    Router::new()
        .route("/", get(export_metrics))
        .with_state(registry)
}

#[axum::debug_handler]
async fn export_metrics(State(registry): State<Registry>) -> Response<Full<Bytes>> {
    tokio::task::spawn_blocking(move || {
        let mut buffer = vec![];
        let encoder = TextEncoder::new();
        let metric_families = registry.gather();
        encoder.encode(&metric_families, &mut buffer).unwrap();

        Response::builder()
            .status(200)
            .header(CONTENT_TYPE, encoder.format_type())
            .header(CONTENT_LENGTH, buffer.len())
            .body(buffer.into())
            .unwrap()
    })
    .await
    .unwrap()
}

/// Same HTTP instrumentation as forge-dpu-agent `WithTracingLayer` (request count + latency + tracing logs).
pub fn with_http_request_trace_layer(router: Router, metrics: Arc<HttpRequestMetrics>) -> Router {
    let metrics_request = metrics.clone();
    let metrics_response = metrics;
    let layer = TraceLayer::new_for_http()
        .make_span_with(|request: &Request<AxumBody>| {
            tracing::info_span!(
                "http-request",
                method = %request.method(),
                uri = %request.uri(),
            )
        })
        .on_request(move |request: &Request<AxumBody>, _span: &Span| {
            metrics_request.http_counter.add(1, &[]);
            tracing::info!("started {} {}", request.method(), request.uri().path());
        })
        .on_response(
            move |_response: &Response<AxumBody>, latency: Duration, _span: &Span| {
                metrics_response
                    .http_req_latency_histogram
                    .record(latency.as_secs_f64() * 1000.0, &[]);
                tracing::info!("response generated in {:?}", latency);
            },
        );

    router.layer(ServiceBuilder::new().layer(layer))
}
