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

use http::header::CONTENT_LENGTH;
use hyper::{
    header::CONTENT_TYPE,
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server,
};
use opentelemetry_prometheus::PrometheusExporter;
use prometheus::{Encoder, TextEncoder};
use std::sync::Arc;
use std::{convert::Infallible, net::SocketAddr};

/// Request handler
async fn handle_metrics_request(
    req: Request<Body>,
    state: Arc<MetricsHandlerState>,
) -> Result<Response<Body>, hyper::Error> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let mut buffer = vec![];
            let encoder = TextEncoder::new();
            let metric_families = state.exporter.registry().gather();
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

/// The shared state between HTTP requests
struct MetricsHandlerState {
    exporter: Arc<PrometheusExporter>,
}

/// Configuration for the metrics endpoint
pub struct MetricsEndpointConfig {
    pub address: SocketAddr,
    pub exporter: Arc<PrometheusExporter>,
}

/// Start a HTTP endpoint which exposes metrics using the provided configuration
pub async fn run_metrics_endpoint(config: &MetricsEndpointConfig) -> Result<(), hyper::Error> {
    let handler_state = Arc::new(MetricsHandlerState {
        exporter: config.exporter.clone(),
    });

    // `connection_handler` defines the closure that will be called at the start
    // of every TCP connection attempt to this server.
    // There can be multiple requests on the same connection
    let connection_handler = make_service_fn(move |_conn| {
        let handler_state = handler_state.clone();
        async move {
            Ok::<_, Infallible>(service_fn(move |req| {
                // this is the function that will be called for every request
                // on the connection
                handle_metrics_request(req, handler_state.clone())
            }))
        }
    });

    tracing::info!("Starting metrics listener on address {}", config.address);

    // TODO: We need timeouts for this listener
    let server = Server::bind(&config.address).serve(connection_handler);
    // This will block until the server is shut down
    server.await?;

    Ok(())
}
