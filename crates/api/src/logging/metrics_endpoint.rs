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

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::header::{CONTENT_LENGTH, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use prometheus::proto::MetricFamily;
use prometheus::{Encoder, TextEncoder};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// Request handler
fn handle_metrics_request(
    req: Request<Incoming>,
    state: Arc<MetricsHandlerState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let response: Response<Full<Bytes>> = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let mut buffer = Vec::new();
            let encoder = TextEncoder::new();
            let mut metric_families = state.registry.gather();

            if let Some((old_prefix, new_prefix)) = &state.additional_prefix {
                let alt_name_families: Vec<MetricFamily> = metric_families
                    .iter()
                    .filter_map(|family| {
                        if !family.get_name().starts_with(old_prefix) {
                            return None;
                        }

                        let mut alt_name_family = family.clone();
                        alt_name_family
                            .set_name(family.get_name().replacen(old_prefix, new_prefix, 1));
                        Some(alt_name_family)
                    })
                    .collect();

                if !alt_name_families.is_empty() {
                    metric_families.extend(alt_name_families);
                }
            }

            encoder.encode(&metric_families, &mut buffer).unwrap();

            Response::builder()
                .status(200)
                .header(CONTENT_TYPE, encoder.format_type())
                .header(CONTENT_LENGTH, buffer.len())
                .body(buffer.into())
                .unwrap()
        }
        (&Method::GET, "/") => Response::builder()
            .status(200)
            .body("Metrics are exposed via /metrics. There is nothing else to see here".into())
            .unwrap(),
        _ => Response::builder()
            .status(404)
            .body("Invalid URL".into())
            .unwrap(),
    };

    Ok(response)
}

/// The shared state between HTTP requests
struct MetricsHandlerState {
    registry: prometheus::Registry,
    additional_prefix: Option<(String, String)>,
}

/// Configuration for the metrics endpoint
pub struct MetricsEndpointConfig {
    pub address: SocketAddr,
    pub registry: prometheus::Registry,
    /// Allows to emit metrics with a certain prefix additionally under a new prefix.
    /// This feature allows for gradual migration of metrics by emitting them under
    /// 2 prefixes for a certain time.
    /// The first member of the tuple is the prefix to replace, the 2nd is the replacemen
    pub additional_prefix: Option<(String, String)>,
}

/// Start a HTTP endpoint which exposes metrics using the provided configuration
pub async fn run_metrics_endpoint(
    config: &MetricsEndpointConfig,
    mut stop_rx: oneshot::Receiver<()>,
) -> eyre::Result<()> {
    let handler_state = Arc::new(MetricsHandlerState {
        registry: config.registry.clone(),
        additional_prefix: config.additional_prefix.clone(),
    });

    tracing::info!(
        address = config.address.to_string(),
        "Starting metrics listener"
    );

    let listener = TcpListener::bind(&config.address).await?;
    loop {
        tokio::select! {
            result = listener.accept() => {
                let handler_state = handler_state.clone();
                let (stream, _) = result?;
                tokio::spawn(http1::Builder::new().serve_connection(
                    TokioIo::new(stream),
                    service_fn(move |req| {
                        let handler_state = handler_state.clone();
                        async move {
                            handle_metrics_request(req, handler_state)
                        }
                    }),
                ));
            },
            _ = &mut stop_rx => {
                break
            }
        }
    }

    Ok(())
}
