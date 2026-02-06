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
