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

use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Method, Request, Response};
use http_body_util::Full;
use hyper::body;
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use opentelemetry::metrics::{Meter, MeterProvider};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use prometheus::Encoder;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::config::Config;
use crate::shutdown_handle::ShutdownHandle;

pub async fn spawn(
    config: Arc<Config>,
    metrics_state: Arc<MetricsState>,
) -> Result<MetricsHandle, SpawnError> {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let listener = TcpListener::bind(config.metrics_address)
        .await
        .map_err(SpawnError::Listen)?;

    tracing::info!("metrics listening on {}", config.metrics_address);

    let join_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    tracing::info!("metrics service shutting down");
                    break;
                }

                res = listener.accept() => match res {
                    Ok((stream, addr)) => {
                        tracing::info!("got metrics connection from {addr}");
                        tokio::task::spawn({
                            let metrics_state = metrics_state.clone();
                            async move {
                                let io = TokioIo::new(stream);
                                auto::Builder::new(TokioExecutor::new())
                                    .serve_connection(
                                        io,
                                        hyper::service::service_fn(move |req| {
                                            let metrics_state = metrics_state.clone();
                                            async move {
                                                serve_metrics(req, metrics_state)
                                            }
                                        }),
                                    )
                                    .await
                            }
                        });
                    }
                    Err(error) => {
                        tracing::error!(%error, "error accepting metrics connection");
                    }
                }
            }
        }
    });

    Ok(MetricsHandle {
        shutdown_tx,
        join_handle,
    })
}

#[derive(thiserror::Error, Debug)]
pub enum SpawnError {
    #[error("error listening on metrics address: {0}")]
    Listen(std::io::Error),
}

fn serve_metrics(
    req: Request<body::Incoming>,
    state: Arc<MetricsState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/metrics") => {
            let mut buffer = vec![];
            let encoder = prometheus::TextEncoder::new();
            let metric_families = state.registry.gather();
            match encoder.encode(&metric_families, &mut buffer) {
                Ok(_) => Response::builder()
                    .status(200)
                    .header(CONTENT_TYPE, encoder.format_type())
                    .header(CONTENT_LENGTH, buffer.len())
                    .body(buffer.into()),
                Err(e) => Response::builder()
                    .status(500)
                    .body(format!("Encoding error: {e}").into()),
            }
        }
        (&Method::GET, "/") => Response::builder().status(200).body("/metrics".into()),
        _ => Response::builder().status(404).body("Invalid URL".into()),
    };

    Ok(response.expect("BUG: Response::builder error"))
}

pub struct MetricsHandle {
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

impl ShutdownHandle<()> for MetricsHandle {
    fn into_parts(self) -> (oneshot::Sender<()>, JoinHandle<()>) {
        (self.shutdown_tx, self.join_handle)
    }
}

pub struct MetricsState {
    pub meter: Meter,
    pub registry: prometheus::Registry,
    _meter_provider: SdkMeterProvider,
}

impl Default for MetricsState {
    fn default() -> Self {
        Self::new()
    }
}

impl MetricsState {
    pub fn new() -> Self {
        let registry = prometheus::Registry::new();
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .without_scope_info()
            .without_target_info()
            .build()
            .expect("BUG: could not build default metrics state");
        let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_reader(exporter)
            .build();
        let meter = meter_provider.meter("ssh-console");

        Self {
            meter,
            registry,
            _meter_provider: meter_provider,
        }
    }
}
