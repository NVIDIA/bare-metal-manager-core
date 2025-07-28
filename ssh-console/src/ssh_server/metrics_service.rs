/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::ShutdownHandle;
use crate::config::Config;
use crate::metrics::MetricsState;
use eyre::Context;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{Method, Request, Response};
use http_body_util::Full;
use hyper::body;
use hyper::body::Bytes;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use prometheus::Encoder;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub async fn spawn(
    config: Arc<Config>,
    metrics_state: Arc<MetricsState>,
) -> eyre::Result<MetricsHandle> {
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
    let listener = TcpListener::bind(config.metrics_address)
        .await
        .context("error listening on metrics address")?;
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
                                            serve_metrics(req, metrics_state.clone())
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

pub struct MetricsHandle {
    shutdown_tx: oneshot::Sender<()>,
    join_handle: JoinHandle<()>,
}

impl ShutdownHandle<()> for MetricsHandle {
    fn into_parts(self) -> (oneshot::Sender<()>, JoinHandle<()>) {
        (self.shutdown_tx, self.join_handle)
    }
}

async fn serve_metrics(
    req: Request<body::Incoming>,
    state: Arc<MetricsState>,
) -> eyre::Result<Response<Full<Bytes>>, hyper::Error> {
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
