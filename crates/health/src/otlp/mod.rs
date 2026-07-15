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

pub mod convert;
pub mod drain;
pub mod metrics_drain;

use std::time::Duration;

use carbide_instrument::LabelValue;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};

use crate::HealthError;
use crate::config::OtlpTargetConfig;

/// Maximum time allowed to establish a replacement OTLP channel.
const OTLP_RELOAD_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Which OTLP signal a drain exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum OtlpSignal {
    Logs,
    Metrics,
}

/// Builds an OTLP endpoint with the target's current TLS or mTLS policy.
///
/// HTTPS targets without an explicit TLS profile use platform trust roots. An
/// explicit profile is reread on every call so reconnects can adopt rotated
/// certificate files.
///
/// # Errors
///
/// Returns an error when the endpoint URI is invalid or the configured TLS
/// material cannot be loaded, validated, or applied.
pub(crate) async fn target_endpoint(target: &OtlpTargetConfig) -> Result<Endpoint, HealthError> {
    let endpoint = Channel::from_shared(target.endpoint.clone()).map_err(|error| {
        HealthError::GenericError(format!(
            "invalid OTLP target endpoint {}: {error}",
            target.endpoint
        ))
    })?;

    let tls_config = match &target.tls {
        Some(tls) => crate::tls::otlp_tonic_tls_config(tls).await?,
        None if endpoint.uri().scheme_str() == Some("https") => {
            ClientTlsConfig::new().with_enabled_roots()
        }
        None => return Ok(endpoint),
    };

    endpoint.tls_config(tls_config).map_err(|error| {
        HealthError::GenericError(format!(
            "invalid TLS configuration for OTLP target {}: {error}",
            target.endpoint
        ))
    })
}

/// Establishes a replacement channel before a drain adopts refreshed TLS material.
///
/// The function returns only after the TCP and TLS handshakes succeed. Reload
/// failures and attempts exceeding ten seconds return an error, allowing the
/// caller to retain its current channel.
///
/// # Errors
///
/// Returns an error when endpoint construction fails, the connection cannot be
/// established, or the connection attempt exceeds its deadline.
pub(crate) async fn connect_replacement_target(
    target: &OtlpTargetConfig,
) -> Result<Channel, HealthError> {
    connect_replacement_target_with_timeout(target, OTLP_RELOAD_CONNECT_TIMEOUT).await
}

async fn connect_replacement_target_with_timeout(
    target: &OtlpTargetConfig,
    connect_timeout: Duration,
) -> Result<Channel, HealthError> {
    let endpoint = target_endpoint(target).await?;

    let channel = tokio::time::timeout(connect_timeout, endpoint.connect())
        .await
        .map_err(|_| {
            HealthError::GenericError(format!(
                "timed out connecting replacement channel for OTLP target {} after {:?}",
                target.endpoint, connect_timeout
            ))
        })?;

    channel.map_err(|error| {
        HealthError::GenericError(format!(
            "failed to connect replacement channel for OTLP target {}: {error}",
            target.endpoint
        ))
    })
}

/// A gRPC status code as a bounded metric label: one variant per
/// [`tonic::Code`], a set closed by the gRPC protocol itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum GrpcCode {
    Ok,
    Cancelled,
    Unknown,
    InvalidArgument,
    DeadlineExceeded,
    NotFound,
    AlreadyExists,
    PermissionDenied,
    ResourceExhausted,
    FailedPrecondition,
    Aborted,
    OutOfRange,
    Unimplemented,
    Internal,
    Unavailable,
    DataLoss,
    Unauthenticated,
}

impl From<tonic::Code> for GrpcCode {
    fn from(code: tonic::Code) -> Self {
        match code {
            tonic::Code::Ok => Self::Ok,
            tonic::Code::Cancelled => Self::Cancelled,
            tonic::Code::Unknown => Self::Unknown,
            tonic::Code::InvalidArgument => Self::InvalidArgument,
            tonic::Code::DeadlineExceeded => Self::DeadlineExceeded,
            tonic::Code::NotFound => Self::NotFound,
            tonic::Code::AlreadyExists => Self::AlreadyExists,
            tonic::Code::PermissionDenied => Self::PermissionDenied,
            tonic::Code::ResourceExhausted => Self::ResourceExhausted,
            tonic::Code::FailedPrecondition => Self::FailedPrecondition,
            tonic::Code::Aborted => Self::Aborted,
            tonic::Code::OutOfRange => Self::OutOfRange,
            tonic::Code::Unimplemented => Self::Unimplemented,
            tonic::Code::Internal => Self::Internal,
            tonic::Code::Unavailable => Self::Unavailable,
            tonic::Code::DataLoss => Self::DataLoss,
            tonic::Code::Unauthenticated => Self::Unauthenticated,
        }
    }
}

/// A drain dropped a whole export batch: the collector rejected it with a
/// non-retryable status, or the retry budget ran out.
#[derive(carbide_instrument::Event)]
#[event(
    name = "carbide_health_otlp_export_failures_total",
    component = "nico-hardware-health",
    log = error,
    metric = counter,
    message = "otlp export failed, dropping batch",
    describe = "Number of OTLP export batches dropped after a send failure, by signal and gRPC status code."
)]
pub(crate) struct OtlpExportFailed {
    #[label]
    pub signal: OtlpSignal,
    #[label]
    pub code: GrpcCode,
    /// The status message the collector returned.
    #[context]
    pub error: String,
    /// How many log records or metric points the dropped batch held.
    #[context]
    pub record_count: usize,
    /// The attempt index the drop happened on (the retry cap for retryable
    /// statuses, earlier for non-retryable ones).
    #[context]
    pub attempt: usize,

    /// Configured endpoint that rejected or failed to accept the batch.
    #[context]
    pub endpoint: String,
}

#[allow(clippy::all)]
pub mod opentelemetry {
    pub mod proto {
        pub mod common {
            pub mod v1 {
                tonic::include_proto!("opentelemetry.proto.common.v1");
            }
        }
        pub mod resource {
            pub mod v1 {
                tonic::include_proto!("opentelemetry.proto.resource.v1");
            }
        }
        pub mod logs {
            pub mod v1 {
                tonic::include_proto!("opentelemetry.proto.logs.v1");
            }
        }
        pub mod metrics {
            pub mod v1 {
                tonic::include_proto!("opentelemetry.proto.metrics.v1");
            }
        }
        pub mod collector {
            pub mod logs {
                pub mod v1 {
                    tonic::include_proto!("opentelemetry.proto.collector.logs.v1");
                }
            }
            pub mod metrics {
                pub mod v1 {
                    tonic::include_proto!("opentelemetry.proto.collector.metrics.v1");
                }
            }
        }
    }
}

pub use opentelemetry::proto::collector::logs::v1 as collector_logs;
pub use opentelemetry::proto::collector::metrics::v1 as collector_metrics;
pub use opentelemetry::proto::common::v1 as common;
pub use opentelemetry::proto::logs::v1 as logs;
pub use opentelemetry::proto::metrics::v1 as metrics;
pub use opentelemetry::proto::resource::v1 as resource;

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use carbide_instrument::emit;
    use carbide_instrument::testing::{MetricsCapture, capture_logs};
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::timeout;

    use super::{
        OtlpExportFailed, OtlpSignal, connect_replacement_target_with_timeout, target_endpoint,
    };
    use crate::HealthError;
    use crate::config::OtlpTargetConfig;

    #[tokio::test]
    async fn https_target_without_tls_profile_starts_tls_handshake()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;

        let target = OtlpTargetConfig {
            endpoint: format!("https://{address}"),
            tls: None,
            batch_size: 1,
            flush_interval: Duration::from_secs(1),
            include_diagnostics: false,
        };

        let endpoint = target_endpoint(&target).await?;

        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut content_type = [0_u8; 1];

            stream.read_exact(&mut content_type).await?;

            Ok::<_, std::io::Error>(content_type[0])
        });

        let _connect_result = timeout(Duration::from_secs(1), endpoint.connect()).await?;

        let content_type = timeout(Duration::from_secs(1), peer).await??;

        assert_eq!(
            content_type?, 0x16,
            "connection must start with a TLS record"
        );

        Ok(())
    }

    #[tokio::test]
    async fn replacement_connection_times_out_without_tls_handshake()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel::<()>();

        let target = OtlpTargetConfig {
            endpoint: format!("https://{address}"),
            tls: None,
            batch_size: 1,
            flush_interval: Duration::from_secs(1),
            include_diagnostics: false,
        };

        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;

            accepted_tx
                .send(())
                .map_err(|_| std::io::Error::other("replacement connection task stopped"))?;

            let _ = release_rx.await;

            drop(stream);

            Ok::<_, std::io::Error>(())
        });

        let replacement = tokio::spawn(async move {
            connect_replacement_target_with_timeout(&target, Duration::from_millis(100)).await
        });

        accepted_rx.await?;

        let result = replacement.await?;

        drop(release_tx);
        peer.await??;

        assert!(
            matches!(result, Err(HealthError::GenericError(message)) if message.contains("timed out connecting replacement channel"))
        );

        Ok(())
    }

    /// A dropped logs batch writes one ERROR line and ticks the counter's
    /// logs-signal series, labelled with the gRPC status code.
    #[test]
    fn otlp_export_failure_logs_error_and_ticks_counter() {
        let metrics = MetricsCapture::start();
        let logs = capture_logs(|| {
            emit(OtlpExportFailed {
                signal: OtlpSignal::Logs,
                code: tonic::Code::Unavailable.into(),
                error: "connection refused".to_string(),
                record_count: 17,
                attempt: 5,
                endpoint: "http://localhost:4317".to_string(),
            });
        });

        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].level, tracing::Level::ERROR);
        assert_eq!(logs[0].message, "otlp export failed, dropping batch");
        assert_eq!(
            metrics.counter_delta(
                "carbide_health_otlp_export_failures_total",
                &[("signal", "logs"), ("code", "unavailable")],
            ),
            1.0
        );
    }

    /// The metrics drain counts on its own signal series, and multi-word
    /// gRPC codes render as snake_case label values.
    #[test]
    fn otlp_metrics_export_failure_counts_on_the_metrics_signal_series() {
        let metrics = MetricsCapture::start();
        emit(OtlpExportFailed {
            signal: OtlpSignal::Metrics,
            code: tonic::Code::DeadlineExceeded.into(),
            error: "deadline exceeded".to_string(),
            record_count: 3,
            attempt: 0,
            endpoint: "http://localhost:4317".to_string(),
        });

        assert_eq!(
            metrics.counter_delta(
                "carbide_health_otlp_export_failures_total",
                &[("signal", "metrics"), ("code", "deadline_exceeded")],
            ),
            1.0
        );
    }
}
