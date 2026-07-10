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

use carbide_instrument::LabelValue;

/// Which OTLP signal a drain exports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum OtlpSignal {
    Logs,
    Metrics,
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
    use carbide_instrument::emit;
    use carbide_instrument::testing::{MetricsCapture, capture_logs};

    use super::{OtlpExportFailed, OtlpSignal};

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
