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

//! The bmc-proxy metrics endpoint, and the proxy's instrumentation events:
//! the outbound forward to a BMC records a duration histogram whose
//! `_count` series, split by status class, is the request and outcome rate.

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use carbide_instrument::{Event, LabelValue};
use http::Method;
use metrics_endpoint::{MetricsEndpointConfig, MetricsSetup};
use tokio::net::TcpListener;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

pub async fn start(
    address: SocketAddr,
    metrics_setup: MetricsSetup,
    cancellation_token: CancellationToken,
    join_set: &mut JoinSet<()>,
) -> io::Result<()> {
    let listener = TcpListener::bind(&address).await?;
    tracing::info!(metrics_address = %address, "Starting metrics listener");

    join_set
        .build_task()
        .name("bmc-proxy metrics service")
        .spawn(async move {
            if let Err(e) = metrics_endpoint::run_metrics_endpoint_with_listener(
                &MetricsEndpointConfig {
                    address,
                    registry: metrics_setup.registry,
                    health_controller: Some(metrics_setup.health_controller),
                    additional_prefix: None,
                },
                cancellation_token,
                listener,
            )
            .await
            {
                tracing::error!(error = %e, "metrics endpoint exited with error");
            }
        })
        // Safety: Should only fail if not in a tokio runtime
        .expect("Error spawning metrics endpoint");

    Ok(())
}

/// The HTTP method of a proxied request, as a bounded metric label: the
/// methods Redfish traffic uses, with anything else bucketed as `other`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum MethodLabel {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Other,
}

impl From<&Method> for MethodLabel {
    fn from(method: &Method) -> Self {
        match *method {
            Method::GET => Self::Get,
            Method::HEAD => Self::Head,
            Method::POST => Self::Post,
            Method::PUT => Self::Put,
            Method::PATCH => Self::Patch,
            Method::DELETE => Self::Delete,
            _ => Self::Other,
        }
    }
}

/// How the BMC answered a proxied request, as a bounded metric label: the
/// response's HTTP status class, or `error` when the forward produced no
/// response at all (a connect failure, timeout, or TLS failure on the
/// upstream leg). A status outside the standard 2xx-5xx classes -- which no
/// real BMC sends as a final response -- also counts as `error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
pub(crate) enum UpstreamStatus {
    Http2xx,
    Http3xx,
    Http4xx,
    Http5xx,
    Error,
}

impl From<reqwest::StatusCode> for UpstreamStatus {
    fn from(status: reqwest::StatusCode) -> Self {
        match status.as_u16() / 100 {
            2 => Self::Http2xx,
            3 => Self::Http3xx,
            4 => Self::Http4xx,
            5 => Self::Http5xx,
            _ => Self::Error,
        }
    }
}

impl UpstreamStatus {
    /// The class of a completed forward: the response's status class, or
    /// `Error` when the request never produced a response.
    pub(crate) fn from_result(result: &Result<reqwest::Response, reqwest::Error>) -> Self {
        match result {
            Ok(response) => response.status().into(),
            Err(_) => Self::Error,
        }
    }
}

/// A request the proxy forwarded to a BMC completed, successfully or not.
/// The duration covers the upstream leg through the response headers;
/// response bodies stream back separately. One send may follow up to five
/// redirects internally, so the status is the final hop's -- `http3xx`
/// generally means a non-followed 3xx such as a 304. Metric-only: the
/// forward has never logged per request in either direction, and a
/// failure's detail already reaches the caller in the 502 response body.
#[derive(Event)]
#[event(
    name = "carbide_bmc_proxy_upstream_request_duration_milliseconds",
    component = "nico-bmc-proxy",
    log = off,
    metric = histogram,
    describe = "Duration of requests the proxy forwarded to BMCs, by HTTP method and upstream status class; the _count series, split by status, gives the request and outcome rates."
)]
pub(crate) struct UpstreamRequestCompleted {
    #[label]
    pub method: MethodLabel,
    #[label]
    pub status: UpstreamStatus,
    #[observation]
    pub took: Duration,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use carbide_instrument::emit;
    use carbide_instrument::testing::{MetricsCapture, capture_logs};
    use carbide_test_support::{Check, check_values};
    use tokio::time::timeout;

    use super::*;

    #[tokio::test]
    async fn start_binds_listener_and_spawns_endpoint_task() {
        let address = "127.0.0.1:0".parse().expect("valid listen address");
        let metrics_setup =
            metrics_endpoint::new_metrics_setup("carbide-bmc-proxy-test", "test", false)
                .expect("metrics setup succeeds");
        let cancellation_token = CancellationToken::new();
        let mut join_set = JoinSet::new();

        start(
            address,
            metrics_setup,
            cancellation_token.clone(),
            &mut join_set,
        )
        .await
        .expect("metrics endpoint starts");

        assert_eq!(join_set.len(), 1);

        cancellation_token.cancel();
        timeout(Duration::from_secs(5), join_set.join_next())
            .await
            .expect("metrics endpoint exits after cancellation")
            .expect("metrics endpoint task is joined")
            .expect("metrics endpoint task succeeds");
    }

    #[test]
    fn method_label_maps_the_proxied_set_and_buckets_the_rest() {
        check_values(
            [
                Check {
                    scenario: "GET",
                    input: Method::GET,
                    expect: MethodLabel::Get,
                },
                Check {
                    scenario: "HEAD",
                    input: Method::HEAD,
                    expect: MethodLabel::Head,
                },
                Check {
                    scenario: "POST",
                    input: Method::POST,
                    expect: MethodLabel::Post,
                },
                Check {
                    scenario: "PUT",
                    input: Method::PUT,
                    expect: MethodLabel::Put,
                },
                Check {
                    scenario: "PATCH",
                    input: Method::PATCH,
                    expect: MethodLabel::Patch,
                },
                Check {
                    scenario: "DELETE",
                    input: Method::DELETE,
                    expect: MethodLabel::Delete,
                },
                Check {
                    scenario: "OPTIONS buckets as other",
                    input: Method::OPTIONS,
                    expect: MethodLabel::Other,
                },
                Check {
                    scenario: "extension method buckets as other",
                    input: Method::from_bytes(b"PROPFIND").expect("valid method token"),
                    expect: MethodLabel::Other,
                },
            ],
            |method| MethodLabel::from(&method),
        );
    }

    #[test]
    fn upstream_status_classes_map_from_status_codes() {
        check_values(
            [
                Check {
                    scenario: "200 OK",
                    input: reqwest::StatusCode::OK,
                    expect: UpstreamStatus::Http2xx,
                },
                Check {
                    scenario: "204 No Content",
                    input: reqwest::StatusCode::NO_CONTENT,
                    expect: UpstreamStatus::Http2xx,
                },
                Check {
                    scenario: "304 Not Modified",
                    input: reqwest::StatusCode::NOT_MODIFIED,
                    expect: UpstreamStatus::Http3xx,
                },
                Check {
                    scenario: "401 Unauthorized",
                    input: reqwest::StatusCode::UNAUTHORIZED,
                    expect: UpstreamStatus::Http4xx,
                },
                Check {
                    scenario: "404 Not Found",
                    input: reqwest::StatusCode::NOT_FOUND,
                    expect: UpstreamStatus::Http4xx,
                },
                Check {
                    scenario: "500 Internal Server Error",
                    input: reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                    expect: UpstreamStatus::Http5xx,
                },
                Check {
                    scenario: "503 Service Unavailable",
                    input: reqwest::StatusCode::SERVICE_UNAVAILABLE,
                    expect: UpstreamStatus::Http5xx,
                },
                Check {
                    scenario: "interim 1xx class buckets as error",
                    input: reqwest::StatusCode::CONTINUE,
                    expect: UpstreamStatus::Error,
                },
                Check {
                    scenario: "non-standard 6xx class buckets as error",
                    input: reqwest::StatusCode::from_u16(600).expect("in the valid range"),
                    expect: UpstreamStatus::Error,
                },
            ],
            UpstreamStatus::from,
        );
    }

    #[test]
    fn upstream_status_from_result_uses_the_response_or_error() {
        let response = reqwest::Response::from(
            http::Response::builder()
                .status(http::StatusCode::BAD_GATEWAY)
                .body("")
                .expect("response builds"),
        );
        assert_eq!(
            UpstreamStatus::from_result(&Ok(response)),
            UpstreamStatus::Http5xx
        );

        let error = reqwest::Client::new()
            .get("http://")
            .build()
            .expect_err("an empty host cannot build a request");
        assert_eq!(
            UpstreamStatus::from_result(&Err(error)),
            UpstreamStatus::Error
        );
    }

    /// The label vocabulary is the dashboard contract: each variant renders
    /// as its snake_case name, byte for byte.
    #[test]
    fn label_values_render_as_snake_case() {
        check_values(
            [
                Check {
                    scenario: "get",
                    input: MethodLabel::Get.label_value(),
                    expect: "get".to_string(),
                },
                Check {
                    scenario: "head",
                    input: MethodLabel::Head.label_value(),
                    expect: "head".to_string(),
                },
                Check {
                    scenario: "post",
                    input: MethodLabel::Post.label_value(),
                    expect: "post".to_string(),
                },
                Check {
                    scenario: "put",
                    input: MethodLabel::Put.label_value(),
                    expect: "put".to_string(),
                },
                Check {
                    scenario: "patch",
                    input: MethodLabel::Patch.label_value(),
                    expect: "patch".to_string(),
                },
                Check {
                    scenario: "delete",
                    input: MethodLabel::Delete.label_value(),
                    expect: "delete".to_string(),
                },
                Check {
                    scenario: "other method",
                    input: MethodLabel::Other.label_value(),
                    expect: "other".to_string(),
                },
                Check {
                    scenario: "2xx class",
                    input: UpstreamStatus::Http2xx.label_value(),
                    expect: "http2xx".to_string(),
                },
                Check {
                    scenario: "3xx class",
                    input: UpstreamStatus::Http3xx.label_value(),
                    expect: "http3xx".to_string(),
                },
                Check {
                    scenario: "4xx class",
                    input: UpstreamStatus::Http4xx.label_value(),
                    expect: "http4xx".to_string(),
                },
                Check {
                    scenario: "5xx class",
                    input: UpstreamStatus::Http5xx.label_value(),
                    expect: "http5xx".to_string(),
                },
                Check {
                    scenario: "no response",
                    input: UpstreamStatus::Error.label_value(),
                    expect: "error".to_string(),
                },
            ],
            |value| value.to_string(),
        );
    }

    /// Each forward moves exactly its label pair's series, records the
    /// duration in the milliseconds the metric name declares, and builds no
    /// log line -- the forward boundary has never logged per request.
    #[test]
    fn upstream_request_events_record_per_label_without_logging() {
        let metrics = MetricsCapture::start();
        let logs = capture_logs(|| {
            emit(UpstreamRequestCompleted {
                method: MethodLabel::Patch,
                status: UpstreamStatus::Http5xx,
                took: Duration::from_millis(1500),
            });
            emit(UpstreamRequestCompleted {
                method: MethodLabel::Patch,
                status: UpstreamStatus::Http5xx,
                took: Duration::from_millis(500),
            });
            emit(UpstreamRequestCompleted {
                method: MethodLabel::Delete,
                status: UpstreamStatus::Error,
                took: Duration::from_millis(250),
            });
        });

        assert!(
            logs.is_empty(),
            "log = off must not construct any log line, got {logs:?}"
        );
        assert_eq!(
            metrics.histogram_count_delta(
                "carbide_bmc_proxy_upstream_request_duration_milliseconds",
                &[("method", "patch"), ("status", "http5xx")],
            ),
            2
        );
        let sum = metrics.histogram_sum_delta(
            "carbide_bmc_proxy_upstream_request_duration_milliseconds",
            &[("method", "patch"), ("status", "http5xx")],
        );
        assert!(
            (sum - 2000.0).abs() < 1e-9,
            "1500ms + 500ms record as milliseconds, got {sum}"
        );
        assert_eq!(
            metrics.histogram_count_delta(
                "carbide_bmc_proxy_upstream_request_duration_milliseconds",
                &[("method", "delete"), ("status", "error")],
            ),
            1
        );
        assert_eq!(
            metrics.histogram_count_delta(
                "carbide_bmc_proxy_upstream_request_duration_milliseconds",
                &[("method", "get"), ("status", "http2xx")],
            ),
            0,
            "an untouched label pair must not move",
        );
    }
}
