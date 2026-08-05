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

//! Carbide API admission policy and middleware integration.
//!
//! The nested engine module owns application-independent admission. This
//! module supplies Carbide configuration, route classification, transport
//! responses, metrics, and rate-limited diagnostics.

mod engine;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Response, StatusCode, header};
use axum::middleware::Next;
use axum::response::IntoResponse;
pub(crate) use engine::AdmissionLimits;
use engine::{AdmissionObserver, RejectionReason, SemaphoreAdmission};
use opentelemetry::metrics::{Meter, ObservableGauge};
use tokio_util::sync::CancellationToken;

use crate::cfg::file::ApiAdmissionControlConfig;
use crate::logging::log_limiter::LogLimiter;

const EXCLUDED_ADMIN_PATHS: &[&str] = &["/admin/static", "/admin/auth-callback", "/admin/logs"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum RequestTransport {
    Grpc,
    Http,
}

impl RequestTransport {
    fn classify(path: &str) -> Option<Self> {
        // Keep these route prefixes in sync with the gRPC services and admin
        // routes mounted by the listener. The descriptor-backed test below
        // makes adding a gRPC service without updating this policy fail in CI;
        // the table test documents the intentional admin bypasses.
        if path.starts_with(::rpc::service_path!("")) {
            return Some(Self::Grpc);
        }

        if !is_path_or_child(path, "/admin")
            || EXCLUDED_ADMIN_PATHS
                .iter()
                .any(|excluded_path| is_path_or_child(path, excluded_path))
        {
            return None;
        }

        Some(Self::Http)
    }

    fn overloaded_response(self) -> Response<Body> {
        match self {
            Self::Grpc => tonic::Status::resource_exhausted("API admission capacity exhausted")
                .into_http::<Body>(),
            Self::Http => (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, "1")],
                "API admission capacity exhausted",
            )
                .into_response(),
        }
    }
}

fn is_path_or_child(path: &str, root: &str) -> bool {
    path == root
        || path
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, carbide_instrument::LabelValue)]
enum RejectionReasonLabel {
    QueueFull,
    QueueTimeout,
    ControllerUnavailable,
    ShuttingDown,
}

impl From<RejectionReason> for RejectionReasonLabel {
    fn from(reason: RejectionReason) -> Self {
        match reason {
            RejectionReason::QueueFull => Self::QueueFull,
            RejectionReason::QueueTimeout => Self::QueueTimeout,
            RejectionReason::ControllerUnavailable => Self::ControllerUnavailable,
            RejectionReason::ShuttingDown => Self::ShuttingDown,
        }
    }
}

#[derive(carbide_instrument::Event)]
#[event(
    event_name = "api_admission_request_admitted",
    metric_name = "carbide_api_admission_admitted_total",
    component = "nico-api",
    log = off,
    metric = counter,
    describe = "Number of API requests admitted for execution"
)]
struct RequestAdmitted;

#[derive(carbide_instrument::Event)]
#[event(
    event_name = "api_admission_request_rejected",
    metric_name = "carbide_api_admission_rejected_total",
    component = "nico-api",
    log = off,
    metric = counter,
    describe = "Number of API requests rejected before handler execution"
)]
struct RequestRejected {
    #[label]
    reason: RejectionReasonLabel,
}

#[derive(carbide_instrument::Event)]
#[event(
    event_name = "api_admission_pending_wait_finished",
    metric_name = "carbide_api_admission_pending_wait_duration_seconds",
    component = "nico-api",
    log = off,
    metric = histogram,
    describe = "Duration API requests spent waiting for admission"
)]
struct PendingWaitFinished {
    #[observation]
    duration: Duration,
}

#[derive(carbide_instrument::Event)]
#[event(
    event_name = "api_admission_handler_execution_finished",
    metric_name = "carbide_api_admission_handler_execution_duration_seconds",
    component = "nico-api",
    log = off,
    metric = histogram,
    describe = "Duration of admitted API request handler execution"
)]
struct HandlerExecutionFinished {
    #[observation]
    duration: Duration,
}

struct CarbideAdmissionObserver;

impl AdmissionObserver for CarbideAdmissionObserver {
    fn admitted(&self) {
        carbide_instrument::emit(RequestAdmitted);
    }

    fn pending_finished(&self, duration: Duration) {
        carbide_instrument::emit(PendingWaitFinished { duration });
    }

    fn execution_finished(&self, duration: Duration) {
        carbide_instrument::emit(HandlerExecutionFinished { duration });
    }
}

pub(crate) struct ApiAdmissionControl {
    engine: Arc<SemaphoreAdmission>,
    rejection_log_limiter: LogLimiter<(RejectionReason, RequestTransport)>,
    _work_in_flight_gauge: ObservableGauge<u64>,
    _pending_requests_gauge: ObservableGauge<u64>,
}

impl ApiAdmissionControl {
    pub(crate) fn from_config(
        config: &ApiAdmissionControlConfig,
        meter: &Meter,
        shutdown: CancellationToken,
    ) -> eyre::Result<Option<Arc<Self>>> {
        let Some(limits) = config.admission_limits()? else {
            return Ok(None);
        };

        let observer: Arc<dyn AdmissionObserver> = Arc::new(CarbideAdmissionObserver);
        let engine = SemaphoreAdmission::new(limits, shutdown, observer);
        let work_in_flight_gauge = register_occupancy_gauge(
            meter,
            "carbide_api_admission_work_in_flight",
            "Number of API requests currently holding an execution slot",
            Arc::clone(&engine),
            |snapshot| snapshot.work_in_flight,
        );
        let pending_requests_gauge = register_occupancy_gauge(
            meter,
            "carbide_api_admission_pending_requests",
            "Number of API requests currently waiting for an execution slot",
            Arc::clone(&engine),
            |snapshot| snapshot.pending,
        );

        Ok(Some(Arc::new(Self {
            engine,
            rejection_log_limiter: LogLimiter::default(),
            _work_in_flight_gauge: work_in_flight_gauge,
            _pending_requests_gauge: pending_requests_gauge,
        })))
    }

    fn rejection_response(
        &self,
        transport: RequestTransport,
        reason: RejectionReason,
    ) -> Response<Body> {
        carbide_instrument::emit(RequestRejected {
            reason: reason.into(),
        });
        if self.rejection_log_limiter.should_log(
            &(reason, transport),
            "API request rejected by admission control",
        ) {
            tracing::warn!(
                rejection_reason = ?reason,
                request_transport = ?transport,
                "API request rejected by admission control"
            );
        }
        transport.overloaded_response()
    }

    #[cfg(test)]
    fn snapshot(&self) -> engine::AdmissionSnapshot {
        self.engine.snapshot()
    }
}

fn register_occupancy_gauge(
    meter: &Meter,
    name: &'static str,
    description: &'static str,
    engine: Arc<SemaphoreAdmission>,
    value: fn(engine::AdmissionSnapshot) -> usize,
) -> ObservableGauge<u64> {
    meter
        .u64_observable_gauge(name)
        .with_description(description)
        .with_callback(move |observer| {
            observer.observe(value(engine.snapshot()) as u64, &[]);
        })
        .build()
}

pub(crate) async fn enforce(
    State(control): State<Arc<ApiAdmissionControl>>,
    request: Request,
    next: Next,
) -> Response<Body> {
    let Some(transport) = RequestTransport::classify(request.uri().path()) else {
        return next.run(request).await;
    };

    let permit = match control.engine.acquire(()).await {
        Ok(permit) => permit,
        Err(reason) => return control.rejection_response(transport, reason),
    };
    let response = next.run(request).await;
    drop(permit);
    response
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::http::Request;
    use axum::routing::get;
    use carbide_instrument::testing::MetricsCapture;
    use futures::poll;
    use prost::Message;
    use prost_types::FileDescriptorSet;
    use tokio::sync::Notify;
    use tower::ServiceExt;

    use super::*;

    static ADMISSION_TEST_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn controller(
        max_work_in_flight: usize,
        max_pending: usize,
        pending_timeout: Duration,
        shutdown: CancellationToken,
    ) -> Arc<ApiAdmissionControl> {
        ApiAdmissionControl::from_config(
            &ApiAdmissionControlConfig {
                enabled: true,
                max_work_in_flight,
                max_pending,
                pending_timeout,
            },
            &opentelemetry::global::meter("api-admission-tests"),
            shutdown,
        )
        .expect("test admission config is valid")
        .expect("test admission is enabled")
    }

    #[test]
    fn request_classification_covers_business_and_infrastructure_routes() {
        let cases = [
            (
                ::rpc::service_path!("FindMachines"),
                Some(RequestTransport::Grpc),
            ),
            ("/admin", Some(RequestTransport::Http)),
            ("/admin/machine", Some(RequestTransport::Http)),
            ("/", None),
            (
                "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
                None,
            ),
            ("/administrator", None),
            ("/admin/staticity", Some(RequestTransport::Http)),
            ("/unrecognized", None),
        ];

        for (path, expected) in cases {
            assert_eq!(RequestTransport::classify(path), expected, "path: {path}");
        }

        for excluded_path in EXCLUDED_ADMIN_PATHS {
            assert!(
                is_path_or_child(excluded_path, "/admin"),
                "excluded path must be an admin path: {excluded_path}"
            );
            assert_eq!(RequestTransport::classify(excluded_path), None);
            let child_path = format!("{excluded_path}/child");
            assert_eq!(RequestTransport::classify(&child_path), None);
        }
    }

    #[test]
    fn every_forge_grpc_route_is_classified_for_admission() {
        let descriptor = FileDescriptorSet::decode(::rpc::REFLECTION_API_SERVICE_DESCRIPTOR)
            .expect("API service descriptor is valid");
        let mut route_count = 0;

        for file in descriptor.file {
            let package = file.package.unwrap_or_default();
            // The reflection descriptor also contains protocols used by API
            // clients. Only the forge package is mounted by this listener.
            if package != "forge" {
                continue;
            }

            for service in file.service {
                let service_name = service.name.clone().expect("service has a name");
                let qualified_service = if package.is_empty() {
                    service_name
                } else {
                    format!("{package}.{service_name}")
                };

                for method in service.method {
                    let method = method.name.expect("method has a name");
                    let path = format!("/{qualified_service}/{method}");
                    route_count += 1;
                    assert_eq!(
                        RequestTransport::classify(&path),
                        Some(RequestTransport::Grpc),
                        "gRPC route {path} bypasses admission; update the route policy"
                    );
                }
            }
        }

        assert!(route_count > 0, "API descriptor contains no gRPC routes");
    }

    #[test]
    fn overload_responses_match_the_request_transport() {
        let grpc = RequestTransport::Grpc.overloaded_response();
        assert_eq!(grpc.status(), StatusCode::OK);
        assert_eq!(grpc.headers().get("grpc-status").unwrap(), "8");

        let http = RequestTransport::Http.overloaded_response();
        assert_eq!(http.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(http.headers().get(header::RETRY_AFTER).unwrap(), "1");
    }

    #[tokio::test(start_paused = true)]
    async fn rejection_reason_is_preserved_in_metrics() {
        let _serial = ADMISSION_TEST_SERIAL.lock().await;
        let metrics = MetricsCapture::start();
        let control = controller(1, 1, Duration::from_secs(5), CancellationToken::new());
        let executing = control
            .engine
            .acquire(())
            .await
            .expect("first work is admitted");
        let pending = control.engine.acquire(());
        tokio::pin!(pending);
        assert!(poll!(&mut pending).is_pending());

        tokio::time::advance(Duration::from_secs(5)).await;
        let reason = pending.await.expect_err("pending work must time out");
        let response = control.rejection_response(RequestTransport::Grpc, reason);
        assert_eq!(response.headers().get("grpc-status").unwrap(), "8");
        drop(executing);

        assert_eq!(
            metrics.counter_delta(
                "carbide_api_admission_rejected_total",
                &[("reason", "queue_timeout")],
            ),
            1.0
        );
        assert_eq!(
            metrics
                .histogram_count_delta("carbide_api_admission_pending_wait_duration_seconds", &[]),
            1
        );

        let cases = [
            (RejectionReason::QueueFull, "queue_full"),
            (
                RejectionReason::ControllerUnavailable,
                "controller_unavailable",
            ),
            (RejectionReason::ShuttingDown, "shutting_down"),
        ];
        for (reason, label) in cases {
            let response = control.rejection_response(RequestTransport::Http, reason);
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(
                metrics
                    .counter_delta("carbide_api_admission_rejected_total", &[("reason", label)],),
                1.0,
                "rejection reason {reason:?} must be preserved"
            );
        }
    }

    #[test]
    fn rejection_log_limiter_distinguishes_reason_and_transport() {
        let control = controller(1, 1, Duration::from_secs(1), CancellationToken::new());
        let summary = "API request rejected by admission control";

        assert!(control.rejection_log_limiter.should_log(
            &(RejectionReason::QueueFull, RequestTransport::Grpc),
            summary
        ));
        assert!(!control.rejection_log_limiter.should_log(
            &(RejectionReason::QueueFull, RequestTransport::Grpc),
            summary
        ));
        assert!(control.rejection_log_limiter.should_log(
            &(RejectionReason::QueueFull, RequestTransport::Http),
            summary
        ));
        assert!(control.rejection_log_limiter.should_log(
            &(RejectionReason::QueueTimeout, RequestTransport::Grpc),
            summary
        ));
    }

    #[tokio::test]
    async fn grpc_and_admin_routes_share_capacity_and_bypasses_remain_available() {
        let _serial = ADMISSION_TEST_SERIAL.lock().await;
        let controller = controller(1, 1, Duration::from_secs(1), CancellationToken::new());
        let handler_calls = Arc::new(AtomicUsize::new(0));
        let handler_started = Arc::new(Notify::new());
        let release_handler = Arc::new(Notify::new());
        let blocking_handler = {
            let handler_calls = Arc::clone(&handler_calls);
            let handler_started = Arc::clone(&handler_started);
            let release_handler = Arc::clone(&release_handler);
            move || {
                let handler_calls = Arc::clone(&handler_calls);
                let handler_started = Arc::clone(&handler_started);
                let release_handler = Arc::clone(&release_handler);
                async move {
                    handler_calls.fetch_add(1, Ordering::SeqCst);
                    handler_started.notify_one();
                    release_handler.notified().await;
                    "business response"
                }
            }
        };
        let immediate_handler = {
            let handler_calls = Arc::clone(&handler_calls);
            move || {
                let handler_calls = Arc::clone(&handler_calls);
                async move {
                    handler_calls.fetch_add(1, Ordering::SeqCst);
                    "business response"
                }
            }
        };
        let router = Router::new()
            .route(::rpc::service_path!("Test"), get(immediate_handler))
            .route("/admin/business", get(blocking_handler))
            .route("/admin/static/test.css", get(|| async { "static" }))
            .layer(axum::middleware::from_fn_with_state(
                Arc::clone(&controller),
                enforce,
            ));

        let executing_router = router.clone();
        let executing = tokio::spawn(async move {
            executing_router
                .oneshot(
                    Request::builder()
                        .uri("/admin/business")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        handler_started.notified().await;
        assert_eq!(handler_calls.load(Ordering::SeqCst), 1);

        let pending_router = router.clone();
        let pending = tokio::spawn(async move {
            pending_router
                .oneshot(
                    Request::builder()
                        .uri(::rpc::service_path!("Test"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        for _ in 0..100 {
            if controller.snapshot().pending == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(controller.snapshot().pending, 1);

        let bypass = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/static/test.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bypass.status(), StatusCode::OK);

        let rejected = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/admin/business")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(rejected.headers().get(header::RETRY_AFTER).unwrap(), "1");
        assert_eq!(handler_calls.load(Ordering::SeqCst), 1);

        release_handler.notify_one();
        let executing = executing.await.unwrap();
        let admitted_grpc = pending.await.unwrap();
        assert_eq!(executing.status(), StatusCode::OK);
        assert_eq!(admitted_grpc.status(), StatusCode::OK);
        assert_eq!(handler_calls.load(Ordering::SeqCst), 2);
        // Capacity is released when handlers return, even while their response
        // bodies remain alive and unconsumed.
        assert_eq!(controller.snapshot().work_in_flight, 0);
    }
}
