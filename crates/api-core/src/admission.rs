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

//! Shared admission control for gRPC and admin HTTP business requests.
//!
//! The middleware owns transport classification and response mapping. The
//! controller owns admission policy and returns an RAII work permit. Keeping
//! that boundary explicit lets fair scheduling replace the global semaphore
//! policy without moving handler futures out of their requesting tasks.

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{Response, StatusCode, header};
use axum::middleware::Next;
use axum::response::IntoResponse;
use opentelemetry::metrics::{Meter, ObservableGauge};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, TryAcquireError};
use tokio_util::sync::CancellationToken;

use crate::cfg::file::ApiAdmissionControlConfig;
use crate::logging::log_limiter::LogLimiter;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
            || is_path_or_child(path, "/admin/static")
            || is_path_or_child(path, "/admin/auth-callback")
            || is_path_or_child(path, "/admin/logs")
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, carbide_instrument::LabelValue)]
enum RejectionReason {
    QueueFull,
    QueueTimeout,
    ControllerUnavailable,
    ShuttingDown,
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
    reason: RejectionReason,
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

pub(crate) struct AdmissionController {
    work_slots: Arc<Semaphore>,
    pending_slots: Arc<Semaphore>,
    pending_timeout: Duration,
    shutdown: CancellationToken,
    rejection_log_limiter: LogLimiter<RejectionReason>,
    _work_in_flight_gauge: ObservableGauge<u64>,
    _pending_requests_gauge: ObservableGauge<u64>,
}

impl AdmissionController {
    pub(crate) fn new(
        config: &ApiAdmissionControlConfig,
        meter: &Meter,
        shutdown: CancellationToken,
    ) -> eyre::Result<Arc<Self>> {
        config.validate()?;

        let work_slots = Arc::new(Semaphore::new(config.max_work_in_flight));
        let pending_slots = Arc::new(Semaphore::new(config.max_pending));
        let work_in_flight_gauge = register_occupancy_gauge(
            meter,
            "carbide_api_admission_work_in_flight",
            "Number of API requests currently holding an execution slot",
            config.max_work_in_flight,
            Arc::clone(&work_slots),
        );
        let pending_requests_gauge = register_occupancy_gauge(
            meter,
            "carbide_api_admission_pending_requests",
            "Number of API requests currently waiting for an execution slot",
            config.max_pending,
            Arc::clone(&pending_slots),
        );

        Ok(Arc::new(Self {
            work_slots,
            pending_slots,
            pending_timeout: config.pending_timeout,
            shutdown,
            rejection_log_limiter: LogLimiter::default(),
            _work_in_flight_gauge: work_in_flight_gauge,
            _pending_requests_gauge: pending_requests_gauge,
        }))
    }

    async fn acquire(&self) -> Result<WorkPermit, RejectionReason> {
        if self.shutdown.is_cancelled() {
            return self.reject(RejectionReason::ShuttingDown);
        }

        match Arc::clone(&self.work_slots).try_acquire_owned() {
            Ok(permit) => return Ok(self.admit(permit)),
            Err(TryAcquireError::Closed) => {
                return self.reject(RejectionReason::ControllerUnavailable);
            }
            Err(TryAcquireError::NoPermits) => {}
        }

        let pending_permit = match Arc::clone(&self.pending_slots).try_acquire_owned() {
            Ok(permit) => permit,
            Err(TryAcquireError::NoPermits) => {
                return self.reject(RejectionReason::QueueFull);
            }
            Err(TryAcquireError::Closed) => {
                return self.reject(RejectionReason::ControllerUnavailable);
            }
        };

        let pending_wait = PendingWait {
            _permit: pending_permit,
            started: Instant::now(),
        };
        let acquisition = tokio::time::timeout(
            self.pending_timeout,
            Arc::clone(&self.work_slots).acquire_owned(),
        );
        let result = tokio::select! {
            biased;
            () = self.shutdown.cancelled() => Err(RejectionReason::ShuttingDown),
            result = acquisition => match result {
                Ok(Ok(permit)) => Ok(permit),
                Ok(Err(_)) => Err(RejectionReason::ControllerUnavailable),
                Err(_) => Err(RejectionReason::QueueTimeout),
            },
        };
        drop(pending_wait);

        match result {
            Ok(permit) => Ok(self.admit(permit)),
            Err(reason) => self.reject(reason),
        }
    }

    fn admit(&self, permit: OwnedSemaphorePermit) -> WorkPermit {
        carbide_instrument::emit(RequestAdmitted);
        WorkPermit {
            _permit: permit,
            started: Instant::now(),
        }
    }

    fn reject<T>(&self, reason: RejectionReason) -> Result<T, RejectionReason> {
        carbide_instrument::emit(RequestRejected { reason });
        if self
            .rejection_log_limiter
            .should_log(&reason, "API request rejected by admission control")
        {
            tracing::warn!(?reason, "API request rejected by admission control");
        }
        Err(reason)
    }

    #[cfg(test)]
    fn occupancy(&self) -> (usize, usize) {
        (
            self.work_slots.available_permits(),
            self.pending_slots.available_permits(),
        )
    }
}

fn register_occupancy_gauge(
    meter: &Meter,
    name: &'static str,
    description: &'static str,
    capacity: usize,
    semaphore: Arc<Semaphore>,
) -> ObservableGauge<u64> {
    meter
        .u64_observable_gauge(name)
        .with_description(description)
        .with_callback(move |observer| {
            let occupied = capacity.saturating_sub(semaphore.available_permits());
            observer.observe(occupied as u64, &[]);
        })
        .build()
}

#[derive(Debug)]
struct WorkPermit {
    _permit: OwnedSemaphorePermit,
    started: Instant,
}

struct PendingWait {
    _permit: OwnedSemaphorePermit,
    started: Instant,
}

impl Drop for PendingWait {
    fn drop(&mut self) {
        carbide_instrument::emit(PendingWaitFinished {
            duration: self.started.elapsed(),
        });
    }
}

impl Drop for WorkPermit {
    fn drop(&mut self) {
        carbide_instrument::emit(HandlerExecutionFinished {
            duration: self.started.elapsed(),
        });
    }
}

pub(crate) async fn enforce(
    State(controller): State<Arc<AdmissionController>>,
    request: Request,
    next: Next,
) -> Response<Body> {
    let Some(transport) = RequestTransport::classify(request.uri().path()) else {
        return next.run(request).await;
    };

    let permit = match controller.acquire().await {
        Ok(permit) => permit,
        Err(_) => return transport.overloaded_response(),
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
    ) -> Arc<AdmissionController> {
        AdmissionController::new(
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
            ("/admin/static/carbide.css", None),
            ("/admin/auth-callback", None),
            ("/admin/logs/api/stream", None),
            ("/administrator", None),
            ("/admin/staticity", Some(RequestTransport::Http)),
            ("/unrecognized", None),
        ];

        for (path, expected) in cases {
            assert_eq!(RequestTransport::classify(path), expected, "path: {path}");
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

    #[tokio::test]
    async fn pending_capacity_is_bounded_and_cancellation_releases_it() {
        let _serial = ADMISSION_TEST_SERIAL.lock().await;
        let controller = controller(1, 1, Duration::from_secs(1), CancellationToken::new());
        let executing = controller.acquire().await.expect("first work is admitted");
        assert_eq!(controller.occupancy(), (0, 1));

        {
            let pending = controller.acquire();
            tokio::pin!(pending);
            assert!(
                tokio::time::timeout(Duration::from_millis(10), &mut pending)
                    .await
                    .is_err(),
                "request should remain pending"
            );
            assert_eq!(controller.occupancy(), (0, 0));
            assert_eq!(
                controller
                    .acquire()
                    .await
                    .expect_err("pending queue is full"),
                RejectionReason::QueueFull
            );
        }

        assert_eq!(controller.occupancy(), (0, 1));
        drop(executing);
        assert_eq!(controller.occupancy(), (1, 1));
    }

    #[tokio::test]
    async fn timed_out_request_is_removed_and_metrics_record_the_outcomes() {
        let _serial = ADMISSION_TEST_SERIAL.lock().await;
        let metrics = MetricsCapture::start();
        let controller = controller(1, 1, Duration::from_millis(10), CancellationToken::new());
        let executing = controller.acquire().await.expect("first work is admitted");
        let rejection = controller
            .acquire()
            .await
            .expect_err("second request should time out");
        assert_eq!(rejection, RejectionReason::QueueTimeout);
        assert_eq!(controller.occupancy(), (0, 1));
        drop(executing);

        assert_eq!(
            metrics.counter_delta("carbide_api_admission_admitted_total", &[]),
            1.0
        );
        assert_eq!(
            metrics.counter_delta(
                "carbide_api_admission_rejected_total",
                &[("reason", "queue_timeout")],
            ),
            1.0
        );
        assert_eq!(
            metrics
                .histogram_count_delta("carbide_api_admission_pending_wait_duration_seconds", &[],),
            1
        );
        assert_eq!(
            metrics.histogram_count_delta(
                "carbide_api_admission_handler_execution_duration_seconds",
                &[],
            ),
            1
        );
    }

    #[tokio::test]
    async fn shutdown_and_closed_controller_are_rejected() {
        let _serial = ADMISSION_TEST_SERIAL.lock().await;
        let shutdown = CancellationToken::new();
        let shutting_down_controller = controller(1, 1, Duration::from_secs(1), shutdown.clone());
        shutdown.cancel();
        assert_eq!(
            shutting_down_controller
                .acquire()
                .await
                .expect_err("shutdown rejects work"),
            RejectionReason::ShuttingDown
        );

        let controller = controller(1, 1, Duration::from_secs(1), CancellationToken::new());
        controller.work_slots.close();
        assert_eq!(
            controller
                .acquire()
                .await
                .expect_err("closed controller rejects work"),
            RejectionReason::ControllerUnavailable
        );
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
            if controller.occupancy() == (0, 0) {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(controller.occupancy(), (0, 0));

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
        assert_eq!(controller.occupancy(), (1, 1));
    }
}
