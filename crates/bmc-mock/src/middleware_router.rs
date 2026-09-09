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

use axum::Router;
use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use carbide_axum_utils::router::call_router_with_new_request;
use tracing::instrument;

use crate::availability::BmcAvailabilityState;
use crate::injection::InjectionStore;
use crate::{Callbacks, refresh_backend_state};

#[derive(Clone)]
pub(crate) struct StateRefreshHandled;

pub(super) fn append(
    mat_host_id: String,
    router: Router,
    injection: Arc<InjectionStore>,
    availability: Option<Arc<BmcAvailabilityState>>,
    callbacks: Arc<dyn Callbacks>,
) -> Router {
    Router::new()
        .route("/{*all}", any(process))
        .with_state(Middleware {
            mat_host_id,
            inner: router,
            injection,
            availability,
            callbacks,
        })
}

#[instrument(skip_all, fields(mat_host_id = %state.mat_host_id))]
async fn process(State(mut state): State<Middleware>, request: Request<Body>) -> Response {
    let is_safe = request.method().is_safe();
    let method = request.method().clone();
    let path = request.uri().path().to_string();

    // BMC self-reset window: while the (simulated) controller reboots,
    // NOTHING answers — before auth, before injection, before routing.
    //
    // A real BMC mid-reset yields transport errors first, then 503s while
    // its web server restarts. We can only produce the latter: all mocks
    // share one TLS listener (authority-multiplexed CombinedServer) with
    // pooled keep-alive connections, so by the time a handler runs it can
    // only return HTTP. Behaviorally equivalent for nico: its readiness
    // probe and error paths collapse transport errors and error statuses
    // into the same retry decision (machine-controller factory_reset.rs,
    // `wait_for_bmc`).
    if let Some(availability) = state.availability.as_ref()
        && availability.is_offline()
    {
        return axum::http::StatusCode::SERVICE_UNAVAILABLE.into_response();
    }

    if let Some(short) = state.injection.pre_handle(&method, &path).await {
        return short;
    }

    let response = state.call_inner_router(request).await;
    let response = state.injection.post_handle(&path, response).await;

    if !response.status().is_success() {
        tracing::warn!(
            method = %method,
            path,
            http_status = %response.status(),
            "BMC mock request returned unsuccessful response"
        );
    }
    if !is_safe
        && response.status().is_success()
        && response.extensions().get::<StateRefreshHandled>().is_none()
        && let Err(error) = refresh_backend_state(Arc::clone(&state.callbacks)).await
    {
        tracing::error!(
            method = %method,
            path,
            error = %error,
            "could not reconcile backend state after BMC mock request",
        );
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    response
}

#[derive(Clone)]
struct Middleware {
    mat_host_id: String,
    inner: Router,
    injection: Arc<InjectionStore>,
    availability: Option<Arc<BmcAvailabilityState>>,
    callbacks: Arc<dyn Callbacks>,
}

impl Middleware {
    async fn call_inner_router(&mut self, request: Request<Body>) -> axum::response::Response {
        call_router_with_new_request(&mut self.inner, request).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use super::*;
    use crate::{MockPowerState, SetSystemPowerError, SystemPowerControl};

    #[derive(Debug)]
    struct BlockingRefresh {
        started: Arc<AtomicBool>,
        finished: Arc<AtomicBool>,
    }

    impl Callbacks for BlockingRefresh {
        fn get_power_state(&self) -> MockPowerState {
            MockPowerState::Off
        }

        fn send_power_command(
            &self,
            _reset_type: SystemPowerControl,
        ) -> Result<(), SetSystemPowerError> {
            Ok(())
        }

        fn state_refresh_indication(&self) -> Result<(), String> {
            self.started.store(true, Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(100));
            self.finished.store(true, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn backend_refresh_does_not_block_the_async_executor() {
        let started = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let callbacks: Arc<dyn Callbacks> = Arc::new(BlockingRefresh {
            started: Arc::clone(&started),
            finished: Arc::clone(&finished),
        });

        let refresh = tokio::spawn(refresh_backend_state(callbacks));
        tokio::task::yield_now().await;

        assert!(!finished.load(Ordering::SeqCst));
        refresh.await.unwrap().unwrap();
        assert!(started.load(Ordering::SeqCst));
        assert!(finished.load(Ordering::SeqCst));
    }
}
