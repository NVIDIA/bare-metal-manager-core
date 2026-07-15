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

use axum::body::Body;
use axum::extract::{Request, State};
use axum::response::{Html, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use tower::Service;

use crate::host_machine::HostMachineHandle;
use crate::status::{MachineStatusConfig, MachinesStatusResponse};

pub fn append(router: Router, control_state: ControlState) -> Router {
    Router::new()
        .route("/", get(get_machines_ui))
        .route("/machines/status", get(get_machines_status))
        .route("/{*all}", any(process))
        .with_state(ControlRouter {
            inner: router,
            control_state,
        })
}

#[derive(Clone)]
pub struct ControlState {
    machine_handles: Arc<Vec<HostMachineHandle>>,
    status_config: MachineStatusConfig,
}

impl ControlState {
    pub fn new(
        machine_handles: Vec<HostMachineHandle>,
        status_config: MachineStatusConfig,
    ) -> Self {
        Self {
            machine_handles: Arc::new(machine_handles),
            status_config,
        }
    }

    fn machines_status(&self) -> MachinesStatusResponse {
        MachinesStatusResponse {
            machines: self
                .machine_handles
                .iter()
                .map(|machine| machine.status(&self.status_config))
                .collect(),
        }
    }
}

#[derive(Clone)]
struct ControlRouter {
    inner: Router,
    control_state: ControlState,
}

async fn get_machines_status(State(state): State<ControlRouter>) -> Json<MachinesStatusResponse> {
    Json(state.control_state.machines_status())
}

async fn get_machines_ui() -> Html<&'static str> {
    Html(include_str!("../web/index.html"))
}

async fn process(State(mut state): State<ControlRouter>, request: Request<Body>) -> Response {
    call_inner_router(&mut state.inner, request).await
}

async fn call_inner_router(router: &mut Router, request: Request<Body>) -> Response {
    let (head, body) = request.into_parts();

    let mut rb = Request::builder().uri(&head.uri).method(&head.method);
    for (key, value) in &head.headers {
        rb = rb.header(key, value);
    }
    let inner_request = rb.body(body).unwrap();

    router.call(inner_request).await.expect("Infallible error")
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    use super::{ControlState, append};
    use crate::status::MachineStatusConfig;

    #[tokio::test]
    async fn machines_status_does_not_require_bmc_routes() {
        let router = append(
            Router::new(),
            ControlState::new(Vec::new(), MachineStatusConfig::new(1266)),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/machines/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], br#"{"machines":[]}"#);
    }

    #[tokio::test]
    async fn machines_ui_returns_html() {
        let router = append(
            Router::new().route("/redfish/v1", get(|| async { "bmc" })),
            ControlState::new(Vec::new(), MachineStatusConfig::new(1266)),
        );

        let response = router
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("machine-a-tron machines"));
    }

    #[tokio::test]
    async fn unmatched_paths_forward_to_inner_router() {
        let router = append(
            Router::new().route("/redfish/v1", get(|| async { "bmc" })),
            ControlState::new(Vec::new(), MachineStatusConfig::new(1266)),
        );

        let response = router
            .oneshot(
                Request::builder()
                    .uri("/redfish/v1")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"bmc");
    }
}
