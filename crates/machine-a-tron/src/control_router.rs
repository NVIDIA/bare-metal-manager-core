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
use axum::extract::{Path, Request, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{any, get};
use axum::{Json, Router};
use bmc_mock::injection::{InjectionStore, Rule, RuleId};
use carbide_uuid::machine::MachineId;
use tower::Service;
use uuid::Uuid;

use crate::host_machine::HostMachineHandle;
use crate::status::{MachineStatusConfig, MachinesStatusResponse};

pub fn append(router: Router, control_state: ControlState) -> Router {
    Router::new()
        .route("/", get(get_machines_ui))
        .route("/machines/status", get(get_machines_status))
        .route(
            "/machines/{id}/bmc/injection/rules",
            get(list_bmc_injection_rules).post(upsert_bmc_injection_rule),
        )
        .route(
            "/machines/{id}/bmc/injection/rules/{rule_id}",
            axum::routing::delete(delete_bmc_injection_rule),
        )
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

    fn machine(&self, id: &str) -> Option<Arc<InjectionStore>> {
        let mat_id = Uuid::parse_str(id).ok();
        let machine_id = id.parse::<MachineId>().ok();
        let matches = |candidate_mat_id, candidate_machine_id: Option<MachineId>| {
            mat_id.is_some_and(|id| candidate_mat_id == id)
                || machine_id
                    .as_ref()
                    .is_some_and(|id| candidate_machine_id.as_ref() == Some(id))
        };

        for machine in self.machine_handles.iter() {
            if matches(machine.mat_id(), machine.observed_machine_id()) {
                return Some(machine.bmc_injection_store());
            }
            if let Some(dpu) = machine
                .dpus()
                .iter()
                .find(|dpu| matches(dpu.mat_id(), dpu.observed_machine_id()))
            {
                return Some(dpu.bmc_injection_store());
            }
        }
        None
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

async fn list_bmc_injection_rules(
    State(state): State<ControlRouter>,
    Path(id): Path<String>,
) -> Response {
    let Some(machine) = state.control_state.machine(&id) else {
        return machine_not_found();
    };
    Json(list_rules(&machine)).into_response()
}

async fn upsert_bmc_injection_rule(
    State(state): State<ControlRouter>,
    Path(id): Path<String>,
    Json(rule): Json<Rule>,
) -> Response {
    let Some(machine) = state.control_state.machine(&id) else {
        return machine_not_found();
    };
    machine.upsert(rule);
    Json(list_rules(&machine)).into_response()
}

async fn delete_bmc_injection_rule(
    State(state): State<ControlRouter>,
    Path((id, rule_id)): Path<(String, String)>,
) -> Response {
    let Some(machine) = state.control_state.machine(&id) else {
        return machine_not_found();
    };
    let rule_id = RuleId::from(rule_id);
    if machine.delete(&rule_id) {
        Json(list_rules(&machine)).into_response()
    } else {
        (
            StatusCode::NOT_FOUND,
            format!("BMC injection rule not found: {rule_id}"),
        )
            .into_response()
    }
}

fn list_rules(machine: &InjectionStore) -> Vec<Rule> {
    machine
        .list()
        .into_iter()
        .map(|rule| (*rule).clone())
        .collect()
}

fn machine_not_found() -> Response {
    (StatusCode::NOT_FOUND, "machine not found").into_response()
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
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::{ControlState, append};
    use crate::dpu_machine::DpuMachineHandle;
    use crate::host_machine::HostMachineHandle;
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
    async fn bmc_injection_rules_require_known_machine() {
        let router = append(
            Router::new(),
            ControlState::new(Vec::new(), MachineStatusConfig::new(1266)),
        );

        let get_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/machines/unknown/bmc/injection/rules")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::NOT_FOUND);

        let body = to_bytes(get_response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], b"machine not found");

        let post_response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/machines/unknown/bmc/injection/rules")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"id":"test","selector":{"Path":{"method":"GET","glob":"/**"}},"action":{"Status":503}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post_response.status(), StatusCode::NOT_FOUND);

        let delete_response = router
            .oneshot(
                Request::builder()
                    .method(Method::DELETE)
                    .uri("/machines/unknown/bmc/injection/rules/test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(delete_response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn bmc_injection_rules_accept_dpu_id() {
        let dpu_id = Uuid::new_v4();
        let observed_dpu_id = "fm100ds7blqjsadm2uuh3qqbf1h7k8pmf47um6v9uckrg7l03po8mhqgvng"
            .parse()
            .unwrap();
        let dpu = DpuMachineHandle::for_control_test(dpu_id, Some(observed_dpu_id));
        let host = HostMachineHandle::for_control_test(vec![dpu]);
        let router = append(
            Router::new(),
            ControlState::new(vec![host.clone()], MachineStatusConfig::new(1266)),
        );

        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("/machines/{dpu_id}/bmc/injection/rules"))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"id":"dpu-test","selector":{"Path":{"method":"GET","glob":"/**"}},"action":{"Status":503}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("dpu-test"));

        let response = router
            .oneshot(
                Request::builder()
                    .uri(format!("/machines/{observed_dpu_id}/bmc/injection/rules"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(String::from_utf8_lossy(&body).contains("dpu-test"));
        assert!(host.bmc_injection_store().list().is_empty());
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
