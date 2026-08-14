/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

use std::collections::{BTreeMap, VecDeque};
use std::convert::Infallible;
use std::sync::Mutex;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;

use crate::bmc_state::BmcState;
use crate::json::JsonExt;

pub const SERVICE_PATH: &str = "/redfish/v1/EventService";
pub const SSE_PATH: &str = "/redfish/v1/EventService/SSE";
pub const TRIGGER_PATH: &str = "/redfish/v1/EventService/Actions/EventService.TriggerScenario";

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventServiceConfig {
    #[serde(default)]
    pub scenarios: BTreeMap<String, EventScenario>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EventScenario {
    pub payload: Value,
    #[serde(default)]
    pub linked_resources: BTreeMap<String, Vec<LinkedResourceResponse>>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LinkedResourceResponse {
    pub status: u16,
    #[serde(default)]
    pub body: Value,
}

pub(crate) struct EventServiceState {
    config: EventServiceConfig,
    linked_responses: Mutex<BTreeMap<String, VecDeque<LinkedResourceResponse>>>,
    events: broadcast::Sender<Value>,
}

impl EventServiceState {
    pub(crate) fn new(config: EventServiceConfig) -> Self {
        let (events, _) = broadcast::channel(16);
        Self {
            config,
            linked_responses: Mutex::new(BTreeMap::new()),
            events,
        }
    }

    fn trigger(&self, name: &str) -> Result<(), TriggerError> {
        let scenario = self
            .config
            .scenarios
            .get(name)
            .ok_or(TriggerError::UnknownScenario)?;
        let mut linked_responses = self.linked_responses.lock().unwrap();
        linked_responses.clear();
        for (path, responses) in &scenario.linked_resources {
            linked_responses.insert(path.clone(), responses.clone().into());
        }
        drop(linked_responses);
        self.events
            .send(scenario.payload.clone())
            .map(|_| ())
            .map_err(|_| TriggerError::NoSubscriber)
    }

    fn linked_response(&self, path: &str) -> Option<LinkedResourceResponse> {
        let mut responses = self.linked_responses.lock().unwrap();
        let responses = responses.get_mut(path)?;
        if responses.len() > 1 {
            responses.pop_front()
        } else {
            responses.front().cloned()
        }
    }
}

enum TriggerError {
    UnknownScenario,
    NoSubscriber,
}

#[derive(Deserialize)]
struct TriggerRequest {
    scenario: String,
}

pub(crate) fn add_routes(router: Router<BmcState>) -> Router<BmcState> {
    router
        .route(SERVICE_PATH, get(get_service))
        .route(SSE_PATH, get(sse))
        .route(TRIGGER_PATH, post(trigger))
        .route("/redfish/v1/{*resource}", get(get_linked_resource))
}

async fn get_service(State(state): State<BmcState>) -> Response {
    let Some(_) = state.event_service_state else {
        return StatusCode::NOT_FOUND.into_response();
    };
    json!({
        "@odata.id": SERVICE_PATH,
        "@odata.type": "#EventService.v1_8_0.EventService",
        "Id": "EventService",
        "Name": "Event Service",
        "ServiceEnabled": true,
        "ServerSentEventUri": SSE_PATH,
        "Actions": {
            "#EventService.TriggerScenario": { "target": TRIGGER_PATH }
        }
    })
    .into_ok_response()
}

async fn sse(State(state): State<BmcState>) -> Response {
    let Some(event_service) = state.event_service_state else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let stream = BroadcastStream::new(event_service.events.subscribe()).filter_map(|event| async {
        event
            .ok()
            .map(|payload| Ok::<_, Infallible>(Event::default().data(payload.to_string())))
    });
    Sse::new(stream)
        .keep_alive(KeepAlive::default())
        .into_response()
}

async fn trigger(State(state): State<BmcState>, Json(request): Json<TriggerRequest>) -> Response {
    let Some(event_service) = state.event_service_state else {
        return StatusCode::NOT_FOUND.into_response();
    };
    match event_service.trigger(&request.scenario) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(TriggerError::UnknownScenario) => {
            (StatusCode::NOT_FOUND, "unknown event scenario").into_response()
        }
        Err(TriggerError::NoSubscriber) => {
            (StatusCode::CONFLICT, "no active SSE subscriber").into_response()
        }
    }
}

async fn get_linked_resource(
    State(state): State<BmcState>,
    Path(resource): Path<String>,
) -> Response {
    let Some(event_service) = state.event_service_state else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let path = format!("/redfish/v1/{resource}");
    let Some(response) = event_service.linked_response(&path) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let status = StatusCode::from_u16(response.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    (status, Json(response.body)).into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    use super::*;
    use crate::test_support::{NoopCallbacks, host_info};
    use crate::{HardwareType, MachineRouterOptions, machine_router};

    #[tokio::test]
    async fn event_service_is_opt_in() {
        let (router, _) = machine_router(
            &host_info(HardwareType::GenericAmi),
            Arc::new(NoopCallbacks),
            "test-host-id".to_string(),
            false,
            MachineRouterOptions::default(),
        );

        let root = router
            .clone()
            .oneshot(Request::get("/redfish/v1").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let root = http_body_util::BodyExt::collect(root.into_body())
            .await
            .unwrap()
            .to_bytes();
        let root: Value = serde_json::from_slice(&root).unwrap();
        assert!(root.get("EventService").is_none());

        let response = router
            .oneshot(Request::get(SERVICE_PATH).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
