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

use std::str::FromStr;
use std::sync::Arc;

use askama::Template;
use axum::Json;
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use carbide_uuid::switch::SwitchId;
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "switch.html")]
struct Switch {
    switches: Vec<SwitchRecord>,
}

#[derive(Debug, serde::Serialize)]
struct SwitchRecord {
    id: String,
    name: String,
    state: String,
    location: String,
}

/// Show all switches
pub async fn show_html(state: AxumState<Arc<Api>>) -> Response {
    let switches = match fetch_switches(&state).await {
        Ok(switches) => switches,
        Err((code, msg)) => return (code, msg).into_response(),
    };

    let display = Switch { switches };
    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

/// Show all switches as JSON
pub async fn show_json(state: AxumState<Arc<Api>>) -> Response {
    let switches = match fetch_switches(&state).await {
        Ok(switches) => switches,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    (StatusCode::OK, Json(switches)).into_response()
}

async fn fetch_switches(api: &Api) -> Result<Vec<SwitchRecord>, (http::StatusCode, String)> {
    let response = match api
        .find_switches(tonic::Request::new(rpc::forge::SwitchQuery {
            name: None,
            switch_id: None,
        }))
        .await
    {
        Ok(response) => response.into_inner(),
        Err(err) => {
            tracing::error!(%err, "list_switches");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to list switches".to_string(),
            ));
        }
    };

    let switches = response
        .switches
        .into_iter()
        .map(|switch| {
            let state = if let Some(status) = &switch.status {
                if let Some(state_reason) = &status.state_reason {
                    match rpc::forge::ControllerStateOutcome::try_from(state_reason.outcome) {
                        Ok(outcome) => outcome.as_str_name().to_string(),
                        Err(_) => "Unknown".to_string(),
                    }
                } else {
                    status
                        .power_state
                        .clone()
                        .unwrap_or_else(|| "Unknown".to_string())
                }
            } else {
                "Unknown".to_string()
            };

            let config = switch.config.unwrap();
            SwitchRecord {
                id: switch.id.unwrap().to_string(),
                name: config.name,
                state,
                location: config.location.unwrap_or_else(|| "N/A".to_string()),
            }
        })
        .collect();

    Ok(switches)
}

#[derive(Template)]
#[template(path = "switch_detail.html")]
struct SwitchDetail {
    id: String,
    controller_state: String,
    name: String,
    location: String,
    enable_nmxc: bool,
    state_reason: Option<rpc::forge::ControllerStateReason>,
    power_state: Option<String>,
    health_status: Option<String>,
    bmc_info: Option<rpc::forge::BmcInfo>,
}

#[derive(serde::Serialize)]
struct SwitchDetailJson {
    id: String,
    controller_state: String,
    name: String,
    location: String,
    enable_nmxc: bool,
    power_state: Option<String>,
    health_status: Option<String>,
    bmc_ip: Option<String>,
    bmc_mac: Option<String>,
}

impl From<rpc::forge::Switch> for SwitchDetail {
    fn from(switch: rpc::forge::Switch) -> Self {
        let id = switch
            .id
            .as_ref()
            .map(|id| id.to_string())
            .unwrap_or_default();
        let config = switch.config.unwrap_or_default();
        let state_reason = switch.status.as_ref().and_then(|s| s.state_reason.clone());
        let power_state = switch.status.as_ref().and_then(|s| s.power_state.clone());
        let health_status = switch.status.as_ref().and_then(|s| s.health_status.clone());
        Self {
            id,
            controller_state: switch.controller_state,
            name: config.name,
            location: config.location.unwrap_or_else(|| "N/A".to_string()),
            enable_nmxc: config.enable_nmxc,
            state_reason,
            power_state,
            health_status,
            bmc_info: switch.bmc_info,
        }
    }
}

/// View details about a Switch.
pub async fn detail(
    AxumState(api): AxumState<Arc<Api>>,
    AxumPath(switch_id): AxumPath<String>,
) -> Response {
    let (show_json, switch_id) = match switch_id.strip_suffix(".json") {
        Some(id) => (true, id.to_string()),
        None => (false, switch_id),
    };

    let switch = match fetch_switch(&api, &switch_id).await {
        Ok(Some(switch)) => switch,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                format!("Switch {switch_id} not found"),
            )
                .into_response();
        }
        Err(response) => return response,
    };

    let detail = SwitchDetail::from(switch);

    if show_json {
        let json = SwitchDetailJson {
            id: detail.id.clone(),
            controller_state: detail.controller_state.clone(),
            name: detail.name.clone(),
            location: detail.location.clone(),
            enable_nmxc: detail.enable_nmxc,
            power_state: detail.power_state.clone(),
            health_status: detail.health_status.clone(),
            bmc_ip: detail.bmc_info.as_ref().and_then(|b| b.ip.clone()),
            bmc_mac: detail.bmc_info.as_ref().and_then(|b| b.mac.clone()),
        };
        return (StatusCode::OK, Json(json)).into_response();
    }

    (StatusCode::OK, Html(detail.render().unwrap())).into_response()
}

async fn fetch_switch(api: &Api, switch_id: &str) -> Result<Option<rpc::forge::Switch>, Response> {
    let switch_id_parsed = match SwitchId::from_str(switch_id) {
        Ok(id) => id,
        Err(_) => return Err((StatusCode::BAD_REQUEST, "Invalid switch ID").into_response()),
    };

    let response = match api
        .find_switches(tonic::Request::new(rpc::forge::SwitchQuery {
            name: None,
            switch_id: Some(switch_id_parsed),
        }))
        .await
    {
        Ok(response) => response.into_inner(),
        Err(err) if err.code() == tonic::Code::NotFound => return Ok(None),
        Err(err) => {
            tracing::error!(%err, %switch_id, "fetch_switch");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response());
        }
    };

    Ok(response.switches.into_iter().next())
}
