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

use askama::Template;
use axum::Json;
use axum::extract::State as AxumState;
use axum::response::{Html, IntoResponse, Response};
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;

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
            include_addresses: None,
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
