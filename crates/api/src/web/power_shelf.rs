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
#[template(path = "power_shelf.html")]
struct PowerShelf {
    power_shelves: Vec<PowerShelfRecord>,
}

#[derive(Debug, serde::Serialize)]
struct PowerShelfRecord {
    id: String,
    name: String,
    state: String,
    capacity: String,
    voltage: String,
    location: String,
}

/// Show all power shelves
pub async fn show_html(state: AxumState<Arc<Api>>) -> Response {
    let power_shelves = match fetch_power_shelves(&state).await {
        Ok(shelves) => shelves,
        Err((code, msg)) => return (code, msg).into_response(),
    };

    let display = PowerShelf { power_shelves };
    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

/// Show all power shelves as JSON
pub async fn show_json(state: AxumState<Arc<Api>>) -> Response {
    let power_shelves = match fetch_power_shelves(&state).await {
        Ok(shelves) => shelves,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    (StatusCode::OK, Json(power_shelves)).into_response()
}

async fn fetch_power_shelves(
    api: &Api,
) -> Result<Vec<PowerShelfRecord>, (http::StatusCode, String)> {
    let response = match api
        .find_power_shelves(tonic::Request::new(rpc::forge::PowerShelfQuery {
            name: None,
            power_shelf_id: None,
        }))
        .await
    {
        Ok(response) => response.into_inner(),
        Err(err) => {
            tracing::error!(%err, "list_power_shelves");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to list power shelves".to_string(),
            ));
        }
    };

    let power_shelves = response
        .power_shelves
        .into_iter()
        .map(|shelf| {
            let state = if let Some(status) = &shelf.status {
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

            let config = shelf.config.unwrap();
            PowerShelfRecord {
                id: shelf.id.unwrap().to_string(),
                name: config.name,
                state,
                capacity: config
                    .capacity
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
                voltage: config
                    .voltage
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
                location: config.location.unwrap_or_else(|| "N/A".to_string()),
            }
        })
        .collect();

    Ok(power_shelves)
}
