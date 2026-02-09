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
#[template(path = "rack.html")]
struct Rack {
    racks: Vec<RackRecord>,
}

#[derive(Debug, serde::Serialize)]
struct RackRecord {
    id: String,
    rack_state: String,
    expected_compute_trays: String,
    current_compute_trays: String,
    expected_power_shelves: String,
    current_power_shelves: String,
}

/// Show all racks
pub async fn show_html(state: AxumState<Arc<Api>>) -> Response {
    let racks = match fetch_racks(&state).await {
        Ok(racks) => racks,
        Err((code, msg)) => return (code, msg).into_response(),
    };

    let display = Rack { racks };
    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

/// Show all racks as JSON
pub async fn show_json(state: AxumState<Arc<Api>>) -> Response {
    let racks = match fetch_racks(&state).await {
        Ok(racks) => racks,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    (StatusCode::OK, Json(racks)).into_response()
}

async fn fetch_racks(api: &Api) -> Result<Vec<RackRecord>, (http::StatusCode, String)> {
    let response = match api
        .get_rack(tonic::Request::new(rpc::forge::GetRackRequest { id: None }))
        .await
    {
        Ok(response) => response.into_inner(),
        Err(err) => {
            tracing::error!(%err, "list_racks");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to list racks".to_string(),
            ));
        }
    };

    let racks = response
        .rack
        .into_iter()
        .map(|rack| {
            let expected_compute_trays = rack.expected_compute_trays.join(", ");
            let current_compute_trays = rack
                .compute_trays
                .iter()
                .map(|m| m.to_string())
                .collect::<Vec<String>>()
                .join(", ");
            let expected_power_shelves = rack.expected_power_shelves.join(", ");
            let current_power_shelves = rack
                .power_shelves
                .iter()
                .map(|ps| ps.to_string())
                .collect::<Vec<String>>()
                .join(", ");

            RackRecord {
                id: rack.id.map(|id| id.to_string()).unwrap_or_default(),
                rack_state: rack.rack_state,
                expected_compute_trays: if expected_compute_trays.is_empty() {
                    "N/A".to_string()
                } else {
                    expected_compute_trays
                },
                current_compute_trays: if current_compute_trays.is_empty() {
                    "N/A".to_string()
                } else {
                    current_compute_trays
                },
                expected_power_shelves: if expected_power_shelves.is_empty() {
                    "N/A".to_string()
                } else {
                    expected_power_shelves
                },
                current_power_shelves: if current_power_shelves.is_empty() {
                    "N/A".to_string()
                } else {
                    current_power_shelves
                },
            }
        })
        .collect();

    Ok(racks)
}
