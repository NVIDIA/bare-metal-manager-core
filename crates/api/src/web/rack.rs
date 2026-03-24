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

use std::collections::HashMap;
use std::sync::Arc;

use askama::Template;
use axum::Json;
use axum::extract::{Path as AxumPath, Query, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use carbide_uuid::rack::RackId;
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "rack_show.html")]
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

#[derive(Template)]
#[template(path = "rack_detail.html")]
struct RackDetail {
    id: String,
    rack: Option<rpc::forge::Rack>,
    associated_machines: Vec<String>,
    associated_switches: Vec<String>,
    associated_power_shelves: Vec<String>,
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

pub async fn fetch_rack(
    api: &Api,
    rack_id: &RackId,
) -> Result<Option<::rpc::forge::Rack>, Response> {
    let request = tonic::Request::new(rpc::forge::GetRackRequest {
        id: Some(rack_id.to_string()),
    });

    // TODO: This should use FindRacksByIds
    let rack = match api
        .get_rack(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(r) if r.rack.is_empty() => {
            return Ok(None);
        }
        Ok(r) if r.rack.len() != 1 => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Rack list for {rack_id} returned {} racks", r.rack.len()),
            )
                .into_response());
        }
        Ok(mut r) => Some(r.rack.remove(0)),
        Err(err) if err.code() == tonic::Code::NotFound => {
            return Ok(None);
        }
        Err(err) => {
            tracing::error!(%err, %rack_id, "find_racks_by_ids");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, Html(err.to_string())).into_response());
        }
    };

    Ok(rack)
}

/// View details about a Rack
pub async fn detail(
    AxumState(api): AxumState<Arc<Api>>,
    AxumPath(rack_id): AxumPath<String>,
    Query(_params): Query<HashMap<String, String>>,
) -> Response {
    let (show_json, rack_id) = match rack_id.strip_suffix(".json") {
        Some(rack_id) => (true, rack_id.to_string()),
        None => (false, rack_id),
    };

    let rack_id = match rack_id.parse::<RackId>() {
        Ok(rack_id) => rack_id,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
    };

    let maybe_rack = match fetch_rack(&api, &rack_id).await {
        Ok(maybe_rack) => maybe_rack,
        Err(response) => return response,
    };

    if show_json {
        return (StatusCode::OK, Json(maybe_rack)).into_response();
    };

    let associated_machines = match fetch_machine_ids(api, rack_id.clone()).await {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, "fetch_machine_ids");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading machine IDs",
            )
                .into_response();
        }
    };

    let display = RackDetail {
        id: rack_id.to_string(),
        rack: maybe_rack,
        associated_machines,
        // TODO: Add discovered switches and powershelves
        associated_power_shelves: vec![],
        associated_switches: vec![],
    };

    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

pub async fn fetch_machine_ids(
    api: Arc<Api>,
    rack_id: RackId,
) -> Result<Vec<String>, tonic::Status> {
    let request = tonic::Request::new(rpc::forge::MachineSearchConfig {
        include_predicted_host: true,
        rack_id: Some(rack_id.clone()),
        ..Default::default()
    });

    Ok(api
        .find_machine_ids(request)
        .await?
        .into_inner()
        .machine_ids
        .into_iter()
        .map(|id| id.to_string())
        .collect())
}
