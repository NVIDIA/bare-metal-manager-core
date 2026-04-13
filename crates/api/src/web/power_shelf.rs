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
use carbide_uuid::power_shelf::PowerShelfId;
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;

use super::filters;
use crate::api::Api;

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[derive(Template)]
#[template(path = "power_shelf_show.html")]
struct PowerShelfShow {
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
        Err(err) => {
            tracing::error!(%err, "fetch_power_shelves");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading power shelves",
            )
                .into_response();
        }
    };

    let power_shelves = power_shelves
        .power_shelves
        .into_iter()
        .map(|shelf| {
            let state = shelf
                .status
                .as_ref()
                .and_then(|s| s.controller_state.clone())
                .map(|s| capitalize(&s))
                .unwrap_or_else(|| "Unknown".to_string());

            let config = shelf.config.unwrap_or_default();
            PowerShelfRecord {
                id: shelf.id.map(|id| id.to_string()).unwrap_or_default(),
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

    let display = PowerShelfShow { power_shelves };
    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

/// Show all power shelves as JSON
pub async fn show_json(state: AxumState<Arc<Api>>) -> Response {
    let power_shelves = match fetch_power_shelves(&state).await {
        Ok(shelves) => shelves,
        Err(err) => {
            tracing::error!(%err, "fetch_power_shelves");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Error loading power shelves",
            )
                .into_response();
        }
    };
    let _ = serde_json::to_string(&power_shelves);
    (StatusCode::OK, Json(power_shelves)).into_response()
}

#[derive(Template)]
#[template(path = "power_shelf_detail.html")]
struct PowerShelfDetail {
    id: String,
    rack_id: String,
    controller_state: String,
    state_version: String,
    time_in_state: String,
    state_reason: Option<rpc::forge::ControllerStateReason>,
    power_state: Option<String>,
    name: String,
    location: String,
    capacity: String,
    voltage: String,
    bmc_info: Option<rpc::forge::BmcInfo>,
    metadata_detail: super::MetadataDetail,
}

impl PowerShelfDetail {
    fn new(shelf: rpc::forge::PowerShelf) -> Self {
        let id = shelf
            .id
            .as_ref()
            .map(|id| id.to_string())
            .unwrap_or_default();
        let config = shelf.config.unwrap_or_default();
        let state_reason = shelf.status.as_ref().and_then(|s| s.state_reason.clone());
        let power_state = shelf.status.as_ref().and_then(|s| s.power_state.clone());
        let controller_state = shelf
            .status
            .as_ref()
            .and_then(|s| s.controller_state.clone())
            .map(|s| capitalize(&s))
            .unwrap_or_else(|| "Unknown".to_string());
        let time_in_state = config_version::since_state_change_humanized(&shelf.state_version);
        let metadata_detail = super::MetadataDetail {
            metadata: shelf.metadata.unwrap_or_default(),
            metadata_version: shelf.version,
        };
        Self {
            id,
            rack_id: shelf.rack_id.map(|id| id.to_string()).unwrap_or_default(),
            controller_state,
            state_version: shelf.state_version,
            time_in_state,
            state_reason,
            power_state,
            name: config.name,
            location: config.location.unwrap_or_else(|| "N/A".to_string()),
            capacity: config
                .capacity
                .map(|c| c.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            voltage: config
                .voltage
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            bmc_info: shelf.bmc_info,
            metadata_detail,
        }
    }
}

/// View details about a Power Shelf.
pub async fn detail(
    AxumState(api): AxumState<Arc<Api>>,
    AxumPath(power_shelf_id): AxumPath<String>,
) -> Response {
    let (show_json, power_shelf_id) = match power_shelf_id.strip_suffix(".json") {
        Some(id) => (true, id.to_string()),
        None => (false, power_shelf_id),
    };

    let shelf = match fetch_power_shelf(&api, &power_shelf_id).await {
        Ok(Some(shelf)) => shelf,
        Ok(None) => {
            return super::not_found_response(power_shelf_id);
        }
        Err(response) => return response,
    };

    if show_json {
        return (StatusCode::OK, Json(shelf)).into_response();
    }

    let detail = PowerShelfDetail::new(shelf);
    (StatusCode::OK, Html(detail.render().unwrap())).into_response()
}

async fn fetch_power_shelf(
    api: &Api,
    power_shelf_id: &str,
) -> Result<Option<rpc::forge::PowerShelf>, Response> {
    let power_shelf_id_parsed = match PowerShelfId::from_str(power_shelf_id) {
        Ok(id) => id,
        Err(_) => return Err((StatusCode::BAD_REQUEST, "Invalid power shelf ID").into_response()),
    };

    let response = match api
        .find_power_shelves(tonic::Request::new(rpc::forge::PowerShelfQuery {
            name: None,
            power_shelf_id: Some(power_shelf_id_parsed),
        }))
        .await
    {
        Ok(response) => response.into_inner(),
        Err(err) if err.code() == tonic::Code::NotFound => return Ok(None),
        Err(err) => {
            tracing::error!(%err, %power_shelf_id, "fetch_power_shelf");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, err.to_string()).into_response());
        }
    };

    Ok(response.power_shelves.into_iter().next())
}

async fn fetch_power_shelves(api: &Api) -> Result<rpc::forge::PowerShelfList, tonic::Status> {
    // Use find_power_shelf_ids (which respects DeletedFilter::Exclude by default)
    // followed by find_power_shelves_by_ids (which also fetches BMC info).
    let power_shelf_ids = api
        .find_power_shelf_ids(tonic::Request::new(
            rpc::forge::PowerShelfSearchFilter::default(),
        ))
        .await?
        .into_inner()
        .ids;

    if power_shelf_ids.is_empty() {
        return Ok(Default::default());
    }

    let mut power_shelves = Vec::new();
    let mut offset = 0;
    while offset < power_shelf_ids.len() {
        const PAGE_SIZE: usize = 100;
        let page_size = PAGE_SIZE.min(power_shelf_ids.len() - offset);
        let next_ids = &power_shelf_ids[offset..offset + page_size];
        let page = api
            .find_power_shelves_by_ids(tonic::Request::new(rpc::forge::PowerShelvesByIdsRequest {
                power_shelf_ids: next_ids.to_vec(),
            }))
            .await?
            .into_inner();

        power_shelves.extend(page.power_shelves);
        offset += page_size;
    }

    Ok(rpc::forge::PowerShelfList { power_shelves })
}
