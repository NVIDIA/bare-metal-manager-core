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

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "expected_rack.html")]
struct ExpectedRacks {
    racks: Vec<ExpectedRackRow>,
}

#[derive(Debug, serde::Serialize)]
struct ExpectedRackRow {
    rack_id: String,
    rack_profile_id: String,
    compute_trays: String,
    switches: String,
    power_shelves: String,
}

/// Show all expected racks.
pub async fn show_html(state: AxumState<Arc<Api>>) -> Response {
    let racks = match fetch_expected_racks(&state).await {
        Ok(racks) => racks,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    let display = ExpectedRacks { racks };
    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

/// Show all expected racks as JSON.
pub async fn show_json(state: AxumState<Arc<Api>>) -> Response {
    let racks = match fetch_expected_racks(&state).await {
        Ok(racks) => racks,
        Err((code, msg)) => return (code, msg).into_response(),
    };
    (StatusCode::OK, Json(racks)).into_response()
}

async fn fetch_expected_racks(
    api: &Api,
) -> Result<Vec<ExpectedRackRow>, (http::StatusCode, String)> {
    let expected_response = match api.get_all_expected_racks(tonic::Request::new(())).await {
        Ok(response) => response.into_inner(),
        Err(err) => {
            tracing::error!(%err, "get_all_expected_racks");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to list expected racks".to_string(),
            ));
        }
    };

    let rack_response = match super::rack::fetch_racks(api).await {
        Ok(racks) => racks,
        Err(err) => {
            tracing::error!(%err, "fetch_racks");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to list racks".to_string(),
            ));
        }
    };

    // Index actual racks by their ID for quick lookup.
    let racks_by_id: std::collections::HashMap<String, &rpc::forge::Rack> = rack_response
        .racks
        .iter()
        .filter_map(|r| r.id.as_ref().map(|id| (id.to_string(), r)))
        .collect();

    let rows = expected_response
        .expected_racks
        .into_iter()
        .map(|er| {
            let rack_id = er
                .rack_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_default();
            let rack_profile_id = er
                .rack_profile_id
                .as_ref()
                .map(|id| id.to_string())
                .unwrap_or_default();

            // Look up capabilities from the rack profile config.
            let profile = api.runtime_config.rack_profiles.get(&rack_profile_id);

            // Look up the actual rack to count adopted devices.
            let actual_rack = racks_by_id.get(&rack_id);

            let compute_trays = match (actual_rack, profile) {
                (Some(rack), Some(p)) => {
                    format!(
                        "{}/{}",
                        rack.expected_compute_trays.len(),
                        p.rack_capabilities.compute.count
                    )
                }
                (None, Some(p)) => format!("0/{}", p.rack_capabilities.compute.count),
                _ => "?/?".to_string(),
            };

            let switches = match (actual_rack, profile) {
                (Some(rack), Some(p)) => {
                    format!(
                        "{}/{}",
                        rack.expected_nvlink_switches.len(),
                        p.rack_capabilities.switch.count
                    )
                }
                (None, Some(p)) => format!("0/{}", p.rack_capabilities.switch.count),
                _ => "?/?".to_string(),
            };

            let power_shelves = match (actual_rack, profile) {
                (Some(rack), Some(p)) => {
                    format!(
                        "{}/{}",
                        rack.expected_power_shelves.len(),
                        p.rack_capabilities.power_shelf.count
                    )
                }
                (None, Some(p)) => format!("0/{}", p.rack_capabilities.power_shelf.count),
                _ => "?/?".to_string(),
            };

            ExpectedRackRow {
                rack_id,
                rack_profile_id,
                compute_trays,
                switches,
                power_shelves,
            }
        })
        .collect();

    Ok(rows)
}
