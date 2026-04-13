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
#[template(path = "switch_show.html")]
struct SwitchShow {
    switches: Vec<SwitchRecord>,
}

#[derive(Debug, serde::Serialize)]
struct SwitchRecord {
    id: String,
    name: String,
    state: String,
    slot_number: String,
    tray_index: String,
}

/// Show all switches
pub async fn show_html(state: AxumState<Arc<Api>>) -> Response {
    let switches = match fetch_switches(&state).await {
        Ok(switches) => switches,
        Err(err) => {
            tracing::error!(%err, "fetch_switches");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading switches").into_response();
        }
    };

    let switches = switches
        .switches
        .into_iter()
        .map(|switch| {
            let state = parse_controller_state(&switch.controller_state);

            let config = switch.config.unwrap_or_default();
            SwitchRecord {
                id: switch.id.map(|id| id.to_string()).unwrap_or_default(),
                name: config.name,
                state,
                slot_number: switch
                    .placement_in_rack
                    .as_ref()
                    .and_then(|p| p.slot_number)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
                tray_index: switch
                    .placement_in_rack
                    .as_ref()
                    .and_then(|p| p.tray_index)
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "N/A".to_string()),
            }
        })
        .collect();

    let display = SwitchShow { switches };
    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

/// Show all switches as JSON
pub async fn show_json(state: AxumState<Arc<Api>>) -> Response {
    let switches = match fetch_switches(&state).await {
        Ok(switches) => switches,
        Err(err) => {
            tracing::error!(%err, "fetch_switches");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Error loading switches").into_response();
        }
    };
    (StatusCode::OK, Json(switches)).into_response()
}

async fn fetch_switches(api: &Api) -> Result<rpc::forge::SwitchList, tonic::Status> {
    // Use find_switch_ids (which respects DeletedFilter::Exclude by default)
    // followed by find_switches_by_ids.
    let switch_ids = api
        .find_switch_ids(tonic::Request::new(
            rpc::forge::SwitchSearchFilter::default(),
        ))
        .await?
        .into_inner()
        .ids;

    if switch_ids.is_empty() {
        return Ok(Default::default());
    }

    let mut switches = Vec::new();
    let mut offset = 0;
    while offset < switch_ids.len() {
        const PAGE_SIZE: usize = 100;
        let page_size = PAGE_SIZE.min(switch_ids.len() - offset);
        let next_ids = &switch_ids[offset..offset + page_size];
        let page = api
            .find_switches_by_ids(tonic::Request::new(rpc::forge::SwitchesByIdsRequest {
                switch_ids: next_ids.to_vec(),
            }))
            .await?
            .into_inner();

        switches.extend(page.switches);
        offset += page_size;
    }

    Ok(rpc::forge::SwitchList { switches })
}

/// Parse the JSON controller_state string into a human-friendly state name.
fn parse_controller_state(controller_state: &str) -> String {
    serde_json::from_str::<serde_json::Value>(controller_state)
        .ok()
        .and_then(|v| v.get("state")?.as_str().map(capitalize))
        .unwrap_or_else(|| "Unknown".to_string())
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        None => String::new(),
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
    }
}

#[derive(Template)]
#[template(path = "switch_detail.html")]
struct SwitchDetail {
    id: String,
    rack_id: String,
    controller_state: String,
    state_version: String,
    time_in_state: String,
    name: String,
    slot_number: String,
    tray_index: String,
    enable_nmxc: bool,
    state_reason: Option<rpc::forge::ControllerStateReason>,
    power_state: Option<String>,
    health_status: Option<String>,
    bmc_info: Option<rpc::forge::BmcInfo>,
    metadata_detail: super::MetadataDetail,
}

impl SwitchDetail {
    fn new(switch: rpc::forge::Switch) -> Self {
        let id = switch
            .id
            .as_ref()
            .map(|id| id.to_string())
            .unwrap_or_default();
        let config = switch.config.unwrap_or_default();
        let state_reason = switch.status.as_ref().and_then(|s| s.state_reason.clone());
        let power_state = switch.status.as_ref().and_then(|s| s.power_state.clone());
        let health_status = switch.status.as_ref().and_then(|s| s.health_status.clone());
        let time_in_state = config_version::since_state_change_humanized(&switch.state_version);
        let metadata_detail = super::MetadataDetail {
            metadata: switch.metadata.unwrap_or_default(),
            metadata_version: switch.version,
        };
        Self {
            id,
            rack_id: switch.rack_id.map(|id| id.to_string()).unwrap_or_default(),
            controller_state: parse_controller_state(&switch.controller_state),
            state_version: switch.state_version,
            time_in_state,
            name: config.name,
            slot_number: switch
                .placement_in_rack
                .as_ref()
                .and_then(|p| p.slot_number)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            tray_index: switch
                .placement_in_rack
                .as_ref()
                .and_then(|p| p.tray_index)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
            enable_nmxc: config.enable_nmxc,
            state_reason,
            power_state,
            health_status,
            bmc_info: switch.bmc_info,
            metadata_detail,
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
            return super::not_found_response(switch_id);
        }
        Err(response) => return response,
    };

    if show_json {
        return (StatusCode::OK, Json(switch)).into_response();
    }

    let detail = SwitchDetail::new(switch);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_controller_state_ready() {
        assert_eq!(parse_controller_state(r#"{"state":"ready"}"#), "Ready");
    }

    #[test]
    fn parse_controller_state_initializing() {
        assert_eq!(
            parse_controller_state(
                r#"{"state":"initializing","initializing_state":"WaitForOsMachineInterface"}"#
            ),
            "Initializing"
        );
    }

    #[test]
    fn parse_controller_state_error() {
        assert_eq!(
            parse_controller_state(r#"{"state":"error","cause":"something broke"}"#),
            "Error"
        );
    }

    #[test]
    fn parse_controller_state_invalid_json() {
        assert_eq!(parse_controller_state("not json"), "Unknown");
    }
}
