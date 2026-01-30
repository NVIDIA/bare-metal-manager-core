/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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

use crate::api::Api;

#[derive(Template)]
#[template(path = "switch_state_history.html")]
struct SwitchStateHistory {
    id: String,
    records: Vec<SwitchStateHistoryRecord>,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct SwitchStateHistoryRecord {
    pub state: String,
    pub version: String,
    pub time: String,
}

/// Show the state history for a certain Switch
pub async fn show_state_history(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(switch_id): AxumPath<String>,
) -> Response {
    let (switch_id, records) = match fetch_state_history_records(&state, &switch_id).await {
        Ok((id, records)) => (id, records),
        Err((code, msg)) => return (code, msg).into_response(),
    };

    let records = records
        .into_iter()
        .map(|record| SwitchStateHistoryRecord {
            state: record.state,
            version: record.version,
            time: record
                .time
                .map(|t| t.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
        })
        .collect();

    let display = SwitchStateHistory {
        id: switch_id.to_string(),
        records,
    };

    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

pub async fn show_state_history_json(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(switch_id): AxumPath<String>,
) -> Response {
    let (_switch_id, state_records) = match fetch_state_history_records(&state, &switch_id).await {
        Ok((id, records)) => (id, records),
        Err((code, msg)) => return (code, msg).into_response(),
    };

    let records: Vec<SwitchStateHistoryRecord> = state_records
        .into_iter()
        .map(|record| SwitchStateHistoryRecord {
            state: record.state,
            version: record.version,
            time: record
                .time
                .map(|t| t.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
        })
        .collect();

    (StatusCode::OK, Json(records)).into_response()
}

pub async fn fetch_state_history_records(
    api: &Api,
    switch_id: &str,
) -> Result<
    (
        carbide_uuid::switch::SwitchId,
        Vec<::rpc::forge::SwitchStateHistoryRecord>,
    ),
    (http::StatusCode, String),
> {
    let Ok(switch_id) = SwitchId::from_str(switch_id) else {
        return Err((StatusCode::BAD_REQUEST, "invalid switch id".to_string()));
    };

    let mut histories = match api
        .find_switch_state_histories(tonic::Request::new(
            ::rpc::forge::SwitchStateHistoriesRequest {
                switch_ids: vec![switch_id],
            },
        ))
        .await
    {
        Ok(response) => response.into_inner().histories,
        Err(err) => {
            tracing::error!(%err, %switch_id, "find_switch_state_histories");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed FindSwitchStateHistories".to_string(),
            ));
        }
    };

    let mut records = histories
        .remove(&switch_id.to_string())
        .unwrap_or_default()
        .records;
    // History is delivered with the oldest Entry First. Reverse for better display ordering
    records.reverse();

    Ok((switch_id, records))
}
