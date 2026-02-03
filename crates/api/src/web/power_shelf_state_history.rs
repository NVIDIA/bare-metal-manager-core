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
use carbide_uuid::power_shelf::PowerShelfId;
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;

use crate::api::Api;

#[derive(Template)]
#[template(path = "power_shelf_state_history.html")]
struct PowerShelfStateHistory {
    id: String,
    records: Vec<PowerShelfStateHistoryRecord>,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct PowerShelfStateHistoryRecord {
    pub state: String,
    pub version: String,
    pub time: String,
}

/// Show the state history for a certain Power Shelf
pub async fn show_state_history(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(power_shelf_id): AxumPath<String>,
) -> Response {
    let (power_shelf_id, records) = match fetch_state_history_records(&state, &power_shelf_id).await
    {
        Ok((id, records)) => (id, records),
        Err((code, msg)) => return (code, msg).into_response(),
    };

    let records = records
        .into_iter()
        .map(|record| PowerShelfStateHistoryRecord {
            state: record.state,
            version: record.version,
            time: record
                .time
                .map(|t| t.to_string())
                .unwrap_or_else(|| "N/A".to_string()),
        })
        .collect();

    let display = PowerShelfStateHistory {
        id: power_shelf_id.to_string(),
        records,
    };

    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

pub async fn show_state_history_json(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(power_shelf_id): AxumPath<String>,
) -> Response {
    let (_power_shelf_id, health_records) =
        match fetch_state_history_records(&state, &power_shelf_id).await {
            Ok((id, records)) => (id, records),
            Err((code, msg)) => return (code, msg).into_response(),
        };

    let records: Vec<PowerShelfStateHistoryRecord> = health_records
        .into_iter()
        .map(|record| PowerShelfStateHistoryRecord {
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
    power_shelf_id: &str,
) -> Result<
    (
        carbide_uuid::power_shelf::PowerShelfId,
        Vec<::rpc::forge::PowerShelfStateHistoryRecord>,
    ),
    (http::StatusCode, String),
> {
    let Ok(power_shelf_id) = PowerShelfId::from_str(power_shelf_id) else {
        return Err((
            StatusCode::BAD_REQUEST,
            "invalid power shelf id".to_string(),
        ));
    };

    let mut histories = match api
        .find_power_shelf_state_histories(tonic::Request::new(
            ::rpc::forge::PowerShelfStateHistoriesRequest {
                power_shelf_ids: vec![power_shelf_id],
            },
        ))
        .await
    {
        Ok(response) => response.into_inner().histories,
        Err(err) => {
            tracing::error!(%err, %power_shelf_id, "find_power_shelf_state_histories");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed FindPowerShelfStateHistories".to_string(),
            ));
        }
    };

    let mut records = histories
        .remove(&power_shelf_id.to_string())
        .unwrap_or_default()
        .records;
    // History is delivered with the oldest Entry First. Reverse for better display ordering
    records.reverse();

    Ok((power_shelf_id, records))
}
