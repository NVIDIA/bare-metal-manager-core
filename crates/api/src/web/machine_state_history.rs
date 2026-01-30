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
use carbide_uuid::machine::MachineId;
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "machine_state_history.html")]
struct MachineStateHistory {
    id: String,
    history: MachineStateHistoryTable,
}

#[derive(Template)]
#[template(path = "machine_state_history_table.html")]
pub(super) struct MachineStateHistoryTable {
    pub records: Vec<MachineStateHistoryRecord>,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct MachineStateHistoryRecord {
    pub state: String,
    pub version: String,
}

/// Show the state history for a certain Machine
pub async fn show_state_history(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
) -> Response {
    let (machine_id, records) = match fetch_state_history_records(&state, &machine_id).await {
        Ok((id, records)) => (id, records),
        Err((code, msg)) => return (code, msg).into_response(),
    };

    let records = records
        .into_iter()
        .map(|record| MachineStateHistoryRecord {
            state: record.event,
            version: record.version,
        })
        .collect();

    let display = MachineStateHistory {
        id: machine_id.to_string(),
        history: MachineStateHistoryTable { records },
    };

    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

pub async fn show_state_history_json(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
) -> Response {
    let (_machine_id, health_records) = match fetch_state_history_records(&state, &machine_id).await
    {
        Ok((id, records)) => (id, records),
        Err((code, msg)) => return (code, msg).into_response(),
    };
    (StatusCode::OK, Json(health_records)).into_response()
}

pub async fn fetch_state_history_records(
    api: &Api,
    machine_id: &str,
) -> Result<(MachineId, Vec<::rpc::forge::MachineEvent>), (http::StatusCode, String)> {
    let Ok(machine_id) = MachineId::from_str(machine_id) else {
        return Err((StatusCode::BAD_REQUEST, "invalid machine id".to_string()));
    };

    let mut histories = match api
        .find_machine_state_histories(tonic::Request::new(
            ::rpc::forge::MachineStateHistoriesRequest {
                machine_ids: vec![machine_id],
            },
        ))
        .await
    {
        Ok(response) => response.into_inner().histories,
        Err(err) => {
            tracing::error!(%err, %machine_id, "find_machine_state_histories");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed FindMachineStateHistories".to_string(),
            ));
        }
    };

    let mut records = histories
        .remove(&machine_id.to_string())
        .unwrap_or_default()
        .records;
    // History is delivered with the oldest Entry First. Reverse for better display ordering
    records.reverse();

    Ok((machine_id, records))
}
