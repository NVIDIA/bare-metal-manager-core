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
use carbide_uuid::machine::MachineId;
use hyper::http::StatusCode;

use super::health::{MachineHealthHistoryRecord, MachineHealthHistoryTable, fetch_health_history};
use crate::api::Api;

#[derive(Template)]
#[template(path = "machine_health_history.html")]
struct MachineHealth {
    id: String,
    history: MachineHealthHistoryTable,
}

/// Show the health history for a certain Machine
pub async fn show_health_history(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
) -> Response {
    let (machine_id, records) = match fetch_health_records(&state, &machine_id).await {
        Ok((id, records)) => (id, records),
        Err((code, msg)) => return (code, msg).into_response(),
    };

    let display = MachineHealth {
        id: machine_id.to_string(),
        history: MachineHealthHistoryTable { records },
    };

    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

pub async fn show_health_history_json(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
) -> Response {
    let (_machine_id, health_records) = match fetch_health_records(&state, &machine_id).await {
        Ok((id, records)) => (id, records),
        Err((code, msg)) => return (code, msg).into_response(),
    };
    (StatusCode::OK, Json(health_records)).into_response()
}

pub async fn fetch_health_records(
    api: &Api,
    machine_id: &str,
) -> Result<(MachineId, Vec<MachineHealthHistoryRecord>), (http::StatusCode, String)> {
    let Ok(machine_id) = MachineId::from_str(machine_id) else {
        return Err((StatusCode::BAD_REQUEST, "invalid machine id".to_string()));
    };
    if machine_id.machine_type().is_dpu() {
        return Err((
            StatusCode::NOT_FOUND,
            "no health for dpu. see host machine instead".to_string(),
        ));
    }

    let health_records = match fetch_health_history(api, &machine_id).await {
        Ok(records) => records,
        Err(err) => {
            tracing::error!(%err, %machine_id, "find_machine_health_histories");
            return Err((StatusCode::INTERNAL_SERVER_ERROR, String::new()));
        }
    };

    Ok((machine_id, health_records))
}
