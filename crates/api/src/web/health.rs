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
use axum::extract::{self, Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use carbide_uuid::machine::{MachineId, MachineType};
use health_report::HealthReport;
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    InsertHealthReportOverrideRequest, MachinesByIdsRequest, OverrideMode,
    RemoveHealthReportOverrideRequest,
};

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "machine_health.html")]
struct MachineHealth {
    id: MachineId,
    machine_type: MachineType,
    overrides: Vec<HealthReportOverride>,
    aggregate_health: LabeledHealthReport,
    component_health: Vec<LabeledHealthReport>,
    history: MachineHealthHistoryTable,
}

#[derive(Template)]
#[template(path = "machine_health_history_table.html")]
pub(super) struct MachineHealthHistoryTable {
    pub records: Vec<MachineHealthHistoryRecord>,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct MachineHealthHistoryRecord {
    pub timestamp: String,
    pub health: health_report::HealthReport,
}

impl MachineHealthHistoryRecord {
    pub fn from_rpc_convert_invalid(record: ::rpc::forge::MachineHealthHistoryRecord) -> Self {
        MachineHealthHistoryRecord {
            timestamp: record.time.map(|time| time.to_string()).unwrap_or_default(),
            health: record
                .health
                .map(health_report_from_rpc_convert_invalid)
                .unwrap_or_else(health_report::HealthReport::missing_report),
        }
    }
}

#[derive(Template)]
#[template(path = "machine_health_component.html")]
struct LabeledHealthReport {
    label: String,
    report: Option<health_report::HealthReport>,
}

/// View machine
pub async fn health(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
) -> Response {
    let Ok(machine_id) = MachineId::from_str(&machine_id) else {
        return (StatusCode::BAD_REQUEST, "invalid machine id").into_response();
    };
    if machine_id.machine_type().is_dpu() {
        return (
            StatusCode::NOT_FOUND,
            "no health for dpu. see host machine instead",
        )
            .into_response();
    }

    let machine = match state
        .find_machines_by_ids(tonic::Request::new(rpc::forge::MachinesByIdsRequest {
            machine_ids: vec![machine_id],
            include_history: false,
        }))
        .await
        .map(|response| response.into_inner())
    {
        Ok(m) if m.machines.is_empty() => None,
        Ok(m) if m.machines.len() != 1 => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "Machine list for {machine_id} returned {} machines",
                    m.machines.len()
                ),
            )
                .into_response();
        }
        Ok(mut m) => Some(m.machines.remove(0)),
        Err(err) if err.code() == tonic::Code::NotFound => None,
        Err(err) => {
            tracing::error!(%err, %machine_id, "find_machines_by_ids");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(err.to_string())).into_response();
        }
    };

    let aggregate_health = machine
        .as_ref()
        .and_then(|m| m.health.as_ref())
        .map(|health| health_report_from_rpc_convert_invalid(health.clone()));
    let associated_dpu_machine_ids = match machine {
        Some(m) => m.associated_dpu_machine_ids,
        None => Vec::new(),
    };

    let request = tonic::Request::new(machine_id);
    let mut overrides = match state
        .list_health_report_overrides(request)
        .await
        .map(|response| response.into_inner().overrides)
    {
        Ok(m) => m,
        Err(err) if err.code() == tonic::Code::NotFound => Vec::new(),
        Err(err) => {
            tracing::error!(%err, %machine_id, "list_health_report_overrides");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(err.to_string())).into_response();
        }
    };
    // Sort by type first and source name second.
    overrides.sort_by(|a, b| {
        if a.mode() == OverrideMode::Replace {
            return std::cmp::Ordering::Less;
        } else if b.mode() == OverrideMode::Replace {
            return std::cmp::Ordering::Greater;
        }
        a.report
            .as_ref()
            .map(|a| &a.source)
            .cmp(&b.report.as_ref().map(|b| &b.source))
    });

    let overrides: Vec<HealthReportOverride> = overrides
        .iter()
        .map(|o| HealthReportOverride::from_rpc_convert_invalid(o.clone()))
        .collect();

    let mut component_health = Vec::new();

    let request = tonic::Request::new(machine_id);
    let hw_report = match state
        .get_hardware_health_report(request)
        .await
        .map(|response| response.into_inner().report)
    {
        Ok(m) => m,
        Err(err) if err.code() == tonic::Code::NotFound => None,
        Err(err) => {
            tracing::error!(%err, %machine_id, "get_hardware_health_report");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(err.to_string())).into_response();
        }
    };
    component_health.push(LabeledHealthReport {
        label: "Hardware Health".to_string(),
        report: hw_report.map(health_report_from_rpc_convert_invalid),
    });

    if !associated_dpu_machine_ids.is_empty() {
        let request = tonic::Request::new(MachinesByIdsRequest {
            machine_ids: associated_dpu_machine_ids,
            include_history: false,
        });
        let dpus = match state
            .find_machines_by_ids(request)
            .await
            .map(|response| response.into_inner())
        {
            Ok(m) => m.machines,
            Err(err) if err.code() == tonic::Code::NotFound => Vec::new(),
            Err(err) => {
                tracing::error!(%err, %machine_id, "find_machines_by_ids");
                return (StatusCode::INTERNAL_SERVER_ERROR, Html(err.to_string())).into_response();
            }
        };
        for dpu in dpus {
            component_health.push(LabeledHealthReport {
                label: format!(
                    "DPU Health {}",
                    dpu.id.map(|id| id.to_string()).unwrap_or_default()
                ),
                report: dpu.health.map(health_report_from_rpc_convert_invalid),
            })
        }
    }

    component_health.extend(overrides.iter().map(|o| LabeledHealthReport {
        label: format!("Override {} {}", o.mode, o.health_report.source),
        report: Some(o.health_report.clone()),
    }));

    let health_records = match fetch_health_history(&state, &machine_id).await {
        Ok(records) => records,
        Err(err) => {
            tracing::error!(%err, %machine_id, "find_machine_health_histories");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(err.to_string())).into_response();
        }
    };

    let display = MachineHealth {
        id: machine_id,
        machine_type: machine_id.machine_type(),
        aggregate_health: LabeledHealthReport {
            label: "Aggregate Health".to_string(),
            report: aggregate_health,
        },
        component_health,
        overrides,
        history: MachineHealthHistoryTable {
            records: health_records,
        },
    };

    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct HealthReportOverride {
    mode: String,
    health_report: HealthReport,
}

impl HealthReportOverride {
    fn from_rpc_convert_invalid(o: ::rpc::forge::HealthReportOverride) -> Self {
        let mode = match o.mode() {
            OverrideMode::Merge => "Merge",
            OverrideMode::Replace => "Replace",
        }
        .to_string();

        let health_report = o
            .report
            .map(health_report_from_rpc_convert_invalid)
            .unwrap_or_else(HealthReport::missing_report);

        HealthReportOverride {
            mode,
            health_report,
        }
    }
}

impl TryFrom<HealthReportOverride> for ::rpc::forge::HealthReportOverride {
    type Error = String;

    fn try_from(value: HealthReportOverride) -> Result<Self, Self::Error> {
        let mode = match value.mode.as_str() {
            "Replace" => OverrideMode::Replace,
            "Merge" => OverrideMode::Merge,
            m => {
                return Err(format!(
                    "Override mode must be \"Replace\" or \"Merge\", but was \"{m}\""
                ));
            }
        };

        Ok(::rpc::forge::HealthReportOverride {
            mode: mode as i32,
            report: Some(::rpc::health::HealthReport::from(value.health_report)),
        })
    }
}

#[derive(serde::Deserialize)]
pub struct RemoveOverride {
    source: String,
}

pub async fn add_override(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
    extract::Json(payload): extract::Json<HealthReportOverride>,
) -> impl IntoResponse {
    let report_override = match ::rpc::forge::HealthReportOverride::try_from(payload) {
        Ok(report_override) => report_override,
        Err(e) => return (StatusCode::BAD_REQUEST, e),
    };

    let machine_id = match machine_id.parse::<MachineId>() {
        Ok(id) => id,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()),
    };

    let request = tonic::Request::new(InsertHealthReportOverrideRequest {
        machine_id: Some(machine_id),
        r#override: Some(report_override),
    });
    match state
        .insert_health_report_override(request)
        .await
        .map(|response| response.into_inner())
    {
        Err(err) if err.code() == tonic::Code::NotFound => {
            (StatusCode::NOT_FOUND, format!("Not found: {machine_id}"))
        }
        Err(err) => {
            tracing::error!(%err, %machine_id, "insert_health_report_overrides");
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        }
        Ok(_) => (StatusCode::OK, String::new()),
    }
}

pub async fn remove_override(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
    extract::Json(payload): extract::Json<RemoveOverride>,
) -> impl IntoResponse {
    let machine_id = match machine_id.parse::<MachineId>() {
        Ok(id) => id,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()),
    };
    let request = tonic::Request::new(RemoveHealthReportOverrideRequest {
        machine_id: Some(machine_id),
        source: payload.source,
    });
    match state
        .remove_health_report_override(request)
        .await
        .map(|response| response.into_inner())
    {
        Err(err) if err.code() == tonic::Code::NotFound => {
            (StatusCode::NOT_FOUND, format!("Not found: {machine_id}"))
        }
        Err(err) => {
            tracing::error!(%err, %machine_id, "remove_health_report_overrides");
            (StatusCode::INTERNAL_SERVER_ERROR, err.to_string())
        }
        Ok(_) => (StatusCode::OK, String::new()),
    }
}

fn health_report_from_rpc_convert_invalid(
    report: rpc::health::HealthReport,
) -> health_report::HealthReport {
    health_report::HealthReport::try_from(report)
        .unwrap_or_else(health_report::HealthReport::malformed_report)
}

pub(super) async fn fetch_health_history(
    api: &Api,
    machine_id: &MachineId,
) -> Result<Vec<MachineHealthHistoryRecord>, tonic::Status> {
    let mut records = api
        .find_machine_health_histories(tonic::Request::new(
            ::rpc::forge::MachineHealthHistoriesRequest {
                machine_ids: vec![*machine_id],
                start_time: None,
                end_time: None,
            },
        ))
        .await
        .map(|response| response.into_inner())?
        .histories
        .remove(&machine_id.to_string())
        .unwrap_or_default()
        .records;
    // History is delivered with the oldest Entry First. Reverse for better display ordering
    records.reverse();

    let records = records
        .into_iter()
        .map(MachineHealthHistoryRecord::from_rpc_convert_invalid)
        .collect();

    Ok(records)
}
