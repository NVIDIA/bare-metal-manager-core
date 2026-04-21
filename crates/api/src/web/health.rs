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
use model::health::HealthReportSources;
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    HealthReportApplyMode, InsertHealthReportOverrideRequest, MachinesByIdsRequest,
    RemoveHealthReportOverrideRequest,
};

use super::filters;
use crate::api::Api;
use crate::auth::AuthContext;

#[derive(Template)]
#[template(path = "machine_health.html")]
struct MachineHealth {
    id: MachineId,
    machine_type: MachineType,
    overrides: Vec<HealthReportEntry>,
    aggregate_health: LabeledHealthReport,
    component_health: Vec<LabeledHealthReport>,
    history: HealthHistoryTable,
}

#[derive(Template)]
#[template(path = "health_history_table.html")]
pub(super) struct HealthHistoryTable {
    pub records: Vec<HealthHistoryRecord>,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct HealthHistoryRecord {
    pub timestamp: String,
    pub health: health_report::HealthReport,
}

impl HealthHistoryRecord {
    pub fn from_rpc_convert_invalid(record: ::rpc::forge::HealthHistoryRecord) -> Self {
        HealthHistoryRecord {
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
    let mut listed_overrides = match state
        .list_health_report_overrides(request)
        .await
        .map(|response| response.into_inner().health_report_entries)
    {
        Ok(m) => m,
        Err(err) if err.code() == tonic::Code::NotFound => Vec::new(),
        Err(err) => {
            tracing::error!(%err, %machine_id, "list_health_report_overrides");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(err.to_string())).into_response();
        }
    };
    let mut hardware_health: Option<health_report::HealthReport> = None;
    let mut overrides = Vec::new();
    for override_entry in listed_overrides.drain(..) {
        let source = override_entry
            .report
            .as_ref()
            .map(|report| report.source.as_str())
            .unwrap_or_default();
        if HealthReportSources::is_hardware_health_override_source(source) {
            if let Some(report) = override_entry.report {
                let report = health_report_from_rpc_convert_invalid(report);
                if let Some(aggregated) = hardware_health.as_mut() {
                    aggregated.merge(&report);
                } else {
                    hardware_health = Some(report);
                }
            }
            continue;
        }
        overrides.push(override_entry);
    }

    // Sort by type first and source name second.
    overrides.sort_by(|a, b| {
        if a.mode() == HealthReportApplyMode::Replace {
            return std::cmp::Ordering::Less;
        } else if b.mode() == HealthReportApplyMode::Replace {
            return std::cmp::Ordering::Greater;
        }
        a.report
            .as_ref()
            .map(|a| &a.source)
            .cmp(&b.report.as_ref().map(|b| &b.source))
    });

    let overrides: Vec<HealthReportEntry> = overrides
        .iter()
        .map(|o| HealthReportEntry::from_rpc_convert_invalid(o.clone()))
        .collect();

    let mut component_health = Vec::new();
    component_health.push(LabeledHealthReport {
        label: "Hardware Health".to_string(),
        report: hardware_health,
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
        history: HealthHistoryTable {
            records: health_records,
        },
    };

    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct HealthReportEntry {
    mode: String,
    health_report: HealthReport,
}

impl HealthReportEntry {
    fn from_rpc_convert_invalid(o: ::rpc::forge::HealthReportEntry) -> Self {
        let mode = match o.mode() {
            HealthReportApplyMode::Merge => "Merge",
            HealthReportApplyMode::Replace => "Replace",
        }
        .to_string();

        let health_report = o
            .report
            .map(health_report_from_rpc_convert_invalid)
            .unwrap_or_else(HealthReport::missing_report);

        HealthReportEntry {
            mode,
            health_report,
        }
    }
}

impl TryFrom<HealthReportEntry> for ::rpc::forge::HealthReportEntry {
    type Error = String;

    fn try_from(value: HealthReportEntry) -> Result<Self, Self::Error> {
        let mode = match value.mode.as_str() {
            "Replace" => HealthReportApplyMode::Replace,
            "Merge" => HealthReportApplyMode::Merge,
            m => {
                return Err(format!(
                    "Override mode must be \"Replace\" or \"Merge\", but was \"{m}\""
                ));
            }
        };

        Ok(::rpc::forge::HealthReportEntry {
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
    auth_context: Option<axum::Extension<AuthContext>>,
    extract::Json(payload): extract::Json<HealthReportEntry>,
) -> impl IntoResponse {
    let report_override = match ::rpc::forge::HealthReportEntry::try_from(payload) {
        Ok(report_override) => report_override,
        Err(e) => return (StatusCode::BAD_REQUEST, e),
    };

    let machine_id = match machine_id.parse::<MachineId>() {
        Ok(id) => id,
        Err(e) => return (StatusCode::BAD_REQUEST, e.to_string()),
    };

    let mut request = tonic::Request::new(InsertHealthReportOverrideRequest {
        machine_id: Some(machine_id),
        health_report_entry: Some(report_override),
    });
    if let Some(axum::Extension(auth_context)) = auth_context {
        request.extensions_mut().insert(auth_context);
    }
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
) -> Result<Vec<HealthHistoryRecord>, tonic::Status> {
    let records = api
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

    let records = records
        .into_iter()
        .map(HealthHistoryRecord::from_rpc_convert_invalid)
        .collect();

    Ok(records)
}
