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

use askama::Template;
use axum::extract::{self, Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use forge_uuid::machine::MachineId;
use health_report::HealthReport;
use hyper::http::StatusCode;
use rpc::forge::{
    HealthReportOverride, InsertHealthReportOverrideRequest, MachinesByIdsRequest, OverrideMode,
    RemoveHealthReportOverrideRequest, forge_server::Forge,
};
use std::{str::FromStr, sync::Arc};

use super::{filters, machine::get_machine_type};
use crate::api::Api;

#[derive(Template)]
#[template(path = "machine_health.html")]
struct MachineHealth {
    id: String,
    machine_type: String,
    overrides: Vec<DisplayedOverrideOrigin>,
    reports: Vec<LabeledHealthReport>,
    history: Vec<HealthReportRecord>,
}

struct DisplayedOverrideOrigin {
    source: String,
    mode: String,
}

#[derive(Debug, serde::Serialize)]
pub(super) struct HealthReportRecord {
    pub timestamp: String,
    pub health: health_report::HealthReport,
}

struct LabeledHealthReport {
    label: String,
    report: Option<health_report::HealthReport>,
}

/// View machine
pub async fn health(
    AxumState(state): AxumState<Arc<Api>>,
    AxumPath(machine_id): AxumPath<String>,
) -> Response {
    let Ok(parsed_machine_id) = MachineId::from_str(&machine_id) else {
        return (StatusCode::BAD_REQUEST, "invalid machine id").into_response();
    };
    if parsed_machine_id.machine_type().is_dpu() {
        return (
            StatusCode::NOT_FOUND,
            "no health for dpu. see host machine instead",
        )
            .into_response();
    }
    let machine_id = parsed_machine_id.to_string();

    let rpc_machine_id = ::rpc::common::MachineId {
        id: machine_id.clone(),
    };

    let request = tonic::Request::new(rpc_machine_id.clone());
    let mut overrides = match state
        .list_health_report_overrides(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(m) => m,
        Err(err) if err.code() == tonic::Code::NotFound => {
            return super::not_found_response(machine_id);
        }
        Err(err) => {
            tracing::error!(%err, %machine_id, "list_health_report_overrides");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response();
        }
    }
    .overrides;
    // Sort by source name.
    overrides.sort_by(|a, b| {
        a.report
            .as_ref()
            .map(|a| &a.source)
            .cmp(&b.report.as_ref().map(|b| &b.source))
    });
    // Put override override first. In theory, these modes should be valid since
    // carbide sends them.
    overrides.sort_by_key(|hr| {
        match OverrideMode::try_from(hr.mode).unwrap_or(OverrideMode::Merge) {
            OverrideMode::Replace => 0,
            OverrideMode::Merge => 1,
        }
    });
    // Overrides before others.
    let mut reports = overrides
        .into_iter()
        .filter_map(|o| {
            o.report.map(|hr| LabeledHealthReport {
                label: OverrideMode::try_from(o.mode)
                    .unwrap_or(OverrideMode::Merge)
                    .as_str_name()
                    .to_string()
                    + " "
                    + hr.source.as_str(),
                report: Some(
                    hr.try_into()
                        .unwrap_or_else(health_report::HealthReport::malformed_report),
                ),
            })
        })
        .collect::<Vec<_>>();

    let request = tonic::Request::new(rpc::forge::MachinesByIdsRequest {
        machine_ids: vec![rpc_machine_id.clone()],
        include_history: false,
    });

    let machine = match state
        .find_machines_by_ids(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(m) if m.machines.is_empty() => {
            return super::not_found_response(machine_id);
        }
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
        Ok(mut m) => m.machines.remove(0),
        Err(err) if err.code() == tonic::Code::NotFound => {
            return super::not_found_response(machine_id);
        }
        Err(err) => {
            tracing::error!(%err, %machine_id, "find_machines_by_ids");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response();
        }
    };
    reports.push(LabeledHealthReport {
        label: "Aggregate Health".to_string(),
        report: machine.health.map(|health| {
            HealthReport::try_from(health)
                .unwrap_or_else(health_report::HealthReport::malformed_report)
        }),
    });

    let request = tonic::Request::new(rpc_machine_id.clone());
    let hw_report = match state
        .get_hardware_health_report(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(m) => m,
        Err(err) if err.code() == tonic::Code::NotFound => {
            return super::not_found_response(machine_id);
        }
        Err(err) => {
            tracing::error!(%err, %machine_id, "get_hardware_health_report");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response();
        }
    };
    reports.push(LabeledHealthReport {
        label: "Hardware Health".to_string(),
        report: hw_report.report.map(|health| {
            HealthReport::try_from(health)
                .unwrap_or_else(health_report::HealthReport::malformed_report)
        }),
    });

    let request = tonic::Request::new(MachinesByIdsRequest {
        machine_ids: machine.associated_dpu_machine_ids.clone(),
        include_history: false,
    });
    let dpus = match state
        .find_machines_by_ids(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(m) => m,
        Err(err) if err.code() == tonic::Code::NotFound => {
            return super::not_found_response(machine_id);
        }
        Err(err) => {
            tracing::error!(%err, %machine_id, "find_machines_by_ids");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response();
        }
    }
    .machines;
    // Add aggregate health, dpus, and HW health
    for dpu in dpus {
        reports.push(LabeledHealthReport {
            label: format!(
                "DPU Health {}",
                dpu.id.map(|id| id.to_string()).unwrap_or_default()
            ),
            report: dpu.health.map(|health| {
                HealthReport::try_from(health)
                    .unwrap_or_else(health_report::HealthReport::malformed_report)
            }),
        })
    }

    let health_records = match fetch_health_history(&state, &rpc_machine_id).await {
        Ok(records) => records,
        Err(err) => {
            tracing::error!(%err, %machine_id, "find_machine_health_histories");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response();
        }
    };

    let display = MachineHealth {
        id: machine_id.clone(),
        machine_type: get_machine_type(&machine_id),
        reports,
        overrides: machine
            .health_overrides
            .into_iter()
            .map(|o| DisplayedOverrideOrigin {
                mode: match o.mode() {
                    OverrideMode::Merge => "Merge",
                    OverrideMode::Replace => "Replace",
                }
                .to_string(),
                source: o.source,
            })
            .collect(),
        history: health_records,
    };

    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}

#[derive(serde::Deserialize)]
pub struct AddOverride {
    mode: String,
    health_report: HealthReport,
}

impl TryFrom<AddOverride> for HealthReportOverride {
    type Error = String;

    fn try_from(value: AddOverride) -> Result<Self, Self::Error> {
        let mode = match value.mode.as_str() {
            "Replace" => OverrideMode::Replace,
            "Merge" => OverrideMode::Merge,
            m => {
                return Err(format!(
                    "Override mode must be \"Replace\" or \"Merge\", but was \"{m}\""
                ));
            }
        };
        let hr = value.health_report;

        Ok(HealthReportOverride {
            mode: mode as i32,
            report: Some(rpc::protos::health::HealthReport {
                source: hr.source,
                observed_at: hr.observed_at.map(|t| t.into()),
                successes: hr
                    .successes
                    .into_iter()
                    .map(rpc::protos::health::HealthProbeSuccess::from)
                    .collect::<Vec<_>>(),
                alerts: hr
                    .alerts
                    .into_iter()
                    .map(rpc::protos::health::HealthProbeAlert::from)
                    .collect::<Vec<_>>(),
            }),
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
    extract::Json(payload): extract::Json<AddOverride>,
) -> impl IntoResponse {
    let report_override = match HealthReportOverride::try_from(payload) {
        Ok(report_override) => report_override,
        Err(e) => return (StatusCode::BAD_REQUEST, e),
    };

    let request = tonic::Request::new(InsertHealthReportOverrideRequest {
        machine_id: Some(rpc::common::MachineId {
            id: machine_id.clone(),
        }),
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
    let request = tonic::Request::new(RemoveHealthReportOverrideRequest {
        machine_id: Some(rpc::common::MachineId {
            id: machine_id.clone(),
        }),
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

pub(super) async fn fetch_health_history(
    api: &Api,
    machine_id: &::rpc::common::MachineId,
) -> Result<Vec<HealthReportRecord>, tonic::Status> {
    let mut records = api
        .find_machine_health_histories(tonic::Request::new(
            ::rpc::forge::MachineHealthHistoriesRequest {
                machine_ids: vec![machine_id.clone()],
            },
        ))
        .await
        .map(|response| response.into_inner())?
        .histories
        .remove(&machine_id.id)
        .unwrap_or_default()
        .records;
    // History is delivered with the oldest Entry First. Reverse for better display ordering
    records.reverse();

    let records = records
        .into_iter()
        .map(|record| HealthReportRecord {
            timestamp: record.time.map(|time| time.to_string()).unwrap_or_default(),
            health: record
                .health
                .map(|health| {
                    HealthReport::try_from(health)
                        .unwrap_or_else(health_report::HealthReport::malformed_report)
                })
                .unwrap_or_else(health_report::HealthReport::missing_report),
        })
        .collect();

    Ok(records)
}
