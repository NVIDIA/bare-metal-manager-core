/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use http::StatusCode;
use rpc::forge::forge_server::Forge;
use rpc::forge::{MachinesByIdsRequest, OverrideMode};

use crate::api::Api;
use crate::model::machine::machine_id::MachineId;

use super::machine::get_machine_type;

#[derive(Template)]
#[template(path = "machine_health.html")]
struct MachineHealth {
    id: String,
    machine_type: String,
    reports: Vec<LabeledHealthReport>,
}

struct LabeledHealthReport {
    label: String,
    report: Option<HealthReport>,
}

struct HealthReport {
    successes: Vec<HealthProbeSuccess>,
    alerts: Vec<HealthProbeAlert>,
}
struct HealthProbeAlert {
    id: String,
    target: String,
    in_alert_since: String,
    message: String,
    tenant_message: String,
    classifications: Vec<String>,
}
struct HealthProbeSuccess {
    id: String,
    target: String,
}

impl From<rpc::health::HealthReport> for HealthReport {
    fn from(value: rpc::health::HealthReport) -> Self {
        Self {
            successes: value.successes.into_iter().map(|s| s.into()).collect(),
            alerts: value.alerts.into_iter().map(|s| s.into()).collect(),
        }
    }
}

impl From<rpc::health::HealthProbeAlert> for HealthProbeAlert {
    fn from(value: rpc::health::HealthProbeAlert) -> Self {
        Self {
            id: value.id,
            target: value.target.unwrap_or_default(),
            in_alert_since: value
                .in_alert_since
                .map(|t| t.to_string())
                .unwrap_or_default(),
            message: value.message,
            tenant_message: value.tenant_message.unwrap_or_default(),
            classifications: value.classifications,
        }
    }
}

impl From<rpc::health::HealthProbeSuccess> for HealthProbeSuccess {
    fn from(value: rpc::health::HealthProbeSuccess) -> Self {
        Self {
            id: value.id,
            target: value.target.unwrap_or_default(),
        }
    }
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
            OverrideMode::Override => 0,
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
                report: Some(hr.into()),
            })
        })
        .collect::<Vec<_>>();

    let request = tonic::Request::new(rpc_machine_id.clone());

    let machine = match state
        .get_machine(request)
        .await
        .map(|response| response.into_inner())
    {
        Ok(m) => m,
        Err(err) if err.code() == tonic::Code::NotFound => {
            return super::not_found_response(machine_id);
        }
        Err(err) => {
            tracing::error!(%err, %machine_id, "get_machine");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response();
        }
    };
    reports.push(LabeledHealthReport {
        label: "Aggregate Health".to_string(),
        report: machine.health.map(HealthReport::from),
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
        report: hw_report.report.map(HealthReport::from),
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
            report: dpu.health.map(HealthReport::from),
        })
    }

    let id = machine.id.unwrap_or_default().id;

    let display = MachineHealth {
        id: id.clone(),
        machine_type: get_machine_type(&id),
        reports,
    };

    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}
