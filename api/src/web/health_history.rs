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
use axum::extract::{Path as AxumPath, State as AxumState};
use axum::response::{Html, IntoResponse, Response};
use forge_uuid::machine::MachineId;
use health_report::HealthReport;
use hyper::http::StatusCode;
use rpc::forge::forge_server::Forge;
use std::{str::FromStr, sync::Arc};

use super::filters;
use crate::api::Api;

#[derive(Template)]
#[template(path = "machine_health_history.html")]
struct MachineHealth {
    id: String,
    history: Vec<HealthReportRecord>,
}

struct HealthReportRecord {
    timestamp: String,
    health: health_report::HealthReport,
}

/// Show the health history for a certain Machine
pub async fn health_history(
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

    let health_records = match state
        .find_machine_health_histories(tonic::Request::new(
            ::rpc::forge::MachineHealthHistoriesRequest {
                machine_ids: vec![rpc_machine_id],
            },
        ))
        .await
        .map(|response| response.into_inner())
    {
        Ok(m) => m,
        Err(err) => {
            tracing::error!(%err, %machine_id, "find_machine_health_histories");
            return (StatusCode::INTERNAL_SERVER_ERROR, Html(String::new())).into_response();
        }
    }
    .histories
    .remove(&machine_id)
    .unwrap_or_default()
    .records;

    let display = MachineHealth {
        id: machine_id.clone(),
        history: health_records
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
            .collect(),
    };

    (StatusCode::OK, Html(display.render().unwrap())).into_response()
}
