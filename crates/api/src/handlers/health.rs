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

use ::rpc::forge::{self as rpc, HealthReportEntry};
use carbide_uuid::machine::MachineId;
use health_report::HealthReportApplyMode;
use model::machine::machine_search_config::MachineSearchConfig;
use sqlx::PgConnection;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::Api;
use crate::auth::AuthContext;
use crate::handlers::utils::convert_and_log_machine_id;

pub async fn list_machine_health_reports(
    api: &Api,
    machine_id: Request<MachineId>,
) -> Result<Response<rpc::ListHealthReportResponse>, Status> {
    let mut txn = api.txn_begin().await?;

    let machine_id = convert_and_log_machine_id(Some(&machine_id.into_inner()))?;

    let host_machine = db::machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default())
        .await?
        .ok_or_else(|| CarbideError::NotFoundError {
            kind: "machine",
            id: machine_id.to_string(),
        })?;

    txn.commit().await?;

    Ok(Response::new(rpc::ListHealthReportResponse {
        health_report_entries: host_machine
            .health_reports
            .clone()
            .into_iter()
            .map(|o| HealthReportEntry {
                report: Some(o.0.into()),
                mode: o.1 as i32,
            })
            .collect(),
    }))
}

async fn remove_by_source(
    txn: &mut PgConnection,
    machine_id: MachineId,
    source: String,
) -> Result<(), CarbideError> {
    let host_machine = db::machine::find_one(
        &mut *txn,
        &machine_id,
        MachineSearchConfig {
            // Technically,  an update is going to happen,
            // but we don't seem to need coordination/locking.
            for_update: false,
            ..Default::default()
        },
    )
    .await?
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    // Ensure this source already exists in override list
    let mode = if host_machine
        .health_reports
        .replace
        .as_ref()
        .map(|o| &o.source)
        == Some(&source)
    {
        HealthReportApplyMode::Replace
    } else if host_machine.health_reports.merges.contains_key(&source) {
        HealthReportApplyMode::Merge
    } else {
        return Err(CarbideError::NotFoundError {
            kind: "machine with source",
            id: source.to_string(),
        });
    };

    db::machine::remove_health_report(txn, &machine_id, mode, &source).await?;

    Ok(())
}

pub async fn insert_machine_health_report(
    api: &Api,
    request: Request<rpc::InsertMachineHealthReportRequest>,
) -> Result<Response<()>, Status> {
    let triggered_by = request
        .extensions()
        .get::<AuthContext>()
        .and_then(|ctx| ctx.get_external_user_name())
        .map(String::from);

    let rpc::InsertMachineHealthReportRequest {
        machine_id,
        health_report_entry: Some(rpc::HealthReportEntry { report, mode }),
    } = request.into_inner()
    else {
        return Err(CarbideError::MissingArgument("override").into());
    };
    let machine_id = convert_and_log_machine_id(machine_id.as_ref())?;
    let Some(report) = report else {
        return Err(CarbideError::MissingArgument("report").into());
    };
    let Ok(mode) = rpc::HealthReportApplyMode::try_from(mode) else {
        return Err(CarbideError::InvalidArgument("mode".to_string()).into());
    };
    let mode: HealthReportApplyMode = mode.into();
    if machine_id.machine_type().is_dpu() && mode == HealthReportApplyMode::Replace {
        return Err(CarbideError::InvalidArgument(
            "DPU's cannot have HealthReportApplyMode::Replace health report overrides".to_string(),
        )
        .into());
    }
    let mut txn = api.txn_begin().await?;

    let mut report = health_report::HealthReport::try_from(report.clone())
        .map_err(|e| CarbideError::internal(e.to_string()))?;
    if report.observed_at.is_none() {
        report.observed_at = Some(chrono::Utc::now());
    }
    report.triggered_by = triggered_by;
    report.update_in_alert_since(None);

    // In case a report with the same source exists, either as merge or replace,
    // remove it. If such a report does not exist, ignore error.
    match remove_by_source(&mut txn, machine_id, report.source.clone()).await {
        Ok(_) | Err(CarbideError::NotFoundError { .. }) => {}
        Err(e) => return Err(e.into()),
    }

    db::machine::insert_health_report(&mut txn, &machine_id, mode, &report, false).await?;

    txn.commit().await?;

    Ok(Response::new(()))
}

pub async fn remove_machine_health_report(
    api: &Api,
    request: Request<rpc::RemoveMachineHealthReportRequest>,
) -> Result<Response<()>, Status> {
    let mut txn = api.txn_begin().await?;

    let rpc::RemoveMachineHealthReportRequest { machine_id, source } = request.into_inner();
    let machine_id = convert_and_log_machine_id(machine_id.as_ref())?;
    remove_by_source(&mut txn, machine_id, source).await?;
    txn.commit().await?;

    Ok(Response::new(()))
}
