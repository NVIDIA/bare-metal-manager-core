/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge::{self as rpc, HealthReportOverride};
use health_report::OverrideMode;
use tonic::{Request, Response, Status};

use crate::{
    api::{log_machine_id, Api},
    db::{
        machine::{Machine, MachineSearchConfig},
        DatabaseError,
    },
    model::machine::machine_id::try_parse_machine_id,
    CarbideError,
};

pub async fn record_hardware_health_report(
    api: &Api,
    request: Request<rpc::HardwareHealthReport>,
) -> Result<Response<()>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin record_hardware_health_report",
            e,
        ))
    })?;
    let rpc::HardwareHealthReport { machine_id, report } = request.into_inner();
    let machine_id = match machine_id {
        Some(id) => try_parse_machine_id(&id).map_err(CarbideError::from)?,
        None => {
            return Err(CarbideError::MissingArgument("machine_id").into());
        }
    };
    log_machine_id(&machine_id);
    let Some(report) = report else {
        return Err(CarbideError::MissingArgument("report").into());
    };

    let host_machine = Machine::find_one(
        &mut txn,
        &machine_id,
        MachineSearchConfig {
            include_dpus: false,
            include_history: false,
            include_predicted_host: false,
            only_maintenance: false,
            include_associated_machine_id: false,
            exclude_hosts: false,
        },
    )
    .await
    .map_err(CarbideError::from)?
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    let mut report = health_report::HealthReport::try_from(report.clone())
        .map_err(|e| CarbideError::GenericError(format!("Can not convert health report: {e}")))?;
    report.observed_at = Some(chrono::Utc::now());

    // Fix the in_alert times based on the previously stored report
    report.update_in_alert_since(host_machine.hardware_health_report());
    Machine::update_hardware_health_report(&mut txn, &machine_id, &report)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit record_hardware_health_report",
            e,
        ))
    })?;

    Ok(Response::new(()))
}

pub async fn list_health_report_overrides(
    api: &Api,
    machine_id: Request<::rpc::common::MachineId>,
) -> Result<Response<rpc::ListHealthReportOverrideResponse>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin InsertHealthReportOverrideRequest",
            e,
        ))
    })?;
    let machine_id = try_parse_machine_id(&machine_id.into_inner()).map_err(CarbideError::from)?;
    log_machine_id(&machine_id);

    let host_machine = Machine::find_one(
        &mut txn,
        &machine_id,
        MachineSearchConfig {
            include_dpus: false,
            include_history: false,
            include_predicted_host: false,
            only_maintenance: false,
            include_associated_machine_id: false,
            exclude_hosts: false,
        },
    )
    .await
    .map_err(CarbideError::from)?
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit list_health_report_overrides",
            e,
        ))
    })?;

    Ok(Response::new(rpc::ListHealthReportOverrideResponse {
        overrides: host_machine
            .health_report_overrides()
            .clone()
            .create_iter()
            .map(|o| HealthReportOverride {
                report: Some(o.0.into()),
                mode: o.1 as i32,
            })
            .collect(),
    }))
}

pub async fn insert_health_report_override(
    api: &Api,
    request: Request<rpc::InsertHealthReportOverrideRequest>,
) -> Result<Response<()>, Status> {
    let rpc::InsertHealthReportOverrideRequest {
        machine_id,
        r#override: Some(rpc::HealthReportOverride { report, mode }),
    } = request.into_inner()
    else {
        return Err(CarbideError::MissingArgument("override").into());
    };
    let machine_id = match machine_id {
        Some(id) => try_parse_machine_id(&id).map_err(CarbideError::from)?,
        None => {
            return Err(CarbideError::MissingArgument("machine_id").into());
        }
    };
    log_machine_id(&machine_id);
    let Some(report) = report else {
        return Err(CarbideError::MissingArgument("report").into());
    };
    let Ok(mode) = rpc::OverrideMode::try_from(mode) else {
        return Err(CarbideError::InvalidArgument("mode".to_string()).into());
    };
    let mode: OverrideMode = mode.into();
    if machine_id.machine_type().is_dpu() && mode == OverrideMode::Override {
        return Err(CarbideError::InvalidArgument(
            "DPU's cannot have OverrideMode::Override health report overrides".to_string(),
        )
        .into());
    }

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin insert_health_report_override",
            e,
        ))
    })?;

    let mut report = health_report::HealthReport::try_from(report.clone())
        .map_err(|e| CarbideError::GenericError(format!("Can not convert health report: {e}")))?;
    if report.observed_at.is_none() {
        report.observed_at = Some(chrono::Utc::now());
    }
    report.update_in_alert_since(None);

    Machine::insert_health_report_override(&mut txn, &machine_id, mode, &report)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit insert_health_report_override",
            e,
        ))
    })?;

    Ok(Response::new(()))
}

pub async fn remove_health_report_override(
    api: &Api,
    request: Request<rpc::RemoveHealthReportOverrideRequest>,
) -> Result<Response<()>, Status> {
    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin remove_health_report_override",
            e,
        ))
    })?;

    let rpc::RemoveHealthReportOverrideRequest { machine_id, source } = request.into_inner();
    let machine_id = match machine_id {
        Some(id) => try_parse_machine_id(&id).map_err(CarbideError::from)?,
        None => {
            return Err(CarbideError::MissingArgument("machine_id").into());
        }
    };
    log_machine_id(&machine_id);

    let host_machine = Machine::find_one(
        &mut txn,
        &machine_id,
        MachineSearchConfig {
            include_dpus: false,
            include_history: false,
            include_predicted_host: false,
            only_maintenance: false,
            include_associated_machine_id: false,
            exclude_hosts: false,
        },
    )
    .await
    .map_err(CarbideError::from)?
    .ok_or_else(|| CarbideError::NotFoundError {
        kind: "machine",
        id: machine_id.to_string(),
    })?;

    // Ensure this source already exists in override list
    let mode = if host_machine
        .health_report_overrides()
        .r#override
        .as_ref()
        .map(|o| &o.source)
        == Some(&source)
    {
        OverrideMode::Override
    } else if host_machine
        .health_report_overrides()
        .merges
        .contains_key(&source)
    {
        OverrideMode::Merge
    } else {
        return Err(CarbideError::GenericError(format!(
            "Found no machine with source {}",
            machine_id
        ))
        .into());
    };

    // Not clear if there can be a race condition between obtaining the overrides
    // and updating them: could possibly lead to erasing overrides that were
    // added or removed in the middle.
    Machine::remove_health_report_override(&mut txn, &machine_id, mode, &source)
        .await
        .map_err(CarbideError::from)?;

    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "commit remove_health_report_override",
            e,
        ))
    })?;

    Ok(Response::new(()))
}
