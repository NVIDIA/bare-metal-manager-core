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

use ::rpc::forge as rpc;
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

    // Load the Host Object. Needed to update health report timestamps
    // based on last report.
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
