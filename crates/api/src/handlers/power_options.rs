/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use model::machine::LoadSnapshotOptions;
use tonic::{Request, Response, Status};

use crate::CarbideError;
use crate::api::{Api, log_machine_id, log_request_data};

pub(crate) async fn get_power_options(
    api: &Api,
    request: Request<rpc::PowerOptionRequest>,
) -> Result<Response<rpc::PowerOptionResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let mut txn = api.txn_begin().await?;
    let power_options = if req.machine_id.is_empty() {
        db::power_options::get_all(&mut txn).await
    } else {
        db::power_options::get_by_ids(&req.machine_id, &mut txn).await
    }?;

    txn.commit().await?;

    Ok(Response::new(rpc::PowerOptionResponse {
        response: power_options
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<rpc::PowerOptions>>(),
    }))
}

pub(crate) async fn update_power_option(
    api: &Api,
    request: Request<rpc::PowerOptionUpdateRequest>,
) -> Result<Response<rpc::PowerOptionResponse>, Status> {
    log_request_data(&request);
    let req = request.into_inner();

    let machine_id = req
        .machine_id
        .ok_or_else(|| Status::invalid_argument("Machine ID is missing"))?;

    if machine_id.machine_type().is_dpu() {
        return Err(Status::invalid_argument("Only host id is expected!!"));
    }

    log_machine_id(&machine_id);

    let mut txn = api.txn_begin().await?;

    let current_power_state = db::power_options::get_by_ids(&[machine_id], &mut txn).await?;

    // This should never happen until machine is not forced-deleted or does not exist.
    let Some(current_power_options) = current_power_state.first() else {
        return Err(Status::invalid_argument("Only host id is expected!!"));
    };

    let desired_power_state = req.power_state();

    // if desired_state == Off, maintenance must be set.
    if matches!(desired_power_state, rpc::PowerState::Off) {
        let snapshot = db::managed_host::load_snapshot(
            &mut txn,
            &machine_id,
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: false,
                host_health_config: api.runtime_config.host_health,
            },
        )
        .await?
        .ok_or(CarbideError::NotFoundError {
            kind: "machine",
            id: machine_id.to_string(),
        })?;

        // Start reprovisioning only if the host has an HostUpdateInProgress health alert
        let update_alert = snapshot
            .aggregate_health
            .alerts
            .iter()
            .find(|a| a.id == health_report::HealthProbeId::internal_maintenance());
        if !update_alert.is_some_and(|alert| {
            alert
                .classifications
                .contains(&health_report::HealthAlertClassification::suppress_external_alerting())
        }) {
            return Err(Status::invalid_argument(
                "Machine must have a 'Maintenance' Health Alert with 'SupressExternalAlerting' classification.",
            ));
        }
    }

    // To avoid unnecessary version increment.
    let desired_power_state = desired_power_state.into();
    if desired_power_state == current_power_options.desired_power_state {
        return Err(Status::invalid_argument(format!(
            "Power State is already set as {desired_power_state:?}. No change is performed."
        )));
    }

    let updated_value = db::power_options::update_desired_state(
        &machine_id,
        desired_power_state,
        &current_power_options.desired_power_state_version,
        &mut txn,
    )
    .await?;

    txn.commit().await?;

    Ok(Response::new(rpc::PowerOptionResponse {
        response: vec![updated_value.into()],
    }))
}
