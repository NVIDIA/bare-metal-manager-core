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

use ::rpc::forge as rpc;
use carbide_utils::none_if_empty::NoneIfEmpty;
use carbide_uuid::machine::HostMachineId;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{MachineMaintenanceOperation, ManagedHostState};
use tonic::{Request, Response, Status};

use crate::api::{Api, log_request_data};
use crate::handlers::utils::convert_and_log_machine_id;

pub(super) fn validate_chassis_id(chassis_id: &str) -> Result<(), Status> {
    if !chassis_id
        .bytes()
        .next()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        || !chassis_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(Status::invalid_argument(
            "chassis_id contains unsupported characters",
        ));
    }
    Ok(())
}

pub(crate) async fn admin_chassis_reset(
    api: &Api,
    request: Request<rpc::AdminChassisResetRequest>,
) -> Result<Response<()>, Status> {
    log_request_data(&request);
    let req = request.into_inner();
    let host_machine_id = convert_and_log_machine_id::<HostMachineId>(req.machine_id.as_ref())?;
    let chassis_id = req
        .chassis_id
        .none_if_empty()
        .ok_or_else(|| Status::invalid_argument("chassis_id is required"))?;
    validate_chassis_id(&chassis_id)?;

    let operation = MachineMaintenanceOperation::ChassisReset { chassis_id };
    let machine_id = host_machine_id.into();
    let (host_machine, mut txn) = api
        .load_machine(
            &host_machine_id,
            MachineSearchConfig {
                for_update: true,
                ..Default::default()
            },
        )
        .await?;

    if matches!(
        host_machine.current_state(),
        ManagedHostState::Assigned { .. }
    ) || db::instance::find_id_by_machine_id(&mut txn, &machine_id)
        .await?
        .is_some()
    {
        return Err(Status::failed_precondition(
            "host is assigned to a tenant; a chassis reset is not allowed",
        ));
    }
    if matches!(
        host_machine.current_state(),
        ManagedHostState::ForceDeletion
    ) {
        return Err(Status::failed_precondition(
            "host is marked for forced deletion; a chassis reset is not allowed",
        ));
    }

    if let Some(existing) = host_machine.machine_maintenance_requested.as_ref() {
        if existing.operation != operation {
            return Err(Status::failed_precondition(
                "host already has a pending maintenance operation",
            ));
        }
    } else {
        if matches!(
            host_machine.current_state(),
            ManagedHostState::Maintenance { .. }
        ) {
            return Err(Status::failed_precondition(
                "host is already executing a maintenance operation",
            ));
        }
        db::machine::set_machine_maintenance_requested(&mut txn, machine_id, "rest-api", operation)
            .await?;
    }
    txn.commit().await?;

    if let Err(error) = api
        .machine_state_handler_enqueuer
        .enqueue_object(&host_machine_id)
        .await
    {
        tracing::warn!(
            %host_machine_id,
            %error,
            "Failed to enqueue managed host after recording chassis reset request",
        );
    }

    Ok(Response::new(()))
}

#[cfg(test)]
mod tests {
    use carbide_test_support::value_scenarios;

    use super::validate_chassis_id;

    #[test]
    fn chassis_id_rejects_path_characters() {
        value_scenarios!(run = |id: &str| { validate_chassis_id(id).map_err(|_| ()) };
            "chassis ID validation" {
                "Chassis_0" => Ok(()),
                "../Chassis_0" => Err(()),
                "Chassis/0" => Err(()),
            }
        );
    }
}
