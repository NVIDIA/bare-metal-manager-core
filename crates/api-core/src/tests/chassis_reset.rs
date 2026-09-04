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

use carbide_redfish::libredfish::test_support::RedfishSimAction;
use model::machine::{MachineMaintenanceOperation, ManagedHostState};
use rpc::forge::AdminChassisResetRequest;
use rpc::forge::admin_power_control_request::SystemPowerControl;
use rpc::forge::forge_server::Forge;
use tonic::Request;

use crate::tests::common::api_fixtures::{create_managed_host, create_test_env};

#[crate::sqlx_test]
async fn admin_chassis_reset_queues_maintenance_without_override(
    db_pool: sqlx::PgPool,
) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool).await;
    let managed_host = create_managed_host(&env).await;
    let mut txn = env.db_txn().await;
    db::machine::update_state(&mut txn, &managed_host.host().id, &ManagedHostState::Ready).await?;
    txn.commit().await?;

    let mut txn = env.db_txn().await;
    let bmc_access = managed_host.host().bmc_access(&mut txn).await;
    txn.rollback().await?;
    let redfish_timepoint = env.redfish_sim.timepoint();

    env.api
        .admin_chassis_reset(Request::new(AdminChassisResetRequest {
            machine_id: Some(managed_host.host().id.into()),
            chassis_id: "HGX_Chassis_0".to_string(),
            action: SystemPowerControl::ForceRestart as i32,
        }))
        .await?;

    let duplicate_error = env
        .api
        .admin_chassis_reset(Request::new(AdminChassisResetRequest {
            machine_id: Some(managed_host.host().id.into()),
            chassis_id: "HGX_Chassis_1".to_string(),
            action: SystemPowerControl::ForceRestart as i32,
        }))
        .await
        .unwrap_err();
    assert_eq!(duplicate_error.code(), tonic::Code::FailedPrecondition);

    let mut txn = env.db_txn().await;
    let machine = managed_host.host().db_machine(&mut txn).await;
    assert_eq!(machine.current_state(), &ManagedHostState::Ready);
    assert_eq!(
        machine
            .machine_maintenance_requested
            .as_ref()
            .map(|request| &request.operation),
        Some(&MachineMaintenanceOperation::ChassisReset {
            chassis_id: "HGX_Chassis_0".to_string(),
        }),
    );
    txn.rollback().await?;
    assert!(
        env.redfish_sim
            .actions_since(&redfish_timepoint)
            .for_host(&bmc_access.host)
            .is_empty(),
    );

    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;
    assert_eq!(
        managed_host
            .host()
            .db_machine(&mut txn)
            .await
            .current_state(),
        &ManagedHostState::Maintenance {
            operation: MachineMaintenanceOperation::ChassisReset {
                chassis_id: "HGX_Chassis_0".to_string(),
            },
        },
    );
    txn.rollback().await?;

    env.run_machine_state_controller_iteration().await;
    let mut txn = env.db_txn().await;
    let machine = managed_host.host().db_machine(&mut txn).await;
    assert_eq!(machine.current_state(), &ManagedHostState::Ready);
    assert!(machine.machine_maintenance_requested.is_none());
    txn.rollback().await?;
    assert_eq!(
        env.redfish_sim
            .actions_since(&redfish_timepoint)
            .for_host(&bmc_access.host),
        vec![RedfishSimAction::ChassisReset {
            chassis_id: "HGX_Chassis_0".to_string(),
            reset_type: libredfish::SystemPowerControl::ForceRestart,
        }],
    );

    Ok(())
}

#[crate::sqlx_test]
async fn admin_chassis_reset_rejects_live_instance_even_if_machine_state_is_ready(
    db_pool: sqlx::PgPool,
) -> Result<(), eyre::Report> {
    let env = create_test_env(db_pool).await;
    let managed_host = create_managed_host(&env).await;
    let _instance = managed_host.instance_builer(&env).build().await;

    // Model allocation having committed immediately before the reset request,
    // while the machine controller has not yet observed the live instance.
    let mut txn = env.db_txn().await;
    db::machine::update_state(&mut txn, &managed_host.host().id, &ManagedHostState::Ready).await?;
    txn.commit().await?;

    let error = env
        .api
        .admin_chassis_reset(Request::new(AdminChassisResetRequest {
            machine_id: Some(managed_host.host().id.into()),
            chassis_id: "HGX_Chassis_0".to_string(),
            action: SystemPowerControl::ForceRestart as i32,
        }))
        .await
        .unwrap_err();
    assert_eq!(error.code(), tonic::Code::FailedPrecondition);

    let mut txn = env.db_txn().await;
    assert!(
        managed_host
            .host()
            .db_machine(&mut txn)
            .await
            .machine_maintenance_requested
            .is_none()
    );

    Ok(())
}
