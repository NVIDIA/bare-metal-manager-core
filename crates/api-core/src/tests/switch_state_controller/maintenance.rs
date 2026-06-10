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

//! Direct-invocation tests for the Switch `Maintenance` state handler.

use carbide_switch_controller::context::{
    SwitchStateHandlerContextObjects, SwitchStateHandlerServices,
};
use carbide_switch_controller::handler::SwitchStateHandler;
use carbide_switch_controller::metrics::SwitchMetrics;
use carbide_uuid::switch::SwitchId;
use db::switch as db_switch;
use model::switch::{Switch, SwitchControllerState, SwitchMaintenanceOperation};
use rpc::common::SystemPowerControl;
use rpc::forge::component_power_control_request::Target;
use rpc::forge::forge_server::Forge;
use rpc::forge::{ComponentPowerControlRequest, SwitchIdList, SwitchesByIdsRequest};
use state_controller::db_write_batch::DbWriteBatch;
use state_controller::state_handler::{StateHandler, StateHandlerContext, StateHandlerOutcome};
use tonic::Request;

use crate::tests::common::api_fixtures::site_explorer::new_switch;
use crate::tests::common::api_fixtures::{TestEnv, create_test_env};
use crate::tests::switch_state_controller::fixtures::switch::set_switch_controller_state;

fn cm_power_action(operation: SwitchMaintenanceOperation) -> SystemPowerControl {
    match operation {
        SwitchMaintenanceOperation::PowerOn => SystemPowerControl::On,
        SwitchMaintenanceOperation::PowerOff => SystemPowerControl::ForceOff,
        SwitchMaintenanceOperation::Reset => SystemPowerControl::ForceRestart,
    }
}

async fn request_switch_maintenance_via_cm(
    env: &TestEnv,
    switch_id: &SwitchId,
    operation: SwitchMaintenanceOperation,
) {
    env.api
        .component_power_control(Request::new(ComponentPowerControlRequest {
            target: Some(Target::SwitchIds(SwitchIdList {
                ids: vec![*switch_id],
            })),
            action: cm_power_action(operation) as i32,
            bypass_state_controller: false,
        }))
        .await
        .expect("component_power_control should succeed");
}

async fn load_switch(env: &TestEnv, id: &SwitchId) -> Switch {
    let switches = env
        .api
        .find_switches_by_ids(Request::new(SwitchesByIdsRequest {
            switch_ids: vec![*id],
        }))
        .await
        .expect("find_switches_by_ids should succeed")
        .into_inner()
        .switches;
    assert_eq!(switches.len(), 1, "switch should exist");

    // The state handler operates on the full model, including fields such as
    // `switch_maintenance_requested` that are not exposed on the RPC Switch.
    let mut conn = env.pool.acquire().await.unwrap();
    db_switch::find_by_id(conn.as_mut(), id)
        .await
        .unwrap()
        .expect("switch should exist")
}

async fn run_handler(
    services: &mut SwitchStateHandlerServices,
    state: &mut Switch,
) -> StateHandlerOutcome<SwitchControllerState> {
    let handler = SwitchStateHandler::default();
    let mut metrics = SwitchMetrics::default();
    let mut writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<SwitchStateHandlerContextObjects> {
        services,
        metrics: &mut metrics,
        pending_db_writes: &mut writes,
    };
    let controller_state = state.controller_state.value.clone();
    let switch_id = state.id;
    handler
        .handle_object_state(&switch_id, state, &controller_state, &mut ctx)
        .await
        .expect("state handler should not return an error result")
}

async fn commit_and_extract_transition(
    mut outcome: StateHandlerOutcome<SwitchControllerState>,
) -> Option<SwitchControllerState> {
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await.unwrap();
    }
    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => Some(next_state),
        _ => None,
    }
}

fn services_without_component_manager(env: &TestEnv) -> SwitchStateHandlerServices {
    SwitchStateHandlerServices {
        db_pool: env.pool.clone(),
        component_manager: None,
        credential_manager: env.test_credential_manager.clone(),
    }
}

async fn services_with_component_manager(env: &TestEnv) -> SwitchStateHandlerServices {
    SwitchStateHandlerServices {
        db_pool: env.pool.clone(),
        component_manager: super::build_test_component_manager(env, env.rms_sim.as_rms_client())
            .await,
        credential_manager: env.test_credential_manager.clone(),
    }
}

#[crate::sqlx_test]
async fn ready_transitions_to_maintenance_when_request_is_set(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let switch_id = new_switch(&env, None, None).await?;

    request_switch_maintenance_via_cm(&env, &switch_id, SwitchMaintenanceOperation::PowerOff).await;

    {
        let mut txn = pool.acquire().await?;
        set_switch_controller_state(&mut txn, &switch_id, SwitchControllerState::Ready).await?;
    }

    let mut switch = load_switch(&env, &switch_id).await;
    let mut services = services_without_component_manager(&env);
    let outcome = run_handler(&mut services, &mut switch).await;

    assert!(matches!(
        outcome,
        StateHandlerOutcome::Transition {
            next_state: SwitchControllerState::Maintenance {
                operation: SwitchMaintenanceOperation::PowerOff,
            },
            ..
        }
    ));

    Ok(())
}

/// `Ready` must not dispatch maintenance power operations while idling.
#[crate::sqlx_test]
async fn ready_state_does_not_invoke_power_control(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let switch_id = new_switch(&env, None, None).await?;

    {
        let mut txn = pool.acquire().await?;
        set_switch_controller_state(&mut txn, &switch_id, SwitchControllerState::Ready).await?;
    }

    let mut services = services_with_component_manager(&env).await;
    let mut switch = load_switch(&env, &switch_id).await;
    let outcome = run_handler(&mut services, &mut switch).await;
    let _ = commit_and_extract_transition(outcome).await;

    let calls = env
        .rms_sim
        .submitted_set_power_state_by_device_list_requests()
        .await;
    assert!(
        calls.is_empty(),
        "Ready state must not call set_power_state_by_device_list"
    );

    Ok(())
}
