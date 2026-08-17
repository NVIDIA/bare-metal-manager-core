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

//! Tests for power-shelf rack firmware reprovisioning.

use std::sync::Arc;

use carbide_power_shelf_controller::context::{
    PowerShelfStateHandlerContextObjects, PowerShelfStateHandlerServices,
};
use carbide_power_shelf_controller::handler::PowerShelfStateHandler;
use carbide_power_shelf_controller::metrics::PowerShelfMetrics;
use carbide_secrets::test_support::credentials::TestCredentialManager;
use carbide_uuid::power_shelf::PowerShelfId;
use db::power_shelf as db_power_shelf;
use model::power_shelf::{PowerShelf, PowerShelfControllerState, ReProvisioningState};
use model::rack::MaintenanceActivity;
use sqlx::PgConnection;
use state_controller::db_write_batch::DbWriteBatch;
use state_controller::state_handler::{StateHandler, StateHandlerContext, StateHandlerOutcome};

use crate::tests::common::api_fixtures::create_test_env;
use crate::tests::common::api_fixtures::site_explorer::new_power_shelf;
use crate::tests::power_shelf_state_controller::fixtures::power_shelf::set_power_shelf_controller_state;

fn firmware_only_activities() -> Vec<MaintenanceActivity> {
    vec![MaintenanceActivity::FirmwareUpgrade {
        firmware_version: None,
        components: vec![],
        force_update: false,
    }]
}

fn services(
    env: &crate::tests::common::api_fixtures::TestEnv,
    rack_firmware_reprovisioning_enabled: bool,
) -> PowerShelfStateHandlerServices {
    PowerShelfStateHandlerServices {
        db_pool: env.pool.clone(),
        component_manager: None,
        credential_manager: Arc::new(TestCredentialManager::default()),
        per_object_metrics_registry: env.per_object_metrics_registry(),
        rack_firmware_reprovisioning_enabled,
        redfish_client_pool: env.redfish_sim.clone(),
        bmc_rotation_gate: carbide_credential_rotation::RotationGate::new_for_family(
            db::credential_rotation::CredentialRotationType::Bmc,
        ),
        bmc_rotation_enabled: false,
    }
}

async fn load_power_shelf(pool: &sqlx::PgPool, id: &PowerShelfId) -> PowerShelf {
    let mut conn = pool.acquire().await.unwrap();
    db_power_shelf::find_by_id(conn.as_mut(), id)
        .await
        .unwrap()
        .expect("power shelf should exist")
}

async fn run_handler(
    services: &mut PowerShelfStateHandlerServices,
    state: &mut PowerShelf,
) -> StateHandlerOutcome<PowerShelfControllerState> {
    let handler = PowerShelfStateHandler::default();
    let mut metrics = PowerShelfMetrics::default();
    let mut writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<PowerShelfStateHandlerContextObjects> {
        services,
        metrics: &mut metrics,
        pending_db_writes: &mut writes,
    };
    let controller_state = state.controller_state.value.clone();
    let power_shelf_id = state.id;
    handler
        .handle_object_state(&power_shelf_id, state, &controller_state, &mut ctx)
        .await
        .expect("state handler should not return an error result")
}

async fn commit_outcome(mut outcome: StateHandlerOutcome<PowerShelfControllerState>) {
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await.unwrap();
    }
}

async fn park_ready(txn: &mut PgConnection, power_shelf_id: &PowerShelfId) {
    set_power_shelf_controller_state(txn, power_shelf_id, PowerShelfControllerState::Ready)
        .await
        .expect("set Ready");
}

#[crate::sqlx_test]
async fn test_ready_clears_reprovision_request_when_flag_disabled(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id = new_power_shelf(&env, None, None, None, None).await?;

    let mut txn = pool.begin().await?;
    park_ready(txn.as_mut(), &power_shelf_id).await;
    db_power_shelf::set_power_shelf_reprovisioning_requested(
        txn.as_mut(),
        power_shelf_id,
        "rack-test",
        firmware_only_activities(),
    )
    .await?;
    txn.commit().await?;

    let mut state = load_power_shelf(&pool, &power_shelf_id).await;
    let mut services = services(&env, false);
    let outcome = run_handler(&mut services, &mut state).await;
    assert!(matches!(outcome, StateHandlerOutcome::DoNothing { .. }));
    commit_outcome(outcome).await;

    let state = load_power_shelf(&pool, &power_shelf_id).await;
    assert!(state.power_shelf_reprovisioning_requested.is_none());
    assert!(matches!(
        state.controller_state.value,
        PowerShelfControllerState::Ready
    ));
    Ok(())
}

#[crate::sqlx_test]
async fn test_ready_enters_waiting_for_rack_firmware_when_flag_enabled(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id = new_power_shelf(&env, None, None, None, None).await?;

    let mut txn = pool.begin().await?;
    park_ready(txn.as_mut(), &power_shelf_id).await;
    db_power_shelf::set_power_shelf_reprovisioning_requested(
        txn.as_mut(),
        power_shelf_id,
        "rack-test",
        firmware_only_activities(),
    )
    .await?;
    txn.commit().await?;

    let mut state = load_power_shelf(&pool, &power_shelf_id).await;
    let mut services = services(&env, true);
    let outcome = run_handler(&mut services, &mut state).await;
    assert!(matches!(
        outcome,
        StateHandlerOutcome::Transition {
            next_state: PowerShelfControllerState::ReProvisioning {
                reprovisioning_state: ReProvisioningState::WaitingForRackFirmwareUpgrade,
            },
            ..
        }
    ));
    Ok(())
}

#[crate::sqlx_test]
async fn test_waiting_for_rack_firmware_completes_to_ready(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id = new_power_shelf(&env, None, None, None, None).await?;

    let mut txn = pool.begin().await?;
    db_power_shelf::set_power_shelf_reprovisioning_requested(
        txn.as_mut(),
        power_shelf_id,
        "rack-test",
        firmware_only_activities(),
    )
    .await?;
    let power_shelf = db_power_shelf::find_by_id(txn.as_mut(), &power_shelf_id)
        .await?
        .expect("power shelf should exist");
    let requested_at = power_shelf
        .power_shelf_reprovisioning_requested
        .as_ref()
        .expect("request should exist")
        .requested_at;
    set_power_shelf_controller_state(
        txn.as_mut(),
        &power_shelf_id,
        PowerShelfControllerState::ReProvisioning {
            reprovisioning_state: ReProvisioningState::WaitingForRackFirmwareUpgrade,
        },
    )
    .await?;
    db_power_shelf::update_firmware_upgrade_status(
        txn.as_mut(),
        power_shelf_id,
        Some(&model::rack::RackFirmwareUpgradeStatus {
            task_id: "rack-job".to_string(),
            status: model::rack::RackFirmwareUpgradeState::Completed,
            started_at: Some(requested_at),
            ended_at: Some(requested_at + chrono::Duration::seconds(1)),
        }),
    )
    .await?;
    txn.commit().await?;

    let mut state = load_power_shelf(&pool, &power_shelf_id).await;
    let mut services = services(&env, true);
    let outcome = run_handler(&mut services, &mut state).await;
    assert!(matches!(
        outcome,
        StateHandlerOutcome::Transition {
            next_state: PowerShelfControllerState::Ready,
            ..
        }
    ));
    commit_outcome(outcome).await;

    let state = load_power_shelf(&pool, &power_shelf_id).await;
    assert!(state.power_shelf_reprovisioning_requested.is_none());
    Ok(())
}
