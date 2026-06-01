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

//! Tests for the PowerShelf `Error` state handler.

use std::sync::Arc;

use carbide_power_shelf_controller::context::{
    PowerShelfStateHandlerContextObjects, PowerShelfStateHandlerServices,
};
use carbide_power_shelf_controller::handler::PowerShelfStateHandler;
use carbide_power_shelf_controller::metrics::PowerShelfMetrics;
use carbide_uuid::power_shelf::PowerShelfId;
use db::power_shelf as db_power_shelf;
use forge_secrets::credentials::TestCredentialManager;
use model::power_shelf::{PowerShelf, PowerShelfControllerState, PowerShelfMaintenanceOperation};
use sqlx::PgConnection;
use state_controller::db_write_batch::DbWriteBatch;
use state_controller::state_handler::{StateHandler, StateHandlerContext, StateHandlerOutcome};

use crate::tests::common::api_fixtures::create_test_env;
use crate::tests::common::api_fixtures::site_explorer::new_power_shelf;
use crate::tests::power_shelf_state_controller::fixtures::power_shelf::{
    mark_power_shelf_as_deleted, set_power_shelf_controller_state,
};

const TEST_ERROR_CAUSE: &str = "test error";

fn services(env: &crate::tests::common::api_fixtures::TestEnv) -> PowerShelfStateHandlerServices {
    let services = env.state_handler_services();
    PowerShelfStateHandlerServices {
        db_pool: services.db_pool.clone(),
        rms_client: services.rms_client.clone(),
        credential_manager: Arc::new(TestCredentialManager::default()),
    }
}

async fn load_power_shelf(pool: &sqlx::PgPool, id: &PowerShelfId) -> PowerShelf {
    let mut conn = pool.acquire().await.unwrap();
    db_power_shelf::find_by_id(conn.as_mut(), id)
        .await
        .unwrap()
        .expect("power shelf should exist")
}

async fn park_in_error(txn: &mut PgConnection, power_shelf_id: &PowerShelfId) {
    set_power_shelf_controller_state(
        txn,
        power_shelf_id,
        PowerShelfControllerState::Error {
            cause: TEST_ERROR_CAUSE.into(),
        },
    )
    .await
    .unwrap();
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

fn extract_transition(
    outcome: StateHandlerOutcome<PowerShelfControllerState>,
) -> Option<PowerShelfControllerState> {
    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => Some(next_state),
        _ => None,
    }
}

#[crate::sqlx_test]
async fn error_with_power_on_maintenance_request_transitions_to_maintenance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id = new_power_shelf(
        &env,
        Some("Error->Maintenance PowerOn".into()),
        None,
        None,
        None,
    )
    .await?;

    {
        let mut txn = pool.acquire().await?;
        park_in_error(txn.as_mut(), &power_shelf_id).await;
        db_power_shelf::set_power_shelf_maintenance_requested(
            txn.as_mut(),
            power_shelf_id,
            "test-initiator",
            PowerShelfMaintenanceOperation::PowerOn,
        )
        .await?;
    }

    let mut services = services(&env);
    let mut shelf = load_power_shelf(&pool, &power_shelf_id).await;
    let outcome = run_handler(&mut services, &mut shelf).await;
    let transition = extract_transition(outcome).expect("should transition out of Error");

    assert!(
        matches!(
            transition,
            PowerShelfControllerState::Maintenance {
                operation: PowerShelfMaintenanceOperation::PowerOn,
            }
        ),
        "expected transition to Maintenance {{ PowerOn }}, got {:?}",
        transition,
    );
    Ok(())
}

#[crate::sqlx_test]
async fn error_with_power_off_maintenance_request_transitions_to_maintenance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id = new_power_shelf(
        &env,
        Some("Error->Maintenance PowerOff".into()),
        None,
        None,
        None,
    )
    .await?;

    {
        let mut txn = pool.acquire().await?;
        park_in_error(txn.as_mut(), &power_shelf_id).await;
        db_power_shelf::set_power_shelf_maintenance_requested(
            txn.as_mut(),
            power_shelf_id,
            "test-initiator",
            PowerShelfMaintenanceOperation::PowerOff,
        )
        .await?;
    }

    let mut services = services(&env);
    let mut shelf = load_power_shelf(&pool, &power_shelf_id).await;
    let outcome = run_handler(&mut services, &mut shelf).await;
    let transition = extract_transition(outcome).expect("should transition out of Error");

    assert!(
        matches!(
            transition,
            PowerShelfControllerState::Maintenance {
                operation: PowerShelfMaintenanceOperation::PowerOff,
            }
        ),
        "expected transition to Maintenance {{ PowerOff }}, got {:?}",
        transition,
    );
    Ok(())
}

#[crate::sqlx_test]
async fn error_without_maintenance_request_holds_in_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id =
        new_power_shelf(&env, Some("Error stays in Error".into()), None, None, None).await?;

    {
        let mut txn = pool.acquire().await?;
        park_in_error(txn.as_mut(), &power_shelf_id).await;
    }

    let mut services = services(&env);
    let mut shelf = load_power_shelf(&pool, &power_shelf_id).await;
    let outcome = run_handler(&mut services, &mut shelf).await;

    assert!(
        !matches!(outcome, StateHandlerOutcome::Transition { .. }),
        "Error state without maintenance request must not transition",
    );
    Ok(())
}

#[crate::sqlx_test]
async fn error_with_deletion_takes_precedence_over_maintenance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id = new_power_shelf(
        &env,
        Some("Error deletion wins over maintenance".into()),
        None,
        None,
        None,
    )
    .await?;

    {
        let mut txn = pool.acquire().await?;
        park_in_error(txn.as_mut(), &power_shelf_id).await;
        db_power_shelf::set_power_shelf_maintenance_requested(
            txn.as_mut(),
            power_shelf_id,
            "test-initiator",
            PowerShelfMaintenanceOperation::PowerOff,
        )
        .await?;
        mark_power_shelf_as_deleted(txn.as_mut(), &power_shelf_id).await?;
    }

    let mut services = services(&env);
    let mut shelf = load_power_shelf(&pool, &power_shelf_id).await;
    let outcome = run_handler(&mut services, &mut shelf).await;
    let transition = extract_transition(outcome).expect("should transition out of Error");

    assert!(
        matches!(transition, PowerShelfControllerState::Deleting),
        "deletion must win over maintenance, got {:?}",
        transition,
    );
    Ok(())
}
