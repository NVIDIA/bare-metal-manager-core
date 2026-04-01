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

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use carbide_uuid::rack::RackId;
use db::rack as db_rack;
use model::rack::{
    Rack, RackFirmwareUpgradeState, RackMaintenanceState, RackState, RackValidationState,
};
use rpc::forge::RackStateHistoryRecord;
use rpc::forge::forge_server::Forge;
use tokio_util::sync::CancellationToken;

use crate::state_controller::config::IterationConfig;
use crate::state_controller::controller::StateController;
use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::rack::io::RackStateControllerIO;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};
use crate::tests::common::api_fixtures::create_test_env;
use crate::tests::common::api_fixtures::site_explorer::TestRackDbBuilder;

mod fixtures;
mod handler;
use fixtures::rack::set_rack_controller_state;

#[derive(Debug, Default, Clone)]
pub struct TestRackStateHandler {
    /// The total count for the handler
    pub count: Arc<AtomicUsize>,
    /// We count for every rack ID how often the handler was called
    pub counts_per_id: Arc<Mutex<HashMap<String, usize>>>,
}

#[async_trait::async_trait]
impl StateHandler for TestRackStateHandler {
    type State = Rack;
    type ControllerState = RackState;
    type ObjectId = RackId;
    type ContextObjects = RackStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        rack_id: &RackId,
        state: &mut Rack,
        controller_state: &Self::ControllerState,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<Self::ControllerState>, StateHandlerError> {
        assert_eq!(state.id, *rack_id);
        self.count.fetch_add(1, Ordering::SeqCst);
        {
            let mut guard = self.counts_per_id.lock().unwrap();
            *guard.entry(rack_id.to_string()).or_default() += 1;
        }

        // Mirror the real handler: if the rack is marked deleted in DB,
        // transition to Deleting regardless of current state.
        if state.deleted.is_some() && !matches!(controller_state, RackState::Deleting) {
            return Ok(StateHandlerOutcome::transition(RackState::Deleting));
        }

        let state = match controller_state {
            RackState::Expected => RackState::Discovering,
            RackState::Discovering => RackState::Maintenance {
                rack_maintenance: RackMaintenanceState::FirmwareUpgrade {
                    rack_firmware_upgrade: RackFirmwareUpgradeState::Compute,
                },
            },
            RackState::Maintenance { rack_maintenance } => match rack_maintenance {
                RackMaintenanceState::FirmwareUpgrade { .. } => RackState::Maintenance {
                    rack_maintenance: RackMaintenanceState::Completed,
                },
                RackMaintenanceState::Completed => RackState::Validation {
                    rack_validation: RackValidationState::Pending,
                },
                _ => return Ok(StateHandlerOutcome::do_nothing()),
            },
            RackState::Validation { rack_validation } => match rack_validation {
                RackValidationState::Pending => RackState::Validation {
                    rack_validation: RackValidationState::InProgress,
                },
                RackValidationState::InProgress => RackState::Validation {
                    rack_validation: RackValidationState::Partial,
                },
                RackValidationState::Partial => RackState::Validation {
                    rack_validation: RackValidationState::Validated,
                },
                RackValidationState::Validated => RackState::Ready,
                _ => return Ok(StateHandlerOutcome::do_nothing()),
            },
            RackState::Deleting => {
                // Rack is being deleted
                let mut txn = ctx.services.db_pool.begin().await?;
                db::rack::final_delete(&mut txn, rack_id).await?;
                return Ok(StateHandlerOutcome::deleted().with_txn(txn));
            }
            _ => return Ok(StateHandlerOutcome::do_nothing()),
        };

        Ok(StateHandlerOutcome::transition(state))
    }
}

fn validate_state_change_history(
    histories: &[RackStateHistoryRecord],
    expected: &Vec<&str>,
) -> bool {
    for &s in expected {
        if !histories.iter().any(|e| e.state == s) {
            return false;
        }
    }
    true
}

#[crate::sqlx_test]
async fn test_can_retrieve_rack_state_history(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a rack
    let mut txn = pool.acquire().await?;
    let rack_id = TestRackDbBuilder::new()
        .with_expected_compute_trays(vec![
            [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x50],
            [0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x51],
        ])
        .with_expected_power_shelves(vec![
            [0x01, 0x1A, 0x2B, 0x3C, 0x4D, 0x50],
            [0x01, 0x1A, 0x2B, 0x3C, 0x4D, 0x51],
        ])
        .with_expected_switches(vec![[0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x50]])
        .with_rack_type("NVL72")
        .persist(&mut txn)
        .await?;

    // Verify rack exists
    db_rack::get(&mut *txn, &rack_id).await?;

    // Start the state controller to process the rack while it's active
    let rack_handler = Arc::new(TestRackStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);

    let handler_services = Arc::new(env.state_handler_services());

    let cancel_token = CancellationToken::new();
    let mut controller = StateController::<RackStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services)
        .state_handler(rack_handler)
        .build_for_manual_iterations(cancel_token.clone())
        .unwrap();

    // iterate enough times to walk through the full state chain:
    for _ in 0..10 {
        controller.run_single_iteration().await;
    }

    // get state history

    let state_histories_request = rpc::forge::RackStateHistoriesRequest {
        rack_ids: vec![rack_id.clone()],
    };

    let result = env
        .api
        .find_rack_state_histories(tonic::Request::new(state_histories_request))
        .await?;

    let mut histories = result.into_inner().histories;

    let records = histories
        .remove(&rack_id.to_string())
        .unwrap_or_default()
        .records;

    assert!(records.len() > 1);

    // We should have run through a few states, validate that we did.
    // States are serialized via serde with #[serde(tag = "state", rename_all = "snake_case")].
    let expected = vec![
        "{\"state\": \"discovering\"}",
        "{\"state\": \"maintenance\", \"rack_maintenance\": {\"FirmwareUpgrade\": {\"rack_firmware_upgrade\": \"Compute\"}}}",
        "{\"state\": \"maintenance\", \"rack_maintenance\": \"Completed\"}",
        "{\"state\": \"validation\", \"rack_validation\": \"Pending\"}",
        "{\"state\": \"validation\", \"rack_validation\": \"Validated\"}",
        "{\"state\": \"ready\"}",
    ];
    assert!(validate_state_change_history(&records, &expected));

    Ok(())
}

#[crate::sqlx_test]
async fn test_rack_state_transitions(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a rack
    let rack_id = RackId::new(uuid::Uuid::new_v4().to_string());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(rack_id.clone())
        .persist(&mut txn)
        .await?;

    // Verify rack exists
    let rack = db_rack::get(&mut *txn, &rack_id).await?;

    // Verify initial state is Expected
    assert!(matches!(rack.controller_state.value, RackState::Expected));

    // Start the state controller
    let rack_handler = Arc::new(TestRackStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);

    let handler_services = Arc::new(env.state_handler_services());

    let cancel_token = CancellationToken::new();
    let mut controller = StateController::<RackStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(rack_handler.clone())
        .build_for_manual_iterations(cancel_token.clone())
        .unwrap();

    // iterate a few times
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;

    // Verify that the handler was called
    let count = rack_handler.count.load(Ordering::SeqCst);
    assert!(
        count > 0,
        "State handler should have been called at least once"
    );

    // Verify that the rack ID was processed
    let guard = rack_handler.counts_per_id.lock().unwrap();
    let rack_id_str = rack_id.to_string();
    let count = guard.get(&rack_id_str).copied().unwrap_or_default();
    assert!(count > 0, "Rack ID should have been processed");

    Ok(())
}

#[crate::sqlx_test]
async fn test_rack_error_state_handling(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a rack
    let rack_id = RackId::new(uuid::Uuid::new_v4().to_string());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(rack_id.clone())
        .persist(&mut txn)
        .await?;

    // Manually set the rack to error state for testing
    let error_state = RackState::Error {
        cause: "Test error state".to_string(),
    };

    // Update the controller state directly in the database
    set_rack_controller_state(pool.acquire().await?.as_mut(), &rack_id, error_state).await?;

    // Start the state controller
    let rack_handler = Arc::new(TestRackStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);

    let handler_services = Arc::new(env.state_handler_services());

    let cancel_token = CancellationToken::new();
    let mut controller = StateController::<RackStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(rack_handler.clone())
        .build_for_manual_iterations(cancel_token.clone())
        .unwrap();

    controller.run_single_iteration().await;

    // Verify that the handler was called even in error state
    let count = rack_handler.count.load(Ordering::SeqCst);
    assert!(
        count > 0,
        "State handler should have been called in error state"
    );

    // Verify that the rack ID was processed
    let guard = rack_handler.counts_per_id.lock().unwrap();
    let rack_id_str = rack_id.to_string();
    let count = guard.get(&rack_id_str).copied().unwrap_or_default();
    assert!(
        count > 0,
        "Rack ID should have been processed in error state"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_rack_state_transition_validation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a rack
    let rack_id = RackId::new(uuid::Uuid::new_v4().to_string());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(rack_id.clone())
        .persist(&mut txn)
        .await?;
    let rack = db_rack::get(&mut *txn, &rack_id).await?;

    // Verify initial state is Expected
    assert!(matches!(rack.controller_state.value, RackState::Expected));

    // Test state transitions by manually setting different states
    let states = vec![
        RackState::Discovering,
        RackState::Maintenance {
            rack_maintenance: RackMaintenanceState::FirmwareUpgrade {
                rack_firmware_upgrade: RackFirmwareUpgradeState::Compute,
            },
        },
        RackState::Maintenance {
            rack_maintenance: RackMaintenanceState::Completed,
        },
        RackState::Validation {
            rack_validation: RackValidationState::Pending,
        },
        RackState::Validation {
            rack_validation: RackValidationState::InProgress,
        },
        RackState::Validation {
            rack_validation: RackValidationState::Partial,
        },
        RackState::Validation {
            rack_validation: RackValidationState::FailedPartial,
        },
        RackState::Validation {
            rack_validation: RackValidationState::Validated,
        },
        RackState::Validation {
            rack_validation: RackValidationState::Failed,
        },
        RackState::Ready,
        RackState::Error {
            cause: "Test error".to_string(),
        },
        RackState::Deleting,
    ];

    for state in states {
        set_rack_controller_state(pool.acquire().await?.as_mut(), &rack_id, state.clone()).await?;

        // Verify the state was set correctly
        let rack = db_rack::get(&pool, &rack_id).await?;
        assert!(matches!(rack.controller_state.value, _ if rack.controller_state.value == state));
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_rack_deletion_with_state_controller(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a rack
    let rack_id = RackId::new(uuid::Uuid::new_v4().to_string());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(rack_id.clone())
        .persist(&mut txn)
        .await?;

    // Start the state controller
    let rack_handler = Arc::new(TestRackStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);

    let handler_services = Arc::new(env.state_handler_services());

    let cancel_token = CancellationToken::new();
    let mut controller = StateController::<RackStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(rack_handler.clone())
        .build_for_manual_iterations(cancel_token.clone())
        .unwrap();

    controller.run_single_iteration().await;

    // Mark the rack as deleted
    db::rack::mark_as_deleted(&rack_id, pool.acquire().await?.as_mut()).await?;

    // Let the controller continue to run
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;

    // Verify that the DB object is gone
    let racks = env
        .api
        .find_racks_by_ids(tonic::Request::new(rpc::forge::RacksByIdsRequest {
            rack_ids: vec![rack_id],
        }))
        .await?
        .into_inner()
        .racks;
    assert!(racks.is_empty());

    Ok(())
}

#[crate::sqlx_test]
async fn test_rack_controller_state_version_increment(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create a rack
    let rack_id = RackId::new(uuid::Uuid::new_v4().to_string());
    let mut txn = pool.begin().await?;
    db_rack::create(&mut txn, &rack_id, vec![], vec![], vec![]).await?;

    // Verify initial state
    let rack = db_rack::get(&mut *txn, &rack_id).await?;
    assert!(matches!(rack.controller_state.value, RackState::Expected));
    let initial_version = rack.controller_state.version;

    // Update controller state with correct version
    let new_version = initial_version.increment();
    let updated = db_rack::try_update_controller_state(
        &mut txn,
        &rack_id,
        initial_version,
        new_version,
        &RackState::Discovering,
    )
    .await?;
    assert!(updated, "update with correct version should succeed");

    // Verify version was incremented
    let rack = db_rack::get(&mut *txn, &rack_id).await?;
    assert_eq!(
        rack.controller_state.version.version_nr(),
        initial_version.version_nr() + 1,
        "version should be incremented after update"
    );

    // Trying to update with the old version should fail (optimistic lock)
    let stale_update = db_rack::try_update_controller_state(
        &mut txn,
        &rack_id,
        initial_version,
        initial_version.increment(),
        &RackState::Ready,
    )
    .await?;
    assert!(
        !stale_update,
        "update with stale version should be rejected"
    );

    // Updating with the current version should succeed
    let current_version = rack.controller_state.version;
    let updated_again = db_rack::try_update_controller_state(
        &mut txn,
        &rack_id,
        current_version,
        current_version.increment(),
        &RackState::Ready,
    )
    .await?;
    assert!(updated_again, "update with current version should succeed");

    txn.rollback().await?;

    Ok(())
}
