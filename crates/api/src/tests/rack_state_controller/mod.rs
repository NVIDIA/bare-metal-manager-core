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
//use sqlx::PgConnection;

use db::rack as db_rack;

use config_version::ConfigVersion;
use db::rack_state_history;
use model::rack::{Rack, RackMaintenanceState, RackReadyState, RackState, RackValidationState};
use rpc::forge::RackEvent;
use rpc::forge::forge_server::Forge;
use crate::state_controller::config::IterationConfig;
use crate::state_controller::controller::StateController;
use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::rack::io::RackStateControllerIO;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
    StateHandlerOutcomeWithTransaction,
};
use crate::tests::common::api_fixtures::{create_test_env, site_explorer::TestRackDbBuilder};

mod fixtures;
use fixtures::rack::{mark_rack_as_deleted, set_rack_controller_state};

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
    ) -> Result<StateHandlerOutcomeWithTransaction<Self::ControllerState>, StateHandlerError> {
        assert_eq!(state.id, *rack_id);
        self.count.fetch_add(1, Ordering::SeqCst);
        {
            let mut guard = self.counts_per_id.lock().unwrap();
            *guard.entry(rack_id.to_string()).or_default() += 1;
        }

        let new_state = match controller_state {
            RackState::Expected => {
                let new_state = &RackState::Discovering;
                new_state
            }

            RackState::Discovering => {
                let new_state = &RackState::Ready {
                    rack_ready: RackReadyState::Partial,
                };
                new_state
            }

            RackState::Ready {
                rack_ready: ready_state,
            } => match ready_state {
                RackReadyState::Partial => {
                    let new_state = &RackState::Ready {
                        rack_ready: RackReadyState::Full,
                    };
                    new_state
                }
                RackReadyState::Full => {
                    return Ok(StateHandlerOutcome::transition(RackState::Maintenance {
                        rack_maintenance: RackMaintenanceState::RackValidation {
                            rack_validation: RackValidationState::Topology
                        }
                    })
                    .with_txn(None));
                }
            },

            _ => return Ok(StateHandlerOutcome::do_nothing().with_txn(None)),
        };

        let old_version = ConfigVersion::initial();

        let mut txn = ctx.services.db_pool.begin().await?;

        db_rack::try_update_controller_state(&mut txn, rack_id, old_version, &new_state).await?;

        // Persist state history so we can get at it from UT
        rack_state_history::persist(
            &mut txn,
            &rack_id,
            &controller_state.clone(),
            old_version,
        )
        .await?;

        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(StateHandlerOutcome::transition(new_state.clone()).with_txn(None))
    }
}

fn validate_state_change_history(histories: &Vec<RackEvent>, expected: &Vec<&str>) -> bool {
    for &s in expected {
        if !histories.iter().any(|e| e.event == s) {
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
        .persist(&mut txn)
        .await?;

    // Verify rack exists
    db_rack::get(&mut txn, &rack_id).await?;

    // Start the state controller to process the rack while it's active
    let rack_handler = Arc::new(TestRackStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);
    const TEST_TIME: Duration = Duration::from_secs(2);

    let handler_services = Arc::new(env.state_handler_services());

    let _handle = StateController::<RackStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services)
        .state_handler(rack_handler)
        .build_and_spawn()
        .unwrap();

    // Let the controller process the active rack
    tokio::time::sleep(TEST_TIME).await;

    // get state history

    let state_histories_request = rpc::forge::RackStateHistoriesRequest {
        rack_ids: vec![rack_id.clone()],
    };

    let result = env
        .api
        .find_rack_state_histories(tonic::Request::new(state_histories_request))
        .await?;

    let mut histories = result.into_inner().histories;

    let records = histories.remove(&rack_id).unwrap_or_default().records;

    assert!(records.len() > 1);

    // we should have run through a few states, validate that we did.
    let expected = vec![
        "{\"state\": \"discovering\"}",
        "{\"state\": \"ready\", \"rack_ready\": \"Partial\"}",
        "{\"state\": \"ready\", \"rack_ready\": \"Full\"}",
        "{\"state\": \"maintenance\", \"rack_maintenance\": {\"RackValidation\": {\"rack_validation\": \"Topology\"}}}",
    ];
    assert!(validate_state_change_history(&records, &expected));

    Ok(())
}

#[crate::sqlx_test]
async fn test_rack_state_transitions(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a rack
    let rack_id = RackId::from(uuid::Uuid::new_v4());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(&rack_id)
        .persist(&mut txn)
        .await?;

    // Verify rack exists
    let rack = db_rack::get(&mut txn, &rack_id).await?;

    // Verify initial state is Expected
    assert!(matches!(rack.controller_state.value, RackState::Expected));

    // Start the state controller
    let rack_handler = Arc::new(TestRackStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);
    const TEST_TIME: Duration = Duration::from_secs(5);

    let handler_services = Arc::new(env.state_handler_services());

    let handle = StateController::<RackStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(rack_handler.clone())
        .build_and_spawn()
        .unwrap();

    tokio::time::sleep(TEST_TIME).await;
    drop(handle);
    tokio::time::sleep(Duration::from_secs(1)).await;

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
async fn test_rack_deletion_flow(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a rack
    let rack_id = RackId::from(uuid::Uuid::new_v4());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(&rack_id)
        .persist(&mut txn)
        .await?;

    // Verify rack exists
    let rack = db_rack::get(&mut txn, &rack_id).await?;
    assert_eq!(rack.id, rack_id);

    // Start the state controller to process the rack while it's active
    let rack_handler = Arc::new(TestRackStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);
    const TEST_TIME: Duration = Duration::from_secs(2);

    let handler_services = Arc::new(env.state_handler_services());

    let handle = StateController::<RackStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(rack_handler.clone())
        .build_and_spawn()
        .unwrap();

    // Let the controller process the active rack
    tokio::time::sleep(TEST_TIME).await;

    // Verify that the handler was called while the rack was active
    let count_before_deletion = rack_handler.count.load(Ordering::SeqCst);
    assert!(
        count_before_deletion > 0,
        "State handler should have been called while rack was active"
    );

    // Mark the rack as deleted
    mark_rack_as_deleted(pool.acquire().await?.as_mut(), rack_id).await?;

    // Let the controller run for a bit more after deletion
    tokio::time::sleep(TEST_TIME).await;
    drop(handle);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify that the handler count didn't increase significantly after deletion
    // (since deleted racks should not be processed)
    let count_after_deletion = rack_handler.count.load(Ordering::SeqCst);
    let count_increase = count_after_deletion - count_before_deletion;

    // The count might increase slightly due to timing, but should not increase significantly
    // since deleted racks are excluded from processing
    assert!(
        count_increase <= 5, // Allow for some timing-related calls
        "State handler should not process deleted racks significantly. Count increase: {}",
        count_increase
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_rack_error_state_handling(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a rack
    let rack_id = RackId::from(uuid::Uuid::new_v4());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(&rack_id)
        .persist(&mut txn)
        .await?;

    // Manually set the rack to error state for testing
    let error_state = RackState::Error {
        cause: "Test error state".to_string(),
    };

    // Update the controller state directly in the database
    set_rack_controller_state(pool.acquire().await?.as_mut(), rack_id, error_state).await?;

    // Start the state controller
    let rack_handler = Arc::new(TestRackStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);
    const TEST_TIME: Duration = Duration::from_secs(5);

    let handler_services = Arc::new(env.state_handler_services());

    let handle = StateController::<RackStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(rack_handler.clone())
        .build_and_spawn()
        .unwrap();

    tokio::time::sleep(TEST_TIME).await;
    drop(handle);
    tokio::time::sleep(Duration::from_secs(1)).await;

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
    let rack_id = RackId::from(uuid::Uuid::new_v4());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(&rack_id)
        .persist(&mut txn)
        .await?;
    let rack = db_rack::get(&mut txn, &rack_id).await?;

    // Verify initial state is Expected
    assert!(matches!(rack.controller_state.value, RackState::Expected));

    // Test state transitions by manually setting different states
    let states = vec![
        RackState::Discovering,
        RackState::Maintenance {
            rack_maintenance: RackMaintenanceState::Completed,
        },
        RackState::Ready {
            rack_ready: RackReadyState::Partial,
        },
        RackState::Ready {
            rack_ready: RackReadyState::Full,
        },
        RackState::Error {
            cause: "Test error".to_string(),
        },
        RackState::Deleting,
    ];

    for state in states {
        set_rack_controller_state(pool.acquire().await?.as_mut(), rack_id, state.clone()).await?;

        // Verify the state was set correctly
        let rack = db_rack::get(&pool, rack_id).await?;
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
    let rack_id = RackId::from(uuid::Uuid::new_v4());
    let mut txn = pool.acquire().await?;
    TestRackDbBuilder::new()
        .with_rack_id(&rack_id)
        .persist(&mut txn)
        .await?;

    // Start the state controller
    let rack_handler = Arc::new(TestRackStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);
    const TEST_TIME: Duration = Duration::from_secs(2);

    let handler_services = Arc::new(env.state_handler_services());

    let handle = StateController::<RackStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(rack_handler.clone())
        .build_and_spawn()
        .unwrap();

    // Let the controller run for a bit to process the active rack
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify that the handler was called while the rack was active
    let count_before_deletion = rack_handler.count.load(Ordering::SeqCst);
    assert!(
        count_before_deletion > 0,
        "State handler should have been called while rack was active"
    );

    // Mark the rack as deleted
    mark_rack_as_deleted(pool.acquire().await?.as_mut(), rack_id).await?;

    // Let the controller run for a bit more after marking as deleted
    tokio::time::sleep(TEST_TIME).await;
    drop(handle);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify that the handler count didn't increase significantly after marking as deleted
    // (since deleted racks should not be processed)
    let count_after_deletion = rack_handler.count.load(Ordering::SeqCst);
    let count_increase = count_after_deletion - count_before_deletion;

    // The count might increase slightly due to timing, but should not increase significantly
    // since deleted racks are excluded from processing
    assert!(
        count_increase <= 5, // Allow for some timing-related calls
        "State handler should not process deleted racks significantly. Count increase: {}",
        count_increase
    );

    Ok(())
}
