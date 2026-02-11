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
use model::rack::{Rack, RackMaintenanceState, RackReadyState, RackState};

use crate::state_controller::common_services::CommonStateHandlerServices;
use crate::state_controller::config::IterationConfig;
use crate::state_controller::controller::StateController;
use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::rack::io::RackStateControllerIO;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};
use crate::tests::common::api_fixtures::create_test_env;

mod fixtures;
use fixtures::rack::{mark_rack_as_deleted, set_rack_controller_state};

use crate::state_controller::machine::db_write_batch::DbWriteBatch;

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
        _controller_state: &Self::ControllerState,
        _ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<Self::ControllerState>, StateHandlerError> {
        assert_eq!(state.id, *rack_id);
        self.count.fetch_add(1, Ordering::SeqCst);
        {
            let mut guard = self.counts_per_id.lock().unwrap();
            *guard.entry(rack_id.to_string()).or_default() += 1;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(StateHandlerOutcome::do_nothing())
    }

    async fn take_pending_writes(&self) -> Option<DbWriteBatch> {
        None
    }
}

/// Helper function to create a rack for testing
async fn create_test_rack(
    pool: &sqlx::PgPool,
    rack_id: RackId,
) -> Result<Rack, Box<dyn std::error::Error>> {
    let mut txn = pool.acquire().await?;
    let rack = db_rack::create(
        &mut txn,
        rack_id,
        vec![], // expected_compute_trays
        vec![], // expected_nvlink_switches
        vec![], // expected_power_shelves
    )
    .await?;
    Ok(rack)
}

#[crate::sqlx_test]
async fn test_rack_state_transitions(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a rack
    let rack_id = RackId::from(uuid::Uuid::new_v4());
    let rack = create_test_rack(&pool, rack_id).await?;

    // Verify initial state is Expected
    assert!(matches!(rack.controller_state.value, RackState::Expected));

    // Start the state controller
    let rack_handler = Arc::new(TestRackStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);
    const TEST_TIME: Duration = Duration::from_secs(5);

    let handler_services = Arc::new(CommonStateHandlerServices {
        db_pool: pool.clone(),
        db_reader: pool.clone().into(),
        redfish_client_pool: env.redfish_sim.clone(),
        ib_fabric_manager: env.ib_fabric_manager.clone(),
        ib_pools: env.common_pools.infiniband.clone(),
        ipmi_tool: env.ipmi_tool.clone(),
        site_config: env.config.clone(),
        dpa_info: None,
        rms_client: None,
    });

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
    let _rack = create_test_rack(&pool, rack_id).await?;

    // Verify rack exists
    let rack = db_rack::get(&pool, rack_id).await?;
    assert_eq!(rack.id, rack_id);

    // Start the state controller to process the rack while it's active
    let rack_handler = Arc::new(TestRackStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);
    const TEST_TIME: Duration = Duration::from_secs(2);

    let handler_services = Arc::new(CommonStateHandlerServices {
        db_pool: pool.clone(),
        db_reader: pool.clone().into(),
        redfish_client_pool: env.redfish_sim.clone(),
        ib_fabric_manager: env.ib_fabric_manager.clone(),
        ib_pools: env.common_pools.infiniband.clone(),
        ipmi_tool: env.ipmi_tool.clone(),
        site_config: env.config.clone(),
        dpa_info: None,
        rms_client: None,
    });

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
    let _rack = create_test_rack(&pool, rack_id).await?;

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

    let handler_services = Arc::new(CommonStateHandlerServices {
        db_pool: pool.clone(),
        db_reader: pool.clone().into(),
        redfish_client_pool: env.redfish_sim.clone(),
        ib_fabric_manager: env.ib_fabric_manager.clone(),
        ib_pools: env.common_pools.infiniband.clone(),
        ipmi_tool: env.ipmi_tool.clone(),
        site_config: env.config.clone(),
        dpa_info: None,
        rms_client: None,
    });

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
    let _env = create_test_env(pool.clone()).await;

    // Create a rack
    let rack_id = RackId::from(uuid::Uuid::new_v4());
    let rack = create_test_rack(&pool, rack_id).await?;

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
    let _rack = create_test_rack(&pool, rack_id).await?;

    // Start the state controller
    let rack_handler = Arc::new(TestRackStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);
    const TEST_TIME: Duration = Duration::from_secs(2);

    let handler_services = Arc::new(CommonStateHandlerServices {
        db_pool: pool.clone(),
        db_reader: pool.clone().into(),
        redfish_client_pool: env.redfish_sim.clone(),
        ib_fabric_manager: env.ib_fabric_manager.clone(),
        ib_pools: env.common_pools.infiniband.clone(),
        ipmi_tool: env.ipmi_tool.clone(),
        site_config: env.config.clone(),
        dpa_info: None,
        rms_client: None,
    });

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
