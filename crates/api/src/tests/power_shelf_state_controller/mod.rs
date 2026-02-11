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

use carbide_uuid::power_shelf::PowerShelfId;
use db::power_shelf as db_power_shelf;
use model::power_shelf::{PowerShelf, PowerShelfControllerState};
use rpc::forge::forge_server::Forge;

use crate::state_controller::config::IterationConfig;
use crate::state_controller::controller::StateController;
use crate::state_controller::power_shelf::context::PowerShelfStateHandlerContextObjects;
use crate::state_controller::power_shelf::io::PowerShelfStateControllerIO;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};
use crate::tests::common;
use crate::tests::common::api_fixtures::create_test_env;

mod fixtures;
use fixtures::power_shelf::{mark_power_shelf_as_deleted, set_power_shelf_controller_state};

use crate::state_controller::common_services::CommonStateHandlerServices;
use crate::state_controller::machine::db_write_batch::DbWriteBatch;

#[derive(Debug, Default, Clone)]
pub struct TestPowerShelfStateHandler {
    /// The total count for the handler
    pub count: Arc<AtomicUsize>,
    /// We count for every power shelf ID how often the handler was called
    pub counts_per_id: Arc<Mutex<HashMap<String, usize>>>,
}

#[async_trait::async_trait]
impl StateHandler for TestPowerShelfStateHandler {
    type State = PowerShelf;
    type ControllerState = PowerShelfControllerState;
    type ObjectId = PowerShelfId;
    type ContextObjects = PowerShelfStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        power_shelf_id: &PowerShelfId,
        state: &mut PowerShelf,
        _controller_state: &Self::ControllerState,
        _ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<Self::ControllerState>, StateHandlerError> {
        assert_eq!(state.id, *power_shelf_id);
        self.count.fetch_add(1, Ordering::SeqCst);
        {
            let mut guard = self.counts_per_id.lock().unwrap();
            *guard.entry(power_shelf_id.to_string()).or_default() += 1;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        Ok(StateHandlerOutcome::do_nothing())
    }

    async fn take_pending_writes(&self) -> Option<DbWriteBatch> {
        None
    }
}

#[crate::sqlx_test]
async fn test_power_shelf_state_transitions(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a power shelf
    let power_shelf_id = common::api_fixtures::site_explorer::new_power_shelf(
        &env,
        Some("State Transition Test Power Shelf".to_string()),
        Some(5000),
        Some(240),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;

    // Verify initial state is Initializing
    let mut txn = pool.acquire().await?;
    let power_shelf = db_power_shelf::find_by_id(&mut txn, &power_shelf_id).await?;
    assert!(power_shelf.is_some());
    let power_shelf = power_shelf.unwrap();
    assert!(matches!(
        power_shelf.controller_state.value,
        PowerShelfControllerState::Initializing
    ));

    // Start the state controller
    let power_shelf_handler = Arc::new(TestPowerShelfStateHandler::default());
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

    let handle = StateController::<PowerShelfStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(power_shelf_handler.clone())
        .build_and_spawn()
        .unwrap();

    tokio::time::sleep(TEST_TIME).await;
    drop(handle);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify that the handler was called
    let count = power_shelf_handler.count.load(Ordering::SeqCst);
    assert!(
        count > 0,
        "State handler should have been called at least once"
    );

    // Verify that the power shelf ID was processed
    let guard = power_shelf_handler.counts_per_id.lock().unwrap();
    let count = guard
        .get(&power_shelf_id.to_string())
        .copied()
        .unwrap_or_default();
    assert!(count > 0, "Power shelf ID should have been processed");

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_shelf_deletion_flow(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a power shelf
    let power_shelf_id = common::api_fixtures::site_explorer::new_power_shelf(
        &env,
        Some("Deletion Test Power Shelf".to_string()),
        Some(5000),
        Some(240),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;

    // Verify power shelf exists
    let mut txn = pool.acquire().await?;
    let power_shelf = db_power_shelf::find_by_id(&mut txn, &power_shelf_id).await?;
    assert!(power_shelf.is_some());

    // Start the state controller to process the power shelf while it's active
    let power_shelf_handler = Arc::new(TestPowerShelfStateHandler::default());
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

    let handle = StateController::<PowerShelfStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(power_shelf_handler.clone())
        .build_and_spawn()
        .unwrap();

    // Let the controller process the active power shelf
    tokio::time::sleep(TEST_TIME).await;

    // Verify that the handler was called while the power shelf was active
    let count_before_deletion = power_shelf_handler.count.load(Ordering::SeqCst);
    assert!(
        count_before_deletion > 0,
        "State handler should have been called while power shelf was active"
    );

    // Delete the power shelf
    let delete_request = rpc::forge::PowerShelfDeletionRequest {
        id: Some(power_shelf_id),
    };

    env.api
        .delete_power_shelf(tonic::Request::new(delete_request))
        .await?;

    // Let the controller run for a bit more after deletion
    tokio::time::sleep(TEST_TIME).await;
    drop(handle);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify that the handler count didn't increase significantly after deletion
    // (since deleted power shelves should not be processed)
    let count_after_deletion = power_shelf_handler.count.load(Ordering::SeqCst);
    let count_increase = count_after_deletion - count_before_deletion;

    // The count might increase slightly due to timing, but should not increase significantly
    // since deleted power shelves are excluded from processing
    assert!(
        count_increase <= 5, // Allow for some timing-related calls
        "State handler should not process deleted power shelves significantly. Count increase: {}",
        count_increase
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_shelf_error_state_handling(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a power shelf
    let power_shelf_id = common::api_fixtures::site_explorer::new_power_shelf(
        &env,
        Some("Error State Test Power Shelf".to_string()),
        Some(5000),
        Some(240),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;

    // Manually set the power shelf to error state for testing
    let error_state = PowerShelfControllerState::Error {
        cause: "Test error state".to_string(),
    };

    // Update the controller state directly in the database
    set_power_shelf_controller_state(pool.acquire().await?.as_mut(), &power_shelf_id, error_state)
        .await?;

    // Start the state controller
    let power_shelf_handler = Arc::new(TestPowerShelfStateHandler::default());
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

    let handle = StateController::<PowerShelfStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(power_shelf_handler.clone())
        .build_and_spawn()
        .unwrap();

    tokio::time::sleep(TEST_TIME).await;
    drop(handle);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify that the handler was called even in error state
    let count = power_shelf_handler.count.load(Ordering::SeqCst);
    assert!(
        count > 0,
        "State handler should have been called in error state"
    );

    // Verify that the power shelf ID was processed
    let guard = power_shelf_handler.counts_per_id.lock().unwrap();
    let count = guard
        .get(&power_shelf_id.to_string())
        .copied()
        .unwrap_or_default();
    assert!(
        count > 0,
        "Power shelf ID should have been processed in error state"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_shelf_state_transition_validation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a power shelf
    let power_shelf_id = common::api_fixtures::site_explorer::new_power_shelf(
        &env,
        Some("State Transition Validation Test Power Shelf".to_string()),
        Some(5000),
        Some(240),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;

    // Verify initial state is Initializing
    let mut txn = pool.acquire().await?;
    let power_shelf = db_power_shelf::find_by_id(&mut txn, &power_shelf_id).await?;
    assert!(power_shelf.is_some());
    let power_shelf = power_shelf.unwrap();
    assert!(matches!(
        power_shelf.controller_state.value,
        PowerShelfControllerState::Initializing
    ));

    // Test state transitions by manually setting different states
    let states = vec![
        PowerShelfControllerState::FetchingData,
        PowerShelfControllerState::Configuring,
        PowerShelfControllerState::Ready,
        PowerShelfControllerState::Error {
            cause: "Test error".to_string(),
        },
    ];

    for state in states {
        set_power_shelf_controller_state(
            pool.acquire().await?.as_mut(),
            &power_shelf_id,
            state.clone(),
        )
        .await?;

        // Verify the state was set correctly
        let mut txn = pool.acquire().await?;
        let power_shelf = db_power_shelf::find_by_id(&mut txn, &power_shelf_id).await?;
        assert!(power_shelf.is_some());
        let power_shelf = power_shelf.unwrap();
        assert!(
            matches!(power_shelf.controller_state.value, _ if power_shelf.controller_state.value == state)
        );
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_shelf_deletion_with_state_controller(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a power shelf
    let power_shelf_id = common::api_fixtures::site_explorer::new_power_shelf(
        &env,
        Some("Deletion with State Controller Test Power Shelf".to_string()),
        Some(5000),
        Some(240),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;

    // Start the state controller
    let power_shelf_handler = Arc::new(TestPowerShelfStateHandler::default());
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

    let handle = StateController::<PowerShelfStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(power_shelf_handler.clone())
        .build_and_spawn()
        .unwrap();

    // Let the controller run for a bit to process the active power shelf
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify that the handler was called while the power shelf was active
    let count_before_deletion = power_shelf_handler.count.load(Ordering::SeqCst);
    assert!(
        count_before_deletion > 0,
        "State handler should have been called while power shelf was active"
    );

    // Mark the power shelf as deleted
    mark_power_shelf_as_deleted(pool.acquire().await?.as_mut(), &power_shelf_id).await?;

    // Let the controller run for a bit more after marking as deleted
    tokio::time::sleep(TEST_TIME).await;
    drop(handle);
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Verify that the handler count didn't increase significantly after marking as deleted
    // (since deleted power shelves should not be processed)
    let count_after_deletion = power_shelf_handler.count.load(Ordering::SeqCst);
    let count_increase = count_after_deletion - count_before_deletion;

    // The count might increase slightly due to timing, but should not increase significantly
    // since deleted power shelves are excluded from processing
    assert!(
        count_increase <= 5, // Allow for some timing-related calls
        "State handler should not process deleted power shelves significantly. Count increase: {}",
        count_increase
    );

    Ok(())
}
