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

use std::sync::Arc;
use std::time::Duration;

use db::power_shelf as db_power_shelf;
use model::power_shelf::PowerShelfControllerState;
use rpc::forge::forge_server::Forge;
use tokio_util::sync::CancellationToken;

use crate::state_controller::config::IterationConfig;
use crate::state_controller::controller::StateController;
use crate::state_controller::power_shelf::handler::PowerShelfStateHandler;
use crate::state_controller::power_shelf::io::PowerShelfStateControllerIO;
use crate::tests::common;
use crate::tests::common::api_fixtures::create_test_env;
mod fixtures;
use fixtures::power_shelf::{mark_power_shelf_as_deleted, set_power_shelf_controller_state};
use forge_secrets::credentials::TestCredentialManager;

use crate::state_controller::common_services::CommonStateHandlerServices;

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
    let power_shelf_handler = Arc::new(PowerShelfStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);

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
        switch_system_image_rms_client: None,
        credential_manager: Arc::new(TestCredentialManager::default()),
    });

    let cancel_token = CancellationToken::new();
    let mut controller = StateController::<PowerShelfStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(power_shelf_handler.clone())
        .build_for_manual_iterations(cancel_token.clone())
        .unwrap();

    // Walk through state machine
    for _ in 0..20 {
        controller.run_single_iteration().await;
    }

    let power_shelf = env
        .api
        .find_power_shelves_by_ids(tonic::Request::new(rpc::forge::PowerShelvesByIdsRequest {
            power_shelf_ids: vec![power_shelf_id],
        }))
        .await?
        .into_inner()
        .power_shelves
        .remove(0);
    assert_eq!(
        power_shelf.controller_state,
        "{\"state\":\"ready\"}".to_string()
    );

    // Mark the power shelf as deleted
    mark_power_shelf_as_deleted(pool.acquire().await?.as_mut(), &power_shelf_id).await?;

    // Walk through state machine
    for _ in 0..20 {
        controller.run_single_iteration().await;
    }

    // Verify that the DB object is gone
    let power_shelves = env
        .api
        .find_power_shelves_by_ids(tonic::Request::new(rpc::forge::PowerShelvesByIdsRequest {
            power_shelf_ids: vec![power_shelf_id],
        }))
        .await?
        .into_inner()
        .power_shelves;
    assert!(power_shelves.is_empty());

    Ok(())
}
