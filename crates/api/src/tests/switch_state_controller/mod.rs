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

use db::switch as db_switch;
use forge_secrets::credentials::TestCredentialManager;
use model::switch::{ConfiguringState, SwitchControllerState};
use rpc::forge::forge_server::Forge;
use tokio_util::sync::CancellationToken;

use crate::state_controller::common_services::CommonStateHandlerServices;
use crate::state_controller::config::IterationConfig;
use crate::state_controller::controller::StateController;
use crate::state_controller::switch::handler::SwitchStateHandler;
use crate::state_controller::switch::io::SwitchStateControllerIO;
use crate::tests::common;
use crate::tests::common::api_fixtures::create_test_env;

mod fixtures;
use fixtures::switch::{mark_switch_as_deleted, set_switch_controller_state};

#[crate::sqlx_test]
async fn test_switch_state_transition_validation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a switch
    let switch_id = common::api_fixtures::site_explorer::new_switch(
        &env,
        Some("Switch2".to_string()),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;

    // Verify initial state is Initializing
    let mut txn = pool.acquire().await?;
    let switch = db_switch::find_by_id(&mut txn, &switch_id).await?;
    assert!(switch.is_some());
    let switch = switch.unwrap();
    assert!(matches!(
        switch.controller_state.value,
        SwitchControllerState::Created
    ));

    // Test state transitions by manually setting different states
    let states = vec![
        SwitchControllerState::Configuring {
            config_state: ConfiguringState::RotateOsPassword,
        },
        SwitchControllerState::Ready,
        SwitchControllerState::Error {
            cause: "Test error".to_string(),
        },
    ];

    for state in states {
        set_switch_controller_state(pool.acquire().await?.as_mut(), &switch_id, state.clone())
            .await?;

        // Verify the state was set correctly
        let mut txn = pool.acquire().await?;
        let switch = db_switch::find_by_id(&mut txn, &switch_id).await?;
        assert!(switch.is_some());
        let switch = switch.unwrap();
        assert!(
            matches!(switch.controller_state.value, _ if switch.controller_state.value == state)
        );
    }

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_deletion_with_state_controller(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    // Create a switch
    let switch_id = common::api_fixtures::site_explorer::new_switch(
        &env,
        Some("Switch1".to_string()),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;

    // Start the state controller
    let switch_handler = Arc::new(SwitchStateHandler::default());
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
        credential_manager: Arc::new(TestCredentialManager::default()),
    });

    let cancel_token = CancellationToken::new();
    let mut controller = StateController::<SwitchStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(switch_handler.clone())
        .build_for_manual_iterations(cancel_token.clone())
        .unwrap();

    // Walk through state machine
    for _ in 0..20 {
        controller.run_single_iteration().await;
    }

    let switch = env
        .api
        .find_switches_by_ids(tonic::Request::new(rpc::forge::SwitchesByIdsRequest {
            switch_ids: vec![switch_id],
        }))
        .await?
        .into_inner()
        .switches
        .remove(0);
    assert_eq!(switch.controller_state, "{\"state\":\"ready\"}".to_string());

    // Mark the switch as deleted
    mark_switch_as_deleted(pool.acquire().await?.as_mut(), &switch_id).await?;

    // Walk through state machine
    for _ in 0..20 {
        controller.run_single_iteration().await;
    }

    // Verify that the DB object is gone
    let switches = env
        .api
        .find_switches_by_ids(tonic::Request::new(rpc::forge::SwitchesByIdsRequest {
            switch_ids: vec![switch_id],
        }))
        .await?
        .into_inner()
        .switches;
    assert!(switches.is_empty());

    Ok(())
}

/// Tests the entire Switch ControllerState transition flow: Initializing -> Configuring
/// (RotateOsPassword) -> Validating (ValidationComplete) -> BomValidating
/// (BomValidationComplete) -> Ready. Uses the real SwitchStateHandler so each state handler
/// performs its transition.
#[crate::sqlx_test]
async fn test_switch_entire_state_transition_flow(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    let switch_id = common::api_fixtures::site_explorer::new_switch(
        &env,
        Some("Switch3".to_string()),
        Some("Data Center A, Rack 1".to_string()),
    )
    .await?;

    // Verify initial state is Initializing
    {
        let mut txn = pool.acquire().await?;
        let switch = db_switch::find_by_id(&mut txn, &switch_id).await?;
        let switch = switch.expect("switch should exist");
        assert!(
            matches!(
                switch.controller_state.value,
                SwitchControllerState::Created
            ),
            "initial state should be Created, got {:?}",
            switch.controller_state.value
        );
    }

    // Start the state controller with the real handler
    let switch_handler = Arc::new(SwitchStateHandler::default());
    const ITERATION_TIME: Duration = Duration::from_millis(50);

    let handler_services = Arc::new(env.state_handler_services());

    let cancel_token = CancellationToken::new();
    let mut controller = StateController::<SwitchStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(handler_services.clone())
        .state_handler(switch_handler.clone())
        .build_for_manual_iterations(cancel_token.clone())
        .unwrap();

    // iterate a few times
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;
    controller.run_single_iteration().await;

    // Final assertion: state is Ready
    let mut txn = pool.acquire().await?;
    let switch = db_switch::find_by_id(&mut txn, &switch_id).await?;
    let switch = switch.expect("switch should exist");
    assert!(
        matches!(switch.controller_state.value, SwitchControllerState::Ready),
        "expected Ready, got {:?}",
        switch.controller_state.value
    );

    Ok(())
}
