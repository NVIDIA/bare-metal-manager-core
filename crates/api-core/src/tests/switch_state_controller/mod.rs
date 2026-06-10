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

use carbide_switch_controller::context::SwitchStateHandlerServices;
use carbide_switch_controller::handler::SwitchStateHandler;
use carbide_switch_controller::io::SwitchStateControllerIO;
use component_manager::compute_tray_manager::Backend;
use component_manager::config::ComponentManagerConfig;
use db::switch as db_switch;
use forge_secrets::test_support::credentials::TestCredentialManager;
use model::switch::{ConfiguringState, SwitchControllerState};
use rpc::forge::forge_server::Forge;
use state_controller::config::IterationConfig;
use state_controller::controller::StateController;
use tokio_util::sync::CancellationToken;

use crate::tests::common;
use crate::tests::common::api_fixtures::create_test_env;

mod fixtures;
mod maintenance;
use fixtures::switch::{mark_switch_as_deleted, set_switch_controller_state};

async fn build_test_component_manager(
    env: &common::api_fixtures::TestEnv,
    rms_client: Option<Arc<dyn librms::RmsApi>>,
) -> Option<Arc<component_manager::component_manager::ComponentManager>> {
    let config = ComponentManagerConfig {
        nv_switch_backend: if rms_client.is_some() {
            "rms".into()
        } else {
            "mock".into()
        },
        power_shelf_backend: "mock".into(),
        compute_tray_backend: Backend::Mock,
        nv_switch_use_state_controller: true,
        ..Default::default()
    };
    component_manager::component_manager::build_component_manager(
        &config,
        rms_client,
        None,
        Some(env.pool.clone()),
        None,
    )
    .await
    .ok()
    .map(Arc::new)
}

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

    let handler_services = Arc::new(SwitchStateHandlerServices {
        db_pool: pool.clone(),
        component_manager: None,
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
    assert_eq!(switch.controller_state, r#"{"state":"ready"}"#.to_string());

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

    let cancel_token = CancellationToken::new();
    let mut controller = StateController::<SwitchStateControllerIO>::builder()
        .iteration_config(IterationConfig {
            iteration_time: ITERATION_TIME,
            processor_dispatch_interval: Duration::from_millis(10),
            ..Default::default()
        })
        .database(pool.clone(), env.api.work_lock_manager_handle.clone())
        .processor_id(uuid::Uuid::new_v4().to_string())
        .services(
            SwitchStateHandlerServices {
                db_pool: pool.clone(),
                component_manager: build_test_component_manager(&env, env.rms_sim.as_rms_client())
                    .await,
                credential_manager: env.test_credential_manager.clone(),
            }
            .into(),
        )
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

#[crate::sqlx_test]
async fn test_switch_waiting_for_rack_firmware_upgrade_waits_for_terminal_status(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let switch_id = common::api_fixtures::site_explorer::new_switch(&env, None, None).await?;

    let mut txn = pool.begin().await?;
    db_switch::set_switch_reprovisioning_requested(txn.as_mut(), switch_id, "rack-test").await?;
    let switch = db_switch::find_by_id(txn.as_mut(), &switch_id)
        .await?
        .expect("switch should exist");
    let requested_at = switch
        .switch_reprovisioning_requested
        .as_ref()
        .expect("switch reprovision request should exist")
        .requested_at;
    db_switch::try_update_controller_state(
        txn.as_mut(),
        switch_id,
        switch.controller_state.version,
        switch.controller_state.version.increment(),
        &SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForRackFirmwareUpgrade,
        },
    )
    .await?;
    db_switch::update_firmware_upgrade_status(
        txn.as_mut(),
        switch_id,
        Some(&model::rack::RackFirmwareUpgradeStatus {
            task_id: "rack-job".to_string(),
            status: model::rack::RackFirmwareUpgradeState::InProgress,
            started_at: Some(requested_at),
            ended_at: None,
        }),
    )
    .await?;
    txn.commit().await?;

    env.run_switch_controller_iteration().await;

    let mut txn = pool.acquire().await?;
    let switch = db_switch::find_by_id(&mut txn, &switch_id)
        .await?
        .expect("switch should exist");
    assert!(matches!(
        switch.controller_state.value,
        SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForRackFirmwareUpgrade,
        }
    ));
    assert!(switch.switch_reprovisioning_requested.is_some());

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_waiting_for_rack_firmware_upgrade_transitions_to_waiting_for_nvos_on_completion(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let switch_id = common::api_fixtures::site_explorer::new_switch(&env, None, None).await?;

    let mut txn = pool.begin().await?;
    db_switch::set_switch_reprovisioning_requested(txn.as_mut(), switch_id, "rack-test").await?;
    let switch = db_switch::find_by_id(txn.as_mut(), &switch_id)
        .await?
        .expect("switch should exist");
    let requested_at = switch
        .switch_reprovisioning_requested
        .as_ref()
        .expect("switch reprovision request should exist")
        .requested_at;
    db_switch::try_update_controller_state(
        txn.as_mut(),
        switch_id,
        switch.controller_state.version,
        switch.controller_state.version.increment(),
        &SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForRackFirmwareUpgrade,
        },
    )
    .await?;
    db_switch::update_firmware_upgrade_status(
        txn.as_mut(),
        switch_id,
        Some(&model::rack::RackFirmwareUpgradeStatus {
            task_id: "rack-job".to_string(),
            status: model::rack::RackFirmwareUpgradeState::Completed,
            started_at: Some(requested_at),
            ended_at: Some(chrono::Utc::now()),
        }),
    )
    .await?;
    txn.commit().await?;

    env.run_switch_controller_iteration().await;

    let mut txn = pool.acquire().await?;
    let switch = db_switch::find_by_id(&mut txn, &switch_id)
        .await?
        .expect("switch should exist");
    assert!(matches!(
        switch.controller_state.value,
        SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForNVOSUpgrade,
        }
    ));
    assert!(switch.switch_reprovisioning_requested.is_some());

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_waiting_for_rack_firmware_upgrade_returns_ready_for_firmware_only_request(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let switch_id = common::api_fixtures::site_explorer::new_switch(&env, None, None).await?;

    let mut txn = pool.begin().await?;
    db_switch::set_switch_reprovisioning_requested_with_firmware_continuation(
        txn.as_mut(),
        switch_id,
        "rack-test",
        false,
    )
    .await?;
    let switch = db_switch::find_by_id(txn.as_mut(), &switch_id)
        .await?
        .expect("switch should exist");
    let requested_at = switch
        .switch_reprovisioning_requested
        .as_ref()
        .expect("switch reprovision request should exist")
        .requested_at;
    db_switch::try_update_controller_state(
        txn.as_mut(),
        switch_id,
        switch.controller_state.version,
        switch.controller_state.version.increment(),
        &SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForRackFirmwareUpgrade,
        },
    )
    .await?;
    db_switch::update_firmware_upgrade_status(
        txn.as_mut(),
        switch_id,
        Some(&model::rack::RackFirmwareUpgradeStatus {
            task_id: "rack-job".to_string(),
            status: model::rack::RackFirmwareUpgradeState::Completed,
            started_at: Some(requested_at),
            ended_at: Some(chrono::Utc::now()),
        }),
    )
    .await?;
    txn.commit().await?;

    env.run_switch_controller_iteration().await;

    let mut txn = pool.acquire().await?;
    let switch = db_switch::find_by_id(&mut txn, &switch_id)
        .await?
        .expect("switch should exist");
    assert!(matches!(
        switch.controller_state.value,
        SwitchControllerState::Ready,
    ));
    assert!(switch.switch_reprovisioning_requested.is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_waiting_for_rack_firmware_upgrade_accepts_completion_when_only_ended_at_is_current(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let switch_id = common::api_fixtures::site_explorer::new_switch(&env, None, None).await?;

    let mut txn = pool.begin().await?;
    db_switch::set_switch_reprovisioning_requested(txn.as_mut(), switch_id, "rack-test").await?;
    let switch = db_switch::find_by_id(txn.as_mut(), &switch_id)
        .await?
        .expect("switch should exist");
    let requested_at = switch
        .switch_reprovisioning_requested
        .as_ref()
        .expect("switch reprovision request should exist")
        .requested_at;
    db_switch::try_update_controller_state(
        txn.as_mut(),
        switch_id,
        switch.controller_state.version,
        switch.controller_state.version.increment(),
        &SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForRackFirmwareUpgrade,
        },
    )
    .await?;
    db_switch::update_firmware_upgrade_status(
        txn.as_mut(),
        switch_id,
        Some(&model::rack::RackFirmwareUpgradeStatus {
            task_id: "rack-job".to_string(),
            status: model::rack::RackFirmwareUpgradeState::Completed,
            started_at: Some(requested_at - chrono::Duration::seconds(1)),
            ended_at: Some(requested_at + chrono::Duration::seconds(1)),
        }),
    )
    .await?;
    txn.commit().await?;

    env.run_switch_controller_iteration().await;

    let mut txn = pool.acquire().await?;
    let switch = db_switch::find_by_id(&mut txn, &switch_id)
        .await?
        .expect("switch should exist");
    assert!(matches!(
        switch.controller_state.value,
        SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForNVOSUpgrade,
        }
    ));
    assert!(switch.switch_reprovisioning_requested.is_some());

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_ready_routes_rack_requests_to_waiting_for_rack_firmware_upgrade(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let switch_id = common::api_fixtures::site_explorer::new_switch(&env, None, None).await?;

    let mut txn = pool.begin().await?;
    db_switch::set_switch_reprovisioning_requested(txn.as_mut(), switch_id, "rack-test").await?;
    let switch = db_switch::find_by_id(txn.as_mut(), &switch_id)
        .await?
        .expect("switch should exist");
    db_switch::try_update_controller_state(
        txn.as_mut(),
        switch_id,
        switch.controller_state.version,
        switch.controller_state.version.increment(),
        &SwitchControllerState::Ready,
    )
    .await?;
    txn.commit().await?;

    env.run_switch_controller_iteration().await;

    let mut txn = pool.acquire().await?;
    let switch = db_switch::find_by_id(&mut txn, &switch_id)
        .await?
        .expect("switch should exist");
    assert!(matches!(
        switch.controller_state.value,
        SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForRackFirmwareUpgrade,
        }
    ));

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_waiting_for_nvos_upgrade_transitions_to_waiting_for_nmxc_on_completion(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let switch_id = common::api_fixtures::site_explorer::new_switch(&env, None, None).await?;

    let mut txn = pool.begin().await?;
    db_switch::set_switch_reprovisioning_requested(txn.as_mut(), switch_id, "rack-nvos-test")
        .await?;
    let switch = db_switch::find_by_id(txn.as_mut(), &switch_id)
        .await?
        .expect("switch should exist");
    let requested_at = switch
        .switch_reprovisioning_requested
        .as_ref()
        .expect("switch reprovision request should exist")
        .requested_at;
    db_switch::try_update_controller_state(
        txn.as_mut(),
        switch_id,
        switch.controller_state.version,
        switch.controller_state.version.increment(),
        &SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForNVOSUpgrade,
        },
    )
    .await?;
    db_switch::update_nvos_update_status(
        txn.as_mut(),
        switch_id,
        Some(&model::switch::SwitchNvosUpdateStatus {
            task_id: "nvos-job".to_string(),
            firmware_id: "fw-1".to_string(),
            image_filename: "nvos-image.bin".to_string(),
            status: model::switch::SwitchNvosUpdateState::Completed,
            started_at: Some(requested_at),
            ended_at: Some(chrono::Utc::now()),
        }),
    )
    .await?;
    txn.commit().await?;

    env.run_switch_controller_iteration().await;

    let mut txn = pool.acquire().await?;
    let switch = db_switch::find_by_id(&mut txn, &switch_id)
        .await?
        .expect("switch should exist");
    assert!(matches!(
        switch.controller_state.value,
        SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForNMXCConfigure,
        }
    ));
    assert!(switch.switch_reprovisioning_requested.is_some());

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_waiting_for_nvos_upgrade_waits_for_current_cycle_status(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let switch_id = common::api_fixtures::site_explorer::new_switch(&env, None, None).await?;

    let mut txn = pool.begin().await?;
    db_switch::set_switch_reprovisioning_requested(txn.as_mut(), switch_id, "rack-nvos-test")
        .await?;
    let switch = db_switch::find_by_id(txn.as_mut(), &switch_id)
        .await?
        .expect("switch should exist");
    let requested_at = switch
        .switch_reprovisioning_requested
        .as_ref()
        .expect("switch reprovision request should exist")
        .requested_at;
    db_switch::try_update_controller_state(
        txn.as_mut(),
        switch_id,
        switch.controller_state.version,
        switch.controller_state.version.increment(),
        &SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForNVOSUpgrade,
        },
    )
    .await?;
    db_switch::update_nvos_update_status(
        txn.as_mut(),
        switch_id,
        Some(&model::switch::SwitchNvosUpdateStatus {
            task_id: "old-nvos-job".to_string(),
            firmware_id: "old-fw".to_string(),
            image_filename: "old-nvos-image.bin".to_string(),
            status: model::switch::SwitchNvosUpdateState::Completed,
            started_at: Some(requested_at - chrono::Duration::seconds(10)),
            ended_at: Some(requested_at - chrono::Duration::seconds(1)),
        }),
    )
    .await?;
    txn.commit().await?;

    env.run_switch_controller_iteration().await;

    let mut txn = pool.acquire().await?;
    let switch = db_switch::find_by_id(&mut txn, &switch_id)
        .await?
        .expect("switch should exist");
    assert!(matches!(
        switch.controller_state.value,
        SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForNVOSUpgrade,
        }
    ));
    assert!(switch.switch_reprovisioning_requested.is_some());

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_waiting_for_nvos_upgrade_transitions_to_error_on_failure(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let switch_id = common::api_fixtures::site_explorer::new_switch(&env, None, None).await?;

    let mut txn = pool.begin().await?;
    db_switch::set_switch_reprovisioning_requested(txn.as_mut(), switch_id, "rack-nvos-test")
        .await?;
    let switch = db_switch::find_by_id(txn.as_mut(), &switch_id)
        .await?
        .expect("switch should exist");
    let requested_at = switch
        .switch_reprovisioning_requested
        .as_ref()
        .expect("switch reprovision request should exist")
        .requested_at;
    db_switch::try_update_controller_state(
        txn.as_mut(),
        switch_id,
        switch.controller_state.version,
        switch.controller_state.version.increment(),
        &SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForNVOSUpgrade,
        },
    )
    .await?;
    db_switch::update_nvos_update_status(
        txn.as_mut(),
        switch_id,
        Some(&model::switch::SwitchNvosUpdateStatus {
            task_id: "nvos-job".to_string(),
            firmware_id: "fw-1".to_string(),
            image_filename: "nvos-image.bin".to_string(),
            status: model::switch::SwitchNvosUpdateState::Failed {
                cause: "image install failed".to_string(),
            },
            started_at: Some(requested_at),
            ended_at: Some(chrono::Utc::now()),
        }),
    )
    .await?;
    txn.commit().await?;

    env.run_switch_controller_iteration().await;

    let mut txn = pool.acquire().await?;
    let switch = db_switch::find_by_id(&mut txn, &switch_id)
        .await?
        .expect("switch should exist");
    assert!(matches!(
        switch.controller_state.value,
        SwitchControllerState::Error { ref cause } if cause == "image install failed"
    ));
    assert!(switch.switch_reprovisioning_requested.is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_waiting_for_nmxc_configure_returns_ready_when_fm_is_running(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let switch_id = common::api_fixtures::site_explorer::new_switch(&env, None, None).await?;

    let mut txn = pool.begin().await?;
    db_switch::set_switch_reprovisioning_requested(txn.as_mut(), switch_id, "rack-nmxc-test")
        .await?;
    let switch = db_switch::find_by_id(txn.as_mut(), &switch_id)
        .await?
        .expect("switch should exist");
    db_switch::try_update_controller_state(
        txn.as_mut(),
        switch_id,
        switch.controller_state.version,
        switch.controller_state.version.increment(),
        &SwitchControllerState::ReProvisioning {
            reprovisioning_state: model::switch::ReProvisioningState::WaitingForNMXCConfigure,
        },
    )
    .await?;
    db_switch::update_fabric_manager_status(
        txn.as_mut(),
        switch_id,
        Some(&model::switch::FabricManagerStatus {
            fabric_manager_state: model::switch::FabricManagerState::Ok,
            addition_info: Some("CONTROL_PLANE_STATE_CONFIGURED".to_string()),
            reason: None,
            error_message: None,
        }),
    )
    .await?;
    txn.commit().await?;

    env.run_switch_controller_iteration().await;

    let mut txn = pool.acquire().await?;
    let switch = db_switch::find_by_id(&mut txn, &switch_id)
        .await?
        .expect("switch should exist");
    assert!(matches!(
        switch.controller_state.value,
        SwitchControllerState::Ready
    ));
    assert!(switch.switch_reprovisioning_requested.is_none());

    Ok(())
}
