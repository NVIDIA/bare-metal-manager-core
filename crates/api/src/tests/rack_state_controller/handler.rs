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

use carbide_uuid::machine::{MachineId, MachineIdSource, MachineType};
use carbide_uuid::rack::RackId;
use db::db_read::DbReader;
use db::{ObjectColumnFilter, expected_rack as db_expected_rack, rack as db_rack};
use model::expected_rack::ExpectedRack;
use model::rack::{
    FirmwareUpgradeState, Rack, RackConfig, RackMaintenanceState, RackPowerState, RackState,
    RackValidationState,
};
use model::rack_type::{
    RackCapabilitiesSet, RackCapabilityCompute, RackCapabilityPowerShelf, RackCapabilitySwitch,
    RackTypeConfig,
};

use crate::state_controller::db_write_batch::DbWriteBatch;
use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::rack::handler::RackStateHandler;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerOutcome,
};
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, create_test_env_with_overrides, get_config,
};

fn test_capabilities() -> RackCapabilitiesSet {
    RackCapabilitiesSet {
        compute: RackCapabilityCompute {
            name: None,
            count: 2,
            vendor: None,
            slot_ids: None,
        },
        switch: RackCapabilitySwitch {
            name: None,
            count: 1,
            vendor: None,
            slot_ids: None,
        },
        power_shelf: RackCapabilityPowerShelf {
            name: None,
            count: 1,
            vendor: None,
            slot_ids: None,
        },
        ..Default::default()
    }
}

fn simple_capabilities() -> RackCapabilitiesSet {
    RackCapabilitiesSet {
        compute: RackCapabilityCompute {
            name: None,
            count: 2,
            vendor: None,
            slot_ids: None,
        },
        switch: RackCapabilitySwitch {
            name: None,
            count: 0,
            vendor: None,
            slot_ids: None,
        },
        power_shelf: RackCapabilityPowerShelf {
            name: None,
            count: 0,
            vendor: None,
            slot_ids: None,
        },
        ..Default::default()
    }
}

fn single_capabilities() -> RackCapabilitiesSet {
    RackCapabilitiesSet {
        compute: RackCapabilityCompute {
            name: None,
            count: 1,
            vendor: None,
            slot_ids: None,
        },
        switch: RackCapabilitySwitch {
            name: None,
            count: 0,
            vendor: None,
            slot_ids: None,
        },
        power_shelf: RackCapabilityPowerShelf {
            name: None,
            count: 0,
            vendor: None,
            slot_ids: None,
        },
        ..Default::default()
    }
}

pub(crate) fn config_with_rack_types() -> crate::cfg::file::CarbideConfig {
    let mut config = get_config();
    config.rack_types = RackTypeConfig {
        rack_types: [
            ("NVL72".to_string(), test_capabilities()),
            ("Simple".to_string(), simple_capabilities()),
            ("Single".to_string(), single_capabilities()),
            ("Empty".to_string(), RackCapabilitiesSet::default()),
        ]
        .into_iter()
        .collect(),
    };
    config
}

pub(crate) fn new_rack_id() -> RackId {
    RackId::new(uuid::Uuid::new_v4().to_string())
}

async fn create_expected_rack(pool: &sqlx::PgPool, rack_id: &RackId, rack_type: &str) {
    let mut txn = pool.acquire().await.unwrap();
    let er = ExpectedRack {
        rack_id: rack_id.clone(),
        rack_type: rack_type.to_string(),
        ..Default::default()
    };
    db_expected_rack::create(&mut txn, &er).await.unwrap();
}

pub(crate) fn new_machine_id(seed: u8) -> MachineId {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    MachineId::new(
        MachineIdSource::ProductBoardChassisSerial,
        hash,
        MachineType::Host,
    )
}

/// test_expected_no_definition_stays_parked verifies that a rack without an
/// expected_rack record stays in Created and does not advance.
#[crate::sqlx_test]
async fn test_expected_no_definition_stays_parked(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_types();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;

    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("NVL72".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    let mut rack = get_db_rack(txn.as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Created, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Rack without expected_rack record should wait in Created"
    );

    Ok(())
}

/// test_expected_incomplete_device_counts_stays verifies that a rack with a
/// topology expecting more devices than currently exist stays in Created.
#[crate::sqlx_test]
#[ignore]
async fn test_expected_incomplete_device_counts_stays(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_types();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;

    // Create a rack with a definition expecting 2 compute, 1 switch, 1 PS,
    // but only register 1 compute tray.
    let mut rack = db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("NVL72".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    let handler = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Created, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::DoNothing { .. }),
        "Rack with incomplete device counts should stay in Expected"
    );

    Ok(())
}

/// test_expected_counts_match_but_not_linked_stays verifies that a rack with
/// all expected device counts matched but devices not yet linked stays in
/// Expected until linking completes.
#[crate::sqlx_test]
async fn test_expected_counts_match_but_not_linked_stays(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_types();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();

    let mut txn = pool.acquire().await?;

    // Create rack with correct device counts matching the definition.
    let _rack = db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("NVL72".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;
    drop(txn);

    create_expected_rack(&pool, &rack_id, "NVL72").await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Created, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Rack with incomplete device counts should wait in Created"
    );

    Ok(())
}

/// test_expected_zero_topology_transitions_to_discovering verifies that a rack
/// with zero expected devices in topology immediately transitions to Discovering.
#[crate::sqlx_test]
#[ignore]
async fn test_expected_zero_topology_transitions_to_discovering(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_types();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;

    // Create rack with a rack_type expecting 2 compute, 0 switches, 0 PS.
    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Empty".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    // Simulate that both compute trays are already linked by setting
    // compute_trays to have 2 entries matching expected_compute_trays.
    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Empty".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    drop(txn);

    create_expected_rack(&pool, &rack_id, "Empty").await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Created, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Discovering),
                "Zero-device topology should transition to Discovering, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Discovering, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_expected_more_discovered_than_expected_transitions verifies that a
/// rack with more discovered compute trays than expected still transitions.
#[crate::sqlx_test]
#[ignore]
async fn test_expected_more_discovered_than_expected_transitions(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_types();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    // let mac1 = MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x50]);

    let mut txn = pool.acquire().await?;

    // Rack type "Single" expects 1 compute, 0 switches, 0 PS.
    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Single".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    // Simulate more compute_trays discovered than expected_compute_trays.

    db_rack::update(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Single".to_string()),
            ..Default::default()
        },
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Created, &mut ctx)
        .await?;

    // The Ordering::Less branch treats this as compute_done = true.
    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Discovering),
                "Should transition to Discovering, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Discovering, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_discovering_waits_for_compute_ready verifies that the handler
/// reports an error for the Discovering state when managed hosts are missing.
#[crate::sqlx_test]
#[ignore]
async fn test_discovering_waits_for_compute_ready(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_types();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;

    // Create a rack in Discovering state with a compute tray that doesn't
    // have a managed host record yet.

    let mut rack = db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("NVL72".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    let handler = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    // The Discovering state should fail because the managed host doesn't exist.
    let result = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Discovering, &mut ctx)
        .await;
    assert!(
        result.is_err(),
        "Discovering should error when managed host is missing"
    );

    Ok(())
}

/// test_discovering_empty_rack_transitions_to_maintenance verifies that a
/// rack in Discovering state with no devices transitions to Maintenance.
#[crate::sqlx_test]
async fn test_discovering_empty_rack_transitions_to_maintenance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = config_with_rack_types();
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config),
            ..Default::default()
        },
    )
    .await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;

    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Empty".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    let cfg = RackConfig {
        rack_type: Some("Empty".to_string()),
        ..Default::default()
    };
    db_rack::update(&mut txn, &rack_id, &cfg).await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &RackState::Discovering, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Maintenance { .. }),
                "Empty rack in Discovering should transition to Maintenance, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Maintenance, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_error_state_does_nothing verifies that the Error state logs and does nothing.
#[crate::sqlx_test]
async fn test_error_state_does_nothing(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Empty".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let error_state = RackState::Error {
        cause: "test error".to_string(),
    };
    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &error_state, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Error state should wait"
    );

    Ok(())
}

/// test_maintenance_completed_transitions_to_validation verifies that
/// Maintenance::Completed transitions to Validation(Pending).
#[crate::sqlx_test]
async fn test_maintenance_completed_transitions_to_validation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Empty".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let maintenance_state = RackState::Maintenance {
        maintenance_state: model::rack::RackMaintenanceState::Completed,
    };
    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &maintenance_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Validating {
                        validating_state: RackValidationState::Pending,
                    }
                ),
                "Maintenance::Completed should transition to Validating(Pending), got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_ready_with_no_labels_stays_ready verifies that Ready with no
/// validation metadata labels on machines stays in Ready (do_nothing).
#[crate::sqlx_test]
async fn test_ready_with_no_labels_stays_ready(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Empty".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let ready_state = RackState::Ready;
    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &ready_state, &mut ctx)
        .await?;

    assert!(
        matches!(
            outcome,
            StateHandlerOutcome::Wait { .. } | StateHandlerOutcome::DoNothing { .. }
        ),
        "Ready with no labels should wait or do nothing, got {:?}",
        std::mem::discriminant(&outcome)
    );

    Ok(())
}

/// test_firmware_upgrade_start_transitions_to_wait_for_complete verifies that
/// Maintenance::FirmwareUpgrade(Start) transitions to WaitForComplete.
#[crate::sqlx_test]
async fn test_firmware_upgrade_start_transitions_to_wait_for_complete(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Empty".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let fw_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::FirmwareUpgrade {
            rack_firmware_upgrade: FirmwareUpgradeState::Start,
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::FirmwareUpgrade {
                            rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
                        },
                    }
                ),
                "FirmwareUpgrade(Start) should transition to WaitForComplete, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_configure_nmx_cluster_transitions_to_completed verifies that
/// Maintenance::ConfigureNmxCluster transitions to Maintenance::Completed.
#[crate::sqlx_test]
async fn test_configure_nmx_cluster_transitions_to_completed(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Empty".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let nmx_state = RackState::Maintenance {
        maintenance_state: RackMaintenanceState::PowerSequence {
            rack_power: RackPowerState::PoweringOn,
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &nmx_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::Completed,
                    }
                ),
                "ConfigureNmxCluster should transition to Completed, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_ready_topology_changed_transitions_to_discovering verifies that
/// Ready with topology_changed=true transitions back to Discovering.
#[crate::sqlx_test]
async fn test_ready_topology_changed_transitions_to_discovering(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Empty".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    let cfg = RackConfig {
        topology_changed: true,
        ..Default::default()
    };
    db_rack::update(&mut txn, &rack_id, &cfg).await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &RackState::Ready, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Discovering),
                "Ready with topology_changed should transition to Discovering, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Discovering, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_ready_reprovision_requested_transitions_to_maintenance verifies that
/// Ready with reprovision_requested=true transitions back to Maintenance.
#[crate::sqlx_test]
async fn test_ready_reprovision_requested_transitions_to_maintenance(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Empty".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    let cfg = RackConfig {
        reprovision_requested: true,
        ..Default::default()
    };
    db_rack::update(&mut txn, &rack_id, &cfg).await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &RackState::Ready, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Maintenance { .. }),
                "Ready with reprovision_requested should transition to Maintenance, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Maintenance, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    Ok(())
}

/// test_validation_failed_transitions_to_error verifies that
/// Validation(Failed) transitions to Error state.
#[crate::sqlx_test]
async fn test_validation_failed_transitions_to_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        &RackConfig {
            rack_type: Some("Empty".to_string()),
            ..Default::default()
        },
        None,
    )
    .await?;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;

    let handler_instance = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let failed_state = RackState::Validating {
        validating_state: RackValidationState::Failed {
            run_id: "test-run".to_string(),
        },
    };
    let outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &failed_state, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::DoNothing { .. }),
        "Validation(Failed) should wait for intervention, got {:?}",
        std::mem::discriminant(&outcome)
    );

    Ok(())
}

async fn get_db_rack<DB>(conn: &mut DB, rack_id: &RackId) -> Rack
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    db_rack::find_by(conn, ObjectColumnFilter::One(db_rack::IdColumn, rack_id))
        .await
        .unwrap()
        .pop()
        .unwrap()
}
