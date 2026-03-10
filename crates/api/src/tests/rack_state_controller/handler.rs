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
use db::rack as db_rack;
use mac_address::MacAddress;
use model::rack::{RackConfig, RackState};
use model::rack_type::{RackTypeConfig, RackTypeDefinition};

use crate::state_controller::db_write_batch::DbWriteBatch;
use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::rack::handler::RackStateHandler;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerOutcome,
};
use crate::tests::common::api_fixtures::{
    TestEnvOverrides, create_test_env_with_overrides, get_config,
};

fn rack_type_def() -> RackTypeDefinition {
    RackTypeDefinition {
        name: "NVL72".to_string(),
        description: "72x1 GB200 NVL72 rack".to_string(),
        expected_compute_trays: 2,
        expected_switches: 1,
        expected_power_shelves: 1,
    }
}

fn config_with_rack_types() -> crate::cfg::file::CarbideConfig {
    let mut config = get_config();
    config.rack_types = RackTypeConfig {
        rack_types: [("NVL72".to_string(), rack_type_def())]
            .into_iter()
            .collect(),
    };
    config
}

fn new_rack_id() -> RackId {
    RackId::from(uuid::Uuid::new_v4())
}

fn new_machine_id(seed: u8) -> MachineId {
    let mut hash = [0u8; 32];
    hash[0] = seed;
    MachineId::new(
        MachineIdSource::ProductBoardChassisSerial,
        hash,
        MachineType::Host,
    )
}

/// test_expected_no_definition_stays_parked verifies that a rack without a
/// rack_type_definition stays parked in Expected and does not advance.
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

    // Create a rack with no rack_type_definition (simulates a device
    // auto-creating the rack before expected_rack arrives).
    db_rack::create(
        &mut txn,
        rack_id,
        vec![MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x50])],
        vec![],
        vec![],
    )
    .await?;

    let mut rack = db_rack::get(&pool, rack_id).await?;
    assert!(rack.config.rack_type_definition.is_none());

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
        .handle_object_state(&rack_id, &mut rack, &RackState::Expected, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::DoNothing { .. }),
        "Rack without rack_type_definition should stay in Expected"
    );

    Ok(())
}

/// test_expected_incomplete_device_counts_stays verifies that a rack with a
/// rack_type_definition but incomplete device counts stays in Expected.
#[crate::sqlx_test]
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
    db_rack::create(
        &mut txn,
        rack_id,
        vec![MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x50])],
        vec![],
        vec![],
    )
    .await?;

    let mut rack = db_rack::get(&pool, rack_id).await?;
    let mut cfg = rack.config.clone();
    cfg.rack_type_definition = Some(rack_type_def());
    db_rack::update(&mut txn, rack_id, &cfg).await?;
    rack = db_rack::get(&pool, rack_id).await?;

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
        .handle_object_state(&rack_id, &mut rack, &RackState::Expected, &mut ctx)
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
    let mac1 = MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x50]);
    let mac2 = MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x51]);
    let switch_mac = MacAddress::new([0x02, 0x1A, 0x2B, 0x3C, 0x4D, 0x50]);
    let ps_mac = MacAddress::new([0x03, 0x1A, 0x2B, 0x3C, 0x4D, 0x50]);

    let mut txn = pool.acquire().await?;

    // Create rack with correct device counts matching the definition.
    db_rack::create(
        &mut txn,
        rack_id,
        vec![mac1, mac2],
        vec![switch_mac],
        vec![ps_mac],
    )
    .await?;

    let cfg = RackConfig {
        compute_trays: vec![],
        power_shelves: vec![],
        expected_compute_trays: vec![mac1, mac2],
        expected_switches: vec![switch_mac],
        expected_power_shelves: vec![ps_mac],
        rack_type_definition: Some(rack_type_def()),
    };
    db_rack::update(&mut txn, rack_id, &cfg).await?;

    let mut rack = db_rack::get(&pool, rack_id).await?;

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
        .handle_object_state(&rack_id, &mut rack, &RackState::Expected, &mut ctx)
        .await?;

    // Devices are registered but not explored/linked, so compute_trays
    // and power_shelves are empty. The handler should not transition yet.
    assert!(
        matches!(outcome, StateHandlerOutcome::DoNothing { .. }),
        "Rack with unlinked devices should stay in Expected"
    );

    Ok(())
}

/// test_expected_all_linked_transitions_to_discovering verifies that when all
/// device counts match and all expected devices are linked, the rack
/// transitions from Expected to Discovering.
#[crate::sqlx_test]
async fn test_expected_all_linked_transitions_to_discovering(
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
    let mac1 = MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x50]);
    let mac2 = MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x51]);

    let mut txn = pool.acquire().await?;

    // Create rack with a definition expecting 2 compute, 0 switches, 0 PS.
    let simple_def = RackTypeDefinition {
        name: "Simple".to_string(),
        description: "Simple rack".to_string(),
        expected_compute_trays: 2,
        expected_switches: 0,
        expected_power_shelves: 0,
    };

    db_rack::create(&mut txn, rack_id, vec![mac1, mac2], vec![], vec![]).await?;

    // Simulate that both compute trays are already linked by setting
    // compute_trays to have 2 entries matching expected_compute_trays.
    let machine_id_1 = new_machine_id(1);
    let machine_id_2 = new_machine_id(2);

    let cfg = RackConfig {
        compute_trays: vec![machine_id_1, machine_id_2],
        power_shelves: vec![],
        expected_compute_trays: vec![mac1, mac2],
        expected_switches: vec![],
        expected_power_shelves: vec![],
        rack_type_definition: Some(simple_def),
    };
    db_rack::update(&mut txn, rack_id, &cfg).await?;

    let mut rack = db_rack::get(&pool, rack_id).await?;

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
        .handle_object_state(&rack_id, &mut rack, &RackState::Expected, &mut ctx)
        .await?;

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

/// test_expected_more_discovered_than_expected_transitions verifies that a
/// rack with more discovered compute trays than expected still transitions.
#[crate::sqlx_test]
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
    let mac1 = MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x50]);

    let mut txn = pool.acquire().await?;

    // Definition expects 1 compute, 0 switches, 0 PS.
    let def = RackTypeDefinition {
        name: "Single".to_string(),
        description: "Single compute rack".to_string(),
        expected_compute_trays: 1,
        expected_switches: 0,
        expected_power_shelves: 0,
    };

    db_rack::create(&mut txn, rack_id, vec![mac1], vec![], vec![]).await?;

    // Simulate more compute_trays discovered than expected_compute_trays.
    let machine_id_1 = new_machine_id(1);
    let machine_id_2 = new_machine_id(2);

    let cfg = RackConfig {
        compute_trays: vec![machine_id_1, machine_id_2],
        power_shelves: vec![],
        expected_compute_trays: vec![mac1],
        expected_switches: vec![],
        expected_power_shelves: vec![],
        rack_type_definition: Some(def),
    };
    db_rack::update(&mut txn, rack_id, &cfg).await?;

    let mut rack = db_rack::get(&pool, rack_id).await?;

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
        .handle_object_state(&rack_id, &mut rack, &RackState::Expected, &mut ctx)
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
    let machine_id = new_machine_id(1);

    db_rack::create(&mut txn, rack_id, vec![], vec![], vec![]).await?;

    let cfg = RackConfig {
        compute_trays: vec![machine_id],
        power_shelves: vec![],
        expected_compute_trays: vec![],
        expected_switches: vec![],
        expected_power_shelves: vec![],
        rack_type_definition: Some(rack_type_def()),
    };
    db_rack::update(&mut txn, rack_id, &cfg).await?;

    let mut rack = db_rack::get(&pool, rack_id).await?;

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

    // Create a rack with empty device lists.
    db_rack::create(&mut txn, rack_id, vec![], vec![], vec![]).await?;

    let cfg = RackConfig {
        compute_trays: vec![],
        power_shelves: vec![],
        expected_compute_trays: vec![],
        expected_switches: vec![],
        expected_power_shelves: vec![],
        rack_type_definition: Some(rack_type_def()),
    };
    db_rack::update(&mut txn, rack_id, &cfg).await?;

    let mut rack = db_rack::get(&pool, rack_id).await?;

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
    db_rack::create(&mut txn, rack_id, vec![], vec![], vec![]).await?;

    let mut rack = db_rack::get(&pool, rack_id).await?;

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
        matches!(outcome, StateHandlerOutcome::DoNothing { .. }),
        "Error state should do nothing"
    );

    Ok(())
}

/// test_maintenance_completed_transitions_to_ready verifies that
/// Maintenance::Completed transitions to Ready::Full.
#[crate::sqlx_test]
async fn test_maintenance_completed_transitions_to_ready(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(&mut txn, rack_id, vec![], vec![], vec![]).await?;

    let mut rack = db_rack::get(&pool, rack_id).await?;

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
        rack_maintenance: model::rack::RackMaintenanceState::Completed,
    };
    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &maintenance_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Ready {
                        rack_ready: model::rack::RackReadyState::Full,
                    }
                ),
                "Maintenance::Completed should transition to Ready::Full, got {:?}",
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

/// test_ready_full_transitions_to_validation verifies that Ready::Full
/// transitions to Maintenance::RackValidation::Topology.
#[crate::sqlx_test]
async fn test_ready_full_transitions_to_validation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(pool.clone(), TestEnvOverrides::default()).await;

    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(&mut txn, rack_id, vec![], vec![], vec![]).await?;

    let mut rack = db_rack::get(&pool, rack_id).await?;

    let handler = RackStateHandler::default();
    let mut services = env.state_handler_services();
    let mut metrics = ();
    let mut db_writes = DbWriteBatch::default();
    let mut ctx = StateHandlerContext::<RackStateHandlerContextObjects> {
        services: &mut services,
        metrics: &mut metrics,
        pending_db_writes: &mut db_writes,
    };

    let ready_state = RackState::Ready {
        rack_ready: model::rack::RackReadyState::Full,
    };
    let outcome = handler
        .handle_object_state(&rack_id, &mut rack, &ready_state, &mut ctx)
        .await?;

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        rack_maintenance: model::rack::RackMaintenanceState::RackValidation {
                            rack_validation: model::rack::RackValidationState::Topology,
                        },
                    }
                ),
                "Ready::Full should transition to RackValidation::Topology, got {:?}",
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
