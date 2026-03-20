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
use model::rack_type::{
    RackCapabilitiesSet, RackCapabilityCompute, RackCapabilityPowerShelf, RackCapabilitySwitch,
    RackTypeConfig,
};

use crate::state_controller::db_write_batch::DbWriteBatch;
use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::rack::handler::{self, RackStateHandler};
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
    }
}

fn config_with_rack_types() -> crate::cfg::file::CarbideConfig {
    let mut config = get_config();
    config.rack_types = RackTypeConfig {
        rack_types: [
            ("NVL72".to_string(), test_capabilities()),
            ("Simple".to_string(), simple_capabilities()),
            ("Single".to_string(), single_capabilities()),
        ]
        .into_iter()
        .collect(),
    };
    config
}

fn new_rack_id() -> RackId {
    RackId::new(uuid::Uuid::new_v4().to_string())
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
/// rack_type stays parked in Expected and does not advance.
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

    // Create a rack with no rack_type (simulates a device
    // auto-creating the rack before expected_rack arrives).
    db_rack::create(
        &mut txn,
        &rack_id,
        vec![MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x50])],
        vec![],
        vec![],
    )
    .await?;

    let mut rack = db_rack::get(&pool, &rack_id).await?;
    assert!(rack.config.rack_type.is_none());

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
        "Rack without rack_type should stay in Expected"
    );

    Ok(())
}

/// test_expected_incomplete_device_counts_stays verifies that a rack with a
/// rack_type but incomplete device counts stays in Expected.
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
        &rack_id,
        vec![MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x50])],
        vec![],
        vec![],
    )
    .await?;

    let mut rack = db_rack::get(&pool, &rack_id).await?;
    let mut cfg = rack.config.clone();
    cfg.rack_type = Some("NVL72".to_string());
    db_rack::update(&mut txn, &rack_id, &cfg).await?;
    rack = db_rack::get(&pool, &rack_id).await?;

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
        &rack_id,
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
        rack_type: Some("NVL72".to_string()),
    };
    db_rack::update(&mut txn, &rack_id, &cfg).await?;

    let mut rack = db_rack::get(&pool, &rack_id).await?;

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

    // Create rack with a rack_type expecting 2 compute, 0 switches, 0 PS.
    db_rack::create(&mut txn, &rack_id, vec![mac1, mac2], vec![], vec![]).await?;

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
        rack_type: Some("Simple".to_string()),
    };
    db_rack::update(&mut txn, &rack_id, &cfg).await?;

    let mut rack = db_rack::get(&pool, &rack_id).await?;

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

    // Rack type "Single" expects 1 compute, 0 switches, 0 PS.
    db_rack::create(&mut txn, &rack_id, vec![mac1], vec![], vec![]).await?;

    // Simulate more compute_trays discovered than expected_compute_trays.
    let machine_id_1 = new_machine_id(1);
    let machine_id_2 = new_machine_id(2);

    let cfg = RackConfig {
        compute_trays: vec![machine_id_1, machine_id_2],
        power_shelves: vec![],
        expected_compute_trays: vec![mac1],
        expected_switches: vec![],
        expected_power_shelves: vec![],
        rack_type: Some("Single".to_string()),
    };
    db_rack::update(&mut txn, &rack_id, &cfg).await?;

    let mut rack = db_rack::get(&pool, &rack_id).await?;

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

    db_rack::create(&mut txn, &rack_id, vec![], vec![], vec![]).await?;

    let cfg = RackConfig {
        compute_trays: vec![machine_id],
        power_shelves: vec![],
        expected_compute_trays: vec![],
        expected_switches: vec![],
        expected_power_shelves: vec![],
        rack_type: Some("NVL72".to_string()),
    };
    db_rack::update(&mut txn, &rack_id, &cfg).await?;

    let mut rack = db_rack::get(&pool, &rack_id).await?;

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
    db_rack::create(&mut txn, &rack_id, vec![], vec![], vec![]).await?;

    let cfg = RackConfig {
        compute_trays: vec![],
        power_shelves: vec![],
        expected_compute_trays: vec![],
        expected_switches: vec![],
        expected_power_shelves: vec![],
        rack_type: Some("NVL72".to_string()),
    };
    db_rack::update(&mut txn, &rack_id, &cfg).await?;

    let mut rack = db_rack::get(&pool, &rack_id).await?;

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
    db_rack::create(&mut txn, &rack_id, vec![], vec![], vec![]).await?;

    let mut rack = db_rack::get(&pool, &rack_id).await?;

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
    db_rack::create(&mut txn, &rack_id, vec![], vec![], vec![]).await?;

    let mut rack = db_rack::get(&pool, &rack_id).await?;

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
    db_rack::create(&mut txn, &rack_id, vec![], vec![], vec![]).await?;

    let mut rack = db_rack::get(&pool, &rack_id).await?;

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

// --- Tests for extracted helper functions ---

/// test_validate_device_counts_all_match verifies that validation passes when
/// all registered device counts match the capabilities.
#[test]
fn test_validate_device_counts_all_match() {
    let rack_id = new_rack_id();
    let config = RackConfig {
        compute_trays: vec![],
        power_shelves: vec![],
        expected_compute_trays: vec![
            MacAddress::new([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
            MacAddress::new([0x00, 0x01, 0x02, 0x03, 0x04, 0x06]),
        ],
        expected_switches: vec![MacAddress::new([0x01, 0x01, 0x02, 0x03, 0x04, 0x05])],
        expected_power_shelves: vec![MacAddress::new([0x02, 0x01, 0x02, 0x03, 0x04, 0x05])],
        rack_type: Some("NVL72".to_string()),
    };
    assert!(handler::validate_device_counts(
        &rack_id,
        &config,
        &test_capabilities()
    ));
}

/// test_validate_device_counts_compute_mismatch verifies that validation fails
/// when the compute tray count doesn't match.
#[test]
fn test_validate_device_counts_compute_mismatch() {
    let rack_id = new_rack_id();
    let config = RackConfig {
        compute_trays: vec![],
        power_shelves: vec![],
        expected_compute_trays: vec![MacAddress::new([0x00, 0x01, 0x02, 0x03, 0x04, 0x05])],
        expected_switches: vec![MacAddress::new([0x01, 0x01, 0x02, 0x03, 0x04, 0x05])],
        expected_power_shelves: vec![MacAddress::new([0x02, 0x01, 0x02, 0x03, 0x04, 0x05])],
        rack_type: Some("NVL72".to_string()),
    };
    assert!(!handler::validate_device_counts(
        &rack_id,
        &config,
        &test_capabilities()
    ));
}

/// test_validate_device_counts_switch_mismatch verifies that validation fails
/// when the switch count doesn't match.
#[test]
fn test_validate_device_counts_switch_mismatch() {
    let rack_id = new_rack_id();
    let config = RackConfig {
        compute_trays: vec![],
        power_shelves: vec![],
        expected_compute_trays: vec![
            MacAddress::new([0x00, 0x01, 0x02, 0x03, 0x04, 0x05]),
            MacAddress::new([0x00, 0x01, 0x02, 0x03, 0x04, 0x06]),
        ],
        expected_switches: vec![],
        expected_power_shelves: vec![MacAddress::new([0x02, 0x01, 0x02, 0x03, 0x04, 0x05])],
        rack_type: Some("NVL72".to_string()),
    };
    assert!(!handler::validate_device_counts(
        &rack_id,
        &config,
        &test_capabilities()
    ));
}

/// test_validate_device_counts_zero_capabilities verifies that validation
/// passes when capabilities expect zero of everything and config is empty.
#[test]
fn test_validate_device_counts_zero_capabilities() {
    let rack_id = new_rack_id();
    let config = RackConfig::default();
    let caps = RackCapabilitiesSet {
        compute: RackCapabilityCompute {
            name: None,
            count: 0,
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
    };
    assert!(handler::validate_device_counts(&rack_id, &config, &caps));
}

/// test_adopt_dangling_devices_no_devices verifies that adoption returns false
/// when there are no dangling devices to adopt.
#[crate::sqlx_test]
async fn test_adopt_dangling_devices_no_devices(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(&mut txn, &rack_id, vec![], vec![], vec![]).await?;
    drop(txn);

    let mut config = RackConfig::default();
    let changed = handler::adopt_dangling_devices(&pool, &rack_id, &mut config).await?;

    assert!(!changed, "No dangling devices should mean no changes");
    assert!(config.expected_compute_trays.is_empty());
    assert!(config.expected_switches.is_empty());
    assert!(config.expected_power_shelves.is_empty());

    Ok(())
}

/// test_check_switches_linked_empty verifies that switch linking returns true
/// when there are no expected switches.
#[crate::sqlx_test]
async fn test_check_switches_linked_empty(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let config = RackConfig::default();
    let done = handler::check_switches_linked(&pool, &config).await?;
    assert!(done, "Empty expected_switches should be considered done");
    Ok(())
}

/// test_expected_unknown_rack_type_stays_parked verifies that a rack with a
/// rack_type that doesn't exist in config stays in Expected.
#[crate::sqlx_test]
async fn test_expected_unknown_rack_type_stays_parked(
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
    db_rack::create(&mut txn, &rack_id, vec![], vec![], vec![]).await?;

    // Set a rack_type that doesn't exist in the config.
    let cfg = RackConfig {
        rack_type: Some("NonExistentType".to_string()),
        ..Default::default()
    };
    db_rack::update(&mut txn, &rack_id, &cfg).await?;

    let mut rack = db_rack::get(&pool, &rack_id).await?;

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
        .handle_object_state(&rack_id, &mut rack, &RackState::Expected, &mut ctx)
        .await?;

    assert!(
        matches!(outcome, StateHandlerOutcome::DoNothing { .. }),
        "Rack with unknown rack_type should stay in Expected"
    );

    Ok(())
}

/// test_expected_config_change_applies_retroactively verifies that updating
/// the rack type definition in config affects existing racks. A rack that
/// previously had unmet counts should pass validation after the config is
/// updated to expect fewer devices.
#[crate::sqlx_test]
async fn test_expected_config_change_applies_retroactively(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let rack_id = new_rack_id();
    let mac1 = MacAddress::new([0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x50]);

    let mut txn = pool.acquire().await?;
    db_rack::create(&mut txn, &rack_id, vec![mac1], vec![], vec![]).await?;

    // Register only 1 compute tray with rack_type "NVL72" (needs 2).
    let cfg = RackConfig {
        compute_trays: vec![],
        power_shelves: vec![],
        expected_compute_trays: vec![mac1],
        expected_switches: vec![],
        expected_power_shelves: vec![],
        rack_type: Some("NVL72".to_string()),
    };
    db_rack::update(&mut txn, &rack_id, &cfg).await?;
    drop(txn);

    // validate_device_counts should fail with NVL72 (expects 2 compute).
    let caps_nvl72 = test_capabilities();
    assert!(
        !handler::validate_device_counts(&rack_id, &cfg, &caps_nvl72),
        "Should fail with NVL72 (expects 2 compute, has 1)"
    );

    // But it passes with Single (expects 1 compute).
    let caps_single = single_capabilities();
    assert!(
        handler::validate_device_counts(&rack_id, &cfg, &caps_single),
        "Should pass with Single (expects 1 compute, has 1)"
    );

    Ok(())
}
