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
use carbide_uuid::rack::{RackId, RackProfileId};
use db::db_read::DbReader;
use db::{ObjectColumnFilter, expected_rack as db_expected_rack, rack as db_rack};
use model::expected_machine::ExpectedMachineData;
use model::expected_rack::ExpectedRack;
use model::rack::{
    FirmwareUpgradeDeviceStatus, FirmwareUpgradeJob, FirmwareUpgradeState, Rack, RackConfig,
    RackFirmwareUpgradeState, RackMaintenanceState, RackPowerState, RackState, RackValidationState,
};
use model::rack_type::{
    RackCapabilitiesSet, RackCapabilityCompute, RackCapabilityPowerShelf, RackCapabilitySwitch,
    RackHardwareClass, RackHardwareType, RackProfile, RackProfileConfig,
};
use serde_json::json;

use crate::state_controller::db_write_batch::DbWriteBatch;
use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::rack::handler::RackStateHandler;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerOutcome,
};
use crate::tests::common::api_fixtures::managed_host::ManagedHostConfig;
use crate::tests::common::api_fixtures::site_explorer::new_host;
use crate::tests::common::api_fixtures::{
    TestEnv, TestEnvOverrides, create_test_env_with_overrides, get_config,
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

pub(crate) fn config_with_rack_profiles() -> crate::cfg::file::CarbideConfig {
    let mut config = get_config();
    config.rack_profiles = RackProfileConfig {
        rack_profiles: [
            (
                "NVL72".to_string(),
                RackProfile {
                    rack_capabilities: test_capabilities(),
                    ..Default::default()
                },
            ),
            (
                "Simple".to_string(),
                RackProfile {
                    rack_hardware_type: Some(RackHardwareType::any()),
                    rack_hardware_class: Some(RackHardwareClass::Prod),
                    rack_capabilities: simple_capabilities(),
                    ..Default::default()
                },
            ),
            (
                "Single".to_string(),
                RackProfile {
                    rack_hardware_type: Some(RackHardwareType::any()),
                    rack_hardware_class: Some(RackHardwareClass::Prod),
                    rack_capabilities: single_capabilities(),
                    ..Default::default()
                },
            ),
            ("Empty".to_string(), RackProfile::default()),
        ]
        .into_iter()
        .collect(),
    };
    config
}

fn default_lookup_table_json() -> serde_json::Value {
    json!({
        "devices": {
            "Compute Node": {
                "HMC_prod": {
                    "filename": "hmc-prod.bin",
                    "target": "/redfish/v1/Chassis/HGX_Chassis_0",
                    "component": "HMC",
                    "bundle": "bundle-hmc",
                    "firmware_type": "prod",
                    "version": "1.0.0"
                },
                "BMC_prod": {
                    "filename": "bmc-prod.bin",
                    "target": "FW_BMC_0",
                    "component": "BMC",
                    "bundle": "bundle-bmc",
                    "firmware_type": "prod",
                    "version": "1.0.0"
                }
            }
        }
    })
}

async fn insert_default_rack_firmware(
    pool: &sqlx::PgPool,
    firmware_id: &str,
    rack_hardware_type: RackHardwareType,
    available: bool,
) {
    let mut txn = pool.begin().await.unwrap();
    db::rack_firmware::create(
        &mut txn,
        firmware_id,
        rack_hardware_type,
        json!({ "Id": firmware_id }),
        Some(default_lookup_table_json()),
    )
    .await
    .unwrap();
    if available {
        db::rack_firmware::set_available(&mut txn, firmware_id, true)
            .await
            .unwrap();
    }
    db::rack_firmware::set_default(&mut txn, firmware_id)
        .await
        .unwrap();
    txn.commit().await.unwrap();
}

async fn create_single_compute_rack(
    env: &TestEnv,
    pool: &sqlx::PgPool,
) -> Result<(RackId, model::machine::ManagedHostStateSnapshot), Box<dyn std::error::Error>> {
    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Single")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);

    let host = new_host(
        env,
        ManagedHostConfig::with_expected_machine_data(ExpectedMachineData {
            rack_id: Some(rack_id.clone()),
            ..Default::default()
        }),
    )
    .await?;

    Ok((rack_id, host))
}

async fn create_two_compute_rack(
    env: &TestEnv,
    pool: &sqlx::PgPool,
) -> Result<
    (
        RackId,
        model::machine::ManagedHostStateSnapshot,
        model::machine::ManagedHostStateSnapshot,
    ),
    Box<dyn std::error::Error>,
> {
    let rack_id = new_rack_id();
    let mut txn = pool.acquire().await?;
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Simple")),
        &RackConfig::default(),
        None,
    )
    .await?;
    drop(txn);

    let host_a = new_host(
        env,
        ManagedHostConfig::with_expected_machine_data(ExpectedMachineData {
            rack_id: Some(rack_id.clone()),
            ..Default::default()
        }),
    )
    .await?;
    let host_b = new_host(
        env,
        ManagedHostConfig::with_expected_machine_data(ExpectedMachineData {
            rack_id: Some(rack_id.clone()),
            ..Default::default()
        }),
    )
    .await?;

    Ok((rack_id, host_a, host_b))
}

pub(crate) fn new_rack_id() -> RackId {
    RackId::new(uuid::Uuid::new_v4().to_string())
}

async fn create_expected_rack(pool: &sqlx::PgPool, rack_id: &RackId, rack_profile_id: &str) {
    let mut txn = pool.acquire().await.unwrap();
    let er = ExpectedRack {
        rack_id: rack_id.clone(),
        rack_profile_id: RackProfileId::new(rack_profile_id),
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
    let config = config_with_rack_profiles();
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
        Some(&RackProfileId::new("NVL72")),
        &RackConfig::default(),
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
    let config = config_with_rack_profiles();
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
        Some(&RackProfileId::new("NVL72")),
        &RackConfig::default(),
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
    let config = config_with_rack_profiles();
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
        Some(&RackProfileId::new("NVL72")),
        &RackConfig::default(),
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
    let config = config_with_rack_profiles();
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

    // Create rack with a rack_profile_id expecting 2 compute, 0 switches, 0 PS.
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    // Simulate that both compute trays are already linked by setting
    // compute_trays to have 2 entries matching expected_compute_trays.
    db_rack::create(
        &mut txn,
        &rack_id,
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
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
    let config = config_with_rack_profiles();
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
        Some(&RackProfileId::new("Single")),
        &RackConfig::default(),
        None,
    )
    .await?;

    // Simulate more compute_trays discovered than expected_compute_trays.

    db_rack::update(&mut txn, &rack_id, &RackConfig::default()).await?;

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
    let config = config_with_rack_profiles();
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
        Some(&RackProfileId::new("NVL72")),
        &RackConfig::default(),
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
    let config = config_with_rack_profiles();
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
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
        None,
    )
    .await?;

    let cfg = RackConfig::default();
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
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
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
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
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
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
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

/// test_firmware_upgrade_start_without_default_skips_to_configure_nmx_cluster
/// verifies that maintenance skips firmware flashing when no default firmware
/// exists for the rack hardware type.
#[crate::sqlx_test]
async fn test_firmware_upgrade_start_without_default_skips_to_configure_nmx_cluster(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host) = create_single_compute_rack(&env, &pool).await?;
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
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::ConfigureNmxCluster,
                    }
                ),
                "FirmwareUpgrade(Start) should skip to ConfigureNmxCluster, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    assert!(env.rms_sim.submitted_firmware_requests().await.is_empty());
    let machine = db::machine::find_one(
        &pool,
        &host.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist");
    assert!(machine.host_reprovision_requested.is_none());

    Ok(())
}

/// test_firmware_upgrade_start_with_unavailable_default_skips_to_configure_nmx_cluster
/// verifies that maintenance skips firmware flashing when a default firmware
/// exists for the hardware type but is not yet available.
#[crate::sqlx_test]
async fn test_firmware_upgrade_start_with_unavailable_default_skips_to_configure_nmx_cluster(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host) = create_single_compute_rack(&env, &pool).await?;
    insert_default_rack_firmware(
        &pool,
        "fw-default-unavailable",
        RackHardwareType::any(),
        false,
    )
    .await;
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
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(
                    next_state,
                    RackState::Maintenance {
                        maintenance_state: RackMaintenanceState::ConfigureNmxCluster,
                    }
                ),
                "FirmwareUpgrade(Start) should skip to ConfigureNmxCluster when default firmware is unavailable, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    assert!(env.rms_sim.submitted_firmware_requests().await.is_empty());
    let machine = db::machine::find_one(
        &pool,
        &host.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist");
    assert!(machine.host_reprovision_requested.is_none());

    Ok(())
}

/// test_firmware_upgrade_start_transitions_to_wait_for_complete verifies that
/// Maintenance::FirmwareUpgrade(Start) transitions to WaitForComplete.
#[crate::sqlx_test]
async fn test_firmware_upgrade_start_transitions_to_wait_for_complete(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host) = create_single_compute_rack(&env, &pool).await?;
    insert_default_rack_firmware(&pool, "fw-default", RackHardwareType::any(), true).await;
    {
        let mut txn = pool.begin().await?;
        db::machine::update_rack_fw_details(
            txn.as_mut(),
            &host.host_snapshot.id,
            Some(&model::rack::RackFirmwareUpgradeStatus {
                task_id: "stale-rack-job".to_string(),
                status: RackFirmwareUpgradeState::Completed,
                started_at: Some(chrono::Utc::now() - chrono::Duration::minutes(10)),
                ended_at: Some(chrono::Utc::now() - chrono::Duration::minutes(9)),
            }),
        )
        .await?;
        txn.commit().await?;
    }
    env.rms_sim
        .queue_update_firmware_response(
            librms::protos::rack_manager::UpdateFirmwareByDeviceListResponse {
                status: librms::protos::rack_manager::ReturnCode::Success as i32,
                message: "queued".to_string(),
                total_nodes: 1,
                successful_updates: 1,
                failed_updates: 0,
                job_id: "batch-job-1".to_string(),
                node_jobs: vec![librms::protos::rack_manager::NodeFirmwareJobInfo {
                    node_id: host.host_snapshot.id.to_string(),
                    job_id: "child-job-1".to_string(),
                }],
                ..Default::default()
            },
        )
        .await;

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
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

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

    let requests = env.rms_sim.submitted_firmware_requests().await;
    assert_eq!(requests.len(), 1);
    assert!(requests[0].activate);
    assert_eq!(requests[0].nodes.as_ref().unwrap().devices.len(), 1);
    assert_eq!(
        requests[0].nodes.as_ref().unwrap().devices[0].node_id,
        host.host_snapshot.id.to_string()
    );

    let persisted_rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let job = persisted_rack
        .firmware_upgrade_job
        .expect("rack firmware job should be persisted");
    assert_eq!(job.batch_job_ids, vec!["batch-job-1".to_string()]);
    assert_eq!(job.machines.len(), 1);
    assert_eq!(job.machines[0].job_id.as_deref(), Some("child-job-1"));

    let machine = db::machine::find_one(
        &pool,
        &host.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist");
    assert!(machine.host_reprovision_requested.is_some());
    assert!(
        machine.rack_fw_details.is_none(),
        "rack firmware details should be cleared at the start of a new rack firmware cycle"
    );
    assert!(
        job.started_at.is_some_and(|started_at| {
            started_at
                >= machine
                    .host_reprovision_requested
                    .as_ref()
                    .expect("rack reprovision request should exist")
                    .requested_at
        }),
        "rack firmware job start time should be at or after the rack reprovision request"
    );

    Ok(())
}

/// test_firmware_upgrade_wait_for_complete_waits_while_jobs_running verifies
/// that WaitForComplete remains in a wait state while RMS child jobs are still
/// running and writes in-progress rack firmware status back to the machine.
#[crate::sqlx_test]
async fn test_firmware_upgrade_wait_for_complete_waits_while_jobs_running(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host) = create_single_compute_rack(&env, &pool).await?;
    env.rms_sim
        .set_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusResponse {
            status: librms::protos::rack_manager::ReturnCode::Success as i32,
            job_id: "child-job-1".to_string(),
            job_state: 1,
            state_description: "running".to_string(),
            node_id: host.host_snapshot.id.to_string(),
            ..Default::default()
        })
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    rack.firmware_upgrade_job = Some(FirmwareUpgradeJob {
        job_id: Some("batch-job-1".to_string()),
        status: Some("in_progress".to_string()),
        started_at: Some(chrono::Utc::now()),
        batch_job_ids: vec!["batch-job-1".to_string()],
        machines: vec![FirmwareUpgradeDeviceStatus {
            node_id: host.host_snapshot.id.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            bmc_ip: "192.0.2.10".to_string(),
            status: "in_progress".to_string(),
            job_id: Some("child-job-1".to_string()),
            parent_job_id: Some("batch-job-1".to_string()),
            error_message: None,
        }],
        ..Default::default()
    });

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
            rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Expected Wait while RMS job is running"
    );

    let machine = db::machine::find_one(
        &pool,
        &host.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist");
    let rack_fw_details = machine
        .rack_fw_details
        .expect("machine should have rack firmware status");
    assert_eq!(rack_fw_details.status, RackFirmwareUpgradeState::InProgress);
    assert!(rack_fw_details.ended_at.is_none());

    Ok(())
}

/// test_firmware_upgrade_wait_for_complete_transitions_to_error_on_job_failure
/// verifies that a failed RMS child job writes failed machine status and moves
/// the rack into Error.
#[crate::sqlx_test]
async fn test_firmware_upgrade_wait_for_complete_transitions_to_error_on_job_failure(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host) = create_single_compute_rack(&env, &pool).await?;
    env.rms_sim
        .set_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusResponse {
            status: librms::protos::rack_manager::ReturnCode::Success as i32,
            job_id: "child-job-1".to_string(),
            job_state: 3,
            state_description: "failed".to_string(),
            node_id: host.host_snapshot.id.to_string(),
            error_message: "upgrade failed".to_string(),
            ..Default::default()
        })
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    rack.firmware_upgrade_job = Some(FirmwareUpgradeJob {
        job_id: Some("batch-job-1".to_string()),
        status: Some("in_progress".to_string()),
        started_at: Some(chrono::Utc::now()),
        batch_job_ids: vec!["batch-job-1".to_string()],
        machines: vec![FirmwareUpgradeDeviceStatus {
            node_id: host.host_snapshot.id.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            bmc_ip: "192.0.2.10".to_string(),
            status: "in_progress".to_string(),
            job_id: Some("child-job-1".to_string()),
            parent_job_id: Some("batch-job-1".to_string()),
            error_message: None,
        }],
        ..Default::default()
    });

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
            rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Error { .. }),
                "Expected rack to transition to Error, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Error, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    let machine = db::machine::find_one(
        &pool,
        &host.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine should exist");
    let rack_fw_details = machine
        .rack_fw_details
        .expect("machine should have rack firmware status");
    assert!(matches!(
        rack_fw_details.status,
        RackFirmwareUpgradeState::Failed { .. }
    ));
    assert!(rack_fw_details.ended_at.is_some());

    Ok(())
}

/// test_firmware_upgrade_wait_for_complete_waits_for_all_nodes_to_be_terminal_before_error
/// verifies that the rack keeps polling when a mixed result contains both
/// failed and in-progress devices, then errors only after all tracked devices
/// reach a terminal state.
#[crate::sqlx_test]
async fn test_firmware_upgrade_wait_for_complete_waits_for_all_nodes_to_be_terminal_before_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host_a, host_b) = create_two_compute_rack(&env, &pool).await?;

    env.rms_sim
        .set_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusResponse {
            status: librms::protos::rack_manager::ReturnCode::Success as i32,
            job_id: "child-job-1".to_string(),
            job_state: 3,
            state_description: "failed".to_string(),
            node_id: host_a.host_snapshot.id.to_string(),
            error_message: "upgrade failed".to_string(),
            ..Default::default()
        })
        .await;
    env.rms_sim
        .set_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusResponse {
            status: librms::protos::rack_manager::ReturnCode::Success as i32,
            job_id: "child-job-2".to_string(),
            job_state: 1,
            state_description: "running".to_string(),
            node_id: host_b.host_snapshot.id.to_string(),
            ..Default::default()
        })
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    rack.firmware_upgrade_job = Some(FirmwareUpgradeJob {
        job_id: Some("batch-job-1".to_string()),
        status: Some("in_progress".to_string()),
        started_at: Some(chrono::Utc::now()),
        batch_job_ids: vec!["batch-job-1".to_string()],
        machines: vec![
            FirmwareUpgradeDeviceStatus {
                node_id: host_a.host_snapshot.id.to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                bmc_ip: "192.0.2.10".to_string(),
                status: "in_progress".to_string(),
                job_id: Some("child-job-1".to_string()),
                parent_job_id: Some("batch-job-1".to_string()),
                error_message: None,
            },
            FirmwareUpgradeDeviceStatus {
                node_id: host_b.host_snapshot.id.to_string(),
                mac: "00:11:22:33:44:66".to_string(),
                bmc_ip: "192.0.2.11".to_string(),
                status: "in_progress".to_string(),
                job_id: Some("child-job-2".to_string()),
                parent_job_id: Some("batch-job-1".to_string()),
                error_message: None,
            },
        ],
        ..Default::default()
    });

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
            rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Expected Wait while some tracked devices are still non-terminal"
    );

    let machine_a = db::machine::find_one(
        &pool,
        &host_a.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine A should exist");
    let machine_b = db::machine::find_one(
        &pool,
        &host_b.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine B should exist");
    assert!(matches!(
        machine_a
            .rack_fw_details
            .as_ref()
            .expect("machine A rack fw details")
            .status,
        RackFirmwareUpgradeState::Failed { .. }
    ));
    assert_eq!(
        machine_b
            .rack_fw_details
            .as_ref()
            .expect("machine B rack fw details")
            .status,
        RackFirmwareUpgradeState::InProgress
    );

    env.rms_sim
        .set_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusResponse {
            status: librms::protos::rack_manager::ReturnCode::Success as i32,
            job_id: "child-job-2".to_string(),
            job_state: 2,
            state_description: "completed".to_string(),
            node_id: host_b.host_snapshot.id.to_string(),
            ..Default::default()
        })
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    match outcome {
        StateHandlerOutcome::Transition { next_state, .. } => {
            assert!(
                matches!(next_state, RackState::Error { .. }),
                "Expected rack to transition to Error after all tracked devices are terminal, got {:?}",
                next_state
            );
        }
        other => panic!(
            "Expected Transition to Error, got {:?}",
            std::mem::discriminant(&other)
        ),
    }

    let machine_b = db::machine::find_one(
        &pool,
        &host_b.host_snapshot.id,
        model::machine::machine_search_config::MachineSearchConfig::default(),
    )
    .await?
    .expect("machine B should exist");
    assert_eq!(
        machine_b
            .rack_fw_details
            .as_ref()
            .expect("machine B rack fw details")
            .status,
        RackFirmwareUpgradeState::Completed
    );

    Ok(())
}

/// test_firmware_upgrade_wait_for_complete_retries_when_job_lookup_fails
/// verifies that a response-level lookup failure from GetFirmwareJobStatus does
/// not mark the device failed and instead keeps the rack waiting.
#[crate::sqlx_test]
async fn test_firmware_upgrade_wait_for_complete_retries_when_job_lookup_fails(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host) = create_single_compute_rack(&env, &pool).await?;
    env.rms_sim
        .set_firmware_job_status(librms::protos::rack_manager::GetFirmwareJobStatusResponse {
            status: librms::protos::rack_manager::ReturnCode::Failure as i32,
            job_id: "child-job-1".to_string(),
            state_description: "Job not found".to_string(),
            error_message: "Job not found: child-job-1".to_string(),
            ..Default::default()
        })
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    rack.firmware_upgrade_job = Some(FirmwareUpgradeJob {
        job_id: Some("batch-job-1".to_string()),
        status: Some("in_progress".to_string()),
        started_at: Some(chrono::Utc::now()),
        batch_job_ids: vec!["batch-job-1".to_string()],
        machines: vec![FirmwareUpgradeDeviceStatus {
            node_id: host.host_snapshot.id.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            bmc_ip: "192.0.2.10".to_string(),
            status: "in_progress".to_string(),
            job_id: Some("child-job-1".to_string()),
            parent_job_id: Some("batch-job-1".to_string()),
            error_message: None,
        }],
        ..Default::default()
    });

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
            rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Expected Wait while RMS job lookup is unavailable"
    );

    let persisted_rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let job = persisted_rack
        .firmware_upgrade_job
        .expect("rack firmware job should still be persisted");
    assert_eq!(job.status.as_deref(), Some("in_progress"));
    assert_eq!(job.machines[0].status, "in_progress");
    assert_eq!(
        job.machines[0].error_message.as_deref(),
        Some("Job not found: child-job-1")
    );

    Ok(())
}

/// test_firmware_upgrade_wait_for_complete_retries_on_transient_poll_error
/// verifies that transport-level polling failures do not immediately fail the
/// rack upgrade.
#[crate::sqlx_test]
async fn test_firmware_upgrade_wait_for_complete_retries_on_transient_poll_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env_with_overrides(
        pool.clone(),
        TestEnvOverrides {
            config: Some(config_with_rack_profiles()),
            ..Default::default()
        },
    )
    .await;
    let (rack_id, host) = create_single_compute_rack(&env, &pool).await?;
    env.rms_sim
        .set_firmware_job_error("child-job-1", "mock transport failure")
        .await;

    let mut rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    rack.firmware_upgrade_job = Some(FirmwareUpgradeJob {
        job_id: Some("batch-job-1".to_string()),
        status: Some("in_progress".to_string()),
        started_at: Some(chrono::Utc::now()),
        batch_job_ids: vec!["batch-job-1".to_string()],
        machines: vec![FirmwareUpgradeDeviceStatus {
            node_id: host.host_snapshot.id.to_string(),
            mac: "00:11:22:33:44:55".to_string(),
            bmc_ip: "192.0.2.10".to_string(),
            status: "in_progress".to_string(),
            job_id: Some("child-job-1".to_string()),
            parent_job_id: Some("batch-job-1".to_string()),
            error_message: None,
        }],
        ..Default::default()
    });

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
            rack_firmware_upgrade: FirmwareUpgradeState::WaitForComplete,
        },
    };
    let mut outcome = handler_instance
        .handle_object_state(&rack_id, &mut rack, &fw_state, &mut ctx)
        .await?;
    if let Some(txn) = outcome.take_transaction() {
        txn.commit().await?;
    }

    assert!(
        matches!(outcome, StateHandlerOutcome::Wait { .. }),
        "Expected Wait while RMS polling has a transport error"
    );

    let persisted_rack = get_db_rack(env.db_reader().as_mut(), &rack_id).await;
    let job = persisted_rack
        .firmware_upgrade_job
        .expect("rack firmware job should still be persisted");
    assert_eq!(job.status.as_deref(), Some("in_progress"));
    assert_eq!(job.machines[0].status, "in_progress");
    assert!(
        job.machines[0]
            .error_message
            .as_deref()
            .is_some_and(|message| message.contains("mock transport failure"))
    );

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
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
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
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
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
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
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
        Some(&RackProfileId::new("Empty")),
        &RackConfig::default(),
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
