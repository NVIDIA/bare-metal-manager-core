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

use carbide_uuid::power_shelf::PowerShelfId;
use db::power_shelf as db_power_shelf;
use model::DeletedFilter;
use model::power_shelf::{
    NewPowerShelf, PowerShelfConfig,
    PowerShelfMaintenanceOperation as ModelPowerShelfMaintenanceOperation, PowerShelfSearchFilter,
    PowerShelfStatus,
};
use rpc::forge::forge_server::Forge;
use rpc::forge::{
    AdminForceDeletePowerShelfRequest, PowerShelfDeletionRequest,
    PowerShelfMaintenanceOperation as RpcPowerShelfMaintenanceOperation,
    PowerShelfMaintenanceRequest, PowerShelfQuery,
};
use tonic::Code;

use crate::tests::common::api_fixtures::create_test_env;
use crate::tests::common::api_fixtures::site_explorer::new_power_shelf;

#[crate::sqlx_test]
async fn test_find_power_shelf_by_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let power_shelf_id = new_power_shelf(
        &env,
        Some("Find Test Power Shelf".to_string()),
        None,
        None,
        None,
    )
    .await?;

    // Now find the power shelf by ID
    let find_request = PowerShelfQuery {
        name: None,
        power_shelf_id: Some(power_shelf_id),
    };

    let find_response = env
        .api
        .find_power_shelves(tonic::Request::new(find_request))
        .await?;

    let power_shelf_list = find_response.into_inner();
    assert_eq!(power_shelf_list.power_shelves.len(), 1);

    let found_power_shelf = &power_shelf_list.power_shelves[0];
    assert_eq!(
        found_power_shelf.id.as_ref().unwrap().to_string(),
        power_shelf_id.to_string()
    );
    assert_eq!(
        found_power_shelf.config.as_ref().unwrap().name,
        "Find Test Power Shelf"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_power_shelf_not_found(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let non_existent_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let find_request = PowerShelfQuery {
        name: None,
        power_shelf_id: Some(non_existent_id),
    };

    let find_response = env
        .api
        .find_power_shelves(tonic::Request::new(find_request))
        .await?;

    let power_shelf_list = find_response.into_inner();
    assert_eq!(power_shelf_list.power_shelves.len(), 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_power_shelf_all(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // Create multiple power shelves
    let configs = vec![
        ("Power Shelf 1", 5000, 240),
        ("Power Shelf 2", 3000, 120),
        ("Power Shelf 3", 4000, 208),
    ];

    for (name, capacity, voltage) in configs {
        let _ = new_power_shelf(
            &env,
            Some(name.to_string()),
            Some(capacity),
            Some(voltage),
            Some("Data Center".to_string()),
        )
        .await?;
    }

    // Find all power shelves
    let find_request = PowerShelfQuery {
        name: None,
        power_shelf_id: None,
    };

    let find_response = env
        .api
        .find_power_shelves(tonic::Request::new(find_request))
        .await?;

    let power_shelf_list = find_response.into_inner();
    assert_eq!(power_shelf_list.power_shelves.len(), 3);

    // Verify all power shelves are present
    let names: Vec<String> = power_shelf_list
        .power_shelves
        .iter()
        .map(|ps| ps.config.as_ref().unwrap().name.clone())
        .collect();

    assert!(names.contains(&"Power Shelf 1".to_string()));
    assert!(names.contains(&"Power Shelf 2".to_string()));
    assert!(names.contains(&"Power Shelf 3".to_string()));

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete_power_shelf_success(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // First create a power shelf
    let power_shelf_id = new_power_shelf(
        &env,
        Some("Delete Test Power Shelf".to_string()),
        Some(5000),
        Some(240),
        Some("Rack 3".to_string()),
    )
    .await?;

    // Now delete the power shelf
    let delete_request = PowerShelfDeletionRequest {
        id: Some(power_shelf_id),
    };

    let _delete_response = env
        .api
        .delete_power_shelf(tonic::Request::new(delete_request))
        .await?;

    // Verify deletion was successful
    // The deletion result is empty, so we just check it doesn't error

    // Verify the power shelf is no longer findable
    let find_request = PowerShelfQuery {
        name: None,
        power_shelf_id: Some(power_shelf_id),
    };

    let find_result = env
        .api
        .find_power_shelves(tonic::Request::new(find_request))
        .await;
    assert!(find_result.is_ok());
    let power_shelf_list = find_result.unwrap().into_inner();

    let power_shelf = &power_shelf_list.power_shelves[0];
    assert!(
        power_shelf.deleted.is_some(),
        "Power shelf should have a deleted timestamp"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete_power_shelf_not_found(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let non_existent_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let delete_request = PowerShelfDeletionRequest {
        id: Some(non_existent_id),
    };

    let result = env
        .api
        .delete_power_shelf(tonic::Request::new(delete_request))
        .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), Code::NotFound);

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_shelf_database_operations(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    // Test NewPowerShelf creation
    let config = PowerShelfConfig {
        name: "Database Test Power Shelf".to_string(),
        capacity: Some(6000),
        voltage: Some(480),
    };

    let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config: config.clone(),
        bmc_mac_address: None,
        metadata: None,
        rack_id: None,
    };

    let created_power_shelf = db_power_shelf::create(&mut txn, &new_power_shelf).await?;

    assert_eq!(created_power_shelf.id, power_shelf_id);
    assert_eq!(created_power_shelf.config.name, "Database Test Power Shelf");
    assert_eq!(created_power_shelf.config.capacity, Some(6000));
    assert_eq!(created_power_shelf.config.voltage, Some(480));

    // Test finding the power shelf
    let found_power_shelves = db_power_shelf::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db::power_shelf::IdColumn, &power_shelf_id),
    )
    .await?;

    assert_eq!(found_power_shelves.len(), 1);
    let mut found_power_shelf = found_power_shelves[0].clone();
    assert_eq!(found_power_shelf.id, power_shelf_id);
    assert_eq!(found_power_shelf.config.name, "Database Test Power Shelf");

    // Test marking as deleted
    let deleted_power_shelf =
        db_power_shelf::mark_as_deleted(&mut found_power_shelf, &mut txn).await?;
    assert!(deleted_power_shelf.deleted.is_some());
    assert!(deleted_power_shelf.is_marked_as_deleted());

    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_shelf_status_update(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    // Create a power shelf
    let config = PowerShelfConfig {
        name: "Status Test Power Shelf".to_string(),
        capacity: Some(5000),
        voltage: Some(240),
    };

    let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config: config.clone(),
        bmc_mac_address: None,
        metadata: None,
        rack_id: None,
    };

    let mut power_shelf = db_power_shelf::create(&mut txn, &new_power_shelf).await?;

    // Update the power shelf with status
    let status = PowerShelfStatus {
        shelf_name: "Status Test Power Shelf".to_string(),
        power_state: "on".to_string(),
        health_status: "ok".to_string(),
    };

    power_shelf.status = Some(status.clone());
    let updated_power_shelf = db_power_shelf::update(&power_shelf, &mut txn).await?;

    assert!(updated_power_shelf.status.is_some());
    let updated_status = updated_power_shelf.status.as_ref().unwrap();
    assert_eq!(updated_status.shelf_name, "Status Test Power Shelf");
    assert_eq!(updated_status.power_state, "on");
    assert_eq!(updated_status.health_status, "ok");

    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_shelf_controller_state_transitions(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    // Create a power shelf
    let config = PowerShelfConfig {
        name: "Controller State Test Power Shelf".to_string(),
        capacity: Some(5000),
        voltage: Some(240),
    };

    let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config: config.clone(),
        bmc_mac_address: None,
        metadata: None,
        rack_id: None,
    };

    let power_shelf = db_power_shelf::create(&mut txn, &new_power_shelf).await?;

    // Test controller state transitions
    let initial_state = &power_shelf.controller_state.value;
    assert!(matches!(
        initial_state,
        model::power_shelf::PowerShelfControllerState::Initializing
    ));

    // Test updating controller state
    let new_state = model::power_shelf::PowerShelfControllerState::Ready;
    let current_version = power_shelf.controller_state.version;

    let next_version = current_version.increment();
    let updated = db_power_shelf::try_update_controller_state(
        &mut txn,
        power_shelf_id,
        current_version,
        next_version,
        &new_state,
    )
    .await?;
    assert!(updated, "update with correct version should succeed");

    // Verify the state was updated
    let updated_power_shelves = db_power_shelf::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db::power_shelf::IdColumn, &power_shelf_id),
    )
    .await?;

    assert_eq!(updated_power_shelves.len(), 1);
    let updated_power_shelf = &updated_power_shelves[0];
    assert!(matches!(
        updated_power_shelf.controller_state.value,
        model::power_shelf::PowerShelfControllerState::Ready
    ));

    // Version should have been incremented
    assert_eq!(
        updated_power_shelf.controller_state.version.version_nr(),
        current_version.version_nr() + 1,
        "version should be incremented after update"
    );

    // Trying to update with the old version should fail (optimistic lock)
    let stale_update = db_power_shelf::try_update_controller_state(
        &mut txn,
        power_shelf_id,
        current_version,
        current_version.increment(),
        &model::power_shelf::PowerShelfControllerState::Initializing,
    )
    .await?;
    assert!(
        !stale_update,
        "update with stale version should be rejected"
    );

    // Updating with the new version should succeed
    let new_version = updated_power_shelf.controller_state.version;
    let updated_again = db_power_shelf::try_update_controller_state(
        &mut txn,
        power_shelf_id,
        new_version,
        new_version.increment(),
        &model::power_shelf::PowerShelfControllerState::Initializing,
    )
    .await?;
    assert!(updated_again, "update with current version should succeed");

    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_shelf_conversion_roundtrip(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    // Create a power shelf with status
    let config = PowerShelfConfig {
        name: "Conversion Test Power Shelf".to_string(),
        capacity: Some(5000),
        voltage: Some(240),
    };

    let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config: config.clone(),
        bmc_mac_address: None,
        metadata: None,
        rack_id: None,
    };

    let mut power_shelf = db_power_shelf::create(&mut txn, &new_power_shelf).await?;

    // Add status
    let status = PowerShelfStatus {
        shelf_name: "Conversion Test Power Shelf".to_string(),
        power_state: "on".to_string(),
        health_status: "ok".to_string(),
    };

    power_shelf.status = Some(status);
    db_power_shelf::update(&power_shelf, &mut txn).await?;

    // Test conversion to RPC format
    let rpc_power_shelf = rpc::forge::PowerShelf::try_from(power_shelf.clone())?;

    assert_eq!(
        rpc_power_shelf.id.unwrap().to_string(),
        power_shelf_id.to_string()
    );
    assert_eq!(
        rpc_power_shelf.config.as_ref().unwrap().name,
        "Conversion Test Power Shelf"
    );
    assert_eq!(
        rpc_power_shelf.config.as_ref().unwrap().capacity,
        Some(5000)
    );
    assert_eq!(rpc_power_shelf.config.as_ref().unwrap().voltage, Some(240));

    // Verify status conversion
    let rpc_status = rpc_power_shelf.status.unwrap();
    assert_eq!(
        rpc_status.shelf_name,
        Some("Conversion Test Power Shelf".to_string())
    );
    assert_eq!(rpc_status.power_state, Some("on".to_string()));
    assert_eq!(rpc_status.health_status, Some("ok".to_string()));

    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_shelf_list_segment_ids(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    // Create multiple power shelves
    let configs = vec![
        ("List Test Power Shelf 1", 5000, 240),
        ("List Test Power Shelf 2", 3000, 120),
        ("List Test Power Shelf 3", 4000, 208),
    ];

    let mut created_ids = Vec::new();

    for (name, capacity, voltage) in configs {
        let config = PowerShelfConfig {
            name: name.to_string(),
            capacity: Some(capacity),
            voltage: Some(voltage),
        };

        let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
        let new_power_shelf = NewPowerShelf {
            id: power_shelf_id,
            config: config.clone(),
            bmc_mac_address: None,
            metadata: None,
            rack_id: None,
        };

        let power_shelf = db_power_shelf::create(&mut txn, &new_power_shelf).await?;
        created_ids.push(power_shelf.id);
    }

    // Test listing all power shelf IDs
    let listed_ids = db_power_shelf::find_ids(
        txn.as_mut(),
        PowerShelfSearchFilter {
            rack_id: None,
            deleted: DeletedFilter::Include,
            controller_state: None,
            bmc_mac: None,
        },
    )
    .await?;

    // Verify all created IDs are in the list
    for created_id in &created_ids {
        assert!(listed_ids.contains(created_id));
    }

    // Verify the list contains at least our created IDs
    assert!(listed_ids.len() >= created_ids.len());

    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_power_shelf_controller_state_outcome(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    // Create a power shelf
    let config = PowerShelfConfig {
        name: "Outcome Test Power Shelf".to_string(),
        capacity: Some(5000),
        voltage: Some(240),
    };

    let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config: config.clone(),
        bmc_mac_address: None,
        metadata: None,
        rack_id: None,
    };

    let _power_shelf = db_power_shelf::create(&mut txn, &new_power_shelf).await?;

    // Test updating controller state outcome
    let outcome =
        model::controller_outcome::PersistentStateHandlerOutcome::Transition { source_ref: None };

    db_power_shelf::update_controller_state_outcome(&mut txn, power_shelf_id, outcome).await?;

    // Verify the outcome was updated
    let updated_power_shelves = db_power_shelf::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db::power_shelf::IdColumn, &power_shelf_id),
    )
    .await?;

    assert_eq!(updated_power_shelves.len(), 1);
    let updated_power_shelf = &updated_power_shelves[0];
    assert!(updated_power_shelf.controller_state_outcome.is_some());

    let updated_outcome = updated_power_shelf
        .controller_state_outcome
        .as_ref()
        .unwrap();
    assert!(matches!(
        updated_outcome,
        model::controller_outcome::PersistentStateHandlerOutcome::Transition { .. }
    ));

    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_new_power_shelf_fixture(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // Test creating a power shelf with default values
    let power_shelf_id = new_power_shelf(&env, None, None, None, None).await?;

    // Verify the power shelf was created
    assert!(!power_shelf_id.to_string().is_empty());

    // Test creating a power shelf with custom values
    let custom_power_shelf_id = new_power_shelf(
        &env,
        Some("Custom Test Power Shelf".to_string()),
        Some(5000),
        Some(480),
        Some("Custom Location".to_string()),
    )
    .await?;

    // Verify the custom power shelf was created
    assert!(!custom_power_shelf_id.to_string().is_empty());
    assert_ne!(power_shelf_id, custom_power_shelf_id);

    Ok(())
}

#[crate::sqlx_test]
async fn test_force_delete_power_shelf_success(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let power_shelf_id = new_power_shelf(
        &env,
        Some("ForceDelete Power Shelf".to_string()),
        Some(5000),
        Some(240),
        None,
    )
    .await?;

    // Force delete without deleting interfaces.
    let response = env
        .api
        .admin_force_delete_power_shelf(tonic::Request::new(AdminForceDeletePowerShelfRequest {
            power_shelf_id: Some(power_shelf_id),
            delete_interfaces: false,
        }))
        .await?
        .into_inner();

    assert_eq!(response.power_shelf_id, power_shelf_id.to_string());
    assert_eq!(response.interfaces_deleted, 0);

    // Verify the power shelf is completely gone (not just soft-deleted).
    let find_result = env
        .api
        .find_power_shelves(tonic::Request::new(PowerShelfQuery {
            name: None,
            power_shelf_id: Some(power_shelf_id),
        }))
        .await?
        .into_inner();

    assert!(
        find_result.power_shelves.is_empty(),
        "Power shelf should be hard-deleted"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_force_delete_power_shelf_not_found(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let non_existent_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let result = env
        .api
        .admin_force_delete_power_shelf(tonic::Request::new(AdminForceDeletePowerShelfRequest {
            power_shelf_id: Some(non_existent_id),
            delete_interfaces: false,
        }))
        .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), Code::NotFound);

    Ok(())
}

#[crate::sqlx_test]
async fn test_force_delete_power_shelf_already_soft_deleted(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let power_shelf_id = new_power_shelf(
        &env,
        Some("SoftDeleted Power Shelf".to_string()),
        Some(3000),
        Some(120),
        None,
    )
    .await?;

    // Soft-delete the power shelf first.
    env.api
        .delete_power_shelf(tonic::Request::new(PowerShelfDeletionRequest {
            id: Some(power_shelf_id),
        }))
        .await?;

    // Force-delete should still work on a soft-deleted power shelf.
    let response = env
        .api
        .admin_force_delete_power_shelf(tonic::Request::new(AdminForceDeletePowerShelfRequest {
            power_shelf_id: Some(power_shelf_id),
            delete_interfaces: false,
        }))
        .await?
        .into_inner();

    assert_eq!(response.power_shelf_id, power_shelf_id.to_string());

    // Verify completely gone.
    let find_result = env
        .api
        .find_power_shelves(tonic::Request::new(PowerShelfQuery {
            name: None,
            power_shelf_id: Some(power_shelf_id),
        }))
        .await?
        .into_inner();

    assert!(
        find_result.power_shelves.is_empty(),
        "Power shelf should be hard-deleted after force delete"
    );

    Ok(())
}

// ── set_power_shelf_maintenance gRPC handler ────────────────────────────────

/// Successful PowerOn request: persists `power_shelf_maintenance_requested`
/// with the right operation and initiator (default "admin-cli" when no auth
/// context is present).
#[crate::sqlx_test]
async fn test_set_power_shelf_maintenance_power_on_persists_request(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id = new_power_shelf(
        &env,
        Some("Maintenance PowerOn Shelf".to_string()),
        None,
        None,
        None,
    )
    .await?;

    env.api
        .set_power_shelf_maintenance(tonic::Request::new(PowerShelfMaintenanceRequest {
            power_shelf_ids: vec![power_shelf_id],
            operation: RpcPowerShelfMaintenanceOperation::PowerOn as i32,
            reference: None,
        }))
        .await?;

    let mut conn = pool.acquire().await?;
    let shelf = db_power_shelf::find_by_id(conn.as_mut(), &power_shelf_id)
        .await?
        .expect("power shelf should still exist");
    let req = shelf
        .power_shelf_maintenance_requested
        .expect("maintenance request should be persisted");
    assert_eq!(req.operation, ModelPowerShelfMaintenanceOperation::PowerOn);
    assert_eq!(
        req.initiator, "admin-cli",
        "no AuthContext / no `reference` should default initiator to admin-cli"
    );

    Ok(())
}

/// Successful PowerOff request: same as PowerOn but operation must be
/// PowerOff and the `reference` must propagate as the initiator.
#[crate::sqlx_test]
async fn test_set_power_shelf_maintenance_power_off_persists_request_with_reference(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id = new_power_shelf(
        &env,
        Some("Maintenance PowerOff Shelf".to_string()),
        None,
        None,
        None,
    )
    .await?;

    env.api
        .set_power_shelf_maintenance(tonic::Request::new(PowerShelfMaintenanceRequest {
            power_shelf_ids: vec![power_shelf_id],
            operation: RpcPowerShelfMaintenanceOperation::PowerOff as i32,
            reference: Some("https://issues.example.com/TICKET-42".to_string()),
        }))
        .await?;

    let mut conn = pool.acquire().await?;
    let shelf = db_power_shelf::find_by_id(conn.as_mut(), &power_shelf_id)
        .await?
        .expect("power shelf should still exist");
    let req = shelf
        .power_shelf_maintenance_requested
        .expect("maintenance request should be persisted");
    assert_eq!(req.operation, ModelPowerShelfMaintenanceOperation::PowerOff);
    assert_eq!(req.initiator, "https://issues.example.com/TICKET-42");

    Ok(())
}

/// Multi-shelf request applies the same operation atomically to every
/// listed power shelf.
#[crate::sqlx_test]
async fn test_set_power_shelf_maintenance_multi_shelf(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let id1 = new_power_shelf(&env, Some("Multi Shelf 1".into()), None, None, None).await?;
    let id2 = new_power_shelf(&env, Some("Multi Shelf 2".into()), None, None, None).await?;

    env.api
        .set_power_shelf_maintenance(tonic::Request::new(PowerShelfMaintenanceRequest {
            power_shelf_ids: vec![id1, id2],
            operation: RpcPowerShelfMaintenanceOperation::PowerOn as i32,
            reference: Some("multi-shelf-ref".to_string()),
        }))
        .await?;

    let mut conn = pool.acquire().await?;
    for shelf_id in [id1, id2] {
        let shelf = db_power_shelf::find_by_id(conn.as_mut(), &shelf_id)
            .await?
            .expect("power shelf should still exist");
        let req = shelf
            .power_shelf_maintenance_requested
            .expect("maintenance request should be persisted on every shelf");
        assert_eq!(req.operation, ModelPowerShelfMaintenanceOperation::PowerOn);
        assert_eq!(req.initiator, "multi-shelf-ref");
    }

    Ok(())
}

/// Empty `power_shelf_ids` must be rejected with InvalidArgument.
#[crate::sqlx_test]
async fn test_set_power_shelf_maintenance_rejects_empty_id_list(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let result = env
        .api
        .set_power_shelf_maintenance(tonic::Request::new(PowerShelfMaintenanceRequest {
            power_shelf_ids: vec![],
            operation: RpcPowerShelfMaintenanceOperation::PowerOn as i32,
            reference: None,
        }))
        .await;

    let status = result.expect_err("empty id list must be rejected");
    assert_eq!(status.code(), Code::InvalidArgument);

    Ok(())
}

/// `Unspecified` operation must be rejected with InvalidArgument.
#[crate::sqlx_test]
async fn test_set_power_shelf_maintenance_rejects_unspecified_operation(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id = new_power_shelf(
        &env,
        Some("Unspecified Op Shelf".to_string()),
        None,
        None,
        None,
    )
    .await?;

    let result = env
        .api
        .set_power_shelf_maintenance(tonic::Request::new(PowerShelfMaintenanceRequest {
            power_shelf_ids: vec![power_shelf_id],
            operation: RpcPowerShelfMaintenanceOperation::Unspecified as i32,
            reference: None,
        }))
        .await;

    let status = result.expect_err("unspecified operation must be rejected");
    assert_eq!(status.code(), Code::InvalidArgument);

    // No request should have been persisted.
    let mut conn = pool.acquire().await?;
    let shelf = db_power_shelf::find_by_id(conn.as_mut(), &power_shelf_id)
        .await?
        .expect("power shelf should still exist");
    assert!(
        shelf.power_shelf_maintenance_requested.is_none(),
        "no maintenance request should be persisted on rejected calls"
    );

    Ok(())
}

/// Unknown power shelf id must be rejected with NotFound and must not
/// persist anything.
#[crate::sqlx_test]
async fn test_set_power_shelf_maintenance_rejects_unknown_id(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let missing_id = PowerShelfId::from(uuid::Uuid::new_v4());

    let result = env
        .api
        .set_power_shelf_maintenance(tonic::Request::new(PowerShelfMaintenanceRequest {
            power_shelf_ids: vec![missing_id],
            operation: RpcPowerShelfMaintenanceOperation::PowerOff as i32,
            reference: None,
        }))
        .await;

    let status = result.expect_err("unknown id must be rejected");
    assert_eq!(status.code(), Code::NotFound);

    Ok(())
}

/// Soft-deleted power shelf must be rejected with InvalidArgument.
#[crate::sqlx_test]
async fn test_set_power_shelf_maintenance_rejects_deleted_shelf(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id = new_power_shelf(
        &env,
        Some("Deleted Maintenance Shelf".to_string()),
        None,
        None,
        None,
    )
    .await?;

    env.api
        .delete_power_shelf(tonic::Request::new(PowerShelfDeletionRequest {
            id: Some(power_shelf_id),
        }))
        .await?;

    let result = env
        .api
        .set_power_shelf_maintenance(tonic::Request::new(PowerShelfMaintenanceRequest {
            power_shelf_ids: vec![power_shelf_id],
            operation: RpcPowerShelfMaintenanceOperation::PowerOn as i32,
            reference: None,
        }))
        .await;

    let status = result.expect_err("deleted power shelf must be rejected");
    assert_eq!(status.code(), Code::InvalidArgument);

    Ok(())
}

/// A second maintenance request overwrites the first one (e.g., switching
/// from PowerOn to PowerOff before the controller has acted on it).
#[crate::sqlx_test]
async fn test_set_power_shelf_maintenance_overwrites_previous_request(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let power_shelf_id = new_power_shelf(
        &env,
        Some("Overwrite Maintenance Shelf".to_string()),
        None,
        None,
        None,
    )
    .await?;

    env.api
        .set_power_shelf_maintenance(tonic::Request::new(PowerShelfMaintenanceRequest {
            power_shelf_ids: vec![power_shelf_id],
            operation: RpcPowerShelfMaintenanceOperation::PowerOn as i32,
            reference: Some("first".to_string()),
        }))
        .await?;

    env.api
        .set_power_shelf_maintenance(tonic::Request::new(PowerShelfMaintenanceRequest {
            power_shelf_ids: vec![power_shelf_id],
            operation: RpcPowerShelfMaintenanceOperation::PowerOff as i32,
            reference: Some("second".to_string()),
        }))
        .await?;

    let mut conn = pool.acquire().await?;
    let shelf = db_power_shelf::find_by_id(conn.as_mut(), &power_shelf_id)
        .await?
        .expect("power shelf should still exist");
    let req = shelf
        .power_shelf_maintenance_requested
        .expect("expected the second maintenance request to be persisted");
    assert_eq!(req.operation, ModelPowerShelfMaintenanceOperation::PowerOff);
    assert_eq!(req.initiator, "second");

    Ok(())
}
