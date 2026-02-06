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
use model::power_shelf::{NewPowerShelf, PowerShelfConfig, PowerShelfStatus};
use rpc::forge::forge_server::Forge;
use rpc::forge::{PowerShelfDeletionRequest, PowerShelfQuery};
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
        power_shelf_id.clone().to_string()
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
    let power_shelf_config = rpc::forge::PowerShelfConfig {
        name: "Delete Test Power Shelf".to_string(),
        capacity: Some(5000),
        voltage: Some(240),
        location: Some("Rack 3".to_string()),
    };

    let power_shelf_id = new_power_shelf(
        &env,
        Some(power_shelf_config.name),
        Some(power_shelf_config.capacity.unwrap_or(5000) as u32),
        Some(power_shelf_config.voltage.unwrap_or(240) as u32),
        power_shelf_config.location,
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
        location: Some("High Voltage Rack".to_string()),
    };

    let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config: config.clone(),
    };

    let created_power_shelf = db_power_shelf::create(&mut txn, &new_power_shelf).await?;

    assert_eq!(created_power_shelf.id, power_shelf_id);
    assert_eq!(created_power_shelf.config.name, "Database Test Power Shelf");
    assert_eq!(created_power_shelf.config.capacity, Some(6000));
    assert_eq!(created_power_shelf.config.voltage, Some(480));
    assert_eq!(
        created_power_shelf.config.location,
        Some("High Voltage Rack".to_string())
    );

    // Test finding the power shelf
    let found_power_shelves = db_power_shelf::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db::power_shelf::IdColumn, &power_shelf_id),
        db::power_shelf::PowerShelfSearchConfig::default(),
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
        location: Some("Status Test Rack".to_string()),
    };

    let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config: config.clone(),
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
        location: Some("Controller Test Rack".to_string()),
    };

    let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config: config.clone(),
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

    db_power_shelf::try_update_controller_state(
        &mut txn,
        power_shelf_id,
        current_version,
        &new_state,
    )
    .await?;

    // Verify the state was updated
    let updated_power_shelves = db_power_shelf::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db::power_shelf::IdColumn, &power_shelf_id),
        db::power_shelf::PowerShelfSearchConfig::default(),
    )
    .await?;

    assert_eq!(updated_power_shelves.len(), 1);
    let updated_power_shelf = &updated_power_shelves[0];
    assert!(matches!(
        updated_power_shelf.controller_state.value,
        model::power_shelf::PowerShelfControllerState::Ready
    ));

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
        location: Some("Conversion Test Rack".to_string()),
    };

    let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config: config.clone(),
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
            location: Some("List Test Rack".to_string()),
        };

        let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
        let new_power_shelf = NewPowerShelf {
            id: power_shelf_id,
            config: config.clone(),
        };

        let power_shelf = db_power_shelf::create(&mut txn, &new_power_shelf).await?;
        created_ids.push(power_shelf.id);
    }

    // Test listing all power shelf IDs
    let listed_ids = db_power_shelf::list_segment_ids(&mut txn).await?;

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
        location: Some("Outcome Test Rack".to_string()),
    };

    let power_shelf_id = PowerShelfId::from(uuid::Uuid::new_v4());
    let new_power_shelf = NewPowerShelf {
        id: power_shelf_id,
        config: config.clone(),
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
        db::power_shelf::PowerShelfSearchConfig::default(),
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
