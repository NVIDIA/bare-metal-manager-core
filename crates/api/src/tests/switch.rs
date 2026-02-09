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
use carbide_uuid::switch::SwitchId;
use db::switch as db_switch;
use model::switch::{NewSwitch, SwitchConfig, SwitchControllerState, SwitchStatus};
use rpc::forge::forge_server::Forge;
use rpc::forge::{SwitchDeletionRequest, SwitchQuery};
use tonic::Code;

use crate::tests::common::api_fixtures::create_test_env;
use crate::tests::common::api_fixtures::site_explorer::new_switch;

#[crate::sqlx_test]
async fn test_find_switch_by_id(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let switch_id = new_switch(&env, Some("Find Test Switch".to_string()), None).await?;

    // Now find the switch by ID
    let find_request = SwitchQuery {
        name: None,
        switch_id: Some(switch_id),
    };

    let find_response = env
        .api
        .find_switches(tonic::Request::new(find_request))
        .await?;

    let switch_list = find_response.into_inner();
    assert_eq!(switch_list.switches.len(), 1);

    let found_switch = &switch_list.switches[0];
    assert_eq!(
        found_switch.id.as_ref().unwrap().to_string(),
        switch_id.clone().to_string()
    );
    assert_eq!(
        found_switch.config.as_ref().unwrap().name,
        "Find Test Switch"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switch_not_found(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let non_existent_id = SwitchId::from(uuid::Uuid::new_v4());
    let find_request = SwitchQuery {
        name: None,
        switch_id: Some(non_existent_id),
    };

    let find_response = env
        .api
        .find_switches(tonic::Request::new(find_request))
        .await?;

    let switch_list = find_response.into_inner();
    assert_eq!(switch_list.switches.len(), 0);

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switch_all(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // Create multiple switches
    let configs = vec![("Switch 1"), ("Switch 2"), ("Switch 3")];

    for name in configs {
        let _ = new_switch(
            &env,
            Some(name.to_string()),
            Some("Data Center".to_string()),
        )
        .await?;
    }

    // Find all switches
    let find_request = SwitchQuery {
        name: None,
        switch_id: None,
    };

    let find_response = env
        .api
        .find_switches(tonic::Request::new(find_request))
        .await?;

    let switch_list = find_response.into_inner();
    assert_eq!(switch_list.switches.len(), 3);

    // Verify all switches are present
    let names: Vec<String> = switch_list
        .switches
        .iter()
        .map(|s| s.config.as_ref().unwrap().name.clone())
        .collect();

    assert!(names.contains(&"Switch 1".to_string()));
    assert!(names.contains(&"Switch 2".to_string()));
    assert!(names.contains(&"Switch 3".to_string()));

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete_switch_success(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // First create a switch
    let switch_config = rpc::forge::SwitchConfig {
        name: "Delete Test Switch".to_string(),
        enable_nmxc: false,
        fabric_manager_config: None,
        location: Some("Rack 3".to_string()),
    };

    let switch_id = new_switch(&env, Some(switch_config.name), switch_config.location).await?;

    // Now delete the switch
    let delete_request = SwitchDeletionRequest {
        id: Some(switch_id),
    };

    let _delete_response = env
        .api
        .delete_switch(tonic::Request::new(delete_request))
        .await?;

    // Verify deletion was successful
    // The deletion result is empty, so we just check it doesn't error

    // Verify the switch is no longer findable
    let find_request = SwitchQuery {
        name: None,
        switch_id: Some(switch_id),
    };

    let find_result = env
        .api
        .find_switches(tonic::Request::new(find_request))
        .await;
    assert!(find_result.is_ok());
    let switch_list = find_result.unwrap().into_inner();

    let switch = &switch_list.switches[0];
    assert!(
        switch.deleted.is_some(),
        "Switch should have a deleted timestamp"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_delete_switch_not_found(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let non_existent_id = SwitchId::from(uuid::Uuid::new_v4());
    let delete_request = SwitchDeletionRequest {
        id: Some(non_existent_id),
    };

    let result = env
        .api
        .delete_switch(tonic::Request::new(delete_request))
        .await;

    assert!(result.is_err());
    assert_eq!(result.unwrap_err().code(), Code::NotFound);

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_database_operations(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    // Test NewSwitch creation
    let config = SwitchConfig {
        name: "Database Test Switch".to_string(),
        enable_nmxc: false,
        fabric_manager_config: None,
        location: Some("High Voltage Rack".to_string()),
    };

    let switch_id = SwitchId::from(uuid::Uuid::new_v4());
    let new_switch = NewSwitch {
        id: switch_id,
        config: config.clone(),
    };

    let created_switch = db_switch::create(&mut txn, &new_switch).await?;

    assert_eq!(created_switch.id, switch_id);
    assert_eq!(created_switch.config.name, "Database Test Switch");
    assert_eq!(
        created_switch.config.location,
        Some("High Voltage Rack".to_string())
    );

    // Test finding the switch
    let found_switches = db_switch::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db_switch::IdColumn, &switch_id),
        db_switch::SwitchSearchConfig::default(),
    )
    .await?;

    assert_eq!(found_switches.len(), 1);
    let mut found_switch = found_switches[0].clone();
    assert_eq!(found_switch.id, switch_id);
    assert_eq!(found_switch.config.name, "Database Test Switch");

    // Test marking as deleted
    let deleted_switch = db_switch::mark_as_deleted(&mut found_switch, &mut txn).await?;
    assert!(deleted_switch.deleted.is_some());
    assert!(deleted_switch.is_marked_as_deleted());

    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_status_update(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    // Create a switch
    let config = SwitchConfig {
        name: "Status Test Switch".to_string(),
        enable_nmxc: false,
        fabric_manager_config: None,
        location: Some("Status Test Rack".to_string()),
    };

    let switch_id = SwitchId::from(uuid::Uuid::new_v4());
    let new_switch = NewSwitch {
        id: switch_id,
        config: config.clone(),
    };

    let mut switch = db_switch::create(&mut txn, &new_switch).await?;

    // Update the switch with status
    let status = SwitchStatus {
        switch_name: "Status Test Switch".to_string(),
        power_state: "on".to_string(),
        health_status: "ok".to_string(),
    };

    switch.status = Some(status.clone());
    let updated_switch = db_switch::update(&switch, &mut txn).await?;

    assert!(updated_switch.status.is_some());
    let updated_status = updated_switch.status.as_ref().unwrap();
    assert_eq!(updated_status.switch_name, "Status Test Switch");
    assert_eq!(updated_status.power_state, "on");
    assert_eq!(updated_status.health_status, "ok");

    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_controller_state_transitions(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    // Create a switch
    let config = SwitchConfig {
        name: "Controller State Test Switch".to_string(),
        enable_nmxc: false,
        fabric_manager_config: None,
        location: Some("Controller Test Rack".to_string()),
    };

    let switch_id = SwitchId::from(uuid::Uuid::new_v4());
    let new_switch = NewSwitch {
        id: switch_id,
        config: config.clone(),
    };

    let switch = db_switch::create(&mut txn, &new_switch).await?;

    // Test controller state transitions
    let initial_state = &switch.controller_state.value;
    assert!(matches!(initial_state, SwitchControllerState::Initializing));

    // Test updating controller state
    let new_state = SwitchControllerState::Ready;
    let current_version = switch.controller_state.version;

    db_switch::try_update_controller_state(&mut txn, switch_id, current_version, &new_state)
        .await?;

    // Verify the state was updated
    let updated_switches = db_switch::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db_switch::IdColumn, &switch_id),
        db_switch::SwitchSearchConfig::default(),
    )
    .await?;

    assert_eq!(updated_switches.len(), 1);
    let updated_switch = &updated_switches[0];
    assert!(matches!(
        updated_switch.controller_state.value,
        SwitchControllerState::Ready
    ));

    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_conversion_roundtrip(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    // Create a switch with status
    let config = SwitchConfig {
        name: "Conversion Test Switch".to_string(),
        enable_nmxc: false,
        fabric_manager_config: None,
        location: Some("Conversion Test Rack".to_string()),
    };

    let switch_id = SwitchId::from(uuid::Uuid::new_v4());
    let new_switch = NewSwitch {
        id: switch_id,
        config: config.clone(),
    };

    let mut switch = db_switch::create(&mut txn, &new_switch).await?;

    // Add status
    let status = SwitchStatus {
        switch_name: "Conversion Test Switch".to_string(),
        power_state: "on".to_string(),
        health_status: "ok".to_string(),
    };

    switch.status = Some(status);
    db_switch::update(&switch, &mut txn).await?;

    // Test conversion to RPC format
    let rpc_switch = rpc::forge::Switch::try_from(switch.clone())?;

    assert_eq!(rpc_switch.id.unwrap().to_string(), switch_id.to_string());
    assert_eq!(
        rpc_switch.config.as_ref().unwrap().name,
        "Conversion Test Switch"
    );

    // Verify status conversion
    let rpc_status = rpc_switch.status.unwrap();
    assert_eq!(
        rpc_status.switch_name,
        Some("Conversion Test Switch".to_string())
    );
    assert_eq!(rpc_status.power_state, Some("on".to_string()));
    assert_eq!(rpc_status.health_status, Some("ok".to_string()));

    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_switch_find_all(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    // Create multiple switches
    let configs = vec![
        ("List Test Switch 1"),
        ("List Test Switch 2"),
        ("List Test Switch 3"),
    ];

    let mut created_ids = Vec::new();

    for name in configs {
        let config = SwitchConfig {
            name: name.to_string(),
            enable_nmxc: false,
            fabric_manager_config: None,
            location: Some("List Test Rack".to_string()),
        };

        let switch_id = SwitchId::from(uuid::Uuid::new_v4());
        let new_switch = NewSwitch {
            id: switch_id,
            config: config.clone(),
        };

        let switch = db_switch::create(&mut txn, &new_switch).await?;
        created_ids.push(switch.id);
    }

    // Test listing all switch IDs
    let listed_ids = db_switch::find_all(&mut txn).await?;

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
async fn test_switch_controller_state_outcome(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    // Create a switch
    let config = SwitchConfig {
        name: "Outcome Test Switch".to_string(),
        enable_nmxc: false,
        fabric_manager_config: None,
        location: Some("Outcome Test Rack".to_string()),
    };

    let switch_id = SwitchId::from(uuid::Uuid::new_v4());
    let new_switch = NewSwitch {
        id: switch_id,
        config: config.clone(),
    };

    let _switch = db_switch::create(&mut txn, &new_switch).await?;

    // Test updating controller state outcome
    let outcome =
        model::controller_outcome::PersistentStateHandlerOutcome::Transition { source_ref: None };

    db_switch::update_controller_state_outcome(&mut txn, switch_id, outcome).await?;

    // Verify the outcome was updated
    let updated_switches = db_switch::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db_switch::IdColumn, &switch_id),
        db_switch::SwitchSearchConfig::default(),
    )
    .await?;

    assert_eq!(updated_switches.len(), 1);
    let updated_switch = &updated_switches[0];
    assert!(updated_switch.controller_state_outcome.is_some());

    let updated_outcome = updated_switch.controller_state_outcome.as_ref().unwrap();
    assert!(matches!(
        updated_outcome,
        model::controller_outcome::PersistentStateHandlerOutcome::Transition { .. }
    ));

    txn.rollback().await?;

    Ok(())
}

#[crate::sqlx_test]
async fn test_new_switch_fixture(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    // Test creating a switch with default values
    let switch_id = new_switch(&env, None, None).await?;

    // Verify the switch was created
    assert!(!switch_id.to_string().is_empty());

    // Test creating a switch with custom values
    let custom_switch_id = new_switch(
        &env,
        Some("Custom Test Switch".to_string()),
        Some("Custom Location".to_string()),
    )
    .await?;

    // Verify the custom switch was created
    assert!(!custom_switch_id.to_string().is_empty());
    assert_ne!(switch_id, custom_switch_id);

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switch_bmc_info_no_matching_data(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let switch_id = new_switch(&env, Some("Test Switch No Match".to_string()), None).await?;

    // bmc_info should be None when no expected_switch or machine_interface data exists
    let find_request = SwitchQuery {
        name: None,
        switch_id: Some(switch_id),
    };

    let find_response = env
        .api
        .find_switches(tonic::Request::new(find_request))
        .await?;

    let switch_list = find_response.into_inner();
    assert_eq!(switch_list.switches.len(), 1);

    let found_switch = &switch_list.switches[0];
    assert!(
        found_switch.bmc_info.is_none(),
        "bmc_info should be None when no expected switch data exists"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switch_with_bmc_info(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap;

    use db::{
        expected_switch as db_expected_switch, machine_interface as db_machine_interface,
        network_segment as db_network_segment,
    };
    use mac_address::MacAddress;
    use model::address_selection_strategy::AddressSelectionStrategy;
    use model::metadata::Metadata;
    use model::network_segment::NetworkSegmentType;

    let env = create_test_env(pool).await;

    let switch_serial = "TestSwitch-001";
    let switch_id = new_switch(&env, Some(switch_serial.to_string()), None).await?;
    let bmc_mac: MacAddress = "AA:BB:CC:DD:EE:FF".parse().unwrap();
    let mut txn = db::Transaction::begin(&env.pool).await?;

    db_expected_switch::create(
        &mut txn,
        bmc_mac,
        "admin".to_string(),
        "password".to_string(),
        switch_serial.to_string(),
        Metadata {
            name: "Test Expected Switch".to_string(),
            description: "Test switch for BMC info lookup".to_string(),
            labels: HashMap::new(),
        },
        None,
        Some("nvos_user".to_string()),
        Some("nvos_pass".to_string()),
    )
    .await?;

    // create switch BMC interface on the underlay segment
    let underlay_segment_id = env
        .underlay_segment
        .expect("Underlay segment should exist in test env");

    let underlay_segments = db_network_segment::find_by(
        &mut txn,
        db::ObjectColumnFilter::One(db_network_segment::IdColumn, &underlay_segment_id),
        Default::default(),
    )
    .await?;
    let underlay_segment = underlay_segments
        .first()
        .expect("Should find underlay segment");
    assert_eq!(underlay_segment.segment_type, NetworkSegmentType::Underlay);

    let machine_interface = db_machine_interface::create(
        &mut txn,
        underlay_segment,
        &bmc_mac,
        underlay_segment.subdomain_id,
        false,
        AddressSelectionStrategy::Automatic,
    )
    .await?;

    txn.commit().await?;

    assert!(
        !machine_interface.addresses.is_empty(),
        "Machine interface should have at least one address"
    );
    let assigned_ip = machine_interface.addresses[0];

    let find_request = SwitchQuery {
        name: None,
        switch_id: Some(switch_id),
    };

    let find_response = env
        .api
        .find_switches(tonic::Request::new(find_request))
        .await?;

    let switch_list = find_response.into_inner();
    assert_eq!(switch_list.switches.len(), 1);

    let found_switch = &switch_list.switches[0];

    // verify bmc_info is populated with the correct IP and MAC
    let bmc_info = found_switch
        .bmc_info
        .as_ref()
        .expect("bmc_info should be populated when expected switch data exists");

    assert_eq!(
        bmc_info.ip.as_ref().unwrap(),
        &assigned_ip.to_string(),
        "bmc_info IP should match the assigned address"
    );
    assert_eq!(
        bmc_info.mac.as_ref().unwrap().to_uppercase(),
        bmc_mac.to_string().to_uppercase(),
        "bmc_info MAC should match the expected switch's BMC MAC"
    );

    Ok(())
}
