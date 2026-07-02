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
use rpc::forge::forge_server::Forge;

use crate::tests::common::api_fixtures::create_test_env;
use crate::tests::common::api_fixtures::site_explorer::new_switch;

#[crate::sqlx_test]
async fn test_find_switch_ids_and_by_ids(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let switch_id1 = new_switch(&env, Some("Switch1".to_string()), None).await?;
    let switch_id2 = new_switch(&env, Some("Switch2".to_string()), None).await?;

    // FindSwitchIds should return both switches
    let switch_ids = env
        .api
        .find_switch_ids(tonic::Request::new(rpc::forge::SwitchSearchFilter {
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(switch_ids.contains(&switch_id1));
    assert!(switch_ids.contains(&switch_id2));

    // FindSwitchesByIds should return the requested switch
    let switches = env
        .api
        .find_switches_by_ids(tonic::Request::new(rpc::forge::SwitchesByIdsRequest {
            switch_ids: vec![switch_id1],
        }))
        .await?
        .into_inner()
        .switches;
    assert_eq!(switches.len(), 1);
    assert_eq!(switches[0].id, Some(switch_id1));

    // FindSwitchesByIds should return both when requested
    let switches = env
        .api
        .find_switches_by_ids(tonic::Request::new(rpc::forge::SwitchesByIdsRequest {
            switch_ids: vec![switch_id1, switch_id2],
        }))
        .await?
        .into_inner()
        .switches;
    assert_eq!(switches.len(), 2);

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switches_by_ids_empty_returns_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let result = env
        .api
        .find_switches_by_ids(tonic::Request::new(rpc::forge::SwitchesByIdsRequest {
            switch_ids: vec![],
        }))
        .await;
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().message(),
        "at least one ID must be provided"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switches_by_ids_over_max(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let count = env.config.max_find_by_ids + 1;
    let switch_ids: Vec<SwitchId> = (0..count)
        .map(|_| SwitchId::from(uuid::Uuid::new_v4()))
        .collect();

    let result = env
        .api
        .find_switches_by_ids(tonic::Request::new(rpc::forge::SwitchesByIdsRequest {
            switch_ids,
        }))
        .await;
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().message(),
        format!(
            "no more than {} IDs can be accepted",
            env.config.max_find_by_ids
        )
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switch_ids_excludes_deleted(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let switch_id1 = new_switch(&env, Some("Switch1".to_string()), None).await?;
    let switch_id2 = new_switch(&env, Some("Switch2".to_string()), None).await?;

    // Delete switch2
    env.api
        .delete_switch(tonic::Request::new(rpc::forge::SwitchDeletionRequest {
            id: Some(switch_id2),
        }))
        .await?;

    // FindSwitchIds should only return the non-deleted switch
    let switch_ids = env
        .api
        .find_switch_ids(tonic::Request::new(rpc::forge::SwitchSearchFilter {
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(switch_ids.contains(&switch_id1));
    assert!(!switch_ids.contains(&switch_id2));

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switch_ids_deleted_only(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let switch_id1 = new_switch(&env, Some("Switch1".to_string()), None).await?;
    let switch_id2 = new_switch(&env, Some("Switch2".to_string()), None).await?;

    env.api
        .delete_switch(tonic::Request::new(rpc::forge::SwitchDeletionRequest {
            id: Some(switch_id2),
        }))
        .await?;

    // DELETED_FILTER_ONLY (1) should return only the deleted switch
    let switch_ids = env
        .api
        .find_switch_ids(tonic::Request::new(rpc::forge::SwitchSearchFilter {
            deleted: 1,
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(!switch_ids.contains(&switch_id1));
    assert!(switch_ids.contains(&switch_id2));

    // DELETED_FILTER_INCLUDE (2) should return both
    let switch_ids = env
        .api
        .find_switch_ids(tonic::Request::new(rpc::forge::SwitchSearchFilter {
            deleted: 2,
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(switch_ids.contains(&switch_id1));
    assert!(switch_ids.contains(&switch_id2));

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switch_ids_by_controller_state(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let switch_id = new_switch(&env, Some("Switch1".to_string()), None).await?;

    // New switches start in "created" state -- filter for it
    let switch_ids = env
        .api
        .find_switch_ids(tonic::Request::new(rpc::forge::SwitchSearchFilter {
            controller_state: Some("created".to_string()),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(switch_ids.contains(&switch_id));

    // Filter for a state that doesn't match
    let switch_ids = env
        .api
        .find_switch_ids(tonic::Request::new(rpc::forge::SwitchSearchFilter {
            controller_state: Some("ready".to_string()),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(!switch_ids.contains(&switch_id));

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switches_by_ids_response_fields(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let switch_id = new_switch(&env, Some("Switch1".to_string()), None).await?;

    let switches = env
        .api
        .find_switches_by_ids(tonic::Request::new(rpc::forge::SwitchesByIdsRequest {
            switch_ids: vec![switch_id],
        }))
        .await?
        .into_inner()
        .switches;
    assert_eq!(switches.len(), 1);

    let switch = &switches[0];

    // controller_state should be populated both on the top-level and in status
    assert!(!switch.controller_state.is_empty());
    let status = switch.status.as_ref().expect("status should be present");
    assert_eq!(
        status.controller_state.as_deref(),
        Some(switch.controller_state.as_str()),
    );

    // state_version should be populated
    assert!(!switch.state_version.is_empty());

    // bmc_info is None when no machine_interface discovery data exists
    assert!(
        switch.bmc_info.is_none(),
        "bmc_info should be None when no discovery data exists"
    );

    Ok(())
}
