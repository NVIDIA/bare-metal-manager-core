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
use rpc::forge::forge_server::Forge;

use crate::tests::common::api_fixtures::create_test_env;
use crate::tests::common::api_fixtures::site_explorer::new_power_shelf;

#[crate::sqlx_test]
async fn test_find_power_shelf_ids_and_by_ids(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let ps_id1 = new_power_shelf(&env, Some("PS1".to_string()), None, None, None).await?;
    let ps_id2 = new_power_shelf(&env, Some("PS2".to_string()), None, None, None).await?;

    // FindPowerShelfIds should return both power shelves
    let power_shelf_ids = env
        .api
        .find_power_shelf_ids(tonic::Request::new(rpc::forge::PowerShelfSearchFilter {
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(power_shelf_ids.contains(&ps_id1));
    assert!(power_shelf_ids.contains(&ps_id2));

    // FindPowerShelvesByIds should return the requested power shelf
    let power_shelves = env
        .api
        .find_power_shelves_by_ids(tonic::Request::new(rpc::forge::PowerShelvesByIdsRequest {
            power_shelf_ids: vec![ps_id1],
        }))
        .await?
        .into_inner()
        .power_shelves;
    assert_eq!(power_shelves.len(), 1);
    assert_eq!(power_shelves[0].id, Some(ps_id1));

    // FindPowerShelvesByIds should return both when requested
    let power_shelves = env
        .api
        .find_power_shelves_by_ids(tonic::Request::new(rpc::forge::PowerShelvesByIdsRequest {
            power_shelf_ids: vec![ps_id1, ps_id2],
        }))
        .await?
        .into_inner()
        .power_shelves;
    assert_eq!(power_shelves.len(), 2);

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_power_shelves_by_ids_empty_returns_error(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let result = env
        .api
        .find_power_shelves_by_ids(tonic::Request::new(rpc::forge::PowerShelvesByIdsRequest {
            power_shelf_ids: vec![],
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
async fn test_find_power_shelves_by_ids_over_max(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let count = env.config.max_find_by_ids + 1;
    let power_shelf_ids: Vec<PowerShelfId> = (0..count)
        .map(|_| PowerShelfId::from(uuid::Uuid::new_v4()))
        .collect();

    let result = env
        .api
        .find_power_shelves_by_ids(tonic::Request::new(rpc::forge::PowerShelvesByIdsRequest {
            power_shelf_ids,
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
async fn test_find_power_shelf_ids_excludes_deleted(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let ps_id1 = new_power_shelf(&env, Some("PS1".to_string()), None, None, None).await?;
    let ps_id2 = new_power_shelf(&env, Some("PS2".to_string()), None, None, None).await?;

    // Delete ps2
    env.api
        .delete_power_shelf(tonic::Request::new(rpc::forge::PowerShelfDeletionRequest {
            id: Some(ps_id2),
        }))
        .await?;

    // FindPowerShelfIds should only return the non-deleted power shelf
    let power_shelf_ids = env
        .api
        .find_power_shelf_ids(tonic::Request::new(rpc::forge::PowerShelfSearchFilter {
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(power_shelf_ids.contains(&ps_id1));
    assert!(!power_shelf_ids.contains(&ps_id2));

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_power_shelf_ids_deleted_only(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let ps_id1 = new_power_shelf(&env, Some("PS1".to_string()), None, None, None).await?;
    let ps_id2 = new_power_shelf(&env, Some("PS2".to_string()), None, None, None).await?;

    env.api
        .delete_power_shelf(tonic::Request::new(rpc::forge::PowerShelfDeletionRequest {
            id: Some(ps_id2),
        }))
        .await?;

    // DELETED_FILTER_ONLY (1) should return only the deleted power shelf
    let power_shelf_ids = env
        .api
        .find_power_shelf_ids(tonic::Request::new(rpc::forge::PowerShelfSearchFilter {
            deleted: 1,
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(!power_shelf_ids.contains(&ps_id1));
    assert!(power_shelf_ids.contains(&ps_id2));

    // DELETED_FILTER_INCLUDE (2) should return both
    let power_shelf_ids = env
        .api
        .find_power_shelf_ids(tonic::Request::new(rpc::forge::PowerShelfSearchFilter {
            deleted: 2,
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(power_shelf_ids.contains(&ps_id1));
    assert!(power_shelf_ids.contains(&ps_id2));

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_power_shelf_ids_by_controller_state(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let ps_id = new_power_shelf(&env, Some("PS1".to_string()), None, None, None).await?;

    // New power shelves start in "initializing" state
    let power_shelf_ids = env
        .api
        .find_power_shelf_ids(tonic::Request::new(rpc::forge::PowerShelfSearchFilter {
            controller_state: Some("initializing".to_string()),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(power_shelf_ids.contains(&ps_id));

    // Filter for a state that doesn't match
    let power_shelf_ids = env
        .api
        .find_power_shelf_ids(tonic::Request::new(rpc::forge::PowerShelfSearchFilter {
            controller_state: Some("ready".to_string()),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(!power_shelf_ids.contains(&ps_id));

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_power_shelves_by_ids_response_fields(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let ps_id = new_power_shelf(&env, Some("PS1".to_string()), None, None, None).await?;

    let power_shelves = env
        .api
        .find_power_shelves_by_ids(tonic::Request::new(rpc::forge::PowerShelvesByIdsRequest {
            power_shelf_ids: vec![ps_id],
        }))
        .await?
        .into_inner()
        .power_shelves;
    assert_eq!(power_shelves.len(), 1);

    let ps = &power_shelves[0];

    // controller_state should be populated both on the top-level and in status
    assert!(!ps.controller_state.is_empty());
    let status = ps.status.as_ref().expect("status should be present");
    assert_eq!(
        status.controller_state.as_deref(),
        Some(ps.controller_state.as_str()),
    );

    // state_version should be populated
    assert!(!ps.state_version.is_empty());

    // bmc_info is None when no machine_interface discovery data exists
    assert!(
        ps.bmc_info.is_none(),
        "bmc_info should be None when no discovery data exists"
    );

    Ok(())
}
