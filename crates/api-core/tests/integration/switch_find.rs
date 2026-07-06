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

use carbide_test_harness::prelude::*;

#[sqlx_test]
async fn test_find_switch_ids_and_by_ids(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = TestHarness::builder(pool).build().await;
    let TestSwitch { id: switch_id1 } = env.create_switch(1, 1).await;
    let TestSwitch { id: switch_id2 } = env.create_switch(2, 1).await;

    let switch_ids = env
        .api()
        .find_switch_ids(tonic::Request::new(rpc::forge::SwitchSearchFilter {
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(switch_ids.contains(&switch_id1));
    assert!(switch_ids.contains(&switch_id2));

    let switches = env
        .api()
        .find_switches_by_ids(tonic::Request::new(rpc::forge::SwitchesByIdsRequest {
            switch_ids: vec![switch_id1],
        }))
        .await?
        .into_inner()
        .switches;
    assert_eq!(switches.len(), 1);
    assert_eq!(switches[0].id, Some(switch_id1));

    let switches = env
        .api()
        .find_switches_by_ids(tonic::Request::new(rpc::forge::SwitchesByIdsRequest {
            switch_ids: vec![switch_id1, switch_id2],
        }))
        .await?
        .into_inner()
        .switches;
    assert_eq!(switches.len(), 2);

    Ok(())
}

// The empty-list and over-max guards for `find_switches_by_ids` are shared
// API-layer code, proven once across representative RPCs in
// `tests::find_by_ids_guards`.

#[sqlx_test]
async fn test_find_switch_ids_excludes_deleted(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = TestHarness::builder(pool).build().await;
    let TestSwitch { id: switch_id1 } = env.create_switch(1, 1).await;
    let TestSwitch { id: switch_id2 } = env.create_switch(2, 1).await;

    env.api()
        .delete_switch(tonic::Request::new(rpc::forge::SwitchDeletionRequest {
            id: Some(switch_id2),
        }))
        .await?;

    let switch_ids = env
        .api()
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

#[sqlx_test]
async fn test_find_switch_ids_deleted_only(pool: PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let env = TestHarness::builder(pool).build().await;
    let TestSwitch { id: switch_id1 } = env.create_switch(1, 1).await;
    let TestSwitch { id: switch_id2 } = env.create_switch(2, 1).await;

    env.api()
        .delete_switch(tonic::Request::new(rpc::forge::SwitchDeletionRequest {
            id: Some(switch_id2),
        }))
        .await?;

    let switch_ids = env
        .api()
        .find_switch_ids(tonic::Request::new(rpc::forge::SwitchSearchFilter {
            deleted: 1,
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(!switch_ids.contains(&switch_id1));
    assert!(switch_ids.contains(&switch_id2));

    let switch_ids = env
        .api()
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

#[sqlx_test]
async fn test_find_switch_ids_by_controller_state(
    pool: PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = TestHarness::builder(pool).build().await;
    let TestSwitch { id: switch_id } = env.create_switch(1, 1).await;

    let switch_ids = env
        .api()
        .find_switch_ids(tonic::Request::new(rpc::forge::SwitchSearchFilter {
            controller_state: Some("created".to_string()),
            ..Default::default()
        }))
        .await?
        .into_inner()
        .ids;
    assert!(switch_ids.contains(&switch_id));

    let switch_ids = env
        .api()
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
