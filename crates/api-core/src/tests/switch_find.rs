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

    // bmc_info should be populated from the seeded machine_interface discovery data
    assert!(
        switch.bmc_info.is_some(),
        "bmc_info should be present when discovery data exists"
    );

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switches_by_ids_includes_resolved_nvos_info(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let switch_id = new_switch(&env, Some("Switch1".to_string()), None).await?;

    let mut rows = db::switch::find_switch_endpoints_by_ids(&env.pool, &[switch_id]).await?;
    let expected = rows.pop().expect("switch endpoint row");
    let host_mac = expected.nvos_mac.expect("nvos mac");
    let host_ip = expected.nvos_ip.expect("nvos ip");

    let response = env
        .api
        .find_switches_by_ids(tonic::Request::new(rpc::forge::SwitchesByIdsRequest {
            switch_ids: vec![switch_id],
        }))
        .await?
        .into_inner();

    assert_eq!(response.switches.len(), 1);
    let switch = &response.switches[0];
    assert_eq!(switch.id, Some(switch_id));
    assert_eq!(
        switch.bmc_info.as_ref().and_then(|info| info.mac.clone()),
        Some(expected.bmc_mac.to_string())
    );
    assert_eq!(
        switch.bmc_info.as_ref().and_then(|info| info.ip.clone()),
        Some(expected.bmc_ip.to_string())
    );

    let nvos_info = switch.nvos_info.as_ref().expect("nvos info");
    let _: &rpc::forge::SwitchNvosInfo = nvos_info;
    assert_eq!(nvos_info.mac, Some(host_mac.to_string()));
    assert_eq!(nvos_info.ip, Some(host_ip.to_string()));

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switches_includes_resolved_nvos_info(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let switch_id = new_switch(&env, Some("Switch1".to_string()), None).await?;

    let mut rows = db::switch::find_switch_endpoints_by_ids(&env.pool, &[switch_id]).await?;
    let expected = rows.pop().expect("switch endpoint row");
    let host_mac = expected.nvos_mac.expect("nvos mac");
    let host_ip = expected.nvos_ip.expect("nvos ip");

    let response = env
        .api
        .find_switches(tonic::Request::new(rpc::forge::SwitchQuery {
            name: None,
            switch_id: Some(switch_id),
        }))
        .await?
        .into_inner();

    assert_eq!(response.switches.len(), 1);
    let nvos_info = response.switches[0].nvos_info.as_ref().expect("nvos info");
    let _: &rpc::forge::SwitchNvosInfo = nvos_info;
    assert_eq!(nvos_info.mac, Some(host_mac.to_string()));
    assert_eq!(nvos_info.ip, Some(host_ip.to_string()));

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_switches_by_ids_returns_no_nvos_info_when_unresolved(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let switch_id = new_switch(&env, Some("Switch1".to_string()), None).await?;
    let rows = db::switch::find_switch_endpoints_by_ids(&env.pool, &[switch_id]).await?;
    let bmc_mac = rows.first().expect("switch endpoint row").bmc_mac;

    {
        let mut txn = env.pool.begin().await?;
        db::expected_switch::update_nvos_mac_addresses(txn.as_mut(), bmc_mac, &[]).await?;
        txn.commit().await?;
    }

    let response = env
        .api
        .find_switches_by_ids(tonic::Request::new(rpc::forge::SwitchesByIdsRequest {
            switch_ids: vec![switch_id],
        }))
        .await?
        .into_inner();

    assert_eq!(response.switches.len(), 1);
    assert!(response.switches[0].nvos_info.is_none());

    Ok(())
}

#[crate::sqlx_test]
async fn test_find_ready_control_plane_configured_switch_ids_in_rack(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    use carbide_uuid::rack::RackId;
    use db::switch as db_switch;
    use model::switch::{
        CONTROL_PLANE_STATE_CONFIGURED, FabricManagerState, FabricManagerStatus,
        SwitchControllerState,
    };

    use crate::tests::common::api_fixtures::site_explorer::TestRackDbBuilder;

    let env = create_test_env(pool).await;
    let mut txn = env.pool.begin().await?;

    let rack_id: RackId = "rack-sw-find".parse().unwrap();
    let other_rack_id: RackId = "rack-other".parse().unwrap();
    TestRackDbBuilder::new()
        .with_rack_id(rack_id.clone())
        .persist(&mut txn)
        .await?;
    TestRackDbBuilder::new()
        .with_rack_id(other_rack_id.clone())
        .persist(&mut txn)
        .await?;
    txn.commit().await?;

    let matching_switch = new_switch(&env, Some("Switch1".to_string()), None).await?;
    let wrong_fm_switch = new_switch(&env, Some("Switch2".to_string()), None).await?;
    let other_rack_switch = new_switch(&env, Some("Switch4".to_string()), None).await?;

    let configured_status = FabricManagerStatus {
        fabric_manager_state: FabricManagerState::Ok,
        addition_info: Some(CONTROL_PLANE_STATE_CONFIGURED.to_string()),
        reason: None,
        error_message: None,
    };

    let mut txn = env.pool.begin().await?;
    for (switch_id, rack, fm_status) in [
        (matching_switch, &rack_id, Some(&configured_status)),
        (wrong_fm_switch, &rack_id, None),
        (other_rack_switch, &other_rack_id, Some(&configured_status)),
    ] {
        sqlx::query("UPDATE switches SET rack_id = $1 WHERE id = $2")
            .bind(rack)
            .bind(switch_id)
            .execute(txn.as_mut())
            .await?;

        let switch = db_switch::find_by_id(txn.as_mut(), &switch_id)
            .await?
            .expect("switch should exist");
        db_switch::try_update_controller_state(
            txn.as_mut(),
            switch_id,
            switch.controller_state.version,
            switch.controller_state.version.increment(),
            &SwitchControllerState::Ready,
        )
        .await?;

        if let Some(status) = fm_status {
            db_switch::update_fabric_manager_status(txn.as_mut(), switch_id, Some(status)).await?;
        }
    }
    txn.commit().await?;

    let mut txn = env.pool.begin().await?;
    let found =
        db_switch::find_ready_control_plane_configured_switch_ids_in_rack(txn.as_mut(), &rack_id)
            .await?;
    assert_eq!(found, vec![matching_switch]);

    let found_other = db_switch::find_ready_control_plane_configured_switch_ids_in_rack(
        txn.as_mut(),
        &other_rack_id,
    )
    .await?;
    assert_eq!(found_other, vec![other_rack_switch]);

    Ok(())
}
