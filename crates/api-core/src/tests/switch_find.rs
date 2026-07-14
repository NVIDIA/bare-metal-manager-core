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

use rpc::forge::forge_server::Forge;

use crate::tests::common::api_fixtures::create_test_env;
use crate::tests::common::api_fixtures::site_explorer::new_switch;

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
    assert!(nvos_info.port.is_none());

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
    assert!(nvos_info.port.is_none());

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
        let updated = db_switch::try_update_controller_state(
            txn.as_mut(),
            switch_id,
            switch.controller_state.version,
            switch.controller_state.version.increment(),
            &SwitchControllerState::Ready,
        )
        .await?;
        assert!(
            updated,
            "setup should update switch controller state with the current version"
        );

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

#[crate::sqlx_test]
async fn test_find_ready_control_plane_configured_switch_endpoints_prefers_primary(
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

    let rack_id: RackId = "rack-sw-endpoint".parse().unwrap();
    TestRackDbBuilder::new()
        .with_rack_id(rack_id.clone())
        .persist(&mut txn)
        .await?;
    txn.commit().await?;

    let secondary_switch = new_switch(&env, Some("Switch1".to_string()), None).await?;
    let primary_switch = new_switch(&env, Some("Switch2".to_string()), None).await?;

    let configured_status = FabricManagerStatus {
        fabric_manager_state: FabricManagerState::Ok,
        addition_info: Some(CONTROL_PLANE_STATE_CONFIGURED.to_string()),
        reason: None,
        error_message: None,
    };

    let mut txn = env.pool.begin().await?;
    for switch_id in [secondary_switch, primary_switch] {
        sqlx::query("UPDATE switches SET rack_id = $1 WHERE id = $2")
            .bind(&rack_id)
            .bind(switch_id)
            .execute(txn.as_mut())
            .await?;

        let switch = db_switch::find_by_id(txn.as_mut(), &switch_id)
            .await?
            .expect("switch should exist");
        let updated = db_switch::try_update_controller_state(
            txn.as_mut(),
            switch_id,
            switch.controller_state.version,
            switch.controller_state.version.increment(),
            &SwitchControllerState::Ready,
        )
        .await?;
        assert!(
            updated,
            "setup should update switch controller state with the current version"
        );

        db_switch::update_fabric_manager_status(txn.as_mut(), switch_id, Some(&configured_status))
            .await?;
    }
    db_switch::set_primary_switch_for_rack(txn.as_mut(), &rack_id, &primary_switch).await?;

    let expected_nvos_ip = db_switch::find_switch_endpoints_by_ids(txn.as_mut(), &[primary_switch])
        .await?
        .pop()
        .expect("primary switch endpoint")
        .nvos_ip
        .expect("primary switch nvos ip");

    let endpoints =
        db_switch::find_ready_control_plane_configured_switch_endpoints(txn.as_mut()).await?;
    let rack_endpoints = endpoints
        .into_iter()
        .filter(|endpoint| endpoint.rack_id == rack_id)
        .collect::<Vec<_>>();

    assert_eq!(rack_endpoints.len(), 1);
    assert_eq!(rack_endpoints[0].switch_id, primary_switch);
    assert_eq!(rack_endpoints[0].rack_id, rack_id);
    assert_eq!(rack_endpoints[0].nvos_ip, expected_nvos_ip);

    Ok(())
}
