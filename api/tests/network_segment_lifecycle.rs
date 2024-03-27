/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::time::Duration;

use carbide::{
    db::network_segment::NetworkSegment,
    state_controller::network_segment::handler::NetworkSegmentStateHandler,
};

pub mod common;
use common::{
    api_fixtures::{create_test_env, network_segment::FIXTURE_NETWORK_SEGMENT_ID},
    network_segment::{create_network_segment_with_api, get_segment_state, text_history},
};
use rpc::forge::forge_server::Forge;
use tonic::Request;

#[ctor::ctor]
fn setup() {
    common::test_logging::init();
}

async fn test_network_segment_lifecycle_impl(
    pool: sqlx::PgPool,
    use_subdomain: bool,
    use_vpc: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    let segment = create_network_segment_with_api(&env.api, use_subdomain, use_vpc, None).await;
    assert!(segment.created.is_some());
    assert!(segment.deleted.is_none());
    assert_eq!(segment.state(), rpc::forge::TenantState::Provisioning);
    assert_eq!(
        segment.segment_type,
        rpc::forge::NetworkSegmentType::Admin as i32
    );
    let segment_id: uuid::Uuid = segment.id.clone().unwrap().try_into().unwrap();
    let _: uuid::Uuid = segment
        .prefixes
        .first()
        .unwrap()
        .id
        .clone()
        .unwrap()
        .try_into()
        .unwrap();

    assert_eq!(
        get_segment_state(&env.api, segment_id).await,
        rpc::forge::TenantState::Provisioning
    );

    let state_handler = NetworkSegmentStateHandler::new(
        chrono::Duration::milliseconds(500),
        env.common_pools.ethernet.pool_vlan_id.clone(),
        env.common_pools.ethernet.pool_vni.clone(),
    );

    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;

    assert_eq!(
        get_segment_state(&env.api, segment_id).await,
        rpc::forge::TenantState::Ready
    );

    env.api
        .delete_network_segment(Request::new(rpc::forge::NetworkSegmentDeletionRequest {
            id: segment.id.clone(),
        }))
        .await
        .expect("expect deletion to succeed");

    // After the API request, the segment should show up as deleting
    assert_eq!(
        get_segment_state(&env.api, segment_id).await,
        rpc::forge::TenantState::Terminating
    );

    // Calling the API again in this state should be a noop
    env.api
        .delete_network_segment(Request::new(rpc::forge::NetworkSegmentDeletionRequest {
            id: segment.id.clone(),
        }))
        .await
        .expect("expect deletion to succeed");

    // Make the controller aware about termination too
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;

    // Wait for the drain period
    tokio::time::sleep(Duration::from_secs(1)).await;

    // delete the segment
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;
    env.run_network_segment_controller_iteration(segment_id, &state_handler)
        .await;

    let segments = env
        .api
        .find_network_segments(Request::new(rpc::forge::NetworkSegmentQuery {
            id: segment.id.clone(),
            search_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .network_segments;

    // After the segment is fully gone, deleting it again should return NotFound
    // Calling the API again in this state should be a noop
    let err = env
        .api
        .delete_network_segment(Request::new(rpc::forge::NetworkSegmentDeletionRequest {
            id: segment.id.clone(),
        }))
        .await
        .expect_err("expect deletion to fail");
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(
        err.message(),
        format!("network segment not found: {}", segment.id.unwrap())
    );

    let mut txn = pool.begin().await.unwrap();
    assert!(segments.is_empty());

    let expected_history = ["provisioning", "ready", "drainallocatedips", "dbdelete"];
    let history = text_history(&mut txn, segment_id).await;
    for (i, state) in history.iter().enumerate() {
        assert!(state.contains(expected_history[i]));
    }
    txn.commit().await.unwrap();

    Ok(())
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_lifecycle(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_lifecycle_impl(pool, false, false).await
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_lifecycle_with_vpc(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_lifecycle_impl(pool, false, true).await
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_lifecycle_with_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_lifecycle_impl(pool, true, false).await
}

#[sqlx::test(fixtures("create_domain", "create_vpc"))]
async fn test_network_segment_lifecycle_with_vpc_and_domain(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    test_network_segment_lifecycle_impl(pool, true, true).await
}

#[sqlx::test(fixtures("create_domain", "create_vpc", "create_network_segment"))]
async fn test_admin_network_exists(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let mut txn = pool.begin().await?;

    let segments = NetworkSegment::admin(&mut txn).await?;

    assert_eq!(segments.id, FIXTURE_NETWORK_SEGMENT_ID);

    Ok(())
}
