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

use carbide::{
    api::rpc::IbPartitionConfig, api::rpc::IbPartitionSearchConfig,
    state_controller::ib_partition::handler::IBPartitionStateHandler,
};

pub mod common;
use common::api_fixtures::{create_test_env, TestApi};
use rpc::forge::{forge_server::Forge, TenantState};
use tonic::Request;

const FIXTURE_CREATED_IB_PARTITION_NAME: &str = "ib_partition_1";
const FIXTURE_TENANT_ORG_ID: &str = "tenant";

async fn create_ib_partition_with_api(api: &TestApi, name: String) -> rpc::forge::IbPartition {
    let request = rpc::forge::IbPartitionCreationRequest {
        config: Some(IbPartitionConfig {
            name,
            tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
        }),
    };

    api.create_ib_partition(Request::new(request))
        .await
        .expect("Unable to create ib partition")
        .into_inner()
}

async fn get_partition_state(api: &TestApi, ib_partition_id: uuid::Uuid) -> TenantState {
    let segment = api
        .find_ib_partitions(Request::new(rpc::forge::IbPartitionQuery {
            id: Some(ib_partition_id.into()),
            search_config: Some(IbPartitionSearchConfig {
                include_history: false,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .ib_partitions
        .remove(0);
    let status = segment.status.unwrap();

    TenantState::from_i32(status.state).unwrap()
}

async fn test_ib_partition_lifecycle_impl(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;

    let segment =
        create_ib_partition_with_api(&env.api, FIXTURE_CREATED_IB_PARTITION_NAME.to_string()).await;

    let segment_id: uuid::Uuid = segment.id.clone().unwrap().try_into().unwrap();
    // The TenantState only switches after the state controller recognized the update
    assert_eq!(
        get_partition_state(&env.api, segment_id).await,
        TenantState::Provisioning
    );

    let state_handler = IBPartitionStateHandler::new(chrono::Duration::milliseconds(500));

    env.run_ib_partition_controller_iteration(segment_id, &state_handler)
        .await;

    // After 1 controller iterations, the segment should be ready
    assert_eq!(
        get_partition_state(&env.api, segment_id).await,
        TenantState::Ready
    );

    env.api
        .delete_ib_partition(Request::new(rpc::forge::IbPartitionDeletionRequest {
            id: segment.id.clone(),
        }))
        .await
        .expect("expect deletion to succeed");

    // After the API request, the segment should show up as deleting
    assert_eq!(
        get_partition_state(&env.api, segment_id).await,
        TenantState::Terminating
    );

    // Make the controller aware about termination too
    env.run_ib_partition_controller_iteration(segment_id, &state_handler)
        .await;
    env.run_ib_partition_controller_iteration(segment_id, &state_handler)
        .await;

    let segments = env
        .api
        .find_ib_partitions(Request::new(rpc::forge::IbPartitionQuery {
            id: segment.id.clone(),
            search_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .ib_partitions;

    assert!(segments.is_empty());

    Ok(())
}

#[sqlx::test]
async fn test_ib_partition_lifecycle(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    test_ib_partition_lifecycle_impl(pool).await
}

#[sqlx::test]
async fn test_find_ib_partition_for_tenant(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone()).await;
    let created_ib_partition =
        create_ib_partition_with_api(&env.api, FIXTURE_CREATED_IB_PARTITION_NAME.to_string()).await;
    let created_ib_partition_id: uuid::Uuid =
        created_ib_partition.id.clone().unwrap().try_into().unwrap();

    let find_ib_partition = env
        .api
        .ib_partitions_for_tenant(Request::new(rpc::forge::TenantSearchQuery {
            tenant_organization_id: Some(FIXTURE_TENANT_ORG_ID.to_string()),
        }))
        .await
        .unwrap()
        .into_inner()
        .ib_partitions
        .remove(0);
    let find_ib_partition_id: uuid::Uuid =
        find_ib_partition.id.clone().unwrap().try_into().unwrap();

    assert_eq!(created_ib_partition_id, find_ib_partition_id);
    Ok(())
}
