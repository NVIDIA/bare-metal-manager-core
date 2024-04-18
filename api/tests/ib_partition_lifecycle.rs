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
    api::rpc::IbPartitionConfig,
    api::rpc::IbPartitionSearchConfig,
    cfg::IBFabricConfig,
    db::ib_partition::{IBPartitionConfig, IBPartitionStatus, NewIBPartition},
    ib::{
        types::{IBNetwork, IBPortMembership},
        IBFabricManagerConfig, IBFabricManagerType,
    },
    state_controller::ib_partition::handler::IBPartitionStateHandler,
};

pub mod common;
use common::api_fixtures::{create_test_env, TestApi};
use rpc::forge::{forge_server::Forge, TenantState};
use tonic::Request;

const FIXTURE_CREATED_IB_PARTITION_NAME: &str = "ib_partition_1";
const FIXTURE_TENANT_ORG_ID: &str = "tenant";

async fn create_ib_partition_with_api(
    api: &TestApi,
    name: String,
) -> Result<tonic::Response<rpc::IbPartition>, tonic::Status> {
    let request = rpc::forge::IbPartitionCreationRequest {
        id: None,
        config: Some(IbPartitionConfig {
            name,
            tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
        }),
    };

    api.create_ib_partition(Request::new(request)).await
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

    TenantState::try_from(status.state).unwrap()
}

async fn test_ib_partition_lifecycle_impl(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;

    let partition =
        create_ib_partition_with_api(&env.api, FIXTURE_CREATED_IB_PARTITION_NAME.to_string())
            .await
            .unwrap()
            .into_inner();

    let segment_id: uuid::Uuid = partition.id.clone().unwrap().try_into().unwrap();
    // The TenantState only switches after the state controller recognized the update
    assert_eq!(
        get_partition_state(&env.api, segment_id).await,
        TenantState::Provisioning
    );

    let state_handler = IBPartitionStateHandler::default();

    env.run_ib_partition_controller_iteration(state_handler.clone())
        .await;

    // After 1 controller iterations, the partition should be ready
    assert_eq!(
        get_partition_state(&env.api, segment_id).await,
        TenantState::Ready
    );

    env.api
        .delete_ib_partition(Request::new(rpc::forge::IbPartitionDeletionRequest {
            id: partition.id.clone(),
        }))
        .await
        .expect("expect deletion to succeed");

    // After the API request, the partition should show up as deleting
    assert_eq!(
        get_partition_state(&env.api, segment_id).await,
        TenantState::Terminating
    );

    // Deletion is idempotent
    env.api
        .delete_ib_partition(Request::new(rpc::forge::IbPartitionDeletionRequest {
            id: partition.id.clone(),
        }))
        .await
        .expect("expect deletion to succeed");

    // Make the controller aware about termination too
    env.run_ib_partition_controller_iteration(state_handler.clone())
        .await;
    env.run_ib_partition_controller_iteration(state_handler)
        .await;

    let segments = env
        .api
        .find_ib_partitions(Request::new(rpc::forge::IbPartitionQuery {
            id: partition.id.clone(),
            search_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .ib_partitions;

    assert!(segments.is_empty());

    // After the partition is fully gone, deleting it again should return NotFound
    // Calling the API again in this state should be a noop
    let err = env
        .api
        .delete_ib_partition(Request::new(rpc::forge::IbPartitionDeletionRequest {
            id: partition.id.clone(),
        }))
        .await
        .expect_err("expect deletion to fail");
    assert_eq!(err.code(), tonic::Code::NotFound);
    assert_eq!(
        err.message(),
        format!("ib_partition not found: {}", partition.id.unwrap())
    );

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
    let env = create_test_env(pool).await;
    let created_ib_partition =
        create_ib_partition_with_api(&env.api, FIXTURE_CREATED_IB_PARTITION_NAME.to_string())
            .await
            .unwrap()
            .into_inner();
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

#[sqlx::test]
async fn test_create_ib_partition_over_max_limit(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    // create max number of ib partitions for the tenant
    for _i in 1..=IBFabricConfig::default_max_partition_per_tenant() {
        let _ =
            create_ib_partition_with_api(&env.api, FIXTURE_CREATED_IB_PARTITION_NAME.to_string())
                .await?;
    }

    // create one more ib partition for this tenant, should be fail with no rows retruned from DB.
    let response =
        create_ib_partition_with_api(&env.api, FIXTURE_CREATED_IB_PARTITION_NAME.to_string()).await;

    let error = response
        .expect_err("expected create ibpartition to fail")
        .to_string();
    assert!(
        error.contains("Maximum Limit of Infiniband partitions had been reached"),
        "Error message should contain 'Maximum Limit of Infiniband partitions had been reached', but is {}",
        error
    );

    Ok(())
}

#[sqlx::test]
async fn create_ib_partition_with_api_with_id(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool).await;
    let id = uuid::Uuid::new_v4();
    let request = rpc::forge::IbPartitionCreationRequest {
        id: Some(::rpc::Uuid {
            value: id.to_string(),
        }),
        config: Some(IbPartitionConfig {
            name: "partition1".to_string(),
            tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string(),
        }),
    };

    let partition = env
        .api
        .create_ib_partition(Request::new(request))
        .await
        .unwrap()
        .into_inner();

    assert_eq!(partition.id.unwrap().value, id.to_string());
    Ok(())
}

#[sqlx::test]
async fn test_update_ib_partition(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    let id = uuid::Uuid::new_v4();
    let new_partition = NewIBPartition {
        id,
        config: IBPartitionConfig {
            name: "partition1".to_string(),
            pkey: Some(42),
            tenant_organization_id: FIXTURE_TENANT_ORG_ID.to_string().try_into().unwrap(),
            mtu: 2000,
            rate_limit: 300,
            service_level: 0,
        },
    };
    let mut txn = pool.begin().await?;
    let mut partition = new_partition
        .create(
            &mut txn,
            &IBFabricManagerConfig {
                manager_type: IBFabricManagerType::Disable,
                max_partition_per_tenant: 10,
            },
        )
        .await?;
    txn.commit().await?;

    let ibnetwork = IBNetwork {
        pkey: 42,
        name: "x".to_string(),
        enable_sharp: false,
        mtu: 2000,
        ipoib: false,
        service_level: 0,
        membership: IBPortMembership::Full,
        index0: false,
        rate_limit: 300.0,
    };
    partition.status = Some(IBPartitionStatus::from(&ibnetwork));

    // What we're testing
    let mut txn = pool.begin().await?;
    partition.update(&mut txn).await?;

    Ok(())
}
