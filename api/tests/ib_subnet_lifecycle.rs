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
    api::rpc::IbSubnetConfig, api::rpc::IbSubnetSearchConfig,
    state_controller::ib_subnet::handler::IBSubnetStateHandler,
};

pub mod common;
use common::api_fixtures::{create_test_env, TestApi};
use rpc::forge::{forge_server::Forge, TenantState};
use tonic::Request;

const FIXTURE_CREATED_VPC_UUID: uuid::Uuid = uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f");
const FIXTURE_CREATED_IB_SUBNET_NAME: &str = "ib_subnet_1";

async fn create_ib_subnet_with_api(api: &TestApi, name: String) -> rpc::forge::IbSubnet {
    let request = rpc::forge::IbSubnetCreationRequest {
        config: Some(IbSubnetConfig {
            name,
            vpc_id: Some(FIXTURE_CREATED_VPC_UUID.into()),
        }),
    };

    api.create_ib_subnet(Request::new(request))
        .await
        .expect("Unable to create ib subnet")
        .into_inner()
}

async fn get_segment_state(api: &TestApi, ibsubnet_id: uuid::Uuid) -> TenantState {
    let segment = api
        .find_ib_subnets(Request::new(rpc::forge::IbSubnetQuery {
            id: Some(ibsubnet_id.into()),
            search_config: Some(IbSubnetSearchConfig {
                include_history: false,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .ib_subnets
        .remove(0);
    let status = segment.status.unwrap();

    TenantState::from_i32(status.state).unwrap()
}

async fn test_ib_subnet_lifecycle_impl(
    pool: sqlx::PgPool,
) -> Result<(), Box<dyn std::error::Error>> {
    let env = create_test_env(pool.clone(), Default::default()).await;

    let segment =
        create_ib_subnet_with_api(&env.api, FIXTURE_CREATED_IB_SUBNET_NAME.to_string()).await;

    let segment_id: uuid::Uuid = segment.id.clone().unwrap().try_into().unwrap();
    // The TenantState only switches after the state controller recognized the update
    assert_eq!(
        get_segment_state(&env.api, segment_id).await,
        TenantState::Provisioning
    );

    let state_handler = IBSubnetStateHandler::new(chrono::Duration::milliseconds(500));

    env.run_ib_subnet_controller_iteration(segment_id, &state_handler)
        .await;

    // After 1 controller iteration, the ibsubnet should be Provisioning (Initialized).
    assert_eq!(
        get_segment_state(&env.api, segment_id).await,
        TenantState::Provisioning,
    );

    env.run_ib_subnet_controller_iteration(segment_id, &state_handler)
        .await;

    // After 2 controller iterations, the segment should be ready
    assert_eq!(
        get_segment_state(&env.api, segment_id).await,
        TenantState::Ready
    );

    env.api
        .delete_ib_subnet(Request::new(rpc::forge::IbSubnetDeletionRequest {
            id: segment.id.clone(),
        }))
        .await
        .expect("expect deletion to succeed");

    // After the API request, the segment should show up as deleting
    assert_eq!(
        get_segment_state(&env.api, segment_id).await,
        TenantState::Terminating
    );
    // Make the controller aware about termination too
    env.run_ib_subnet_controller_iteration(segment_id, &state_handler)
        .await;

    // Wait for the drain period
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    env.run_ib_subnet_controller_iteration(segment_id, &state_handler)
        .await;
    env.run_ib_subnet_controller_iteration(segment_id, &state_handler)
        .await;

    let segments = env
        .api
        .find_ib_subnets(Request::new(rpc::forge::IbSubnetQuery {
            id: segment.id.clone(),
            search_config: None,
        }))
        .await
        .unwrap()
        .into_inner()
        .ib_subnets;

    assert!(segments.is_empty());

    Ok(())
}

#[sqlx::test(fixtures("create_vpc"))]
async fn test_ib_subnet_lifecycle(pool: sqlx::PgPool) -> Result<(), Box<dyn std::error::Error>> {
    test_ib_subnet_lifecycle_impl(pool).await
}
