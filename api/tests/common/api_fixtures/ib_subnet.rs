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

use super::TestEnv;
use carbide::{
    api::rpc::{
        forge_server::Forge, IbSubnetConfig, IbSubnetCreationRequest, IbSubnetSearchConfig,
    },
    state_controller::ib_subnet::handler::IBSubnetStateHandler,
};
use tonic::Request;

const FIXTURE_CREATED_VPC_UUID: uuid::Uuid = uuid::uuid!("60cef902-9779-4666-8362-c9bb4b37184f");

pub async fn create_ib_subnet(env: &TestEnv, name: String) -> (uuid::Uuid, rpc::IbSubnet) {
    let ib_subnet = env
        .api
        .create_ib_subnet(Request::new(IbSubnetCreationRequest {
            config: Some(IbSubnetConfig {
                name,
                vpc_id: Some(FIXTURE_CREATED_VPC_UUID.into()),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    let ib_subnet_id =
        uuid::Uuid::try_from(ib_subnet.id.clone().expect("Missing ib subnet ID")).unwrap();

    let state_handler = IBSubnetStateHandler::new(chrono::Duration::milliseconds(500));
    env.run_ib_subnet_controller_iteration(ib_subnet_id, &state_handler)
        .await;

    let ib_subnet = env
        .api
        .find_ib_subnets(Request::new(rpc::forge::IbSubnetQuery {
            id: Some(ib_subnet_id.into()),
            search_config: Some(IbSubnetSearchConfig {
                include_history: false,
            }),
        }))
        .await
        .unwrap()
        .into_inner()
        .ib_subnets
        .remove(0);

    // check the IB subnet status to make sure it is ready.
    let status = ib_subnet.status.clone().unwrap();
    assert_eq!(status.state, rpc::TenantState::Ready as i32);

    (ib_subnet_id, ib_subnet)
}
