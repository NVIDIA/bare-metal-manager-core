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
        forge_server::Forge, IbPartitionConfig, IbPartitionCreationRequest, IbPartitionSearchConfig,
    },
    state_controller::ib_partition::handler::IBPartitionStateHandler,
};
use tonic::Request;

pub async fn create_ib_partition(env: &TestEnv, name: String) -> (uuid::Uuid, rpc::IbPartition) {
    let ib_partition = env
        .api
        .create_ib_partition(Request::new(IbPartitionCreationRequest {
            config: Some(IbPartitionConfig {
                name,
                tenant_organization_id: "tenant1".to_string(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    let ib_partition_id =
        uuid::Uuid::try_from(ib_partition.id.clone().expect("Missing ib partition ID")).unwrap();

    let state_handler = IBPartitionStateHandler::new(chrono::Duration::milliseconds(500));
    env.run_ib_partition_controller_iteration(ib_partition_id, &state_handler)
        .await;

    let ib_partition = env
        .api
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

    // check the IB partition status to make sure it is ready.
    let status = ib_partition.status.clone().unwrap();
    assert_eq!(status.state, rpc::TenantState::Ready as i32);

    (ib_partition_id, ib_partition)
}
