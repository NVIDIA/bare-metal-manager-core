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

use carbide_uuid::infiniband::IBPartitionId;
use tonic::Request;

use super::TestEnv;
use crate::api::rpc::forge_server::Forge;
use crate::api::rpc::{IbPartitionConfig, IbPartitionCreationRequest};

pub const DEFAULT_TENANT: &str = "Tenant1";

pub async fn create_ib_partition(
    env: &TestEnv,
    name: String,
    tenant: String,
) -> (IBPartitionId, rpc::IbPartition) {
    let ib_partition = env
        .api
        .create_ib_partition(Request::new(IbPartitionCreationRequest {
            id: None,
            config: Some(IbPartitionConfig {
                name: name.clone(),
                tenant_organization_id: tenant,
            }),
            metadata: Some(rpc::Metadata {
                name,
                labels: Default::default(),
                description: "".to_string(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    let ib_partition_id = ib_partition.id.expect("Missing ib partition ID");

    env.run_ib_partition_controller_iteration().await;

    let ib_partition = env
        .api
        .find_ib_partitions_by_ids(Request::new(rpc::forge::IbPartitionsByIdsRequest {
            ib_partition_ids: vec![ib_partition_id],
            include_history: false,
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
