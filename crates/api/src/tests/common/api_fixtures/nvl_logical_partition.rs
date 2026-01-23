/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge::{self as rpc};
use carbide_uuid::nvlink::NvLinkLogicalPartitionId;
use tonic::Request;

use super::TestEnv;
use crate::api::rpc::forge_server::Forge;
use crate::api::rpc::{NvLinkLogicalPartitionConfig, NvLinkLogicalPartitionCreationRequest};

pub struct NvlLogicalPartitionFixture {
    pub id: NvLinkLogicalPartitionId,
    pub logical_partition: rpc::NvLinkLogicalPartition,
}

pub async fn create_nvl_logical_partition(
    env: &TestEnv,
    name: String,
) -> NvlLogicalPartitionFixture {
    let partition = env
        .api
        .create_nv_link_logical_partition(Request::new(NvLinkLogicalPartitionCreationRequest {
            id: None,
            config: Some(NvLinkLogicalPartitionConfig {
                metadata: Some(rpc::Metadata {
                    name,
                    ..Default::default()
                }),
                tenant_organization_id: "example".to_string(),
            }),
        }))
        .await
        .unwrap()
        .into_inner();

    let partition_id = partition.id.expect("Missing nvlink logical partition ID");

    let logical_partition = env
        .api
        .find_nv_link_logical_partitions_by_ids(Request::new(
            rpc::NvLinkLogicalPartitionsByIdsRequest {
                partition_ids: vec![partition_id],
                include_history: false,
            },
        ))
        .await
        .unwrap()
        .into_inner()
        .partitions
        .remove(0);

    NvlLogicalPartitionFixture {
        id: partition_id,
        logical_partition,
    }
}
