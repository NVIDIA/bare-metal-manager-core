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

use nico_rpc::forge;
use nico_rpc::forge::forge_server::Forge;
use nico_rpc::forge::{NvLinkLogicalPartitionConfig, NvLinkLogicalPartitionCreationRequest};
use nico_uuid::nvlink::NvLinkLogicalPartitionId;
use tonic::Request;

use super::TestEnv;

pub struct NvlLogicalPartitionFixture {
    pub id: NvLinkLogicalPartitionId,
    pub logical_partition: forge::NvLinkLogicalPartition,
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
                metadata: Some(forge::Metadata {
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
            forge::NvLinkLogicalPartitionsByIdsRequest {
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
