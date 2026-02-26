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

use ::rpc::admin_cli::CarbideCliResult;
use ::rpc::forge as forgerpc;

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn handle_create(args: Args, api_client: &ApiClient) -> CarbideCliResult<()> {
    create_logical_partition(args, api_client).await?;
    Ok(())
}

pub async fn create_logical_partition(args: Args, api_client: &ApiClient) -> CarbideCliResult<()> {
    let metadata = forgerpc::Metadata {
        name: args.name,
        labels: vec![forgerpc::Label {
            key: "cloud-unsafe-op".to_string(),
            value: Some("true".to_string()),
        }],
        ..Default::default()
    };
    let request = forgerpc::NvLinkLogicalPartitionCreationRequest {
        config: Some(forgerpc::NvLinkLogicalPartitionConfig {
            metadata: Some(metadata),
            tenant_organization_id: args.tenant_organization_id,
        }),
        id: None,
    };
    let _partition = api_client
        .0
        .create_nv_link_logical_partition(request)
        .await?;
    Ok(())
}
