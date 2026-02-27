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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult};
use ::rpc::forge as forgerpc;
use carbide_uuid::nvlink::NvLinkLogicalPartitionId;

use super::args::Args;
use crate::rpc::ApiClient;

pub async fn handle_delete(args: Args, api_client: &ApiClient) -> CarbideCliResult<()> {
    delete_logical_partition(args, api_client).await?;
    Ok(())
}

pub async fn delete_logical_partition(args: Args, api_client: &ApiClient) -> CarbideCliResult<()> {
    let uuid: NvLinkLogicalPartitionId = uuid::Uuid::parse_str(&args.name)
        .map_err(|_| CarbideCliError::GenericError("UUID Conversion failed.".to_string()))?
        .into();
    let request = forgerpc::NvLinkLogicalPartitionDeletionRequest { id: Some(uuid) };
    let _partition = api_client
        .0
        .delete_nv_link_logical_partition(request)
        .await?;
    Ok(())
}
