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
use ::rpc::forge as rpc_forge;

use super::args::Args;
use crate::metadata::parse_rpc_labels;
use crate::rpc::ApiClient;

/// update updates an existing expected rack's rack_type and metadata.
pub async fn update(data: Args, api_client: &ApiClient) -> CarbideCliResult<()> {
    let metadata = rpc_forge::Metadata {
        name: data.meta_name.unwrap_or_default(),
        description: data.meta_description.unwrap_or_default(),
        labels: parse_rpc_labels(data.labels.unwrap_or_default()),
    };

    let expected_rack = api_client
        .0
        .get_expected_rack(data.rack_id.to_string())
        .await?;

    let request = rpc_forge::ExpectedRack {
        rack_id: Some(data.rack_id),
        rack_type: data.rack_type.unwrap_or(expected_rack.rack_type),
        metadata: Some(metadata),
    };

    api_client
        .0
        .update_expected_rack(request)
        .await
        .map_err(CarbideCliError::ApiInvocationError)?;
    Ok(())
}
