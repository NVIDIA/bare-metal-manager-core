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

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge::{self as forgerpc};

use super::args::Args;
use crate::network_security_group::common::convert_nsgs_to_table;
use crate::rpc::ApiClient;

/// Create a network security group.
/// On successful creation, the details of the
/// new group will be displayed.
pub async fn create(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;

    let id = args.id;

    let labels = if let Some(l) = args.labels {
        serde_json::from_str(&l)?
    } else {
        vec![]
    };

    let metadata = forgerpc::Metadata {
        name: args.name.unwrap_or_default(),
        description: args.description.unwrap_or_default(),
        labels,
    };

    let rules = if let Some(r) = args.rules {
        serde_json::from_str(&r)?
    } else {
        vec![]
    };

    let nsg = api_client
        .create_network_security_group(
            id,
            args.tenant_organization_id,
            metadata,
            args.stateful_egress,
            rules,
        )
        .await?;

    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&nsg).map_err(CarbideCliError::JsonError)?
        );
    } else {
        convert_nsgs_to_table(&[nsg], true)?.printstd();
    }

    Ok(())
}
