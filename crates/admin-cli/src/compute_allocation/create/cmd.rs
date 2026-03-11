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
use ::rpc::forge::{
    CreateComputeAllocationRequest, {self as forgerpc},
};

use super::args::Args;
use crate::compute_allocation::common::convert_compute_allocations_to_table;
use crate::rpc::ApiClient;

/// Create a compute allocation.
/// On successful creation, the details of the
/// new allocation will be displayed.
pub async fn create(
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let labels = if let Some(labels_json) = args.labels {
        serde_json::from_str(&labels_json)?
    } else {
        vec![]
    };

    let metadata = forgerpc::Metadata {
        name: args.name.unwrap_or_default(),
        description: args.description.unwrap_or_default(),
        labels,
    };

    let allocation = api_client
        .0
        .create_compute_allocation(CreateComputeAllocationRequest {
            id: args.id,
            tenant_organization_id: args.tenant_organization_id,
            metadata: Some(metadata),
            attributes: Some(forgerpc::ComputeAllocationAttributes {
                instance_type_id: args.instance_type_id,
                count: args.count,
            }),
            created_by: None,
        })
        .await?;
    let allocation = allocation.allocation.ok_or(CarbideCliError::Empty)?;

    match output_format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&allocation).map_err(CarbideCliError::JsonError)?
        ),
        OutputFormat::Yaml => println!(
            "{}",
            serde_yaml::to_string(&allocation).map_err(CarbideCliError::YamlError)?
        ),
        OutputFormat::Csv => {
            convert_compute_allocations_to_table(vec![allocation], true)?
                .to_csv(std::io::stdout())
                .map_err(CarbideCliError::CsvError)?
                .flush()?;
        }
        _ => convert_compute_allocations_to_table(vec![allocation], true)?.printstd(),
    }

    Ok(())
}
