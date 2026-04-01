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

use ::rpc::admin_cli::CarbideCliError;
use ::rpc::forge::{self as forgerpc, CreateComputeAllocationRequest};
use carbide_uuid::compute_allocation::ComputeAllocationId;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[clap(
        short = 'i',
        long,
        help = "Optional, unique ID to use when creating the compute allocation"
    )]
    pub id: Option<ComputeAllocationId>,

    #[clap(
        short = 't',
        long,
        help = "Tenant organization ID for the compute allocation"
    )]
    pub tenant_organization_id: String,

    #[clap(long, help = "Instance type ID from which compute is being allocated")]
    pub instance_type_id: String,

    #[clap(short = 'c', long, help = "Count to allocate for the instance type")]
    pub count: u32,

    #[clap(short = 'n', long, help = "Name of the compute allocation")]
    pub name: Option<String>,

    #[clap(short = 'd', long, help = "Description of the compute allocation")]
    pub description: Option<String>,

    #[clap(
        short = 'l',
        long,
        help = "JSON map of simple key:value pairs to be applied as labels to the compute allocation"
    )]
    pub labels: Option<String>,
}

impl TryFrom<Args> for CreateComputeAllocationRequest {
    type Error = CarbideCliError;

    fn try_from(args: Args) -> Result<Self, Self::Error> {
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

        Ok(CreateComputeAllocationRequest {
            id: args.id,
            tenant_organization_id: args.tenant_organization_id,
            metadata: Some(metadata),
            attributes: Some(forgerpc::ComputeAllocationAttributes {
                instance_type_id: args.instance_type_id,
                count: args.count,
            }),
            created_by: None,
        })
    }
}
