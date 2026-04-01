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

use ::rpc::forge::FindComputeAllocationIdsRequest;
use carbide_uuid::compute_allocation::ComputeAllocationId;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[clap(
        short = 'i',
        long,
        help = "Optional, compute allocation ID to restrict the search"
    )]
    pub id: Option<ComputeAllocationId>,

    #[clap(
        short = 't',
        long,
        help = "Optional, tenant organization ID used to filter results"
    )]
    pub tenant_organization_id: Option<String>,

    #[clap(short = 'n', long, help = "Optional, name used to filter results")]
    pub name: Option<String>,

    #[clap(long, help = "Optional, instance type ID used to filter results")]
    pub instance_type_id: Option<String>,
}

impl From<Args> for FindComputeAllocationIdsRequest {
    fn from(args: Args) -> Self {
        FindComputeAllocationIdsRequest {
            name: args.name,
            tenant_organization_id: args.tenant_organization_id,
            instance_type_id: args.instance_type_id,
        }
    }
}
