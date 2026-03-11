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

use carbide_uuid::compute_allocation::ComputeAllocationId;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct Args {
    #[clap(short = 'i', long, help = "Compute allocation ID to update")]
    pub id: ComputeAllocationId,

    #[clap(
        short = 't',
        long,
        help = "Tenant organization ID for the compute allocation"
    )]
    pub tenant_organization_id: String,

    #[clap(short = 'n', long, help = "Name of the compute allocation")]
    pub name: Option<String>,

    #[clap(short = 'd', long, help = "Description of the compute allocation")]
    pub description: Option<String>,

    #[clap(
        short = 'l',
        long,
        help = "JSON map of simple key:value pairs to be applied as labels to the compute allocation - will COMPLETELY overwrite any existing labels"
    )]
    pub labels: Option<String>,

    #[clap(long, help = "Optional, updated instance type ID for the allocation")]
    pub instance_type_id: Option<String>,

    #[clap(short = 'c', long, help = "Optional, updated count for the allocation")]
    pub count: Option<u32>,

    #[clap(
        short = 'v',
        long,
        help = "Optional, version to use for comparison when performing the update, which will be rejected if the actual version of the record does not match the value of this parameter"
    )]
    pub version: Option<String>,
}
