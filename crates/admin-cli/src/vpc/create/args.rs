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

use carbide_uuid::vpc::VpcId;
use clap::Parser;
use rpc::{Metadata, forge};

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

Create a tenant VPC:
    $ nico-admin-cli --cloud-unsafe-op=my_username vpc create --name tenant-vpc-1 --org-id tenant-org-1

Create a tenant VPC with flat virtualization and a chosen ID:
    $ nico-admin-cli --cloud-unsafe-op=my_username vpc create --name tenant-vpc-1 --org-id tenant-org-1 --id ad1f9fd5-8438-4407-b259-72fdb7896d42 --virtualization-type flat

")]
pub struct Args {
    #[clap(long, help = "Name to give the new VPC")]
    pub name: String,

    #[clap(long, help = "Discription for the new VPC")]
    pub description: Option<String>,

    #[clap(
        long,
        value_name = "VpcId",
        help = "Optional VPC ID to use instead of allowing the API server to generate one"
    )]
    pub id: Option<VpcId>,

    #[clap(
        long,
        help = "Tenant organization ID (Plain text string, used by cloud API)"
    )]
    pub org_id: String,

    #[clap(
        long,
        value_enum,
        default_value = "ethernet-virtualizer",
        help = "Network virtualization type"
    )]
    pub virtualization_type: forge::VpcVirtualizationType,
}

impl From<Args> for forge::VpcCreationRequest {
    fn from(args: Args) -> Self {
        Self {
            tenant_organization_id: args.org_id,
            tenant_keyset_id: None,
            network_virtualization_type: Some(args.virtualization_type as _),
            id: None,
            metadata: Some(Metadata {
                name: args.name,
                description: args.description.unwrap_or_default(),
                ..Default::default()
            }),
            network_security_group_id: None,
            default_nvlink_logical_partition_id: None,
            vni: None,
            routing_profile_type: None,
        }
    }
}
