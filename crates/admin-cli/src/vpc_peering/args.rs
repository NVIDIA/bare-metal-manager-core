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
use carbide_uuid::vpc_peering::VpcPeeringId;
use clap::Parser;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Create VPC peering.")]
    Create(CreateVpcPeering),
    #[clap(about = "Show list of VPC peerings.")]
    Show(ShowVpcPeering),
    #[clap(about = "Delete VPC peering.")]
    Delete(DeleteVpcPeering),
}

#[derive(Parser, Debug)]
pub struct CreateVpcPeering {
    #[clap(help = "The ID of one VPC ID to peer")]
    pub vpc1_id: VpcId,

    #[clap(help = "The ID of other VPC ID to peer")]
    pub vpc2_id: VpcId,

    #[clap(long, help = "Optional desired ID for the VPC peering")]
    pub id: Option<VpcPeeringId>,
}

#[derive(Parser, Debug)]
pub struct ShowVpcPeering {
    #[clap(
        long,
        conflicts_with = "vpc_id",
        help = "The ID of the VPC peering to show"
    )]
    pub id: Option<VpcPeeringId>,

    #[clap(
        long,
        conflicts_with = "id",
        help = "The ID of the VPC to show VPC peerings for"
    )]
    pub vpc_id: Option<VpcId>,
}

#[derive(Parser, Debug)]
pub struct DeleteVpcPeering {
    #[clap(long, required(true), help = "The ID of the VPC peering to delete")]
    pub id: VpcPeeringId,
}
