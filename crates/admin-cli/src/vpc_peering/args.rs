/*
 * SPDX-FileCopyrightText: Copyright (c) 2022-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
