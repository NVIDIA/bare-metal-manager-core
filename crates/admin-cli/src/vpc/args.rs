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
use clap::Parser;
use forge_network::virtualization::VpcVirtualizationType;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(about = "Display VPC information")]
    Show(ShowVpc),
    SetVirtualizer(SetVpcVirt),
}

#[derive(Parser, Debug)]
pub struct ShowVpc {
    #[clap(
        default_value(None),
        help = "The VPC ID to query, leave empty for all (default)"
    )]
    pub id: Option<VpcId>,

    #[clap(short, long, help = "The Tenant Org ID to query")]
    pub tenant_org_id: Option<String>,

    #[clap(short, long, help = "The VPC name to query")]
    pub name: Option<String>,

    #[clap(long, help = "The key of VPC label to query")]
    pub label_key: Option<String>,

    #[clap(long, help = "The value of VPC label to query")]
    pub label_value: Option<String>,
}

#[derive(Parser, Debug)]
pub struct SetVpcVirt {
    #[clap(help = "The VPC ID for the VPC to update")]
    pub id: VpcId,
    #[clap(help = "The virtualizer to use for this VPC")]
    pub virtualizer: VpcVirtualizationType,
}
