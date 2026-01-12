/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use carbide_uuid::instance::InstanceId;
use carbide_uuid::vpc::VpcId;
use clap::Parser;

#[derive(Parser, Debug, Clone)]
#[clap(rename_all = "kebab_case")]
pub enum Cmd {
    #[clap(about = "Create a network security group", visible_alias = "c")]
    Create(CreateNetworkSecurityGroup),

    #[clap(
        about = "Show one or more network security groups",
        visible_alias = "s"
    )]
    Show(ShowNetworkSecurityGroup),

    #[clap(about = "Delete a network security group", visible_alias = "d")]
    Delete(DeleteNetworkSecurityGroup),

    #[clap(about = "Update a network security group", visible_alias = "u")]
    Update(UpdateNetworkSecurityGroup),

    #[clap(
        about = "Show info about the objects referencing a network security group",
        visible_alias = "a"
    )]
    ShowAttachments(ShowNetworkSecurityGroupAttachments),

    #[clap(
        about = "Attach a network security group to a VPC or instance",
        visible_alias = "x"
    )]
    Attach(AttachNetworkSecurityGroup),

    #[clap(
        about = "Remove a network security group from a VPC or instance",
        visible_alias = "r"
    )]
    Detach(DetachNetworkSecurityGroup),
}

#[derive(Parser, Debug, Clone)]
pub struct CreateNetworkSecurityGroup {
    #[clap(
        short = 'i',
        long,
        help = "Optional, unique ID to use when creating the network security group"
    )]
    pub id: Option<String>,

    #[clap(
        short = 't',
        long,
        help = "Tenant organization ID of the network security group"
    )]
    pub tenant_organization_id: String,

    #[clap(short = 'n', long, help = "Name of the network security group")]
    pub name: Option<String>,

    #[clap(short = 'd', long, help = "Description of the network security group")]
    pub description: Option<String>,

    #[clap(
        short = 'l',
        long,
        help = "JSON map of simple key:value pairs to be applied as labels to the network security group"
    )]
    pub labels: Option<String>,

    #[clap(
        short = 's',
        long,
        help = "Optional, whether egress rules are stateful"
    )]
    pub stateful_egress: bool,

    #[clap(
        short = 'r',
        long,
        help = "Optional, JSON array containing a defined set of network security group rules"
    )]
    pub rules: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct ShowNetworkSecurityGroup {
    #[clap(help = "Optional, network security group ID to restrict the search")]
    pub id: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct ShowNetworkSecurityGroupAttachments {
    #[clap(short = 'i', long, help = "network security group ID to query")]
    pub id: String,

    #[clap(
        short = 'a',
        long,
        help = "include indirect relationships (objects that are inheriting the NSG from a parent object)"
    )]
    pub include_indirect: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct UpdateNetworkSecurityGroup {
    #[clap(short = 'i', long, help = "Network security group ID to update")]
    pub id: String,

    #[clap(
        short = 't',
        long,
        help = "Tenant organization ID of the network security group"
    )]
    pub tenant_organization_id: String,

    #[clap(short = 'n', long, help = "Name of the network security group")]
    pub name: Option<String>,

    #[clap(short = 'd', long, help = "Description of the network security group")]
    pub description: Option<String>,

    #[clap(
        short = 'l',
        long,
        help = "JSON map of simple key:value pairs to be applied as labels to the network security group - will COMPLETELY overwrite any existing labels"
    )]
    pub labels: Option<String>,

    #[clap(
        short = 's',
        long,
        help = "Optional, whether egress rules are stateful"
    )]
    pub stateful_egress: Option<bool>,

    #[clap(
        short = 'r',
        long,
        help = "Optional, JSON array containing a defined set of network security group rules - will COMPLETELY overwrite any existing rules"
    )]
    pub rules: Option<String>,

    #[clap(
        short = 'v',
        long,
        help = "Optional, version to use for comparison when performing the update, which will be rejected if the actual version of the record does not match the value of this parameter"
    )]
    pub version: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct DeleteNetworkSecurityGroup {
    #[clap(short = 'i', long, help = "Network security group ID to delete")]
    pub id: String,

    #[clap(
        short = 't',
        long,
        help = "Tenant organization ID of the network security group"
    )]
    pub tenant_organization_id: String,
}

#[derive(Parser, Debug, Clone)]
pub struct AttachNetworkSecurityGroup {
    #[clap(short = 'n', long, help = "Network security group ID to attach")]
    pub id: String,

    #[clap(
        short = 'v',
        long,
        help = "Optional, VPC ID that should have the network security group applied"
    )]
    pub vpc_id: Option<VpcId>,

    #[clap(
        short = 'i',
        long,
        help = "Optional, Instance ID that should have the network security group applied"
    )]
    pub instance_id: Option<InstanceId>,
}

#[derive(Parser, Debug, Clone)]
pub struct DetachNetworkSecurityGroup {
    #[clap(
        short = 'v',
        long,
        help = "Optional, VPC ID that should have the network security group removed"
    )]
    pub vpc_id: Option<VpcId>,

    #[clap(
        short = 'i',
        long,
        help = "Optional, Instance ID that should have the network security group removed"
    )]
    pub instance_id: Option<InstanceId>,
}
