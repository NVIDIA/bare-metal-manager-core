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

use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use clap::Parser;
use ipnet::IpNet;

pub use super::cmds::VpcPrefixSelector;

#[derive(Parser, Debug)]
pub enum Cmd {
    #[clap(hide = true)]
    Create(VpcPrefixCreate),
    Show(VpcPrefixShow),
    #[clap(hide = true)]
    Delete(VpcPrefixDelete),
}

#[derive(Parser, Debug)]
pub struct VpcPrefixCreate {
    #[clap(
        long,
        name = "vpc-id",
        value_name = "VpcId",
        help = "The ID of the VPC to contain this prefix"
    )]
    pub vpc_id: VpcId,

    #[clap(
        long,
        name = "prefix",
        value_name = "CIDR-prefix",
        help = "The IP prefix in CIDR notation"
    )]
    pub prefix: IpNet,

    #[clap(
        long,
        name = "name",
        value_name = "prefix-name",
        help = "A short descriptive name for the prefix"
    )]
    pub name: String,

    #[clap(
        long,
        name = "description",
        value_name = "description",
        help = "Optionally, a longer description for the prefix"
    )]
    pub description: Option<String>,

    #[clap(
        long = "label",
        value_name = "LABEL",
        help = "A labels that will be added as metadata for the newly created VPC prefix. The labels key and value must be separated by a : character. E.g. environment:production",
        action = clap::ArgAction::Append
    )]
    pub labels: Option<Vec<String>>,

    #[clap(
        long,
        name = "vpc-prefix-id",
        value_name = "VpcPrefixId",
        help = "Specify the VpcPrefixId for the API to use instead of it auto-generating one"
    )]
    pub vpc_prefix_id: Option<VpcPrefixId>,
}

#[derive(Parser, Debug)]
pub struct VpcPrefixShow {
    #[clap(
        name = "VpcPrefixSelector",
        help = "The VPC prefix (by ID or exact unique prefix) to show (omit for all)"
    )]
    pub prefix_selector: Option<VpcPrefixSelector>,

    #[clap(
        long,
        name = "vpc-id",
        value_name = "VpcId",
        help = "Search by VPC ID",
        conflicts_with = "VpcPrefixSelector"
    )]
    pub vpc_id: Option<VpcId>,

    #[clap(
        long,
        name = "contains",
        value_name = "address-or-prefix",
        help = "Search by an address or prefix the VPC prefix contains",
        conflicts_with_all = ["VpcPrefixSelector", "contained-by"],
    )]
    pub contains: Option<IpNet>,

    #[clap(
        long,
        name = "contained-by",
        value_name = "prefix",
        help = "Search by a prefix containing the VPC prefix",
        conflicts_with_all = ["VpcPrefixSelector", "contains"],
    )]
    pub contained_by: Option<IpNet>,
}

#[derive(Parser, Debug)]
pub struct VpcPrefixDelete {
    #[clap(value_name = "VpcPrefixId")]
    pub vpc_prefix_id: VpcPrefixId,
}
