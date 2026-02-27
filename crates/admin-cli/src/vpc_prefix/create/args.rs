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

use carbide_uuid::vpc::{VpcId, VpcPrefixId};
use clap::Parser;
use ipnet::IpNet;

#[derive(Parser, Debug)]
pub struct Args {
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
