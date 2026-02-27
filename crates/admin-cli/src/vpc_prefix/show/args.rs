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
use ipnet::IpNet;

use crate::vpc_prefix::common::VpcPrefixSelector;

#[derive(Parser, Debug)]
pub struct Args {
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
