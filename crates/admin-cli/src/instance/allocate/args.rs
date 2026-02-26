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

use carbide_uuid::machine::MachineId;
use carbide_uuid::vpc::VpcPrefixId;
use clap::{ArgGroup, Parser};
use rpc::forge::OperatingSystem;

#[derive(Parser, Debug)]
#[clap(group(ArgGroup::new("selector").required(true).args(&["subnet", "vpc_prefix_id"])))]
pub struct Args {
    #[clap(short, long)]
    pub number: Option<u16>,

    #[clap(short, long, help = "The subnet to assign to a PF")]
    pub subnet: Vec<String>,

    #[clap(short, long, help = "The VPC prefix to assign to a PF")]
    pub vpc_prefix_id: Vec<VpcPrefixId>,

    #[clap(short, long)]
    // This will not be needed after vpc_prefix implementation.
    // Code can query to carbide and fetch it from db using vpc_prefix_id.
    pub tenant_org: Option<String>,

    #[clap(short, long, required = true)]
    pub prefix_name: String,

    #[clap(long, help = "The key of label instance to query")]
    pub label_key: Option<String>,

    #[clap(long, help = "The value of label instance to query")]
    pub label_value: Option<String>,

    #[clap(
        long,
        help = "The ID of a network security group to apply to the new instance upon creation"
    )]
    pub network_security_group_id: Option<String>,

    #[clap(
        long,
        help = "The expected instance type id for the instance, which will be compared to type ID set for the machine of the request"
    )]
    pub instance_type_id: Option<String>,

    #[clap(long, help = "OS definition in JSON format", value_name = "OS_JSON")]
    pub os: Option<OperatingSystem>,

    #[clap(long, help = "The subnet to assign to a VF")]
    pub vf_subnet: Vec<String>,

    #[clap(long, help = "The VPC prefix to assign to a VF")]
    pub vf_vpc_prefix_id: Vec<VpcPrefixId>,

    #[clap(
        long,
        help = "The machine ids for the machines to use (instead of searching)"
    )]
    pub machine_id: Vec<MachineId>,

    #[clap(
        long,
        help = "Use batch API for all-or-nothing allocation (requires --number > 1)"
    )]
    pub transactional: bool,
}
