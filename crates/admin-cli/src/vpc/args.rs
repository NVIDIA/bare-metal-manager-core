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
