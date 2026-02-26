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

use clap::Parser;

#[derive(Parser, Debug, Clone)]
pub struct Args {
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
