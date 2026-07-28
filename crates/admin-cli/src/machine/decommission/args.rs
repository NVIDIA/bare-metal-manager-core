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
use rpc::forge::{AdminDecommissionMachineRequest, AdminDecommissionSiteRequest};

/// Decommission a single machine (must be in Ready state).
#[derive(Parser, Debug, Clone)]
#[command(after_long_help = "\
EXAMPLES:

Decommission a single machine (by UUID, IPv4, MAC, or hostname):
    $ nico-admin-cli machine decommission machine --machine 12345678-1234-5678-90ab-cdef01234567

")]
pub struct MachineArgs {
    #[clap(
        long,
        help = "UUID, IPv4, MAC, or hostname of the host or its attached DPU"
    )]
    pub machine: String,
}

impl From<&MachineArgs> for AdminDecommissionMachineRequest {
    fn from(args: &MachineArgs) -> Self {
        Self {
            host_query: args.machine.clone(),
        }
    }
}

/// Decommission all machines at the site.
#[derive(Parser, Debug, Clone)]
#[command(after_long_help = "\
EXAMPLES:

Decommission the entire site (disables ingestion and begins decommissioning all Ready machines):
    $ nico-admin-cli machine decommission site

")]
pub struct SiteArgs {}

impl From<&SiteArgs> for AdminDecommissionSiteRequest {
    fn from(_: &SiteArgs) -> Self {
        Self {}
    }
}
