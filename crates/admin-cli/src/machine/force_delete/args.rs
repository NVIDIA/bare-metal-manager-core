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
use rpc::forge::AdminForceDeleteMachineRequest;

#[derive(Parser, Debug, Clone)]
#[command(after_long_help = "\
EXAMPLES:

Force delete a machine (by UUID, IPv4, MAC, or hostname):
    $ nico-admin-cli machine force-delete --machine 12345678-1234-5678-90ab-cdef01234567

Force delete a machine and its interfaces (redeploy kea afterward):
    $ nico-admin-cli machine force-delete --machine 12345678-1234-5678-90ab-cdef01234567 \
    --delete-interfaces

")]
pub struct Args {
    #[clap(
        long,
        help = "UUID, IPv4, MAC or hostnmame of the host or DPU machine to delete"
    )]
    pub machine: String,

    #[clap(short = 'd', long, action, help = "Delete interfaces.")]
    pub delete_interfaces: bool,

    #[clap(short = 'b', long, action, help = "Delete BMC interfaces.")]
    pub delete_bmc_interfaces: bool,

    #[clap(
        short = 'c',
        long,
        action,
        help = "Delete BMC credentials. Only applicable if site explorer has configured credentials for the BMCs associated with this managed host."
    )]
    pub delete_bmc_credentials: bool,

    #[clap(
        long,
        action,
        help = "Delete machine with allocated instance. This flag acknowledges destroying the user instance as well."
    )]
    pub allow_delete_with_instance: bool,

    #[clap(
        long,
        action,
        help = "Delete machine even if DPF CRDs exist and DPF is disabled at the site level. This flag acknowledges that orphaned DPF resources may remain"
    )]
    pub allow_delete_with_orphaned_dpf_crds: bool,
}

impl From<&Args> for AdminForceDeleteMachineRequest {
    fn from(args: &Args) -> Self {
        Self {
            host_query: args.machine.clone(),
            delete_interfaces: args.delete_interfaces,
            delete_bmc_interfaces: args.delete_bmc_interfaces,
            delete_bmc_credentials: args.delete_bmc_credentials,
            allow_delete_with_orphaned_dpf_crds: args.allow_delete_with_orphaned_dpf_crds,
        }
    }
}
