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

use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use clap::Parser;
use rpc::forge as forgerpc;

#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

Make a host interface the primary (boot) interface:
    $ carbide-admin-cli managed-host set-primary-interface 12345678-1234-5678-90ab-cdef01234567 \
    abcdef01-2345-6789-abcd-ef0123456789

Promote an interface and reboot the host afterward:
    $ carbide-admin-cli managed-host set-primary-interface 12345678-1234-5678-90ab-cdef01234567 \
    abcdef01-2345-6789-abcd-ef0123456789 --reboot

Tip: list a host's interface ids with 'managed-host show <HOST_MACHINE_ID>'.
")]
pub struct Args {
    #[clap(help = "ID of the host machine")]
    pub host_machine_id: MachineId,
    #[clap(help = "ID of the machine interface to make primary (the boot device)")]
    pub interface_id: MachineInterfaceId,
    #[clap(long, help = "Reboot the host after the update")]
    pub reboot: bool,
}

impl From<Args> for forgerpc::SetPrimaryInterfaceRequest {
    fn from(args: Args) -> Self {
        Self {
            host_machine_id: Some(args.host_machine_id),
            interface_id: Some(args.interface_id),
            reboot: args.reboot,
        }
    }
}
