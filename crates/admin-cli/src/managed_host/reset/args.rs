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
use clap::Parser;
use rpc::forge::dpu_reprovisioning_request::Mode;
use rpc::forge::{DpuReprovisioningRequest, UpdateInitiator};

/// Reset a managed host by reprovisioning its DPU(s) and re-running ingestion,
/// recoverable from most non-ready states (DPF-ingested hosts only).
#[derive(Parser, Debug)]
#[command(after_long_help = "\
EXAMPLES:

Reset a host wedged mid-ingestion (reprovision all its DPUs, then re-ingest):
    $ nico-admin-cli managed-host reset --machine 12345678-1234-5678-90ab-cdef01234567 \
    --update-message \"recovering wedged DPU\"

Reset a host assigned to a live instance (disrupts the tenant):
    $ nico-admin-cli managed-host reset --machine 12345678-1234-5678-90ab-cdef01234567 \
    --allow-reset-with-instance --update-message \"forced recovery\"

")]
pub(crate) struct Args {
    #[clap(long, required(true), help = "Host machine ID to reset")]
    pub(super) machine: MachineId,

    #[clap(
        long,
        action,
        help = "Reset a host assigned to a live instance. Acknowledges disrupting the user instance."
    )]
    pub(super) allow_reset_with_instance: bool,

    #[clap(
        long,
        help = "If set, a HostUpdateInProgress health alert with this message is applied to the host (a precondition for reprovisioning)."
    )]
    pub(super) update_message: Option<String>,
}

impl From<&Args> for DpuReprovisioningRequest {
    fn from(args: &Args) -> Self {
        Self {
            dpu_id: None,
            machine_id: Some(args.machine),
            mode: Mode::Set as i32,
            initiator: UpdateInitiator::AdminCli as i32,
            update_firmware: false,
            allow_reset_with_instance: args.allow_reset_with_instance,
        }
    }
}
