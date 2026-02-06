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

// lockdown/args.rs
// Command-line argument definitions for lockdown commands.

use carbide_uuid::machine::MachineId;
use clap::Parser;
use rpc::protos::mlx_device as mlx_device_pb;

// LockdownCommand are the lockdown subcommands.
#[derive(Parser, Debug)]
pub enum LockdownCommand {
    #[clap(about = "Lock hardware access on a device")]
    Lock(LockdownLockCommand),

    #[clap(about = "Unlock hardware access on a device")]
    Unlock(LockdownUnlockCommand),

    #[clap(about = "Get the current lock/unlock status of a device")]
    Status(LockdownStatusCommand),
}

// LockdownLockCommand locks hardware access on a device.
#[derive(Parser, Debug)]
pub struct LockdownLockCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,

    #[arg(help = "Device ID is the PCI or mst path on the target machine")]
    pub device_id: String,
}

// LockdownUnlockCommand unlocks hardware access on a device.
#[derive(Parser, Debug)]
pub struct LockdownUnlockCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,

    #[arg(help = "Device ID is the PCI or mst path on the target machine")]
    pub device_id: String,
}

// LockdownStatusCommand gets the current lockdown status of a device.
#[derive(Parser, Debug)]
pub struct LockdownStatusCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,

    #[arg(help = "Device ID is the PCI or mst path on the target machine")]
    pub device_id: String,
}

impl From<LockdownLockCommand> for mlx_device_pb::MlxAdminLockdownLockRequest {
    fn from(cmd: LockdownLockCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
            device_id: cmd.device_id,
        }
    }
}

impl From<LockdownUnlockCommand> for mlx_device_pb::MlxAdminLockdownUnlockRequest {
    fn from(cmd: LockdownUnlockCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
            device_id: cmd.device_id,
        }
    }
}

impl From<LockdownStatusCommand> for mlx_device_pb::MlxAdminLockdownStatusRequest {
    fn from(cmd: LockdownStatusCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
            device_id: cmd.device_id,
        }
    }
}
