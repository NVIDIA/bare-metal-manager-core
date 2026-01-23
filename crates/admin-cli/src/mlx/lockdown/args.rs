/*
 * SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
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
