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

// profile/args.rs
// Command-line argument definitions for profile commands.

use carbide_uuid::machine::MachineId;
use clap::Parser;
use rpc::protos::mlx_device as mlx_device_pb;

// ProfileCommand are the profile subcommands.
#[derive(Parser, Debug)]
pub enum ProfileCommand {
    #[clap(about = "Synchronize a profile to a device on a given machine")]
    Sync(ProfileSyncCommand),

    #[clap(about = "Compare a profile to a device on a given machine")]
    Compare(ProfileCompareCommand),

    #[clap(about = "Show profile details")]
    Show(ProfileShowCommand),

    #[clap(about = "List all available profiles")]
    List(ProfileListCommand),
}

// ProfileSyncCommand synchronizes a profile to a device.
#[derive(Parser, Debug)]
pub struct ProfileSyncCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,

    #[arg(help = "Device ID is the PCI or mst path on the target machine")]
    pub device_id: String,

    #[arg(long, help = "Profile name to sync")]
    pub profile_name: String,
}

// ProfileCompareCommand compares a profile against a device.
#[derive(Parser, Debug)]
pub struct ProfileCompareCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,

    #[arg(help = "Device ID is the PCI or mst path on the target machine")]
    pub device_id: String,

    #[arg(long, help = "Profile name to compare")]
    pub profile_name: String,
}

// ProfileShowCommand shows details of a specific profile.
#[derive(Parser, Debug)]
pub struct ProfileShowCommand {
    #[arg(help = "Profile name to show")]
    pub profile_name: String,
}

// ProfileListCommand lists all available profiles.
#[derive(Parser, Debug)]
pub struct ProfileListCommand {}

impl From<ProfileSyncCommand> for mlx_device_pb::MlxAdminProfileSyncRequest {
    fn from(cmd: ProfileSyncCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
            device_id: cmd.device_id,
            profile_name: cmd.profile_name,
        }
    }
}

impl From<ProfileCompareCommand> for mlx_device_pb::MlxAdminProfileCompareRequest {
    fn from(cmd: ProfileCompareCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
            device_id: cmd.device_id,
            profile_name: cmd.profile_name,
        }
    }
}

impl From<ProfileShowCommand> for mlx_device_pb::MlxAdminProfileShowRequest {
    fn from(cmd: ProfileShowCommand) -> Self {
        Self {
            profile_name: cmd.profile_name,
        }
    }
}
