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

// registry/args.rs
// Command-line argument definitions for registry commands.

use carbide_uuid::machine::MachineId;
use clap::Parser;
use rpc::protos::mlx_device as mlx_device_pb;

// RegistryCommand are the registry subcommands.
#[derive(Parser, Debug)]
pub enum RegistryCommand {
    #[clap(about = "List all available registries")]
    List(RegistryListCommand),

    #[clap(about = "Show details of a specific registry")]
    Show(RegistryShowCommand),
}

// RegistryListCommand lists all available registries.
#[derive(Parser, Debug)]
pub struct RegistryListCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,
}

// RegistryShowCommand shows details of a specific registry.
#[derive(Parser, Debug)]
pub struct RegistryShowCommand {
    #[arg(help = "Carbide Machine ID")]
    pub machine_id: MachineId,

    #[arg(help = "Registry name to show")]
    pub registry_name: String,
}

impl From<RegistryListCommand> for mlx_device_pb::MlxAdminRegistryListRequest {
    fn from(cmd: RegistryListCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
        }
    }
}

impl From<RegistryShowCommand> for mlx_device_pb::MlxAdminRegistryShowRequest {
    fn from(cmd: RegistryShowCommand) -> Self {
        Self {
            machine_id: cmd.machine_id.into(),
            registry_name: cmd.registry_name,
        }
    }
}
