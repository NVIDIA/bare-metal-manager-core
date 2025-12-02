/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use clap::{Parser, Subcommand};

use crate::cmd::device::args::DeviceArgs;
pub mod device;

// Cli represents the main CLI structure for the application.
#[derive(Parser)]
#[command(
    author,
    version,
    about = "mlxconfig-device - mellanox device discovery"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

// Commands defines the available top-level commands.
#[derive(Subcommand)]
pub enum Commands {
    // Device management commands for discovering and
    // inspecting Mellanox devices.
    Device(DeviceArgs),
}

// dispatch_command routes CLI commands to their
// appropriate handlers.
pub fn dispatch_command(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        Commands::Device(args) => crate::cmd::device::cmds::handle(args),
    }
}
