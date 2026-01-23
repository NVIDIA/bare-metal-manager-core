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

use clap::{Parser, Subcommand, ValueEnum};

// Cli is a parent Cli struct to give this a complete command
// spec for doing tests. The actual command will be put into
// the mlxconfig-embedded reference CLI example.
#[derive(Parser)]
#[command(name = "mlxconfig-lockdown")]
#[command(about = "Manage Mellanox NIC hardware access locks")]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

// Commands are the available CLI commands.
#[derive(Subcommand)]
pub enum Commands {
    // lockdown manages device lockdown status.
    Lockdown {
        #[command(subcommand)]
        action: LockdownAction,
    },
}

// LockdownAction are the lockdown subcommands.
#[derive(Clone, Subcommand)]
pub enum LockdownAction {
    // lock locks hardware access on the device.
    #[command(about = "Lock hardware access from a given device (PCI address or mst path).")]
    Lock {
        // device_id is the device identifier (PCI address or device path).
        device_id: String,
        // key is the hardware access key (8 hex digits).
        key: String,
        // format is the output format for status.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        // dry_run shows what would be executed without actually running it.
        #[arg(long)]
        dry_run: bool,
    },
    // unlock unlocks hardware access on the device.
    #[command(about = "Unlock hardware access to the given device.")]
    Unlock {
        // device_id is the device identifier (PCI address or device path).
        device_id: String,
        // key is the hardware access key (8 hex digits).
        key: String,
        // format is the output format for status.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        // dry_run shows what would be executed without actually running it.
        #[arg(long)]
        dry_run: bool,
    },
    // status checks current lock and key status of the device.
    #[command(about = "Get the current lock/unlock status of the given device.")]
    Status {
        // device_id is the device identifier (PCI address or device path).
        device_id: String,
        // format is the output format for status.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        // dry_run shows what would be executed without actually running it.
        #[arg(long)]
        dry_run: bool,
    },
    // set-key sets or updates the hardware access key.
    #[command(
        name = "set-key",
        about = "Set a hardware access key on the given device, effectively locking it."
    )]
    SetKey {
        // device_id is the device identifier (PCI address or device path).
        device_id: String,
        // key is the hardware access key (8 hex digits).
        key: String,
        // format is the output format for status.
        #[arg(short, long, value_enum, default_value_t = OutputFormat::Text)]
        format: OutputFormat,
        // dry_run shows what would be executed without actually running it.
        #[arg(long)]
        dry_run: bool,
    },
}

// OutputFormat are the supported output formats.
#[derive(ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    Text,
    Json,
    Yaml,
}
