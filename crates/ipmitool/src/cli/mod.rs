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

//! CLI argument parsing and command dispatch for `carbide-ipmitool`.
//!
//! This module defines the clap-derive CLI structure and dispatches parsed
//! commands to the corresponding handlers in submodules.

pub mod channel;
pub mod chassis;
pub mod fru;
pub mod mc;
pub mod raw;
pub mod sdr;
pub mod sel;
pub mod sensor;
pub mod sol;
pub mod user;

use clap::Parser;

/// IPMI command-line tool supporting v1.5 LAN and v2.0 RMCP+.
#[derive(Parser)]
#[command(name = "carbide-ipmitool", about = "IPMI v1.5/v2.0 tool (lan/lanplus)")]
pub struct Cli {
    /// BMC hostname or IP address.
    #[arg(short = 'H', long)]
    pub host: String,

    /// IPMI username.
    #[arg(short = 'U', long)]
    pub username: String,

    /// IPMI password. If not given, reads from `IPMITOOL_PASSWORD` env var.
    #[arg(short = 'P', long, env = "IPMITOOL_PASSWORD")]
    pub password: Option<String>,

    /// Read password from `IPMITOOL_PASSWORD` environment variable only.
    #[arg(short = 'E')]
    pub env_password: bool,

    /// Interface type: "lanplus" (IPMI v2.0 RMCP+) or "lan" (IPMI v1.5).
    #[arg(short = 'I', long, default_value = "lanplus")]
    pub interface: String,

    /// Cipher suite ID.
    #[arg(short = 'C', long = "cipher-suite", default_value = "17")]
    pub cipher_suite: u8,

    /// Per-request timeout in seconds.
    #[arg(short = 't', long, default_value = "15")]
    pub timeout: u64,

    /// Number of retries.
    #[arg(short = 'R', long, default_value = "3")]
    pub retries: u32,

    /// Increase verbosity (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: CliCommand,
}

/// Top-level subcommands, mirroring the ipmitool CLI groupings.
#[derive(clap::Subcommand)]
pub enum CliCommand {
    /// Chassis status and power control.
    Chassis {
        #[command(subcommand)]
        command: chassis::ChassisCommand,
    },
    /// Send a raw IPMI command.
    Raw(raw::RawCommand),
    /// Management controller commands.
    Mc {
        #[command(subcommand)]
        command: mc::McCommand,
    },
    /// Sensor Data Repository operations.
    Sdr {
        #[command(subcommand)]
        command: sdr::SdrCommand,
    },
    /// System Event Log operations.
    Sel {
        #[command(subcommand)]
        command: sel::SelCommand,
    },
    /// FRU inventory operations.
    Fru {
        #[command(subcommand)]
        command: fru::FruCommand,
    },
    /// Sensor reading and threshold operations.
    Sensor {
        #[command(subcommand)]
        command: sensor::SensorCommand,
    },
    /// User management.
    User {
        #[command(subcommand)]
        command: user::UserCommand,
    },
    /// Serial-over-LAN session.
    Sol {
        #[command(subcommand)]
        command: sol::SolCommand,
    },
    /// Channel configuration and auth capabilities.
    Channel {
        #[command(subcommand)]
        command: channel::ChannelCommand,
    },
}
