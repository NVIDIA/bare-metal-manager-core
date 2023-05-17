/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use clap::Parser;

#[derive(Parser)]
#[clap(name = env!("CARGO_BIN_NAME"))]
pub(crate) struct Options {
    #[clap(long, default_value = "false", help = "Print version number and exit")]
    pub version: bool,

    #[clap(
        short,
        long,
        alias("listen"),
        require_equals(true),
        default_value = "https://[::1]:1079"
    )]
    pub api: String,

    #[clap(
        long,
        help = "Full path of root CA in PEM format",
        default_value_t = rpc::forge_tls_client::DEFAULT_ROOT_CA.to_string(),
    )]
    pub root_ca: String,

    #[clap(subcommand)]
    pub subcmd: Option<Command>,
}

#[derive(Parser)]
pub(crate) enum Command {
    #[clap(about = "Fetch command from Forge API server")]
    AutoDetect(AutoDetect),
    #[clap(about = "Run deprovision")]
    Deprovision(Deprovision),
}

impl Command {
    pub fn machine_interface_id(&self) -> uuid::Uuid {
        match self {
            Command::AutoDetect(command) => command.uuid,
            Command::Deprovision(command) => command.uuid,
        }
    }
}

#[derive(Parser)]
pub struct AutoDetect {
    // This is a machine_INTERFACE_id, not a machine_id
    #[clap(short, long, require_equals(true))]
    pub uuid: uuid::Uuid,
}

#[derive(Parser)]
pub struct Deprovision {
    // This is a machine_INTERFACE_id, not a machine_id
    #[clap(short, long, require_equals(true))]
    pub uuid: uuid::Uuid,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
