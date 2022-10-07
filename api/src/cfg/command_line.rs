/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

// TODO(ajf): always look at crate root
const DEFAULT_CONFIG_PATH: &str = ".config.toml";

#[derive(Parser)]
#[clap(name = env ! ("CARGO_BIN_NAME"))]
pub(crate) struct Options {
    #[clap(short, long, parse(from_occurrences))]
    pub debug: u8,

    #[clap(long, default_value = DEFAULT_CONFIG_PATH)]
    pub config: String,

    #[clap(subcommand)]
    pub sub_cmd: Command,
}

#[derive(Parser)]
pub(crate) enum Command {
    #[clap(about = "Performs database migrations")]
    Migrate(Migrate),

    #[clap(about = "Run the API service")]
    Run(Daemon),
}

#[derive(Parser)]
pub struct Daemon {
    #[clap(
        short,
        long,
        multiple_values(true),
        require_equals(true),
        default_value = "[::]:1079"
    )]
    pub listen: Vec<std::net::SocketAddr>,

    #[clap(long, require_equals(true), env = "DATABASE_URL")]
    pub datastore: String,

    /// Enable kubernetes integrations
    #[clap(short, long)]
    pub kubernetes: bool,
}

#[derive(Parser)]
pub struct Migrate {
    #[clap(long, require_equals(true), env = "DATABASE_URL")]
    pub datastore: String,
}

impl Options {
    #[tracing::instrument]
    pub fn load() -> Self {
        Self::parse()
    }
}
