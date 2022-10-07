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
const DEFAULT_DATASTORE: &str = "postgres://carbide_development@localhost";

#[derive(Parser)]
#[clap(name = env ! ("CARGO_BIN_NAME"))]
pub(crate) struct Options {
    #[clap(short, long, parse(from_occurrences))]
    pub debug: u8,

    #[clap(long, default_value = DEFAULT_CONFIG_PATH)]
    pub config: String,

    #[clap(subcommand)]
    pub subcmd: Command,
}

#[derive(Parser)]
pub(crate) enum Command {
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
        default_value = "0.0.0.0:2222"
    )]
    pub listen: Vec<std::net::SocketAddr>,

    #[clap(
        short,
        long,
        require_equals(true),
        default_value = "http://172.20.0.14:1079"
    )]
    pub api_endpoint: String,

    #[clap(long, require_equals(true), default_value = DEFAULT_DATASTORE)]
    pub datastore: String,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
