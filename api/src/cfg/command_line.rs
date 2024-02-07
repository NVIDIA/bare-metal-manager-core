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
use clap::{ArgAction, Parser};

#[derive(Parser)]
#[clap(name = "carbide-api")]
pub struct Options {
    #[clap(long, default_value = "false", help = "Print version number and exit")]
    pub version: bool,

    #[clap(short, long, action = ArgAction::Count)]
    pub debug: u8,

    #[clap(subcommand)]
    pub sub_cmd: Option<Command>,
}

#[derive(Parser)]
pub enum Command {
    #[clap(about = "Performs database migrations")]
    Migrate(Migrate),

    #[clap(about = "Run the API service")]
    Run(Box<Daemon>),
}

#[derive(Parser)]
pub struct Daemon {
    /// Path to the configuration file
    /// The contents of this configuration file can be patched by providing
    /// site specific configuration overrides via an additional config file at
    /// `site-config-path`.
    /// Additionally all configuration file contents can be overridden using
    /// environmental variables that are prefixed with `CARBIDE_API_`.
    /// E.g. an environmental variable with the name `CARBIDE_API_DATABASE_URL`
    /// will take precedence over the field `database_url` in the site specific
    /// configuration. And the field `database_url` in the site specific configuration
    /// will take precedence over the same field in the global configuration.
    #[clap(long)]
    pub config_path: String,
    /// Path to the configuration file which contains per-site overwrites
    #[clap(long)]
    pub site_config_path: Option<String>,
}

#[derive(Parser)]
pub struct Migrate {
    #[clap(long, require_equals(true), env = "DATABASE_URL")]
    pub datastore: String,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
