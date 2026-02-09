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
