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

// TODO(ajf): always look at crate root
const DEFAULT_CONFIG_PATH: &str = ".config.toml";

#[derive(Parser)]
#[clap(name = "carbide-api")]
pub struct Options {
    #[clap(short, long, action = ArgAction::Count)]
    pub debug: u8,

    #[clap(long, default_value = DEFAULT_CONFIG_PATH)]
    pub config: String,

    #[clap(subcommand)]
    pub sub_cmd: Command,
}

#[derive(Parser)]
pub enum Command {
    #[clap(about = "Performs database migrations")]
    Migrate(Migrate),

    #[clap(about = "Run the API service")]
    Run(Daemon),
}

#[derive(Parser)]
pub struct Daemon {
    /// The socket address that is used for the gRPC API server
    #[clap(
        short,
        long,
        num_args(0..),
        require_equals(true),
        default_value = "[::]:1079"
    )]
    pub listen: Vec<std::net::SocketAddr>,

    /// The socket address that is used for the HTTP server which serves
    /// prometheus metrics under /metrics
    #[clap(long, env = "CARBIDE_METRICS_ENDPOINT")]
    pub metrics_endpoint: Option<std::net::SocketAddr>,

    /// A connection string for the utilized postgres database
    #[clap(long, require_equals(true), env = "DATABASE_URL")]
    pub datastore: String,

    /// Enable kubernetes integrations
    #[clap(short, long)]
    pub kubernetes: bool,

    /// List of DHCP servers that should be announced
    /// TODO: The env variable approach at the moment will just accept a single
    /// server name. We need custom logic to either split a comma separated
    /// env variable, or have a different env variable which supports multiple servers.
    #[clap(long, num_args(0..), env = "CARBIDE_DHCP_SERVER")]
    pub dhcp_server: Vec<String>,

    #[clap(
        long,
        env = "IDENTITY_PEMFILE_PATH",
        default_value = "/opt/forge/server_identity.pem"
    )]
    pub identity_pemfile_path: String,

    #[clap(
        long,
        env = "IDENTITY_KEYFILE_PATH",
        default_value = "/opt/forge/server_identity.key"
    )]
    pub identity_keyfile_path: String,

    // TODO: cfg this out for release builds?
    /// Enable permissive mode in the authorization enforcer (for development).
    #[clap(long, default_value("true"), env = "AUTH_PERMISSIVE_MODE")]
    pub auth_permissive_mode: bool,

    /// The Casbin policy file (in CSV format).
    #[clap(long, require_equals(true), env = "CASBIN_POLICY_FILE")]
    pub casbin_policy_file: std::path::PathBuf,
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
