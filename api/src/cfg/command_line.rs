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

    /// A connection string for the utilized IBFabricManager
    #[clap(long, require_equals(true), env = "IBFABRIC_MANAGER_URL")]
    pub ib_fabric_manager: Option<String>,

    /// The token for IBFabricManager authentication.
    #[clap(long, require_equals(true), env = "IBFABRIC_MANAGER_TOKEN")]
    pub ib_fabric_manager_token: Option<String>,

    /// Set shorter timeouts and run background jobs more often. Appropriate
    /// for local development.
    /// See ServiceConfig type.
    #[clap(long)]
    pub rapid_iterations: bool,

    /// DO NOT USE
    /// Will be removed in next release. Kept for easier upgrade, we need to co-ordinate
    /// other repos (forged and forge-deployment).
    #[clap(
        long,
        default_value = "true",
        help = "Do not use. Will be removed soon"
    )]
    pub manage_vpc: bool,

    /// ASN: Autonomous System Number
    /// Fixed per environment. Used by forge-dpu-agent to write frr.conf (routing).
    ///
    // Move this to per-site toml configuration file once that exists.
    //
    #[clap(long)]
    pub asn: u32,

    /// List of DHCP servers that should be announced
    /// TODO: The env variable approach at the moment will just accept a single
    /// server name. We need custom logic to either split a comma separated
    /// env variable, or have a different env variable which supports multiple servers.
    #[clap(long, num_args(0..), env = "CARBIDE_DHCP_SERVER")]
    pub dhcp_server: Vec<String>,

    /// Comma-separated list of route server IP addresses. Optional, only for L2VPN (Eth Virt).
    #[clap(long, use_value_delimiter = true)]
    pub route_servers: Vec<String>,

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
