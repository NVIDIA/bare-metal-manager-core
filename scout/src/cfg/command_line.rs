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
use forge_tls::default as tls_default;

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
        default_value_t = tls_default::ROOT_CA.to_string(),
    )]
    pub root_ca: String,

    #[clap(
    long,
    help = "Full path of client cert in PEM format",
    default_value_t = tls_default::CLIENT_CERT.to_string(),
    )]
    pub client_cert: String,

    #[clap(
    long,
    help = "Full path of client key",
    default_value_t = tls_default::CLIENT_KEY.to_string(),
    )]
    pub client_key: String,

    // Combined with discovery_retries_max, the default of 60
    // seconds worth of discovery_retry_secs provides for 1
    // week worth of minutely retries.
    #[clap(
        long,
        help = "How often (sec) to retry machine registration after failure",
        default_value_t = 60u64
    )]
    pub discovery_retry_secs: u64,

    #[clap(
        long,
        help = "How many times to reattempt discovery admist failure",
        default_value_t = 10080u32
    )]
    pub discovery_retries_max: u32,

    #[clap(subcommand)]
    pub subcmd: Option<Command>,

    #[clap(
        long,
        help = "Full path of tpm char device",
        // tpmrm0 is a tpm with an in-kernel resource manager (hence the "rm" suffix)
        // tpm0 would be a tpm without a resource manager - https://github.com/tpm2-software/tpm2-tools/issues/1338#issuecomment-469735226
        default_value_t = ("device:/dev/tpmrm0").to_string(),
    )]
    pub tpm_path: String,
}

#[derive(Parser)]
pub(crate) enum Command {
    #[clap(about = "Fetch command from Forge API server")]
    AutoDetect(AutoDetect),
    #[clap(about = "Run deprovision")]
    Deprovision(Deprovision),
    #[clap(about = "Send error report to Carbide API ")]
    Logerror(Logerror),
}

impl Command {
    pub fn machine_interface_id(&self) -> uuid::Uuid {
        match self {
            Command::AutoDetect(command) => command.uuid,
            Command::Deprovision(command) => command.uuid,
            Command::Logerror(command) => command.uuid,
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

#[derive(Parser)]
pub struct Logerror {
    // This is a machine_INTERFACE_id, not a machine_id
    #[clap(short, long, require_equals(true))]
    pub uuid: uuid::Uuid,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
