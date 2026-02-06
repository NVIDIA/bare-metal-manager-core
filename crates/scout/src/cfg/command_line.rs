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
use clap::{Parser, Subcommand, ValueEnum};
use forge_tls::default as tls_default;
use mlxconfig_device::cmd::device::args::DeviceAction;
use mlxconfig_lockdown::cmd::args::LockdownAction;

#[derive(ValueEnum, Clone, Debug, Copy, PartialEq)]
pub(crate) enum Mode {
    Service,
    Standalone,
}

impl std::fmt::Display for Mode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mode::Service => write!(f, "Service"),
            Mode::Standalone => write!(f, "Standalone"),
        }
    }
}
#[derive(Clone, Parser)]
#[clap(name = env!("CARGO_BIN_NAME"))]
pub(crate) struct Options {
    #[clap(long, default_value = "false", help = "Print version number and exit")]
    pub version: bool,

    #[clap(long,
        value_enum,
        default_value_t=Mode::Service)]
    pub mode: Mode,

    #[clap(
        short,
        long,
        help = "The machine interface ID to send to carbide-api. Most commands need this."
    )]
    pub machine_interface_id: Option<uuid::Uuid>,

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
        default_value_t = 10080u32*52*10 // times per one week x 52 weeks x 10 years
    )]
    pub discovery_retries_max: u32,

    #[clap(
        long,
        help = "Full path of tpm char device",
        // tpmrm0 is a tpm with an in-kernel resource manager (hence the "rm" suffix)
        // tpm0 would be a tpm without a resource manager - https://github.com/tpm2-software/tpm2-tools/issues/1338#issuecomment-469735226
        default_value_t = ("device:/dev/tpmrm0").to_string(),
    )]
    pub tpm_path: String,

    #[clap(subcommand)]
    pub subcmd: Option<Command>,
}

#[derive(Parser, Clone)]
pub(crate) enum Command {
    #[clap(about = "Fetch command from Forge API server")]
    AutoDetect(AutoDetect),
    #[clap(about = "Run deprovision")]
    Deprovision(Deprovision),
    #[clap(about = "Send error report to Carbide API ")]
    Logerror(Logerror),
    #[clap(about = "Run Discovery")]
    Discovery(Discovery),
    #[clap(about = "Run reset")]
    Reset(Reset),
    #[clap(about = "Machine Validation")]
    MachineValidation(MachineValidation),
    #[clap(about = "Local Mellanox device management.")]
    Mlx(Mlx),
}

#[derive(Parser, Clone)]
pub struct AutoDetect {}

#[derive(Parser, Clone)]
pub struct Deprovision {}
#[derive(Parser, Clone)]
pub struct Reset {}
#[derive(Parser, Clone)]
pub struct Discovery {}
#[derive(Parser, Clone)]
pub struct Rebuild {}

#[derive(Parser, Clone)]
pub struct Logerror {
    // This is a machine_INTERFACE_id, not a machine_id
    #[clap(short, long, require_equals(true))]
    pub uuid: uuid::Uuid,
}
#[derive(Parser, Clone)]
pub struct MachineValidation {
    #[clap(short, long, require_equals(true))]
    pub validataion_id: uuid::Uuid,
    pub context: String,
}

#[derive(Parser, Clone)]
pub struct Mlx {
    #[command(subcommand)]
    pub action: MlxAction,
}

#[derive(Subcommand, Clone)]
pub enum MlxAction {
    #[clap(about = "Query local Mellanox device information.")]
    Device(MlxDevice),
    #[clap(about = "Mellanox lockdown operations.")]
    Lockdown(MlxLockdown),
}

#[derive(Parser, Clone)]
pub struct MlxDevice {
    #[command(subcommand)]
    pub action: DeviceAction,
}

#[derive(Parser, Clone)]
pub struct MlxLockdown {
    #[command(subcommand)]
    pub action: LockdownAction,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
