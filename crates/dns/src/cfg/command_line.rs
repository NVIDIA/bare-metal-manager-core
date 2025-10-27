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
pub(crate) struct Options {
    #[clap(long, default_value = "false", help = "Print version number and exit")]
    pub version: bool,

    #[clap(subcommand)]
    pub sub_cmd: Option<Command>,
}

#[derive(Parser)]
pub(crate) enum Command {
    #[clap(about = "Start DNS Service")]
    Run(Daemon),
}

#[derive(Parser)]
pub struct Daemon {
    #[clap(short, long, require_equals(true), default_value = "[::]:1053")]
    pub listen: std::net::SocketAddr,

    #[clap(short, long, default_value = "http://[::1]:1079")]
    pub carbide_url: String,

    #[clap(short, long, default_value = "/var/run/secrets/spiffe.io/ca.crt")]
    pub forge_root_ca_path: String,

    #[clap(long, default_value = "/var/run/secrets/spiffe.io/tls.crt")]
    pub server_identity_cert_path: String,

    #[clap(long, default_value = "/var/run/secrets/spiffe.io/tls.key")]
    pub server_identity_key_path: String,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
