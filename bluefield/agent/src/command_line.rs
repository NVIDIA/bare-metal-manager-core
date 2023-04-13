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
use std::{net::Ipv4Addr, path::PathBuf};

use clap::Parser;

#[derive(Parser)]
#[clap(name = env!("CARGO_BIN_NAME"))]
pub(crate) struct Options {
    /// The path to the forge agent configuration file
    /// This file will hold data in the `AgentConfig` format
    #[clap(long, default_value = "/etc/forge/config.toml")]
    pub config_path: PathBuf,

    #[clap(subcommand)]
    pub cmd: Option<AgentCommand>,
}

#[derive(Parser, Debug)]
pub enum AgentCommand {
    #[clap(about = "Run is the normal and default command")]
    Run,

    #[clap(about = "Detect hardware and exit")]
    Hardware,

    #[clap(about = "One-off health check")]
    Health,

    #[clap(about = "Write a templated config file", subcommand)]
    Write(WriteTarget),
}

#[derive(Parser, Debug)]
pub enum WriteTarget {
    #[clap(about = "Write frr.conf")]
    Frr(FrrOptions),
}

#[derive(Parser, Debug)]
pub struct FrrOptions {
    #[clap(long, help = "Full path of frr.conf")]
    pub path: String,
    #[clap(long)]
    pub asn: i64,
    #[clap(long)]
    pub loopback_ip: Ipv4Addr,
    #[clap(long)]
    pub import_default_route: bool,
    #[clap(long, help = "Format is 'id,host_route', e.g. --vlan 1,xyz. Repeats.")]
    pub vlan: Vec<String>,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
