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
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser)]
#[clap(name = "forge-dpu-otel-agent")]
pub struct Options {
    /// The path to the agent configuration file overrides.
    /// This file will hold data in the `AgentConfig` format.
    #[clap(long)]
    pub config_path: Option<PathBuf>,

    #[clap(subcommand)]
    pub cmd: Option<AgentCommand>,
}

#[derive(Parser, Debug)]
pub enum AgentCommand {
    #[clap(about = "Run is the normal command. Runs main loop forever.")]
    Run(Box<RunOptions>),
}

#[derive(Parser, Debug)]
pub struct RunOptions {
    #[clap(long, help = "Copy initial TLS cert file from this path")]
    pub source_tls_cert_path: Option<PathBuf>,

    #[clap(long, help = "Copy initial TLS key file from this path")]
    pub source_tls_key_path: Option<PathBuf>,
}

impl Options {
    pub fn load() -> Self {
        Self::parse()
    }
}
