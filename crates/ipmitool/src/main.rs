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

use clap::Parser;
use color_eyre::eyre::{self, Context};
use ipmitool::cli::{Cli, CliCommand};
use ipmitool::transport::lanplus::LanplusTransport;
use ipmitool::transport::IpmiTransport;
use ipmitool::ConnectionConfig;

#[tokio::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();

    // Set up tracing based on verbosity level.
    // -v = info, -vv = debug, -vvv = trace
    let level = match cli.verbose {
        0 => tracing::Level::WARN,
        1 => tracing::Level::INFO,
        2 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .init();

    let password = resolve_password(&cli).context("resolve IPMI password")?;

    let config = ConnectionConfig {
        host: cli.host.clone(),
        username: cli.username.clone(),
        password,
        cipher_suite: cli.cipher_suite,
        timeout_secs: cli.timeout,
        retries: cli.retries,
        ..Default::default()
    };

    let mut transport = LanplusTransport::connect(config)
        .await
        .context("connect to BMC")?;

    let result = match cli.command {
        CliCommand::Chassis { command } => {
            ipmitool::cli::chassis::run(&mut transport, command).await
        }
        CliCommand::Raw(raw_cmd) => {
            ipmitool::cli::raw::run(&mut transport, raw_cmd).await
        }
        CliCommand::Mc { command } => {
            ipmitool::cli::mc::run(&mut transport, command).await
        }
    };

    // Always attempt to close the session, even if the command failed.
    transport.close().await.ok();

    result
}

/// Resolve the IPMI password from CLI args or environment.
fn resolve_password(cli: &Cli) -> eyre::Result<String> {
    if let Some(ref pw) = cli.password {
        Ok(pw.clone())
    } else if cli.env_password {
        std::env::var("IPMITOOL_PASSWORD")
            .context("IPMITOOL_PASSWORD not set")
    } else {
        // clap's `env = "IPMITOOL_PASSWORD"` on the password field will have
        // already populated it if the env var is set, so reaching here means
        // neither -P nor the env var was provided.
        eyre::bail!("password required: use -P or -E")
    }
}
