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
use ipmitool::transport::lan::LanTransport;
use ipmitool::transport::lanplus::LanplusTransport;
use ipmitool::transport::http::{HttpTransport, HttpTransportConfig};
use ipmitool::transport::{IpmiTransport, Transport};
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
        port: cli.port,
        username: cli.username.clone(),
        password,
        cipher_suite: cli.cipher_suite,
        timeout_secs: cli.timeout,
        retries: cli.retries,
    };

    let mut transport = match cli.interface.as_str() {
        "lanplus" => {
            let t = LanplusTransport::connect(config)
                .await
                .context("connect to BMC via RMCP+")?;
            Transport::Lanplus(t)
        }
        "lan" => {
            let t = LanTransport::connect(config)
                .await
                .context("connect to BMC via IPMI v1.5 LAN")?;
            Transport::Lan(t)
        }
        "http" => {
            let http_config = HttpTransportConfig {
                bmc_host: format!("{}:{}", config.host, config.port),
                proxy_url: String::new(),
            };
            let t = HttpTransport::connect(http_config)
                .context("connect to BMC via HTTPS")?;
            Transport::Http(t)
        }
        other => eyre::bail!("unsupported interface: {other} (supported: lan, lanplus, http)"),
    };

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
        CliCommand::Sdr { command } => {
            ipmitool::cli::sdr::run(&mut transport, command).await
        }
        CliCommand::Sel { command } => {
            ipmitool::cli::sel::run(&mut transport, command).await
        }
        CliCommand::Fru { command } => {
            ipmitool::cli::fru::run(&mut transport, command).await
        }
        CliCommand::Sensor { command } => {
            ipmitool::cli::sensor::run(&mut transport, command).await
        }
        CliCommand::Sol { command } => match command {
            ipmitool::cli::sol::SolCommand::Activate { instance } => {
                // SOL interactive sessions require RMCP+ (lanplus) for the
                // encrypted, bidirectional payload channel.
                match &mut transport {
                    Transport::Lanplus(t) => {
                        let esc = cli.escape_char as u8;
                        t.run_sol_interactive(instance, esc)
                            .await
                            .context("SOL interactive session")
                    }
                    Transport::Lan(_) | Transport::Http(_) => {
                        eyre::bail!("SOL requires RMCP+ (-I lanplus)")
                    }
                }
            }
            other => ipmitool::cli::sol::run(&mut transport, other).await,
        },
        CliCommand::User { command } => {
            ipmitool::cli::user::run(&mut transport, command).await
        }
        CliCommand::Channel { command } => {
            ipmitool::cli::channel::run(&mut transport, command).await
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
