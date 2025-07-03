/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
use eyre::Context;
use ssh_console::config;
use ssh_console::config::Config;
use std::path::PathBuf;
use tracing::metadata::LevelFilter;

#[tokio::main(flavor = "multi_thread")]
pub async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    let cli = Cli::parse();
    setup_logging(&cli);

    match cli.command {
        Command::Run(run_command) => {
            ssh_console::spawn(run_command.try_into()?)
                .await?
                .wait_forever()
                .await?;
        }
        Command::DefaultRunConfig => {
            print!("{}", ssh_console::config::default_config_file())
        }
    }

    Ok(())
}

#[derive(clap::Parser, Debug)]
struct Cli {
    #[clap(long, short, help = "Turn on debug loggging (same as RUST_LOG=debug)")]
    debug: bool,
    #[clap(subcommand)]
    command: Command,
}

#[derive(clap::Parser, Debug)]
enum Command {
    Run(RunCommand),
    #[clap(about = "Output a default TOML config file for use with run -c")]
    DefaultRunConfig,
}

#[derive(clap::Parser, Debug)]
struct RunCommand {
    #[clap(long, short, help = "Path to TOML configuration file")]
    config: Option<PathBuf>,
    #[clap(
        long,
        short,
        help = "Address to listen on, overriding configuration file"
    )]
    address: Option<String>,
    #[clap(long, short = 'u', help = "Address of carbide-api (forge)")]
    forge_url: Option<http::Uri>,
    #[clap(
        long,
        env = "FORGE_ROOT_CA_PATH",
        help = format!("Default to FORGE_ROOT_CA_PATH environment variable or {}", config::Defaults::root_ca_path().display())
    )]
    forge_root_ca_path: Option<PathBuf>,
    #[clap(
        long,
        env = "CLIENT_CERT_PATH",
        help = format!("Client cert to use to talk to forge. Default to CLIENT_CERT_PATH environment variable or {}", config::Defaults::client_cert_path().display())
    )]
    client_cert_path: Option<PathBuf>,
    #[clap(
        long,
        env = "CLIENT_KEY_PATH",
        help = format!("Client cert to use to talk to forge. Default to CLIENT_CERT_PATH environment variable or {}", config::Defaults::client_key_path().display())
    )]
    client_key_path: Option<PathBuf>,
    #[clap(long, short = 'k', help = "Path to SSH host key")]
    host_key: Option<PathBuf>,
    #[clap(long, help = "Path to SSH authorized_keys file (non forge-rpc mode)")]
    authorized_keys: Option<PathBuf>,
    #[clap(long, short = 'g', action, help = "Include DPU consoles")]
    dpus: bool,
    #[clap(
        long,
        short = 'i',
        action,
        help = "Disable client auth enforcement. All incoming SSH connections will succeed."
    )]
    insecure: bool,
    #[clap(long, help = "Override port for SSH to BMCs")]
    bmc_ssh_port: Option<u16>,
    #[clap(long, help = "Override port for IPMI to BMCs")]
    ipmi_port: Option<u16>,
    #[clap(
        long,
        action,
        help = "Use insecure ciphers when connecting to IPMI (useful for ipmi_sim)"
    )]
    insecure_ipmi_ciphers: bool,
}

impl TryInto<Config> for RunCommand {
    type Error = eyre::Error;

    // Load the config file, or the default, allowing CLI flags to override the corresponding settings.
    fn try_into(self) -> Result<Config, Self::Error> {
        let mut config = if let Some(config_path) = self.config {
            Config::load(&config_path)?
        } else {
            Config::default()
        };

        if let Some(address) = self.address {
            config.listen_address = address
                .parse()
                .with_context(|| format!("Invalid listening address {address}"))?;
        }
        if let Some(carbide_url) = self.forge_url {
            config.carbide_uri = carbide_url
        }
        if let Some(host_key) = self.host_key {
            config.host_key_path = host_key;
        }
        if self.dpus {
            config.dpus = true;
        }
        if self.insecure {
            config.insecure = true;
        }
        if self.insecure_ipmi_ciphers {
            config.insecure_ipmi_ciphers = true;
        }
        if let Some(ipmi_port) = self.ipmi_port {
            config.ipmi_port = ipmi_port;
        }
        if let Some(bmc_ssh_port) = self.bmc_ssh_port {
            config.bmc_ssh_port = bmc_ssh_port;
        }
        if let Some(authorized_keys) = self.authorized_keys {
            config.authorized_keys_path = Some(authorized_keys);
        }
        if let Some(forge_root_ca_path) = self.forge_root_ca_path {
            config.forge_root_ca_path = forge_root_ca_path;
        }
        if let Some(client_cert_path) = self.client_cert_path {
            config.client_cert_path = client_cert_path;
        }
        if let Some(client_key_path) = self.client_key_path {
            config.client_key_path = client_key_path;
        }

        Ok(config)
    }
}

fn setup_logging(cli: &Cli) {
    use tracing_subscriber::{filter::EnvFilter, prelude::*, util::SubscriberInitExt};

    let level = if cli.debug {
        Some(LevelFilter::DEBUG)
    } else {
        None
    };

    if let Err(e) = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::Layer::default().compact())
        .with(
            EnvFilter::builder()
                .with_default_directive(level.map(Into::into).unwrap_or(LevelFilter::INFO.into()))
                .from_env_lossy(),
        )
        .try_init()
    {
        panic!(
            "Failed to initialize trace logging for ssh-console. It's possible some earlier \
            code path has already set a global default log subscriber: {e}"
        );
    }
}
