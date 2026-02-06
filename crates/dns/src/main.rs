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
use std::path::PathBuf;

use carbide_dns::config::{Config, ConfigError};
use carbide_dns::start;
use clap::Parser;
use eyre::WrapErr;
use opentelemetry::trace::TracerProvider;
use opentelemetry_otlp::WithExportConfig;
use tonic::codegen::http;
use tracing::metadata::LevelFilter;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> Result<(), eyre::Report> {
    let options = Options::parse();

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tower=warn".parse()?)
        .add_directive("rustls=warn".parse()?)
        .add_directive("hyper=warn".parse()?)
        .add_directive("h2=warn".parse()?)
        .add_directive("tonic=warn".parse()?)
        .add_directive("opentelemetry_sdk=info".parse()?)
        .add_directive("opentelemetry_otlp=info".parse()?)
        .add_directive("hickory_proto=info".parse()?)
        .add_directive("hickory_resolver=info".parse()?)
        .add_directive("carbide_dns=info".parse()?)
        .add_directive("carbide_dns::pdns=debug".parse()?)
        .add_directive("rpc=info".parse()?);

    match options.command {
        Command::Run(run_command) => {
            let config: Config = run_command.try_into()?;

            // Configure OpenTelemetry if endpoint is set
            tracing::info!(
                "OpenTelemetry tracing enabled, exporting to endpoint: {}",
                &config.otlp_endpoint.to_string()
            );

            let otlp_exporter = opentelemetry_otlp::SpanExporter::builder()
                .with_tonic()
                .with_endpoint(config.otlp_endpoint.to_string())
                .build()?;

            let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
                .with_batch_exporter(otlp_exporter)
                .with_resource(
                    opentelemetry_sdk::Resource::builder()
                        .with_attributes([opentelemetry::KeyValue::new(
                            "service.name",
                            "carbide-dns",
                        )])
                        .build(),
                )
                .build();

            let otel_layer =
                tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("carbide-dns"));

            tracing_subscriber::registry()
                .with(fmt::layer().json())
                .with(env_filter)
                .with(otel_layer)
                .try_init()?;

            // Check if legacy mode is configured
            // TODO: Remove this after migration to PowerDNS backend
            if let Some(listen_addr) = config.legacy_listen {
                tracing::warn!(
                    "Running in LEGACY DNS server mode on {}. This mode is deprecated and will be removed in future releases. Please migrate to PowerDNS backend.",
                    listen_addr
                );
                carbide_dns::legacy::LegacyDnsServer::run(config, listen_addr)
                    .await
                    .wrap_err("Failed to start legacy DNS service")?;
            } else {
                // Default: PowerDNS backend mode
                tracing::info!("Running in PowerDNS backend mode (Unix domain socket)");
                start(config)
                    .await
                    .wrap_err("Failed to start DNS service")?;
            }
        }
    }

    Ok(())
}

#[derive(Parser)]
pub struct Options {
    #[clap(subcommand)]
    pub command: Command,
}

#[derive(Parser)]
pub enum Command {
    #[clap(about = "Start DNS Service")]
    Run(RunCommand),
}

#[derive(Parser)]
pub struct RunCommand {
    #[clap(long, short = 'f', help = "Path to TOML configuration file")]
    config_file: Option<PathBuf>,
    #[clap(short = 's', long, help = "Path to the UNIX socket for the DNS server")]
    pub socket_path: Option<PathBuf>,

    #[clap(short = 'p', long, help = "UNIX Permissions for the socket")]
    pub socket_permissions: Option<u32>,

    #[clap(short = 'u', long, help = "URI of the Forge API Server")]
    pub carbide_uri: Option<http::Uri>,

    #[clap(short = 'r', long, help = "Path to the Forge Root CA certificate")]
    pub forge_root_ca_path: Option<PathBuf>,

    #[clap(
        short = 'c',
        long,
        help = "Path to the client certificate for Forge API"
    )]
    pub client_cert_path: Option<PathBuf>,

    #[clap(short = 'k', long, help = "Path to the client key for Forge API")]
    pub client_key_path: Option<PathBuf>,

    // Legacy mode support for migration
    #[clap(
        long,
        help = "LEGACY MODE: Address for DNS server to listen on (e.g., [::]:1053). When set, runs as a direct DNS server instead of PowerDNS backend. This mode is deprecated and will be removed in future releases."
    )]
    pub listen: Option<std::net::SocketAddr>,

    // Backward compatibility alias
    #[clap(
        long,
        help = "DEPRECATED: Use --carbide-uri instead. Will be removed in future releases."
    )]
    pub carbide_url: Option<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum CommandError {
    #[error("Invalid socket path: {path}: {error}")]
    InvalidSocketPath { path: String, error: std::io::Error },
    #[error("Configuration error: {0}")]
    Config(#[from] ConfigError),
}

impl TryInto<Config> for RunCommand {
    type Error = CommandError;

    fn try_into(self) -> Result<Config, Self::Error> {
        let mut config = if let Some(config_path) = self.config_file {
            Config::load(&config_path)?
        } else {
            Config::default()
        };

        if let Some(socket_path) = self.socket_path {
            if !socket_path.is_absolute() {
                return Err(CommandError::InvalidSocketPath {
                    path: socket_path.to_string_lossy().to_string(),
                    error: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "Socket path must be an absolute path",
                    ),
                });
            }
            config.socket_path = socket_path;
        }

        if let Some(socket_permissions) = self.socket_permissions {
            config.socket_permissions = socket_permissions;
        }

        if let Some(carbide_uri) = self.carbide_uri {
            config.carbide_uri = carbide_uri;
        }

        // Backward compatibility for carbide_url
        if let Some(carbide_url) = self.carbide_url {
            tracing::warn!("--carbide-url is deprecated, use --carbide-uri instead");
            config.carbide_uri = carbide_url.try_into().expect("Invalid carbide URL");
        }

        if let Some(forge_root_ca_path) = self.forge_root_ca_path {
            config.forge_root_ca = forge_root_ca_path;
        }
        if let Some(client_cert_path) = self.client_cert_path {
            config.client_cert_path = client_cert_path;
        }
        if let Some(client_key_path) = self.client_key_path {
            config.client_key_path = client_key_path;
        }

        // Set legacy listen mode if specified
        if let Some(listen) = self.listen {
            tracing::warn!(
                "Legacy DNS server mode enabled via --listen flag. This will be removed in future releases."
            );
            config.legacy_listen = Some(listen);
        }

        Ok(config)
    }
}
