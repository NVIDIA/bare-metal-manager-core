/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::env;
use std::sync::Arc;
use std::time::Duration;

use carbide::{
    cfg::{Command, Options},
    logging::otel_stdout_exporter::OtelStdoutExporter,
};
use color_eyre::eyre::Context;
use forge_credentials::ForgeVaultClient;
use opentelemetry::{
    sdk::{self},
    trace::TracerProvider,
};
use opentelemetry_semantic_conventions as semcov;
use sqlx::PgPool;
use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

#[tokio::main]
async fn main() -> Result<(), color_eyre::Report> {
    color_eyre::install()?;

    let config = Options::load();

    // Set up an OpenTelemetry tracer with an exporter to StdOut
    // Note: This doesn't yet make any logs get pushed to the OpenTelemetry library
    // The binding happens later once we initialize tracing_opentelemetry and configure
    // it to forward log events from the `tracing` framework.
    // The application internally only uses `tracing` events.
    let trace_config = sdk::trace::config().with_resource(sdk::Resource::new(vec![
        semcov::resource::SERVICE_NAME.string("carbide-api"),
        semcov::resource::SERVICE_NAMESPACE.string("forge-system"),
    ]));

    let tracer = {
        let exporter = OtelStdoutExporter::new(std::io::stdout());

        let mut provider_builder =
            opentelemetry::sdk::trace::TracerProvider::builder().with_simple_exporter(exporter);
        provider_builder = provider_builder.with_config(trace_config);
        let provider = provider_builder.build();

        let tracer =
            provider.versioned_tracer("opentelemetry", Some(env!("CARGO_PKG_VERSION")), None);
        let _ = opentelemetry::global::set_tracer_provider(provider);

        tracer
    };

    // This configures the tracing framework
    // We ignore a lot of spans and events from 3rd party frameworks
    let env_filter = EnvFilter::from_default_env()
        .add_directive(
            match config.debug {
                0 => LevelFilter::INFO,
                1 => {
                    // command line overrides config file
                    std::env::set_var("RUST_BACKTRACE", "1");
                    LevelFilter::DEBUG
                }
                _ => {
                    std::env::set_var("RUST_BACKTRACE", "1");
                    LevelFilter::TRACE
                }
            }
            .into(),
        )
        .add_directive("sqlxmq::runner=warn".parse()?)
        .add_directive("rustify=error".parse()?)
        .add_directive("vaultrs=error".parse()?)
        .add_directive("sqlx::query=warn".parse()?)
        .add_directive("h2::codec=warn".parse()?);

    // tracing-opentelemetry integration
    // This will make `tracing` create opentelemetry spans, and log
    // tracing events as OTEL events
    let telemetry = tracing_opentelemetry::layer()
        .with_exception_fields(true)
        .with_threads(false)
        .with_tracer(tracer);

    tracing_subscriber::registry()
        .with(fmt::Layer::default().pretty())
        .with(env_filter)
        .with(telemetry)
        .try_init()?;

    match config.sub_cmd {
        Command::Migrate(ref m) => {
            log::debug!("Running migrations");
            let pool = PgPool::connect(&m.datastore[..]).await?;
            carbide::db::migrations::migrate(&pool).await?;
        }
        Command::Run(ref config) => {
            let vault_token = env::var("VAULT_TOKEN").wrap_err("VAULT_TOKEN")?;
            let vault_addr = env::var("VAULT_ADDR").wrap_err("VAULT_ADDR")?;
            let vault_mount_location =
                env::var("VAULT_MOUNT_LOCATION").wrap_err("VAULT_MOUNT_LOCATION")?;

            let vault_client_settings = VaultClientSettingsBuilder::default()
                .address(vault_addr)
                .token(vault_token)
                .timeout(Some(Duration::from_secs(60)))
                .verify(false) //TODO: remove me when we are starting to validate certs
                .build()?;
            let vault_client = VaultClient::new(vault_client_settings)?;
            let forge_vault_client = ForgeVaultClient::new(vault_client, vault_mount_location);
            let forge_vault_client = Arc::new(forge_vault_client);
            carbide::api::Api::run(config, forge_vault_client).await?
        }
    }
    Ok(())
}
