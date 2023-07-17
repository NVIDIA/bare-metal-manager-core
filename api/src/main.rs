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
use std::env;
use std::sync::Arc;
use std::time::Duration;

use carbide::{
    cfg::{CarbideConfig, Command, Options},
    logging::{
        metrics_endpoint::{run_metrics_endpoint, MetricsEndpointConfig},
        otel_stdout_exporter::OtelStdoutExporter,
    },
};
use eyre::WrapErr;
use forge_secrets::ForgeVaultClient;
use opentelemetry::{
    sdk::{self, export::metrics::aggregation, metrics},
    trace::TracerProvider,
};
use opentelemetry_api::trace::TraceError;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::{runtime, trace as sdktrace, Resource};
use opentelemetry_semantic_conventions as semcov;
use sqlx::PgPool;
use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

#[tokio::main]
async fn main() -> eyre::Result<()> {
    let config = Options::load();
    if config.version {
        println!("{}", forge_version::version!());
        return Ok(());
    }

    // This defines attributes that are set on the exported logs **and** metrics
    let service_telemetry_attributes = sdk::Resource::new(vec![
        semcov::resource::SERVICE_NAME.string("carbide-api"),
        semcov::resource::SERVICE_NAMESPACE.string("forge-system"),
    ]);

    // Set up an OpenTelemetry tracer with an exporter to StdOut
    // Note: This doesn't yet make any logs get pushed to the OpenTelemetry library
    // The binding happens later once we initialize tracing_opentelemetry and configure
    // it to forward log events from the `tracing` framework.
    // The application internally only uses `tracing` events.
    let trace_config = sdk::trace::config().with_resource(service_telemetry_attributes.clone());

    let tracer = {
        use opentelemetry::sdk::trace::TracerProvider;
        let mut provider_builder = TracerProvider::builder()
            .with_simple_exporter(OtelStdoutExporter::new(std::io::stdout()));
        provider_builder = provider_builder.with_config(trace_config);
        let provider = provider_builder.build();

        let tracer = provider.tracer("carbide-api");
        let _ = opentelemetry::global::set_tracer_provider(provider);

        tracer
    };

    fn init_otlp_tracer(endpoint: &str) -> Result<sdktrace::Tracer, TraceError> {
        opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(
                opentelemetry_otlp::new_exporter()
                    .tonic()
                    .with_endpoint(endpoint),
            )
            .with_trace_config(sdktrace::config().with_resource(Resource::new(vec![
                semcov::resource::SERVICE_NAME.string("carbide-api"),
                semcov::resource::SERVICE_NAMESPACE.string("forge-system"),
            ])))
            .install_batch(runtime::Tokio)
    }

    // This configures the tracing framework
    // We ignore a lot of spans and events from 3rd party frameworks
    let mut env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    if config.debug != 0 {
        env::set_var("RUST_BACKTRACE", "1");
        env_filter = env_filter.add_directive(
            match config.debug {
                1 => {
                    // command line overrides config file
                    LevelFilter::DEBUG
                }
                _ => LevelFilter::TRACE,
            }
            .into(),
        );
    }
    env_filter = env_filter
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

    let stdout_formatter = fmt::Layer::default()
        .compact()
        .with_file(true)
        .with_line_number(true)
        .with_ansi(false);

    let sub_cmd = match &config.sub_cmd {
        None => {
            tracing::error!("error: 'carbide-api' requires a subcommand but one was not provided. Re-run with '--help'.");
            return Ok(());
        }
        Some(s) => s,
    };
    match sub_cmd {
        Command::Migrate(ref m) => {
            tracing::info!("Running migrations");
            let pool = PgPool::connect(&m.datastore[..]).await?;
            carbide::db::migrations::migrate(&pool).await?;
        }
        Command::Run(ref config) => {
            use figment::providers::Format;
            let mut figment =
                figment::Figment::new().merge(figment::providers::Toml::file(&config.config_path));
            if let Some(site_path) = &config.site_config_path {
                figment = figment.merge(figment::providers::Toml::file(site_path));
            }
            let config: CarbideConfig = figment
                .merge(figment::providers::Env::prefixed("CARBIDE_API_"))
                .extract()
                .expect("Failed to load configuration files");
            let carbide_config = Arc::new(config);

            if let Some(otel) = carbide_config.as_ref().clone().otlp_endpoint {
                let otel_tracer = tracing_opentelemetry::layer()
                    .with_tracer(init_otlp_tracer(otel.as_ref())?)
                    .with_exception_fields(true)
                    .with_threads(false);

                tracing_subscriber::registry()
                    .with(stdout_formatter)
                    .with(env_filter)
                    .with(telemetry)
                    .with(otel_tracer)
                    .try_init()?;
            } else {
                tracing_subscriber::registry()
                    .with(stdout_formatter)
                    .with(env_filter)
                    .with(telemetry)
                    .try_init()?;
            };

            // Redact credentials before printing the config
            let print_config = {
                let mut config = carbide_config.as_ref().clone();
                if let Some(host_index) = config.database_url.find('@') {
                    let host = config.database_url.split_at(host_index).1;
                    config.database_url = format!("postgres://redacted{}", host);
                }
                if config.ib_fabric_manager_token.is_some() {
                    config.ib_fabric_manager_token = Some("redacted".to_string());
                }
                config
            };
            tracing::info!("Using configuration: {:#?}", print_config);

            // Set up OpenTelemetry metrics export via prometheus
            // TODO: The configuration here is copy&pasted from
            // https://github.com/open-telemetry/opentelemetry-rust/blob/main/examples/hyper-prometheus/src/main.rs
            // and should likely be fine-tuned.
            // One particular challenge seems that these histogram buckets are used for all histograms
            // created by the library. But we might want different buckets for e.g. request timings
            // than for e.g. data sizes
            let metrics_controller = metrics::controllers::basic(metrics::processors::factory(
                metrics::selectors::simple::histogram([
                    0.01, 0.05, 0.09, 0.1, 0.5, 0.9, 1.0, 5.0, 9.0, 10.0, 50.0, 90.0, 100.0, 500.0,
                    900.0, 1000.0,
                ]),
                aggregation::cumulative_temporality_selector(),
            ))
            .with_resource(service_telemetry_attributes)
            .build();

            // This sets the global meter provider
            // After this call `global::meter()` will be available
            let metrics_exporter =
                Arc::new(opentelemetry_prometheus::exporter(metrics_controller).init());

            let meter = opentelemetry::global::meter("carbide-api");

            // Spin up the webserver which servers `/metrics` requests
            if let Some(metrics_address) = carbide_config.metrics_endpoint {
                tokio::spawn(async move {
                    if let Err(e) = run_metrics_endpoint(&MetricsEndpointConfig {
                        address: metrics_address,
                        exporter: metrics_exporter,
                    })
                    .await
                    {
                        tracing::error!("Metrics endpoint failed with error: {}", e);
                    }
                });
            }

            let vault_token = env::var("VAULT_TOKEN")
                .wrap_err("VAULT_TOKEN")?
                .trim()
                .to_string();
            let vault_addr = env::var("VAULT_ADDR").wrap_err("VAULT_ADDR")?;
            let kv_mount_location =
                env::var("VAULT_KV_MOUNT_LOCATION").wrap_err("VAULT_KV_MOUNT_LOCATION")?;
            let pki_mount_location =
                env::var("VAULT_PKI_MOUNT_LOCATION").wrap_err("VAULT_PKI_MOUNT_LOCATION")?;
            let pki_role_name = env::var("VAULT_PKI_ROLE_NAME").wrap_err("VAULT_PKI_ROLE_NAME")?;

            let vault_client_settings = VaultClientSettingsBuilder::default()
                .address(vault_addr)
                .token(vault_token)
                .timeout(Some(Duration::from_secs(60)))
                .verify(false) //TODO: remove me when we are starting to validate certs
                .build()?;
            let vault_client = VaultClient::new(vault_client_settings)?;

            let forge_vault_client = ForgeVaultClient::new(
                vault_client,
                kv_mount_location,
                pki_mount_location,
                pki_role_name,
            );
            let forge_vault_client = Arc::new(forge_vault_client);

            tracing::info!(
                "Start carbide-api on {}, {}",
                carbide_config.listen,
                forge_version::version!()
            );
            carbide::api::Api::run(
                carbide_config,
                forge_vault_client.clone(),
                forge_vault_client,
                meter,
            )
            .await?
        }
    }
    Ok(())
}
