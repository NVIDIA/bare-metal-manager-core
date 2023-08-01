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

use eyre::WrapErr;
use figment::providers::{Env, Format, Toml};
use figment::Figment;
use opentelemetry::{
    sdk::{self, export::metrics::aggregation, metrics},
    trace::TracerProvider,
};
use opentelemetry_api::metrics::Meter;
use opentelemetry_api::trace::TraceError;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_prometheus::PrometheusExporter;
use opentelemetry_sdk::{runtime, trace as sdktrace, Resource};
use opentelemetry_semantic_conventions as semcov;
use tracing_subscriber::{
    filter::EnvFilter, filter::LevelFilter, fmt, prelude::*, util::SubscriberInitExt,
};
use vaultrs::client::{VaultClient, VaultClientSettingsBuilder};

use forge_secrets::ForgeVaultClient;

use crate::{
    cfg::CarbideConfig,
    logging::{otel_stdout_exporter::OtelStdoutExporter, sqlx_query_tracing},
};

pub fn parse_carbide_config(
    config_str: String,
    site_config_str: Option<String>,
) -> eyre::Result<Arc<CarbideConfig>> {
    let mut figment = Figment::new().merge(Toml::string(config_str.as_str()));
    if let Some(site_config_str) = site_config_str {
        figment = figment.merge(Toml::string(site_config_str.as_str()));
    }

    let config: CarbideConfig = figment
        .merge(Env::prefixed("CARBIDE_API_"))
        .extract()
        .wrap_err("Failed to load configuration files")?;
    Ok(Arc::new(config))
}

pub fn create_vault_client() -> eyre::Result<Arc<ForgeVaultClient>> {
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
    Ok(Arc::new(forge_vault_client))
}

pub async fn setup_telemetry(
    debug: u8,
    carbide_config: Arc<CarbideConfig>,
    logging_subscriber: Option<impl SubscriberInitExt>,
) -> eyre::Result<(Arc<PrometheusExporter>, Meter)> {
    // This configures the tracing framework

    // We set up some global filtering using `tracing`s `EnvFilter` framework
    // The global filter will apply to all `Layer`s that are added to the
    // `logging_subscriber` later on. This means it applies for both logging to
    // stdout as well as for OpenTelemetry integration.
    // We ignore a lot of spans and events from 3rd party frameworks
    let mut global_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    if debug != 0 {
        env::set_var("RUST_BACKTRACE", "1");
        global_filter = global_filter.add_directive(
            match debug {
                1 => {
                    // command line overrides config file
                    LevelFilter::DEBUG
                }
                _ => LevelFilter::TRACE,
            }
            .into(),
        );
    }

    global_filter = global_filter
        .add_directive("sqlxmq::runner=warn".parse()?)
        .add_directive("rustify=error".parse()?)
        .add_directive("vaultrs=error".parse()?)
        .add_directive("h2::codec=warn".parse()?);

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

    if let Some(logging_subscriber) = logging_subscriber {
        logging_subscriber.try_init()?;
    } else {
        // Create a `Filter` that prevents logs with a level below `WARN` for sqlx
        // We use this solely for stdout and OpenTelemetry logging.
        // We can't make it a global filter, because our postgres tracing layer requires those logs
        let block_sqlx_filter = sqlx_query_tracing::block_sqlx_filter();

        // Set up the tracing subscriber
        // Note that the order here doesn't matter: The global filtering is always
        // applied before all "sinks" (`Layer`s), because the `.enabled()` function of
        // all layers and filters will be called before any event is forwarded.
        let logging_subscriber = tracing_subscriber::registry()
            .with(global_filter)
            .with(stdout_formatter.with_filter(block_sqlx_filter.clone()))
            .with(telemetry.with_filter(block_sqlx_filter.clone()))
            .with(sqlx_query_tracing::create_sqlx_query_tracing_layer());

        if let Some(otel) = carbide_config.as_ref().clone().otlp_endpoint {
            let otel_tracer = tracing_opentelemetry::layer()
                .with_exception_fields(true)
                .with_threads(false)
                .with_tracer(init_otlp_tracer(otel.as_ref())?);

            logging_subscriber
                .with(otel_tracer.with_filter(block_sqlx_filter))
                .try_init()?;
        } else {
            logging_subscriber.try_init()?;
        }
    };

    // Set up OpenTelemetry metrics export via prometheus
    // TODO: The configuration here is copy&pasted from
    // https://github.com/open-telemetry/opentelemetry-rust/blob/main/examples/hyper-prometheus/src/main.rs
    // and should likely be fine-tuned.
    // One particular challenge seems that these histogram buckets are used for all histograms
    // created by the library. But we might want different buckets for e.g. request timings
    // than for e.g. data sizes
    let metrics_controller = metrics::controllers::basic(metrics::processors::factory(
        metrics::selectors::simple::histogram([
            0.01, 0.05, 0.09, 0.1, 0.5, 0.9, 1.0, 5.0, 9.0, 10.0, 50.0, 90.0, 100.0, 500.0, 900.0,
            1000.0,
        ]),
        aggregation::cumulative_temporality_selector(),
    ))
    .with_resource(service_telemetry_attributes)
    .build();

    // This sets the global meter provider
    // After this call `global::meter()` will be available
    let metrics_exporter = Arc::new(opentelemetry_prometheus::exporter(metrics_controller).init());

    let meter = opentelemetry::global::meter("carbide-api");
    Ok((metrics_exporter, meter))
}
