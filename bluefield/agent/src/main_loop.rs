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

use std::ops::Add;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client;
use axum::Router;
pub use command_line::{AgentCommand, NetconfParams, Options, RunOptions, WriteTarget};
use forge_host_support::agent_config::AgentConfig;
use forge_host_support::registration;
use opentelemetry::sdk;
use opentelemetry::sdk::metrics;
use opentelemetry_semantic_conventions as semcov;
use rand::Rng;
use tokio::signal::unix::{signal, SignalKind};
pub use upgrade::upgrade_check;

use crate::command_line;
use crate::ethernet_virtualization;
use crate::health;
use crate::instance_metadata_endpoint::get_instance_metadata_router;
use crate::instance_metadata_fetcher;
use crate::instrumentation::{create_metrics, get_metrics_router, WithTracingLayer};
use crate::network_config_fetcher;
use crate::upgrade;

// Main loop when running in daemon mode
pub async fn run(
    machine_id: &str,
    mac_address: &str,
    forge_tls_config: forge_tls_client::ForgeTlsConfig,
    agent: AgentConfig,
    options: Option<command_line::RunOptions>,
) -> eyre::Result<()> {
    let mut term_signal = signal(SignalKind::terminate())?;

    let enable_metadata_service = options.map(|o| o.enable_metadata_service).unwrap_or(false);
    if enable_metadata_service {
        if let (Some(metadata_service_config), Some(telemetry_config)) =
            (&agent.metadata_service, &agent.telemetry)
        {
            if let Err(e) = run_metadata_service(
                machine_id,
                forge_tls_config.clone(),
                &agent,
                metadata_service_config.address.clone(),
                telemetry_config.metrics_address.clone(),
            )
            .await
            {
                return Err(eyre::eyre!("Failed to run metadata service: {:#}", e));
            }
        } else {
            tracing::error!("metadata-service and telemetry configs are not present. Can't run metadata service");
        }
    }

    let version_check_period = Duration::from_secs(agent.period.version_check_secs);
    let main_loop_period_active = Duration::from_secs(agent.period.main_loop_active_secs);
    let main_loop_period_idle = Duration::from_secs(agent.period.main_loop_idle_secs);

    let forge_api = &agent.forge_system.api_server;
    let build_version = forge_version::v!(build_version).to_string();
    let network_config_fetcher = network_config_fetcher::NetworkConfigFetcher::new(
        network_config_fetcher::NetworkConfigFetcherConfig {
            config_fetch_interval: Duration::from_secs(agent.period.network_config_fetch_secs),
            machine_id: machine_id.to_string(),
            forge_api: forge_api.to_string(),
            forge_tls_config: forge_tls_config.clone(),
        },
    )
    .await;
    let network_config_reader = network_config_fetcher.reader();

    let min_cert_renewal_time = 5 * 24 * 60 * 60; // 5 days
    let max_cert_renewal_time = 7 * 24 * 60 * 60; // 7 days

    // we will attempt to refresh the cert at this frequency.
    let cert_renewal_period =
        rand::thread_rng().gen_range(min_cert_renewal_time..max_cert_renewal_time);
    let mut cert_renewal_time = Instant::now().add(Duration::from_secs(cert_renewal_period));

    let mut version_check_time = Instant::now(); // check it on the first loop
    let mut seen_blank = false;
    let mut is_hbn_up = false;
    let mut has_logged_stable = false;
    loop {
        let mut is_healthy = false;
        let mut has_changed_configs = false;

        let client_certificate_expiry_unix_epoch_secs = forge_tls_config.client_cert_expiry().await;

        let mut status_out = rpc::DpuNetworkStatus {
            dpu_machine_id: Some(machine_id.to_string().into()),
            dpu_agent_version: Some(build_version.clone()),
            observed_at: None, // None makes carbide-api set it on receipt
            health: None,
            network_config_version: None,
            instance_config_version: None,
            interfaces: vec![],
            network_config_error: None,
            instance_id: None,
            client_certificate_expiry_unix_epoch_secs,
        };
        match *network_config_reader.read() {
            Some(ref conf) => {
                let mut tenant_peers = vec![];
                if is_hbn_up {
                    match ethernet_virtualization::update(
                        &agent.hbn.root_dir,
                        conf,
                        agent.hbn.skip_reload,
                    ) {
                        Ok(has_changed) => {
                            // Updating network config succeeded.
                            // Tell the server about the applied version.
                            status_out.network_config_version =
                                Some(conf.managed_host_config_version.clone());
                            status_out.instance_id = conf.instance_id.clone();
                            if !conf.instance_config_version.is_empty() {
                                status_out.instance_config_version =
                                    Some(conf.instance_config_version.clone());
                            }
                            match ethernet_virtualization::interfaces(conf, mac_address) {
                                Ok(interfaces) => status_out.interfaces = interfaces,
                                Err(err) => status_out.network_config_error = Some(err.to_string()),
                            }
                            tenant_peers = ethernet_virtualization::tenant_peers(conf);
                            has_changed_configs = has_changed
                        }
                        Err(err) => {
                            status_out.network_config_error = Some(err.to_string());
                        }
                    }
                }

                let health_report = health::health_check(&agent.hbn.root_dir, &tenant_peers);
                is_healthy = health_report.is_healthy();
                is_hbn_up = health_report.is_up(); // subset of is_healthy
                tracing::trace!("{} HBN health is: {}", machine_id, health_report);
                // If we just applied a new network config report network as unhealthy.
                // This gives HBN / BGP time to act on the config.
                let hs = rpc::NetworkHealth {
                    is_healthy: is_healthy && !has_changed_configs,
                    passed: health_report
                        .checks_passed
                        .iter()
                        .map(|hc| hc.to_string())
                        .collect(),
                    failed: health_report
                        .checks_failed
                        .iter()
                        .map(|hc| hc.to_string())
                        .collect(),
                    message: health_report.message.or_else(|| {
                        if has_changed_configs {
                            Some("Post-config waiting period".to_string())
                        } else {
                            None
                        }
                    }),
                };
                status_out.health = Some(hs);

                record_network_status(status_out, forge_api, forge_tls_config.clone()).await;
                seen_blank = false;
            }
            None => {
                // No network config means server can't find the DPU, usually because it was
                // force-deleted. Only reset network config the _second_ time we can't find the
                // DPU. Safety first.
                if seen_blank {
                    ethernet_virtualization::reset(&agent.hbn.root_dir, agent.hbn.skip_reload);
                }
                seen_blank = true;
                // we don't record_network_status because the server doesn't know about this DPU
            }
        };

        let now = Instant::now();
        if now > cert_renewal_time {
            cert_renewal_time = now.add(Duration::from_secs(cert_renewal_period));
            renew_certificates(forge_api, forge_tls_config.clone()).await;
        }

        // We potentially restart at this point, so make it last in the loop
        if now > version_check_time {
            version_check_time = now.add(version_check_period);
            let upgrade_result = upgrade::upgrade_check(
                forge_api,
                forge_tls_config.clone(),
                machine_id,
                &agent.machine.upgrade_cmd,
            )
            .await;
            match upgrade_result {
                Ok(false) => {
                    // did not upgrade, normal case, continue
                }
                Ok(true) => {
                    // upgraded, need to exit and restart
                    return Ok(());
                }
                Err(e) => {
                    tracing::error!(
                        forge_api,
                        error = format!("{e:#}"), // we need alt display for wrap_err_with to work well
                        "upgrade_check failed"
                    );
                }
            }
        }

        let loop_period = if seen_blank || !is_healthy || has_changed_configs {
            main_loop_period_active
        } else {
            if !has_logged_stable {
                tracing::info!("HBN is healthy and network configuration is stable");
                has_logged_stable = true;
            }
            main_loop_period_idle
        };
        tokio::select! {
            biased;
            _ = term_signal.recv() => {
                tracing::info!(version=forge_version::v!(build_version), "TERM signal received, clean exit");
                return Ok(());
            }
            _ = tokio::time::sleep(loop_period) => {}
        }
    }
}

pub async fn record_network_status(
    status: rpc::DpuNetworkStatus,
    forge_api: &str,
    forge_tls_config: forge_tls_client::ForgeTlsConfig,
) {
    let mut client = match forge_tls_client::ForgeTlsClient::new(forge_tls_config)
        .connect(forge_api)
        .await
    {
        Ok(client) => client,
        Err(err) => {
            tracing::error!(
                forge_api,
                error = format!("{err:#}"),
                "record_network_status: Could not connect to Forge API server. Will retry."
            );
            return;
        }
    };
    let request = tonic::Request::new(status);
    if let Err(err) = client.record_dpu_network_status(request).await {
        tracing::error!(
            error = format!("{err:#}"),
            "Error while executing the record_network_status gRPC call"
        );
    }
}

async fn renew_certificates(forge_api: &str, forge_tls_config: forge_tls_client::ForgeTlsConfig) {
    let mut client = match forge_tls_client::ForgeTlsClient::new(forge_tls_config)
        .connect(forge_api)
        .await
    {
        Ok(client) => client,
        Err(err) => {
            tracing::error!(
                forge_api,
                error = format!("{err:#}"),
                "renew_certificates: Could not connect to Forge API server. Will retry."
            );
            return;
        }
    };

    let request = tonic::Request::new(rpc::MachineCertificateRenewRequest {});
    match client.renew_machine_certificate(request).await {
        Ok(response) => {
            let machine_certificate_result = response.into_inner();
            registration::write_certs(machine_certificate_result.machine_certificate).await;
        }
        Err(err) => {
            tracing::error!(
                error = format!("{err:#}"),
                "Error while executing the renew_certificates gRPC call"
            );
        }
    }
}

async fn run_metadata_service(
    machine_id: &str,
    forge_tls_config: forge_tls_client::ForgeTlsConfig,
    agent: &AgentConfig,
    metadata_service_address: String,
    metrics_address: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let forge_api = &agent.forge_system.api_server;

    // This defines attributes that are set on the exported logs **and** metrics
    let service_telemetry_attributes = sdk::Resource::new(vec![
        semcov::resource::SERVICE_NAME.string("dpu-agent"),
        semcov::resource::SERVICE_NAMESPACE.string("forge-system"),
    ]);

    // Set up OpenTelemetry metrics export via prometheus

    // This sets the global meter provider
    // Note: This configures metrics bucket between 5.0 and 10000.0, which are best suited
    // for tracking milliseconds
    // See https://github.com/open-telemetry/opentelemetry-rust/blob/495330f63576cfaec2d48946928f3dc3332ba058/opentelemetry-sdk/src/metrics/reader.rs#L155-L158
    let prometheus_registry = prometheus::Registry::new();
    let metrics_exporter = opentelemetry_prometheus::exporter()
        .with_registry(prometheus_registry.clone())
        .without_scope_info()
        .without_target_info()
        .build()?;
    let meter_provider = metrics::MeterProvider::builder()
        .with_reader(metrics_exporter)
        .with_resource(service_telemetry_attributes)
        .with_view(create_metric_view_for_retry_histograms(
            "*_(attempts|retries)_*",
        )?)
        .build();
    // After this call `global::meter()` will be available
    opentelemetry::global::set_meter_provider(meter_provider.clone());

    let meter = opentelemetry::global::meter("forge-dpu-agent");

    let instance_metadata_fetcher =
        Arc::new(instance_metadata_fetcher::InstanceMetadataFetcher::new(
            instance_metadata_fetcher::InstanceMetadataFetcherConfig {
                config_fetch_interval: Duration::from_secs(agent.period.network_config_fetch_secs),
                machine_id: machine_id.to_string(),
                forge_api: forge_api.to_string(),
                forge_tls_config,
            },
        ));

    let instance_metadata_reader = instance_metadata_fetcher.reader();

    let metrics_state = create_metrics(meter);

    tokio::spawn(async move {
        run_server(
            metadata_service_address,
            Router::new().nest(
                "/latest/meta-data",
                get_instance_metadata_router(instance_metadata_reader.clone())
                    .with_tracing_layer(metrics_state),
            ),
        )
        .await
        .expect("metadata server panicked");
    });

    run_server(
        metrics_address,
        Router::new().nest("/metrics", get_metrics_router(prometheus_registry)),
    )
    .await?;

    Ok(())
}

async fn run_server(address: String, router: Router) -> Result<(), Box<dyn std::error::Error>> {
    let addr: std::net::SocketAddr = address.parse()?;
    let server = axum::Server::try_bind(&addr)?;

    tokio::spawn(async move {
        if let Err(err) = server.serve(router.into_make_service()).await {
            eprintln!("Error while serving: {}", err);
        }
    });

    Ok(())
}

/// Configures a View for Histograms that describe retries or attempts for operations
/// The view reconfigures the histogram to use a small set of buckets that track
/// the exact amount of retry attempts up to 3, and 2 additional buckets up to 10.
/// This is more useful than the default histogram range where the lowest sets of
/// buckets are 0, 5, 10, 25
fn create_metric_view_for_retry_histograms(
    name_filter: &str,
) -> Result<Box<dyn opentelemetry::sdk::metrics::View>, opentelemetry::metrics::MetricsError> {
    let mut criteria = opentelemetry::sdk::metrics::Instrument::new().name(name_filter.to_string());
    criteria.kind = Some(opentelemetry::sdk::metrics::InstrumentKind::Histogram);
    let mask = opentelemetry::sdk::metrics::Stream::new().aggregation(
        opentelemetry::sdk::metrics::Aggregation::ExplicitBucketHistogram {
            boundaries: vec![0.0, 1.0, 2.0, 3.0, 5.0, 10.0],
            record_min_max: true,
        },
    );
    opentelemetry::sdk::metrics::new_view(criteria, mask)
}
