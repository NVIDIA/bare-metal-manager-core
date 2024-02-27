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

use std::net::{IpAddr, Ipv4Addr};
use std::ops::Add;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::rpc::forge as rpc;
use ::rpc::forge::VpcVirtualizationType;
use ::rpc::forge_tls_client;
use axum::Router;
use eyre::WrapErr;
use forge_host_support::agent_config::AgentConfig;
use forge_host_support::registration;
use opentelemetry_sdk as sdk;
use opentelemetry_sdk::metrics;
use opentelemetry_semantic_conventions as semcov;
use rand::Rng;
use tokio::signal::unix::{signal, SignalKind};

use crate::command_line::NetworkVirtualizationType;
use crate::ethernet_virtualization;
use crate::health;
use crate::instance_metadata_endpoint::get_instance_metadata_router;
use crate::instance_metadata_fetcher;
use crate::instrumentation::{create_metrics, get_metrics_router, WithTracingLayer};
use crate::machine_inventory_updater::MachineInventoryUpdaterConfig;
use crate::mtu;
use crate::network_config_fetcher;
use crate::systemd;
use crate::upgrade;
use crate::util::UrlResolver;
use crate::{command_line, machine_inventory_updater};

// Main loop when running in daemon mode
pub async fn run(
    machine_id: &str,
    mac_address: &str,
    forge_client_config: forge_tls_client::ForgeClientConfig,
    agent: AgentConfig,
    options: command_line::RunOptions,
) -> eyre::Result<()> {
    systemd::notify_start().await?;

    let mut term_signal = signal(SignalKind::terminate())?;
    let mut hup_signal = signal(SignalKind::hangup())?;

    if options.enable_metadata_service {
        if let (Some(metadata_service_config), Some(telemetry_config)) =
            (&agent.metadata_service, &agent.telemetry)
        {
            if let Err(e) = spawn_metadata_service(
                machine_id,
                forge_client_config.clone(),
                &agent,
                metadata_service_config.address.clone(),
                telemetry_config.metrics_address.clone(),
            ) {
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
    // `new` does a network call and spawns a task. It fetches an initial config from carbide-api,
    // then spawns a task fetching config every network_config_fetch_secs.
    let network_config_fetcher = network_config_fetcher::NetworkConfigFetcher::new(
        network_config_fetcher::NetworkConfigFetcherConfig {
            config_fetch_interval: Duration::from_secs(agent.period.network_config_fetch_secs),
            machine_id: machine_id.to_string(),
            forge_api: forge_api.to_string(),
            forge_client_config: forge_client_config.clone(),
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

    let started_at = Instant::now();
    let mut version_check_time = Instant::now(); // check it on the first loop
    let mut inventory_updater_time = Instant::now();
    let mut seen_blank = false;
    let mut is_hbn_up = false;
    let mut has_logged_stable = false;

    let (pxe_ip, ntp_ip, nameservers) = if !agent.machine.is_fake_dpu {
        let mut url_resolver = UrlResolver::try_new()?;

        let pxe_ip = *url_resolver
            .resolve("carbide-pxe.forge")
            .await
            .wrap_err("DNS resolver for carbide-pxe")?
            .first()
            .ok_or_else(|| eyre::eyre!("No pxe ip returned by resolver"))?;

        // This log should be removed after some time.
        tracing::info!(%pxe_ip, "Pxe server resolved");

        let ntp_ip = match url_resolver.resolve("carbide-ntp.forge").await {
            Ok(x) => {
                let ntp_server_ip = x.first();
                // This log should be removed after some time.
                tracing::info!(?ntp_server_ip, "Ntp server resolved");
                ntp_server_ip.cloned()
            }
            Err(e) => {
                tracing::error!(error = %e, "NTP server couldn't be resolved. Dhcp-server won't send NTP server IP in dhcpoffer/ack.");
                None
            }
        };

        let nameservers = url_resolver.nameservers();
        (pxe_ip, ntp_ip, nameservers)
    } else {
        (
            Ipv4Addr::from([127, 0, 0, 1]),
            None,
            vec![IpAddr::from([127, 0, 0, 1])],
        )
    };

    let inventory_updater_config = MachineInventoryUpdaterConfig {
        update_inventory_interval: Duration::from_secs(agent.period.inventory_update_secs),
        machine_id: machine_id.to_string(),
        forge_api: forge_api.to_string(),
        forge_client_config: forge_client_config.clone(),
    };

    loop {
        let loop_start = Instant::now();

        if let Err(err) = systemd::notify_watchdog().await {
            tracing::error!(error = format!("{err:#}"), "systemd::notify_watchdog");
        }

        let mut current_health_report = None;
        let mut current_config_error = None;
        let mut is_healthy = false;
        let mut has_changed_configs = false;
        let mut current_host_config_version = None;
        let mut current_instance_config_version = None;

        let client_certificate_expiry_unix_epoch_secs =
            forge_client_config.client_cert_expiry().await;

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
        // `read` does not block
        match *network_config_reader.read() {
            Some(ref conf) => {
                // i32 -> VpcVirtualizationType -> NetworkVirtualizationType
                let nvt_from_remote = conf
                    .network_virtualization_type
                    .and_then(|vi| VpcVirtualizationType::try_from(vi).ok())
                    .map(|v| v.into());
                let nvt = options
                    .override_network_virtualization_type // dev
                    .or(nvt_from_remote)
                    .unwrap_or_else(|| {
                        tracing::warn!("Missing network_virtualization_type, defaulting");
                        super::DEFAULT_NETWORK_VIRTUALIZATION_TYPE
                    });
                let mut tenant_peers = vec![];
                if is_hbn_up {
                    tracing::trace!("Desired network config is {conf:?}");

                    let dhcp_result = ethernet_virtualization::update_dhcp(
                        &agent.hbn.root_dir,
                        conf,
                        agent.hbn.skip_reload,
                        pxe_ip,
                        ntp_ip,
                        nameservers.clone(),
                        nvt,
                    )
                    .await;

                    let update_result = match nvt {
                        NetworkVirtualizationType::Etv => {
                            ethernet_virtualization::update_files(
                                &agent.hbn.root_dir,
                                conf,
                                agent.hbn.skip_reload,
                            )
                            .await
                        }
                        NetworkVirtualizationType::EtvNvue => {
                            ethernet_virtualization::update_nvue(
                                &agent.hbn.root_dir,
                                conf,
                                agent.hbn.skip_reload,
                            )
                            .await
                        }
                    };

                    let joined_result = match (update_result, dhcp_result) {
                        (Ok(a), Ok(b)) => Ok(a | b),
                        (Err(e1), Err(e2)) => Err(eyre::eyre!("errors update: {e1}, dhcp: {e2}")),
                        (Err(err), _) | (_, Err(err)) => Err(err),
                    };
                    match joined_result {
                        Ok(has_changed) => {
                            has_changed_configs = has_changed;
                            tenant_peers = ethernet_virtualization::tenant_peers(conf);
                            if let Err(err) = mtu::ensure().await {
                                tracing::error!(error = %err, "Error reading/setting MTU for p0 or p1");
                            }

                            // Updating network config succeeded.
                            // Tell the server about the applied version.
                            status_out.network_config_version =
                                Some(conf.managed_host_config_version.clone());
                            status_out.instance_id = conf.instance_id.clone();
                            if !conf.instance_config_version.is_empty() {
                                status_out.instance_config_version =
                                    Some(conf.instance_config_version.clone());
                            }
                            current_host_config_version = status_out.network_config_version.clone();
                            current_instance_config_version =
                                status_out.instance_config_version.clone();

                            match ethernet_virtualization::interfaces(conf, mac_address).await {
                                Ok(interfaces) => status_out.interfaces = interfaces,
                                Err(err) => status_out.network_config_error = Some(err.to_string()),
                            }
                        }
                        Err(err) => {
                            tracing::error!(
                                error = format!("{err:#}"),
                                "Writing network configuration"
                            );
                            status_out.network_config_error = Some(err.to_string());
                        }
                    }
                }

                let health_report =
                    health::health_check(&agent.hbn.root_dir, &tenant_peers, started_at).await;
                let is_missing_ipmi_user = health_report.is_missing_ipmi_user();
                is_healthy = health_report.is_healthy();
                is_hbn_up = health_report.is_up();
                // subset of is_healthy
                tracing::trace!(%machine_id, %health_report, "HBN health");
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
                    message: health_report.message.clone().or_else(|| {
                        if has_changed_configs {
                            Some("Post-config waiting period".to_string())
                        } else {
                            None
                        }
                    }),
                };
                status_out.health = Some(hs);
                current_health_report = Some(health_report);
                current_config_error = status_out.network_config_error.clone();

                record_network_status(status_out, forge_api, forge_client_config.clone()).await;
                seen_blank = false;

                if is_missing_ipmi_user {
                    if let Err(err) =
                        create_forge_admin_user(forge_api, forge_client_config.clone(), machine_id)
                            .await
                    {
                        tracing::error!(
                            error = %err,
                            "Failed creating missing forge_admin user. Will retry."
                        );
                    }
                }
            }
            None => {
                // No network config means server can't find the DPU, usually because it was
                // force-deleted. Only reset network config the _second_ time we can't find the
                // DPU. Safety first.
                if seen_blank {
                    ethernet_virtualization::reset(&agent.hbn.root_dir, agent.hbn.skip_reload)
                        .await;
                }
                seen_blank = true;
                // we don't record_network_status because the server doesn't know about this DPU
            }
        };

        let now = Instant::now();
        if now > cert_renewal_time {
            cert_renewal_time = now.add(Duration::from_secs(cert_renewal_period));
            renew_certificates(forge_api, forge_client_config.clone()).await;
        }

        if now > inventory_updater_time {
            inventory_updater_time = now.add(inventory_updater_config.update_inventory_interval);
            if let Err(err) = machine_inventory_updater::single_run(&inventory_updater_config).await
            {
                tracing::error!(%err, "machine_inventory_updater error");
            }
        }

        // We potentially restart at this point, so make it last in the loop
        if now > version_check_time {
            version_check_time = now.add(version_check_period);
            let upgrade_result = upgrade::upgrade_check(
                forge_api,
                forge_client_config.clone(),
                machine_id,
                agent.updates.override_upgrade_cmd.as_deref(),
            )
            .await;
            match upgrade_result {
                Ok(false) => {
                    // did not upgrade, normal case, continue
                }
                Ok(true) => {
                    // upgraded, need to exit and restart
                    if let Err(err) = systemd::notify_stop().await {
                        tracing::error!(error = format!("{err:#}"), "systemd::notify_stop");
                    }
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

        let cr7 = current_health_report.as_ref();
        tracing::info!(
            is_healthy,
            has_changed_configs,
            seen_blank,
            num_health_check_errors = cr7.map(|hs| hs.checks_failed.len()).unwrap_or_default(),
            health_check_first_error = cr7.and_then(|hs| hs.message.as_deref()).unwrap_or_default(),
            write_config_error = current_config_error.unwrap_or_default(),
            managed_host_config_version = current_host_config_version.unwrap_or_default(),
            instance_config_version = current_instance_config_version.unwrap_or_default(),
            loop_duration = %dt(loop_start.elapsed()),
            version_check_in = %dt(version_check_time - Instant::now()),
            uptime = %dt(started_at.elapsed()),
            "loop metrics",
        );

        tokio::select! {
            biased;
            _ = term_signal.recv() => {
                systemd::notify_stop().await?;
                tracing::info!(version=forge_version::v!(build_version), "TERM signal received, clean exit");
                return Ok(());
            }
            _ = hup_signal.recv() => {
                tracing::info!("Hangup received, timer reset");
                let now = Instant::now();
                cert_renewal_time = now;
                inventory_updater_time = now;
                version_check_time = now;
                // the loop_period sleep is interrupted so we will fetch new network config
            }
            _ = tokio::time::sleep(loop_period) => {}
        }
    }
}

pub async fn record_network_status(
    status: rpc::DpuNetworkStatus,
    forge_api: &str,
    forge_client_config: forge_tls_client::ForgeClientConfig,
) {
    let mut client = match forge_tls_client::ForgeTlsClient::new(forge_client_config)
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

async fn renew_certificates(
    forge_api: &str,
    forge_client_config: forge_tls_client::ForgeClientConfig,
) {
    let mut client = match forge_tls_client::ForgeTlsClient::new(forge_client_config)
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
            tracing::info!("Received new machine certificate. Attempting to write to disk.");
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

/*
async fn start_inventory_updater(
    machine_id: &str,
    forge_client_config: forge_tls_client::ForgeClientConfig,
    agent: &AgentConfig,
) -> eyre::Result<()> {
    let forge_api = &agent.forge_system.api_server;

    let config = MachineInventoryUpdaterConfig {
        update_inventory_interval: Duration::from_secs(agent.period.inventory_update_secs),
        machine_id: machine_id.to_string(),
        forge_api: forge_api.to_string(),
        forge_client_config,
    };

    tokio::task::spawn(machine_inventory_updater::run(config));

    Ok(())
}
*/

fn spawn_metadata_service(
    machine_id: &str,
    forge_client_config: forge_tls_client::ForgeClientConfig,
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
                forge_client_config,
            },
        ));

    let instance_metadata_reader = instance_metadata_fetcher.reader();

    let metrics_state = create_metrics(meter);

    start_server(
        metadata_service_address,
        Router::new().nest(
            "/latest/meta-data",
            get_instance_metadata_router(instance_metadata_reader.clone())
                .with_tracing_layer(metrics_state),
        ),
    )
    .expect("metadata server panicked");

    start_server(
        metrics_address,
        Router::new().nest("/metrics", get_metrics_router(prometheus_registry)),
    )?;

    Ok(())
}

/// Spawns a background task to run an axum server listening on given socket, and returns.
fn start_server(address: String, router: Router) -> Result<(), Box<dyn std::error::Error>> {
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
) -> Result<Box<dyn opentelemetry_sdk::metrics::View>, opentelemetry::metrics::MetricsError> {
    let mut criteria = opentelemetry_sdk::metrics::Instrument::new().name(name_filter.to_string());
    criteria.kind = Some(opentelemetry_sdk::metrics::InstrumentKind::Histogram);
    let mask = opentelemetry_sdk::metrics::Stream::new().aggregation(
        opentelemetry_sdk::metrics::Aggregation::ExplicitBucketHistogram {
            boundaries: vec![0.0, 1.0, 2.0, 3.0, 5.0, 10.0],
            record_min_max: true,
        },
    );
    opentelemetry_sdk::metrics::new_view(criteria, mask)
}

/// DANGER TODO set_ipmi_creds and send_bmc_metadata_update are not async and may block tokio forever
async fn create_forge_admin_user(
    forge_api: &str,
    forge_client_config: forge_tls_client::ForgeClientConfig,
    machine_id: &str,
) -> eyre::Result<()> {
    let ipmi_user = forge_host_support::ipmi::set_ipmi_creds()?;

    let mut client = forge_tls_client::ForgeTlsClient::new(forge_client_config).connect(forge_api).await
        .map_err(|err|
            eyre::eyre!("create_forge_admin_user: Could not connect to Forge API server at {forge_api}. {err}")
        )?;
    forge_host_support::ipmi::send_bmc_metadata_update(&mut client, machine_id, vec![ipmi_user])
        .await?;
    Ok(())
}

const ONE_SECOND: Duration = Duration::from_secs(1);

// Format a Duration for display
fn dt(d: Duration) -> humantime::FormattedDuration {
    humantime::format_duration(if d > ONE_SECOND {
        Duration::from_secs(d.as_secs())
    } else {
        Duration::from_millis(d.as_millis() as u64)
    })
}
