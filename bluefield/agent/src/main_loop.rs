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

use std::collections::HashSet;
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Add;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::rpc::forge::VpcVirtualizationType;
use ::rpc::forge_tls_client::ApiConfig;
use ::rpc::Uuid;
use ::rpc::{forge as rpc, forge_tls_client};
use axum::Router;
use eyre::WrapErr;
use forge_host_support::agent_config::AgentConfig;
use forge_host_support::registration;
use ipnetwork::IpNetwork;
use opentelemetry_sdk::metrics;
use rand::Rng;
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use utils::models::dhcp::{DhcpTimestamps, DhcpTimestampsFilePath};
use version_compare::Version;
use {opentelemetry_sdk as sdk, opentelemetry_semantic_conventions as semcov};

use crate::command_line::NetworkVirtualizationType;
use crate::dpu::interface::Interface;
use crate::dpu::route::{DpuRoutePlan, IpRoute, Route};
use crate::dpu::DpuNetworkInterfaces;
use crate::instance_metadata_endpoint::{get_fmds_router, InstanceMetadataRouterStateImpl};
use crate::instrumentation::{create_metrics, get_metrics_router, MetricsState, WithTracingLayer};
use crate::machine_inventory_updater::MachineInventoryUpdaterConfig;
use crate::network_monitor::{self, NetworkPingerType};
use crate::util::UrlResolver;
use crate::{
    command_line, ethernet_virtualization, hbn, health, instance_metadata_endpoint,
    instance_metadata_fetcher, machine_inventory_updater, mtu, netlink, network_config_fetcher,
    sysfs, systemd, upgrade, FMDS_MINIMUM_HBN_VERSION, NVUE_MINIMUM_HBN_VERSION,
};

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

    let forge_api = &agent.forge_system.api_server;

    let instance_metadata_fetcher =
        Arc::new(instance_metadata_fetcher::InstanceMetadataFetcher::new(
            instance_metadata_fetcher::InstanceMetadataFetcherConfig {
                config_fetch_interval: Duration::from_secs(agent.period.network_config_fetch_secs),
                machine_id: machine_id.to_string(),
                forge_api: forge_api.to_string(),
                forge_client_config: forge_client_config.clone(),
            },
        ));
    let instance_metadata_reader = instance_metadata_fetcher.reader();

    let instance_metadata_state = Arc::new(
        instance_metadata_endpoint::InstanceMetadataRouterStateImpl::new(
            machine_id.to_string(),
            forge_api.to_string(),
            forge_client_config.clone(),
        ),
    );

    let metrics = options
        .enable_metadata_service
        .then(|| {
            spawn_metadata_service(
                agent.metadata_service.address.clone(),
                agent.telemetry.metrics_address.clone(),
                instance_metadata_state.clone(),
                machine_id.to_string(),
            )
            .map_err(|e| eyre::eyre!("Failed to run metadata service: {:#}", e))
            .ok()
        })
        .flatten();

    let fmds_minimum_hbn_version = Version::from(FMDS_MINIMUM_HBN_VERSION).ok_or(eyre::eyre!(
        "Unable to convert string: {FMDS_MINIMUM_HBN_VERSION} to Version"
    ))?;
    let nvue_minimum_hbn_version = Version::from(NVUE_MINIMUM_HBN_VERSION).ok_or(eyre::eyre!(
        "Unable to convert string: {NVUE_MINIMUM_HBN_VERSION} to Version"
    ))?;

    let version_check_period = Duration::from_secs(agent.period.version_check_secs);
    let main_loop_period_active = Duration::from_secs(agent.period.main_loop_active_secs);
    let main_loop_period_idle = Duration::from_secs(agent.period.main_loop_idle_secs);

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

    let (pxe_ip, ntpservers, nameservers) = if !agent.machine.is_fake_dpu {
        let mut url_resolver = UrlResolver::try_new()?;

        let pxe_ip = *url_resolver
            .resolve("carbide-pxe.forge")
            .await
            .wrap_err("DNS resolver for carbide-pxe")?
            .first()
            .ok_or_else(|| eyre::eyre!("No pxe ip returned by resolver"))?;

        // This log should be removed after some time.
        tracing::info!(%pxe_ip, "Pxe server resolved");

        let ntpservers = match url_resolver.resolve("carbide-ntp.forge").await {
            Ok(x) => {
                // This log should be removed after some time.
                tracing::info!(?x, "NTP servers resolved.");
                x
            }
            Err(e) => {
                tracing::error!(error = %e, "NTP servers couldn't be resolved. Dhcp-server won't send NTP server IPs in dhcpoffer/ack.");
                vec![]
            }
        };

        let nameservers = url_resolver.nameservers();
        (pxe_ip, ntpservers, nameservers)
    } else {
        (
            Ipv4Addr::from([127, 0, 0, 1]),
            vec![],
            vec![IpAddr::from([127, 0, 0, 1])],
        )
    };

    let inventory_updater_config = MachineInventoryUpdaterConfig {
        dpu_agent_version: build_version.clone(),
        update_inventory_interval: Duration::from_secs(agent.period.inventory_update_secs),
        machine_id: machine_id.to_string(),
        forge_api: forge_api.to_string(),
        forge_client_config: forge_client_config.clone(),
    };

    // Get all DPU Ip addresses via gRPC call
    let (close_sender, mut close_receiver) = watch::channel(false);

    // Initialize network monitor and perform network check once
    let network_pinger_type = network_config_reader
        .read()
        .as_ref()
        .as_ref()
        .and_then(|response| response.dpu_network_pinger_type.as_ref())
        .and_then(|value| NetworkPingerType::from_str(value).ok());

    let network_monitor_handle: Option<JoinHandle<()>> = match network_pinger_type {
        Some(pinger_type) => {
            tracing::debug!("Starting network monitor with {} pinger", pinger_type);
            let mut network_monitor = network_monitor::NetworkMonitor::new(
                machine_id.to_string(),
                metrics,
                Arc::from(pinger_type),
            );
            let forge_api_clone = forge_api.clone();
            let client_config_clone = forge_client_config.clone();
            let network_monitor_handle = tokio::spawn(async move {
                network_monitor
                    .run(&forge_api_clone, client_config_clone, &mut close_receiver)
                    .await
            });
            Some(network_monitor_handle)
        }
        None => {
            tracing::debug!("No network pinger type provided from ManagedHostNetworkConfigResponse. Network monitor not started.");
            None
        }
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
        let mut current_host_network_config_version = None;
        let mut current_instance_network_config_version = None;
        let mut current_instance_config_version = None;

        let client_certificate_expiry_unix_epoch_secs =
            forge_client_config.client_cert_expiry().await;

        let fabric_interfaces = get_fabric_interfaces_data().await.unwrap_or_else(|err| {
            tracing::warn!("Error getting link data for fabric interfaces: {err:#}");
            vec![]
        });

        let mut status_out = rpc::DpuNetworkStatus {
            dpu_machine_id: Some(machine_id.to_string().into()),
            dpu_health: None,
            dpu_agent_version: Some(build_version.clone()),
            observed_at: None, // None makes carbide-api set it on receipt
            health: None,
            network_config_version: None,
            instance_config_version: None,
            instance_network_config_version: None,
            interfaces: vec![],
            network_config_error: None,
            instance_id: None,
            client_certificate_expiry_unix_epoch_secs,
            fabric_interfaces,
            last_dhcp_requests: vec![],
        };

        let mut last_dhcp_requests = vec![];
        let mut dhcp_timestamps = DhcpTimestamps::new(DhcpTimestampsFilePath::Dpu);
        if let Err(e) = dhcp_timestamps.read() {
            tracing::error!(
                "Failed to read from {}: {e}",
                DhcpTimestampsFilePath::Dpu.path_str()
            );
        }
        for (host_interface_id, timestamp) in dhcp_timestamps.into_iter() {
            last_dhcp_requests.push(rpc::LastDhcpRequest {
                host_interface_id: Some(Uuid {
                    value: host_interface_id.to_string(),
                }),
                timestamp: timestamp.to_string(),
            });
        }
        status_out.last_dhcp_requests = last_dhcp_requests;

        // `read` does not block
        match *network_config_reader.read() {
            Some(ref conf) => {
                let instance_data = instance_metadata_reader.read();

                let proposed_routes: Vec<_> = conf
                    .tenant_interfaces
                    .iter()
                    .filter_map(|x| IpNetwork::from_str(x.prefix.as_str()).ok())
                    .collect();

                // i32 -> VpcVirtualizationType -> NetworkVirtualizationType
                let nvt_from_remote = conf
                    .network_virtualization_type
                    .and_then(|vi| VpcVirtualizationType::try_from(vi).ok())
                    .map(|v| v.into());
                // If HBN is too old, this will be overridden once we are sure HBN is up
                let mut nvt = options
                    .override_network_virtualization_type // dev
                    .or(nvt_from_remote)
                    .unwrap_or_else(|| {
                        tracing::warn!("Missing network_virtualization_type, defaulting");
                        super::DEFAULT_NETWORK_VIRTUALIZATION_TYPE
                    });

                let tenant_peers = ethernet_virtualization::tenant_peers(conf);
                if is_hbn_up {
                    tracing::trace!("Desired network config is {conf:?}");
                    // Generate the fmds interface plan from the config. This does not apply the plan.
                    // The plan is applied when the NVUE template is written
                    let fmds_proposed_interfaces = &agent.fmds_armos_networking;
                    let network_plan = DpuNetworkInterfaces::new(fmds_proposed_interfaces);
                    let fmds_interface_plan = Interface::plan(
                        &fmds_proposed_interfaces.config.interface_name,
                        network_plan,
                    )
                    .await?;
                    tracing::trace!("Interface plan: {:?}", fmds_interface_plan);

                    // Generate the fmds route plan from conf.tenant_interfaces[n].address
                    // the plan is applied when the nvue template is written
                    let route_plan = plan_fmds_armos_routing(
                        &fmds_proposed_interfaces.config.interface_name,
                        &proposed_routes,
                    )
                    .await?;
                    tracing::trace!("Route plan: {:?}", route_plan);

                    let hbn_version = hbn::read_version().await?;
                    let hbn_version = Version::from(hbn_version.as_str())
                        .ok_or(eyre::eyre!("Unable to convert string to version"))?;

                    if hbn_version < nvue_minimum_hbn_version
                        && matches!(nvt, NetworkVirtualizationType::EtvNvue)
                    {
                        tracing::trace!("Site does not support NVUE, HBN version {hbn_version} is too old. Using ETV.");
                        nvt = NetworkVirtualizationType::Etv;
                    }

                    let dhcp_result = ethernet_virtualization::update_dhcp(
                        &agent.hbn.root_dir,
                        conf,
                        agent.hbn.skip_reload,
                        pxe_ip,
                        ntpservers.clone(),
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
                            if hbn_version >= fmds_minimum_hbn_version {
                                // Apply the interface plan. This is where we actually configure
                                // the interface on the Dpu
                                Interface::apply(fmds_interface_plan).await?;

                                // If there are routes, apply the route plan. This is where we actually
                                // add and remove routes.
                                //
                                // When a dpu has recently booted, there may
                                // not be a pf0dpu0_sf interface configured yet.  So routes may
                                // not be applied on the first tick of the loop. Once the interface
                                // is configured, routes can be added and removed.

                                // This means that routes will be added last and might take a few seconds
                                // to appear
                                if let Some(route_plan) = route_plan {
                                    Route::apply(route_plan).await?;
                                }
                            }

                            ethernet_virtualization::update_nvue(
                                &agent.hbn.root_dir,
                                conf,
                                agent.hbn.skip_reload,
                            )
                            .await
                        }
                        // TODO(chet,bill): Fill this in soon!
                        NetworkVirtualizationType::FnnClassic => Err(eyre::eyre!(
                            "fnn-classic support not implemented in the forge-dpu-agent yet"
                        )),
                        NetworkVirtualizationType::FnnL3 => Err(eyre::eyre!(
                            "fnn-l3 support not implemented in the forge-dpu-agent yet"
                        )),
                    };

                    let joined_result = match (update_result, dhcp_result) {
                        (Ok(a), Ok(b)) => Ok(a | b),
                        (Err(e1), Err(e2)) => Err(eyre::eyre!("errors update: {e1}, dhcp: {e2}")),
                        (Err(err), _) | (_, Err(err)) => Err(err),
                    };
                    match joined_result {
                        Ok(has_changed) => {
                            has_changed_configs = has_changed;
                            if let Err(err) = mtu::ensure().await {
                                tracing::error!(error = %err, "Error reading/setting MTU for p0 or p1");
                            }

                            // Updating network config succeeded.
                            // Tell the server about the applied version.
                            status_out.network_config_version =
                                Some(conf.managed_host_config_version.clone());
                            status_out.instance_id = conf.instance_id.clone();
                            // On the admin network we don't have to report the instance network config version
                            if !conf.instance_network_config_version.is_empty() {
                                status_out.instance_network_config_version = Some(
                                    match conf
                                        .instance_network_config_version
                                        .parse::<config_version::ConfigVersion>()
                                    {
                                        Ok(managed_host_instance_network_config_version) => {
                                            match instance_data
                                                .as_ref()
                                                .map(|instance| instance.network_config_version)
                                            {
                                                Some(instance_metadata_network_config_version) => {
                                                    // Report the older version of the versions received via 2 path
                                                    // That makes sure we don't report progress if we haven't received the newest version
                                                    // via both path.
                                                    let reported_instance_network_config_version =
                                                        managed_host_instance_network_config_version
                                                            .min_by_timestamp(
                                                                &instance_metadata_network_config_version,
                                                            );
                                                    if instance_metadata_network_config_version
                                                        != managed_host_instance_network_config_version
                                                    {
                                                        tracing::warn!("Different instance network config version received. GetManagedHostNetworkConfig: {}, FindInstanceByMachineId: {}, Reporting: {}",
                                                        managed_host_instance_network_config_version,
                                                    instance_metadata_network_config_version,
                                                    reported_instance_network_config_version,
                                                );
                                                    }
                                                    reported_instance_network_config_version
                                                        .version_string()
                                                }
                                                None => {
                                                    // TODO: Maybe we want to wait until both receive path provide the same data?
                                                    tracing::warn!("Received instance_network_config_version via GetManagedHostNetworkConfig, but not via FindInstanceByMachineId. Acknowledging received version");
                                                    conf.instance_network_config_version.clone()
                                                }
                                            }
                                        }
                                        Err(err) => {
                                            // We can't compare the 2 received versions since the first is not parseable
                                            // This isn't really supposed to happen.
                                            // However to avoid breaking the system in that case,
                                            // we still report the version received via GetManagedHostNetworkConfig,
                                            // because that is also what we did in the past.
                                            tracing::error!(error = %err, "Failed to parse instance_network_config_version received via GetManagedHostNetworkConfig");
                                            conf.instance_network_config_version.clone()
                                        }
                                    },
                                );
                            }
                            current_host_network_config_version =
                                status_out.network_config_version.clone();
                            current_instance_network_config_version =
                                status_out.instance_network_config_version.clone();

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

                    // In case of secondary DPU, physical interface must be disabled.
                    // TODO:  multidpu: This logic has to be improved to support instance handling where physical
                    // interface should be enabled on secondary DPU also.
                    if let Err(err) =
                        ethernet_virtualization::update_interface_state(conf, agent.hbn.skip_reload)
                            .await
                    {
                        tracing::error!(error = format!("{err:#}"), "Updating interface state.");
                        // no need to mark anything fail. It is just a temporary fix.
                    };
                }

                // Feed the latest instance metadata to FMDS and acknowledge it
                instance_metadata_state.update_instance_data(instance_data.clone());
                status_out.instance_config_version = instance_data
                    .as_ref()
                    .map(|instance| instance.config_version.version_string());
                current_instance_config_version = status_out.instance_config_version.clone();

                let health_report = health::health_check(
                    &agent.hbn.root_dir,
                    &tenant_peers,
                    started_at,
                    has_changed_configs,
                    conf.min_dpu_functioning_links,
                )
                .await;
                is_healthy = health_report.is_healthy();
                is_hbn_up = health_report.is_up();
                // subset of is_healthy
                tracing::trace!(%machine_id, %health_report, "HBN health");
                // If we just applied a new network config report network as unhealthy.
                // This gives HBN / BGP time to act on the config.
                let hs = rpc::NetworkHealth {
                    is_healthy,
                    passed: health_report
                        .checks_passed
                        .iter()
                        .map(|hc| hc.to_string())
                        .collect(),
                    failed: health_report
                        .checks_failed
                        .iter()
                        .map(|hc| hc.0.to_string())
                        .collect(),
                    message: health_report.message.clone(),
                };
                // TODO: Convert the health-report while we still have the old data format around
                let dpu_health: health_report::HealthReport = (&health_report)
                    .try_into()
                    .expect("Can not convert health report");

                status_out.health = Some(hs);
                status_out.dpu_health = Some(dpu_health.into());
                current_health_report = Some(health_report);
                current_config_error = status_out.network_config_error.clone();

                record_network_status(status_out, forge_api, forge_client_config.clone()).await;
                seen_blank = false;
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

        if !options.skip_upgrade_check {
            // We potentially restart at this point, so make it last in the loop
            if now > version_check_time {
                version_check_time = now.add(version_check_period);
                let upgrade_result = upgrade::upgrade(
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
        tracing::debug!(
            is_healthy,
            has_changed_configs,
            seen_blank,
            num_health_check_errors = cr7.map(|hs| hs.checks_failed.len()).unwrap_or_default(),
            health_check_first_error = cr7.and_then(|hs| hs.message.as_deref()).unwrap_or_default(),
            write_config_error = current_config_error.unwrap_or_default(),
            managed_host_network_config_version = current_host_network_config_version.unwrap_or_default(),
            instance_network_config_version = current_instance_network_config_version.unwrap_or_default(),
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
                let _ = close_sender.send(true);
                if let Some(handle) = network_monitor_handle {
                    let _ = handle.await;
                }
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

async fn plan_fmds_armos_routing(
    interface: &str,
    proposed_routes: &Vec<IpNetwork>,
) -> eyre::Result<Option<DpuRoutePlan>> {
    let mut proposed_plan = Vec::new();

    let interfaces = Interface::current_addresses(interface).await?;

    // find all ipv4 addresses on interface
    let fmds_interface = interfaces
        .iter()
        .find_map(|e| e.addr_info.iter().find(|i| i.family == "inet"));

    tracing::trace!("fmds_interface: {:?}", fmds_interface);

    if let Some(ipinterface) = fmds_interface {
        for route in proposed_routes {
            let new_route = IpRoute {
                dst: *route,
                dev: None,
                protocol: None,
                scope: None,
                gateway: Some(IpAddr::from([169, 254, 169, 253])), // use gateway IP from inside HBN container
                prefsrc: Some(ipinterface.local),
                flags: vec![],
            };
            proposed_plan.push(new_route);
        }
        let plan = Route::plan(interface, proposed_plan).await?;
        Ok(Some(plan))
    } else {
        Ok(None)
    }
}
pub async fn record_network_status(
    status: rpc::DpuNetworkStatus,
    forge_api: &str,
    forge_client_config: forge_tls_client::ForgeClientConfig,
) {
    let mut client = match forge_tls_client::ForgeTlsClient::new(forge_client_config)
        .build(forge_api)
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

async fn renew_certificates(forge_api: &str, client_config: forge_tls_client::ForgeClientConfig) {
    let mut client = match forge_tls_client::ForgeTlsClient::retry_build(&ApiConfig::new(
        forge_api,
        client_config,
    ))
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
    metadata_service_address: String,
    metrics_address: String,
    state: Arc<InstanceMetadataRouterStateImpl>,
    machine_id: String,
) -> Result<Arc<MetricsState>, Box<dyn std::error::Error>> {
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
        .with_view(metrics::new_view(
            metrics::Instrument::new().name("*_network_latency*"),
            metrics::Stream::new().aggregation(metrics::Aggregation::ExplicitBucketHistogram {
                boundaries: vec![
                    0.01, 0.02, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 1.0, 5.0, 10.0, 100.0, 500.0, 1000.0,
                ],
                record_min_max: true,
            }),
        )?)
        .with_view(metrics::new_view(
            metrics::Instrument::new().name("*_network_loss_percentage*"),
            metrics::Stream::new().aggregation(metrics::Aggregation::ExplicitBucketHistogram {
                boundaries: vec![0.2, 0.4, 0.6, 0.8, 1.0],
                record_min_max: true,
            }),
        )?)
        .build();
    // After this call `global::meter()` will be available
    opentelemetry::global::set_meter_provider(meter_provider.clone());

    let meter = opentelemetry::global::meter("forge-dpu-agent");

    let instance_metadata_state = state.clone();

    let metrics_state = create_metrics(meter, machine_id);
    metrics_state.register_callback();

    start_server(
        metadata_service_address,
        Router::new()
            .nest(
                "/latest",
                get_fmds_router(instance_metadata_state.clone())
                    .with_tracing_layer(metrics_state.clone()),
            )
            .nest(
                "/2009-04-04",
                get_fmds_router(instance_metadata_state.clone())
                    .with_tracing_layer(metrics_state.clone()),
            ),
    )
    .expect("metadata server panicked");

    start_server(
        metrics_address,
        Router::new().nest("/metrics", get_metrics_router(prometheus_registry)),
    )?;

    Ok(metrics_state)
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

// Get the link type, carrier status, MTU, and whatever else for our uplinks
// into the network fabric.
//
// For a link to be considered an uplink, it must satisfy all of the following:
// 1. The network device is on a PCI bus.
// 2. The network device type is Ethernet.
// 3. The Ethernet MAC address is in the unicast+universal range (last two bits
//    of the first OUI byte are both set to 0).
async fn get_fabric_interfaces_data(
) -> Result<Vec<rpc::FabricInterfaceData>, Box<dyn std::error::Error>> {
    let pci_network_devices: HashSet<_> = {
        let net_devices = sysfs::get_net_devices()?;
        // let net_devices = net_devices.into_iter();
        net_devices
            .into_iter()
            .filter_map(|net_device| {
                net_device
                    .is_pci_device()
                    .map(|is_pci| is_pci.then(|| net_device.entry_name()))
                    .transpose()
            })
            .collect::<Result<_, _>>()?
    };

    let rtnetlink_link_data = netlink::get_all_interface_links().await?;

    fn is_universal_unicast(oui_first_byte: u8) -> bool {
        (oui_first_byte & 0x03) == 0
    }

    let fabric_interface_data = rtnetlink_link_data
        .into_iter()
        .filter_map(|(interface_name, interface_data)| {
            let is_ethernet = interface_data.is_ethernet();
            let is_pci = {
                let iface_name: &OsStr = interface_name.as_ref();
                pci_network_devices.contains(iface_name)
            };
            let is_universal_unicast = interface_data
                .address
                .as_ref()
                .and_then(|address| address.first())
                .map(|first_byte| is_universal_unicast(*first_byte))
                .unwrap_or_else(|| {
                    tracing::warn!(
                        "The MAC address for interface {interface_name} was missing or empty"
                    );
                    false
                });

            (is_ethernet && is_pci && is_universal_unicast).then(|| {
                let link_data: rpc::LinkData = (&interface_data).into();

                let link_data = Some(link_data);
                rpc::FabricInterfaceData {
                    interface_name,
                    link_data,
                }
            })
        })
        .collect();
    Ok(fabric_interface_data)
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

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn test_get_fabric_interfaces_data() {
        let fabric_interfaces_data = get_fabric_interfaces_data().await.unwrap();
        dbg!(fabric_interfaces_data.as_slice());
        // Under virtualization we probably can't make any assertions about
        // whether this list contains any interfaces, but uncommenting this
        // should pass on any Linux host with real hardware or a virtualized PCI
        // network interface.
        // assert!(fabric_interfaces_data.len() > 0);
    }
}
