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

use std::collections::HashSet;
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr};
use std::ops::Add;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ::rpc::forge::ManagedHostNetworkConfigResponse;
use ::rpc::forge_tls_client::ForgeClientConfig;
use ::rpc::{forge as rpc, forge_tls_client};
use carbide_host_support::agent_config::AgentConfig;
use carbide_systemd::systemd;
use carbide_uuid::machine::MachineId;
use eyre::WrapErr;
use forge_certs::cert_renewal::ClientCertRenewer;
use forge_dpu_remediation::remediation::{MachineInfo, RemediationExecutor};
use forge_network::virtualization::{DEFAULT_NETWORK_VIRTUALIZATION_TYPE, VpcVirtualizationType};
use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::log::error;
use utils::models::dhcp::{DhcpTimestamps, DhcpTimestampsFilePath};
use version_compare::Version;

use crate::dpu::DpuNetworkInterfaces;
use crate::dpu::interface::Interface;
use crate::dpu::route::{DpuRoutePlan, IpRoute, Route};
use crate::duppet::{SummaryFormat, SyncOptions};
use crate::ethernet_virtualization::ServiceAddresses;
use crate::instance_metadata_endpoint::InstanceMetadataRouterStateImpl;
use crate::instrumentation::{create_metrics, get_dpu_agent_meter};
use crate::machine_inventory_updater::MachineInventoryUpdaterConfig;
use crate::network_monitor::{self, NetworkPingerType};
use crate::util::{UrlResolver, get_host_boot_timestamp};
use crate::{
    FMDS_MINIMUM_HBN_VERSION, HBNDeviceNames, NVUE_MINIMUM_HBN_VERSION, RunOptions, command_line,
    ethernet_virtualization, extension_services, hbn, health, instance_metadata_endpoint, lldp,
    machine_inventory_updater, managed_files, mtu, netlink, nvue, periodic_config_fetcher,
    pretty_cmd, sysfs, upgrade,
};

// Main loop when running in daemon mode
// Before going into its main loop functionality, the
// code first launches a periodic config fetcher thread.
// The periodic config fetcher uses a grpc call to
// carbide to get network config information as well as
// instance metadata information and stores it. The main loop and the instance
// metadata service use the information fetched be the periodic fetcher by reading
// the information stored by the periodic config fetcher.
pub async fn setup_and_run(
    machine_id: MachineId,
    factory_mac_address: MacAddress,
    forge_client_config: Arc<ForgeClientConfig>,
    agent_config: AgentConfig,
    options: command_line::RunOptions,
) -> eyre::Result<()> {
    systemd::notify_start().await?;
    tracing::info!(
        version = carbide_version::version!(),
        "Started forge-dpu-agent"
    );

    // Issue a *hopefully* one time reboot in the event that a VERY specific case where the dpu
    // is unable to load its 2.9.2 ATF/UEFI, due to a nasty bug that deleted the uefi cert db. This
    // is a manual way to load the ATF/UEFI, because by the time we get to the dpu agent actually
    // running, then we got past all the pre-reqs that would have gotten us out of the state where
    // we cannot load the ATF/UEFI, so we run these commands and reboot, and the next time we check
    // the ATF/UEFI is loaded.
    //
    // Once the fleet is all on 2.9.2, we can remove this ugly hack.
    hack_dpu_os_to_load_atf_uefi_with_specific_versions().await?;

    let process_start_time = SystemTime::now();

    let forge_api_server = agent_config.forge_system.api_server.clone();
    // Setup client certificate renewal
    let client_cert_renewer =
        ClientCertRenewer::new(forge_api_server.clone(), Arc::clone(&forge_client_config));

    let machine_info = MachineInfo::new(machine_id);
    let remediation_executor = RemediationExecutor::new(
        forge_api_server.clone(),
        Arc::clone(&forge_client_config),
        machine_info,
    );
    tokio::task::spawn(async move {
        remediation_executor.run().await;
    });

    let instance_metadata_state = Arc::new(
        instance_metadata_endpoint::InstanceMetadataRouterStateImpl::new(
            machine_id,
            forge_api_server.clone(),
            Arc::clone(&forge_client_config),
        ),
    );

    let agent_meter = get_dpu_agent_meter();
    let metrics = create_metrics(agent_meter);

    if options.enable_metadata_service {
        crate::metadata_service::spawn_metadata_service(
            agent_config.metadata_service.address.clone(),
            agent_config.telemetry.metrics_address.clone(),
            metrics.clone(),
            instance_metadata_state.clone(),
        )
        .unwrap_or_else(|e| {
            tracing::warn!("Failed to run metadata service: {:#}", e);
        });
    }

    // Some of these metrics only need to be set once, let's take care of them
    // now.
    match process_start_time.duration_since(UNIX_EPOCH) {
        Ok(time_since_epoch) => {
            let timestamp = time_since_epoch.as_secs();
            metrics.record_agent_start_time(timestamp);
        }
        Err(e) => {
            tracing::warn!("Error calculating process start timestamp: {e:#}");
        }
    }

    match get_host_boot_timestamp() {
        Ok(timestamp) => {
            metrics.record_machine_boot_time(timestamp);
        }
        Err(e) => {
            tracing::warn!("Error getting host boot timestamp: {e:#}");
        }
    }

    if !agent_config.machine.is_fake_dpu
        && let Err(e) = crate::agent_platform::ensure_doca_containers().await
    {
        // The HBN container health check will notice this problem and
        // turn it into an unhealthy status that gets reported to the
        // API, so we're not going to do much more than log this for
        // now.
        tracing::error!("Couldn't ensure DOCA pods: {e}");
    }

    let fmds_minimum_hbn_version = Version::from(FMDS_MINIMUM_HBN_VERSION).ok_or(eyre::eyre!(
        "Unable to convert string: {FMDS_MINIMUM_HBN_VERSION} to Version"
    ))?;
    let nvue_minimum_hbn_version = Version::from(NVUE_MINIMUM_HBN_VERSION).ok_or(eyre::eyre!(
        "Unable to convert string: {NVUE_MINIMUM_HBN_VERSION} to Version"
    ))?;

    if let Err(err) = crate::ovs::set_vswitchd_yield().await {
        tracing::warn!(%err, "Failed asking ovs_vswitchd to not use 100% of a CPU core. Non-fatal.");
        // We have eight cores. Letting ovs_vswitchd have one is OK.
    };

    let build_version = carbide_version::v!(build_version).to_string();

    let periodic_config_fetcher = periodic_config_fetcher::PeriodicConfigFetcher::new(
        periodic_config_fetcher::PeriodicConfigFetcherConfig {
            config_fetch_interval: Duration::from_secs(
                agent_config.period.network_config_fetch_secs,
            ),
            machine_id,
            forge_api: forge_api_server.clone(),
            forge_client_config: Arc::clone(&forge_client_config),
        },
    )
    .await;

    let duppet_options = SyncOptions {
        dry_run: false,
        quiet: false,
        no_color: false,
        summary_format: SummaryFormat::PlainText,
    };

    managed_files::main_sync(duppet_options, &machine_id, &periodic_config_fetcher);

    if let Err(e) = lldp::set_lldp_system_description(&machine_id) {
        tracing::warn!("Couldn't update LLDP system description: {e}")
    }

    let periodic_config_reader = periodic_config_fetcher.reader();

    let service_addrs = if !agent_config.machine.is_fake_dpu {
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
        ServiceAddresses {
            pxe_ip,
            ntpservers,
            nameservers,
        }
    } else {
        ServiceAddresses {
            pxe_ip: Ipv4Addr::from([127, 0, 0, 1]),
            ntpservers: vec![],
            nameservers: vec![IpAddr::from([127, 0, 0, 1])],
        }
    };

    let inventory_updater_config = MachineInventoryUpdaterConfig {
        dpu_agent_version: build_version.clone(),
        update_inventory_interval: Duration::from_secs(agent_config.period.inventory_update_secs),
        machine_id,
        forge_api: forge_api_server.clone(),
        forge_client_config: Arc::clone(&forge_client_config),
    };

    // Get all DPU Ip addresses via gRPC call
    let (close_sender, mut close_receiver) = watch::channel(false);

    // Initialize network monitor and perform network check once
    let network_pinger_type = periodic_config_reader
        .net_conf_read()
        .as_ref()
        .as_ref()
        .and_then(|response| response.dpu_network_pinger_type.as_ref())
        .and_then(|value| NetworkPingerType::from_str(value).ok());

    let agent_meter = get_dpu_agent_meter();
    let network_monitor_metrics_state =
        crate::instrumentation::NetworkMonitorMetricsState::initialize(agent_meter, machine_id);

    let network_monitor_handle: Option<JoinHandle<()>> = match network_pinger_type {
        Some(pinger_type) => {
            tracing::debug!("Starting network monitor with {} pinger", pinger_type);
            let mut network_monitor = network_monitor::NetworkMonitor::new(
                machine_id,
                Some(network_monitor_metrics_state),
                Arc::from(pinger_type),
            );
            let forge_api_clone = forge_api_server.clone();
            let forge_client_config_clone = Arc::clone(&forge_client_config);
            let network_monitor_handle = tokio::spawn(async move {
                network_monitor
                    .run(
                        &forge_api_clone,
                        forge_client_config_clone,
                        &mut close_receiver,
                    )
                    .await
            });
            Some(network_monitor_handle)
        }
        None => {
            tracing::debug!(
                "No network pinger type provided from ManagedHostNetworkConfigResponse. Network monitor not started."
            );
            None
        }
    };

    // default to hbn 2.3 and above for the hbn device names. This will be properly set once the
    // HBN runtime container is online. This is set here initially so once it is read it can be properly
    // used in the event that hbn crashes and can no longer read the actual version of hbn
    let hbn_device_names = HBNDeviceNames::hbn_23();

    let mut main_loop = MainLoop {
        forge_client_config,
        build_version,
        machine_id,
        periodic_config_reader,
        instance_metadata_state,
        client_cert_renewer,
        hbn_device_names,
        is_hbn_up: false,
        hbn_file_configs: hbn::HBNContainerFileConfigs::default(),
        seen_blank: false,
        has_logged_stable: false,
        version_check_time: std::time::Instant::now(),
        inventory_updater_time: std::time::Instant::now(),
        started_at: std::time::Instant::now(),
        inventory_updater_config,
        options,
        agent_config,
        forge_api_server,
        fmds_minimum_hbn_version,
        nvue_minimum_hbn_version,
        factory_mac_address,
        service_addrs,
        close_sender,
        network_monitor_handle,
        interface_state: None,
        extension_service_manager: extension_services::ExtensionServiceManager::default(),
    };

    main_loop.run().await
}

struct MainLoop {
    forge_client_config: Arc<ForgeClientConfig>,
    machine_id: MachineId,
    factory_mac_address: MacAddress,
    build_version: String,
    periodic_config_reader: Box<periodic_config_fetcher::PeriodicConfigFetcherReader>,
    instance_metadata_state: Arc<InstanceMetadataRouterStateImpl>,
    client_cert_renewer: ClientCertRenewer,
    hbn_device_names: HBNDeviceNames,
    is_hbn_up: bool,
    hbn_file_configs: hbn::HBNContainerFileConfigs,
    seen_blank: bool,
    has_logged_stable: bool,
    started_at: std::time::Instant,
    version_check_time: std::time::Instant,
    inventory_updater_time: std::time::Instant,
    inventory_updater_config: MachineInventoryUpdaterConfig,
    options: command_line::RunOptions,
    agent_config: AgentConfig,
    forge_api_server: String,
    fmds_minimum_hbn_version: Version<'static>,
    nvue_minimum_hbn_version: Version<'static>,
    service_addrs: ServiceAddresses,
    network_monitor_handle: Option<JoinHandle<()>>,
    close_sender: watch::Sender<bool>,
    interface_state: Option<ethernet_virtualization::InterfaceState>,
    extension_service_manager: extension_services::ExtensionServiceManager,
}

struct IterationResult {
    stop_agent: bool,
    loop_period: std::time::Duration,
}

impl MainLoop {
    /// Runs the MainLoop in endless mode
    async fn run(&mut self) -> Result<(), eyre::Report> {
        let mut term_signal = signal(SignalKind::terminate())?;
        let mut hup_signal = signal(SignalKind::hangup())?;

        loop {
            let result = self.run_single_iteration().await?;
            if result.stop_agent {
                return Ok(());
            }

            tokio::select! {
                biased;
                _ = term_signal.recv() => {
                    systemd::notify_stop().await?;
                    let _ = self.close_sender.send(true);
                    if let Some(handle) = self.network_monitor_handle.take() {
                        let _ = handle.await;
                    }
                    tracing::info!(version=carbide_version::v!(build_version), "TERM signal received, clean exit");
                    return Ok(());
                }
                _ = hup_signal.recv() => {
                    tracing::info!("Hangup received, timer reset");
                    let now = Instant::now();
                    self.client_cert_renewer.renew_on_next_check();
                    self.inventory_updater_time = now;
                    self.version_check_time = now;
                    // the loop_period sleep is interrupted so we will fetch new network config
                }
                _ = tokio::time::sleep(result.loop_period) => {}
            }
        }
    }

    /// Runs a single iteration of the main loop
    async fn run_single_iteration(&mut self) -> Result<IterationResult, eyre::Report> {
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
        let mut current_instance_id = None;
        let mut current_extension_service_version = None;

        let client_certificate_expiry_unix_epoch_secs =
            self.forge_client_config.client_cert_expiry();

        let fabric_interfaces = get_fabric_interfaces_data().await.unwrap_or_else(|err| {
            tracing::warn!("Error getting link data for fabric interfaces: {err:#}");
            vec![]
        });

        let mut status_out = rpc::DpuNetworkStatus {
            dpu_machine_id: Some(self.machine_id),
            dpu_health: None,
            dpu_agent_version: Some(self.build_version.clone()),
            observed_at: None, // None makes carbide-api set it on receipt
            network_config_version: None,
            instance_config_version: None,
            instance_network_config_version: None,
            interfaces: vec![],
            network_config_error: None,
            instance_id: None,
            client_certificate_expiry_unix_epoch_secs,
            fabric_interfaces,
            last_dhcp_requests: vec![],
            dpu_extension_service_version: None,
            dpu_extension_services: vec![],
        };

        let mut last_dhcp_requests = vec![];
        let mut dhcp_timestamps = DhcpTimestamps::new(DhcpTimestampsFilePath::Dpu);
        if let Err(e) = dhcp_timestamps.read() {
            tracing::warn!(
                "Failed to read from {}: {e}",
                DhcpTimestampsFilePath::Dpu.path_str()
            );
        }
        for (host_interface_id, timestamp) in dhcp_timestamps.into_iter() {
            last_dhcp_requests.push(rpc::LastDhcpRequest {
                host_interface_id: Some(host_interface_id),
                timestamp: timestamp.to_string(),
            });
        }
        status_out.last_dhcp_requests = last_dhcp_requests;

        // `read` does not block
        match self.periodic_config_reader.net_conf_read() {
            Some(conf) => {
                let instance_data = self.periodic_config_reader.meta_data_conf_reader();

                let proposed_routes: Vec<_> = conf
                    .tenant_interfaces
                    .iter()
                    .filter_map(|x| IpNetwork::from_str(x.prefix.as_str()).ok())
                    .collect();

                let tenant_peers = ethernet_virtualization::tenant_peers(&conf);
                if self.is_hbn_up {
                    // First thing is to read the existing HBN version and properly set the hbn device names
                    // associated with that version.
                    let hbn_version = hbn::read_version().await?;
                    let hbn_version = Version::from(hbn_version.as_str())
                        .ok_or(eyre::eyre!("Unable to convert string to version"))?;
                    // HBN changed their naming scheme in HBN 2.3 from _sf to _if so we will pass that little bit around
                    // after doing an initial version check instead of assuming _sf
                    self.hbn_device_names = HBNDeviceNames::new(hbn_version.clone());
                    // Now issue a one time per container runtime hack in the event the hack is needed for new DPU hardware
                    if let Err(err) = nvue::hack_platform_config_for_nvue().await {
                        tracing::error!(
                            error = format!("{err:#}"),
                            "Hacking the container platform config."
                        );
                    };

                    if let Err(e) = self.hbn_file_configs.ensure_configs().await {
                        tracing::error!(
                            "Error from HBNContainerFileConfigs::ensure_configs(): {e}"
                        );
                    }

                    tracing::trace!("Desired network config is {conf:?}");
                    // Generate the fmds interface plan from the config. This does not apply the plan.
                    // The plan is applied when the NVUE template is written
                    let fmds_proposed_interfaces = &self.agent_config.fmds_armos_networking;
                    let network_plan = DpuNetworkInterfaces::new(fmds_proposed_interfaces);

                    let fmds_interface_plan =
                        Interface::plan(self.hbn_device_names.sfs[0], network_plan).await?;
                    tracing::trace!("Interface plan: {:?}", fmds_interface_plan);

                    // Generate the fmds route plan from conf.tenant_interfaces[n].address
                    // the plan is applied when the nvue template is written
                    let route_plan =
                        plan_fmds_armos_routing(self.hbn_device_names.sfs[0], &proposed_routes)
                            .await?;
                    tracing::trace!("Route plan: {:?}", route_plan);

                    // Get the actual virtualization type to use for configuring
                    // an interface, where we'll default to reading the one provided
                    // by the Carbide API, with the ability to override via RunOptions.
                    let virtualization_type = effective_virtualization_type(
                        &conf,
                        &self.options,
                        &hbn_version,
                        &self.nvue_minimum_hbn_version,
                    )?;

                    let dhcp_result = ethernet_virtualization::update_dhcp(
                        &self.agent_config.hbn.root_dir,
                        &conf,
                        self.agent_config.hbn.skip_reload,
                        &self.service_addrs,
                        self.hbn_device_names.clone(),
                    )
                    .await;

                    let update_result = match virtualization_type {
                        VpcVirtualizationType::EthernetVirtualizer => {
                            ethernet_virtualization::update_files(
                                &self.agent_config.hbn.root_dir,
                                &conf,
                                self.agent_config.hbn.skip_reload,
                                self.hbn_device_names.clone(),
                            )
                            .await
                        }
                        VpcVirtualizationType::EthernetVirtualizerWithNvue
                        | VpcVirtualizationType::Fnn => {
                            if hbn_version >= self.fmds_minimum_hbn_version {
                                // Apply the interface plan. This is where we actually configure
                                // the FMDS phone home interface on the DPU.
                                Interface::apply(fmds_interface_plan).await?;

                                // If there are routes, apply the route plan. This is where we
                                // actually add and remove FMDS phone home routes.
                                //
                                // When a DPU has recently booted, there may not be a pf0dpu1
                                // interface configured yet, so routes may not be applied on the
                                // first tick of the loop. Once the interface is configured, routes
                                // can be added and removed.

                                // This means that routes will be added last and might take a few seconds
                                // to appear
                                if let Some(route_plan) = route_plan {
                                    Route::apply(route_plan).await?;
                                }
                            }

                            // We'll update some internal bridging config if bridging config
                            // for traffic_intercept was sent in.
                            let bridging_result = if conf
                                .traffic_intercept_config
                                .as_ref()
                                .map(|vc| vc.bridging.is_some())
                                .unwrap_or_default()
                            {
                                ethernet_virtualization::update_traffic_intercept_bridging(
                                    &conf,
                                    self.agent_config.hbn.skip_reload,
                                )
                                .await
                            } else {
                                Ok(false) // No errors and no change.
                            };

                            if bridging_result.is_ok() {
                                ethernet_virtualization::update_nvue(
                                    virtualization_type,
                                    &self.agent_config.hbn.root_dir,
                                    &conf,
                                    self.agent_config.hbn.skip_reload,
                                    self.hbn_device_names.clone(),
                                )
                                .await
                            } else {
                                bridging_result
                            }
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
                            if let Err(err) = mtu::ensure().await {
                                tracing::error!(error = %err, "Error reading/setting MTU for p0 or p1");
                            }

                            // Updating network config succeeded.
                            // Tell the server about the applied version.
                            status_out.network_config_version =
                                Some(conf.managed_host_config_version.clone());
                            status_out.instance_id = conf.instance_id;
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
                                                    tracing::warn!(
                                                        "Received instance_network_config_version via GetManagedHostNetworkConfig, but not via FindInstanceByMachineId. Acknowledging received version"
                                                    );
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

                            match ethernet_virtualization::interfaces(
                                &conf,
                                self.factory_mac_address,
                            )
                            .await
                            {
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

                    // In case of secondary DPU, physical interface must be disabled if on admin
                    // network, else enabled.
                    match ethernet_virtualization::update_interface_state(
                        &conf,
                        self.agent_config.hbn.skip_reload,
                        &self.hbn_device_names,
                        &self.interface_state,
                    )
                    .await
                    {
                        Ok(new_state) => {
                            self.interface_state = new_state;
                        }
                        Err(err) => {
                            tracing::error!(
                                error = format!("{err:#}"),
                                "Updating interface state."
                            );
                        }
                    };
                }

                // Feed the latest instance metadata to FMDS and acknowledge it
                // Note: Performing the update here instead of the FMDS mechanism directly
                // pulling the Metadata is preferred - since the mainloop will make sure
                // all the information (Instance Metadata and Network Config) is in sync.
                // It will guarantee that the Instance Config that is acknowledged to
                // carbide via the status message is actually visible to the tenant via
                // FMDS
                self.instance_metadata_state
                    .update_instance_data(instance_data.clone());
                self.instance_metadata_state
                    .update_network_configuration(Some(conf.clone()));
                status_out.instance_config_version = instance_data
                    .as_ref()
                    .map(|instance| instance.config_version.version_string());
                current_instance_config_version = status_out.instance_config_version.clone();
                current_instance_id = status_out.instance_id.as_ref().map(|id| id.to_string());

                let health_report = health::health_check(
                    &self.agent_config.hbn.root_dir,
                    &tenant_peers,
                    self.started_at,
                    has_changed_configs,
                    conf.min_dpu_functioning_links.unwrap_or(2),
                    &conf.route_servers,
                    self.hbn_device_names.clone(),
                )
                .await;
                is_healthy = !health_report.successes.is_empty() && health_report.alerts.is_empty();
                self.is_hbn_up = health::is_up(&health_report);
                // subset of is_healthy
                tracing::trace!(%self.machine_id, ?health_report, "HBN health");
                status_out.dpu_health = Some(health_report.clone().into());
                current_health_report = Some(health_report);
                current_config_error = status_out.network_config_error.clone();

                // Process extension services if configuration is available
                // If use_admin_network is true, it means the instance is being deleted,
                // so we mark all extension services as removed for termination
                let expected_extension_services = if conf.use_admin_network {
                    conf.dpu_extension_services
                        .clone()
                        .into_iter()
                        .map(|mut service| {
                            if service.removed.is_none() {
                                service.removed = Some(chrono::Utc::now().to_rfc3339());
                            }
                            service
                        })
                        .collect()
                } else {
                    conf.dpu_extension_services.clone()
                };

                if let Err(err) = self
                    .extension_service_manager
                    .update_desired_services(expected_extension_services.clone())
                    .await
                {
                    tracing::error!(
                        error = format!("{err:#}"),
                        "Failed to update extension services"
                    );
                }
                status_out.dpu_extension_service_version = instance_data
                    .as_ref()
                    .map(|instance| instance.extension_service_version.version_string());
                status_out.dpu_extension_services = self
                    .extension_service_manager
                    .get_service_statuses(expected_extension_services.clone())
                    .await
                    .unwrap_or_else(|err| {
                        tracing::error!(error = %err, "Error getting extension service statuses");
                        vec![]
                    });
                current_extension_service_version =
                    status_out.dpu_extension_service_version.clone();

                record_network_status(
                    status_out,
                    &self.forge_api_server,
                    &self.forge_client_config,
                )
                .await;
                self.seen_blank = false;
            }
            None => {
                // No network config means server can't find the DPU, usually because it was
                // force-deleted. Only reset network config the _second_ time we can't find the
                // DPU. Safety first.
                if self.seen_blank {
                    ethernet_virtualization::reset(
                        &self.agent_config.hbn.root_dir,
                        self.agent_config.hbn.skip_reload,
                    )
                    .await;
                }
                self.seen_blank = true;
                // we don't record_network_status because the server doesn't know about this DPU
            }
        };

        let now = Instant::now();
        self.client_cert_renewer
            .renew_certificates_if_necessary(None)
            .await;

        if now > self.inventory_updater_time {
            self.inventory_updater_time =
                now.add(self.inventory_updater_config.update_inventory_interval);
            if let Err(err) =
                machine_inventory_updater::single_run(&self.inventory_updater_config).await
            {
                tracing::error!(%err, "machine_inventory_updater error");
            }
        }

        if let result @ IterationResult {
            stop_agent: true, ..
        } = self.perform_upgrade_check(now).await
        {
            return Ok(result);
        }

        let loop_period = if self.seen_blank || !is_healthy || has_changed_configs {
            std::time::Duration::from_secs(self.agent_config.period.main_loop_active_secs)
        } else {
            if !self.has_logged_stable {
                tracing::info!("HBN is healthy and network configuration is stable");
                self.has_logged_stable = true;
            }
            std::time::Duration::from_secs(self.agent_config.period.main_loop_idle_secs)
        };

        let health_alerts = current_health_report
            .as_ref()
            .map(|report| report.alerts.as_slice())
            .unwrap_or_default();
        tracing::info!(
            is_healthy,
            has_changed_configs,
            self.seen_blank,
            num_health_probe_alerts = health_alerts.len(),
            health_probe_alerts = {
                let mut result = String::new();
                for alert in health_alerts.iter() {
                    if !result.is_empty() {
                        result.push(',');
                    }
                    if let Some(target) = &alert.target {
                        result += &format!("{} [Target: {}]: {}", alert.id, target, alert.message);
                    } else {
                        result += &format!("{}: {}", alert.id, alert.message);
                    }
                }
                result
            },
            write_config_error = current_config_error.unwrap_or_default(),
            managed_host_network_config_version = current_host_network_config_version.unwrap_or_default(),
            instance_id = current_instance_id.unwrap_or_default(),
            instance_network_config_version = current_instance_network_config_version.unwrap_or_default(),
            instance_config_version = current_instance_config_version.unwrap_or_default(),
            extension_service_version = current_extension_service_version.unwrap_or_default(),
            loop_duration = %dt(loop_start.elapsed()),
            version_check_in = %dt(self.version_check_time - Instant::now()),
            uptime = %dt(self.started_at.elapsed()),
            "loop metrics",
        );

        Ok(IterationResult {
            stop_agent: false,
            loop_period,
        })
    }

    async fn perform_upgrade_check(&mut self, now: std::time::Instant) -> IterationResult {
        if self.options.skip_upgrade_check {
            return IterationResult {
                stop_agent: false,
                loop_period: Default::default(),
            };
        }

        // We potentially restart at this point, so make it last in the loop
        if now > self.version_check_time {
            self.version_check_time = now.add(std::time::Duration::from_secs(
                self.agent_config.period.version_check_secs,
            ));
            let upgrade_result = upgrade::upgrade(
                &self.forge_api_server,
                &self.forge_client_config,
                &self.machine_id,
                self.agent_config.updates.override_upgrade_cmd.as_deref(),
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
                    return IterationResult {
                        stop_agent: true,
                        loop_period: Duration::from_secs(0),
                    };
                }
                Err(e) => {
                    tracing::error!(
                        self.forge_api_server,
                        error = format!("{e:#}"), // we need alt display for wrap_err_with to work well
                        "upgrade_check failed"
                    );
                }
            }
        }

        IterationResult {
            stop_agent: false,
            loop_period: Default::default(),
        }
    }
}

/// effective_virtualization_type returns the virtualization type
/// to use for generating configuration. This defaults to whatever
/// comes from Carbide API, with the ability to override with runtime
/// options.
///
/// It will fall back to ETV if all else fails.
fn effective_virtualization_type(
    conf: &ManagedHostNetworkConfigResponse,
    options: &RunOptions,
    hbn_version: &Version,
    nvue_minimum_hbn_version: &Version,
) -> eyre::Result<VpcVirtualizationType> {
    // First, grab the VpcVirtualizationType returned to us
    // from the Carbide API (which *should* be what comes from
    // the `network_virtualization_type` column from the `vpcs`
    // table for the VPC this DPU is in).
    //
    // This may be unset, which historically has just meant
    // to use ETV (EthernetVirtualizer), the pre-nvue one.
    let virtualization_type_from_remote = conf
        .network_virtualization_type
        .map(rpc::VpcVirtualizationType::try_from)
        .transpose()?
        .map(|v| v.into());

    // And now see if the remote virtualization type should be overwritten
    // by runtime options. If it's not, and the remote value was also unset,
    // then just use ETV, which has historically been the "default" when
    // no virtualization type is configured.
    let virtualization_type = options
        .override_network_virtualization_type // dev
        .or(virtualization_type_from_remote)
        .unwrap_or_else(|| {
            tracing::warn!(
                "Missing network_virtualization_type, defaulting to {}",
                DEFAULT_NETWORK_VIRTUALIZATION_TYPE
            );
            DEFAULT_NETWORK_VIRTUALIZATION_TYPE
        });

    // If the HBN version is older than the minimum required HBN version to
    // support NVUE, there are a couple of options here:
    // - If we're doing ETV-NVUE, we can just fall back to ETV safely.
    // - If we're doing an FNN-based config, we can't, so return an error.
    if hbn_version < nvue_minimum_hbn_version {
        match virtualization_type {
            VpcVirtualizationType::Fnn => {
                return Err(eyre::eyre!(
                    "{virtualization_type} virtualization requested, but site does not support NVUE. Cannot configure."
                ));
            }
            VpcVirtualizationType::EthernetVirtualizerWithNvue => {
                tracing::warn!(
                    "{virtualization_type} virtualization requested, but site does not support NVUE (HBN version {hbn_version} is too old). Using ETV."
                );
                return Ok(VpcVirtualizationType::EthernetVirtualizer);
            }
            // If it's already set to ETV, things are good. Log a debug
            // message just incase.
            VpcVirtualizationType::EthernetVirtualizer => {
                tracing::debug!(
                    "HBN version is below the NVUE minimum HBN version, but already set to non-NVUE virtualization. No changes needed."
                );
            }
        }
    }

    Ok(virtualization_type)
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
    forge_client_config: &forge_tls_client::ForgeClientConfig,
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

// Get the link type, carrier status, MTU, and whatever else for our uplinks
// into the network fabric.
//
// For a link to be considered an uplink, it must satisfy all of the following:
// 1. The network device is on a PCI bus.
// 2. The network device type is Ethernet.
// 3. The Ethernet MAC address is in the unicast+universal range (last two bits
//    of the first OUI byte are both set to 0).
async fn get_fabric_interfaces_data()
-> Result<Vec<rpc::FabricInterfaceData>, Box<dyn std::error::Error>> {
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

// Do horrible things to the DPU including an out of band, unknown to forge, reboot.
//
// If a DPU cannot load its 2.9 ATF/UEFI, issue hacky commands to force load it and reboot
// which actually does the loading of the ATU/UEFI. Upon reboot, the bfvcheck will be valid or
// the dpu will be left in a broken state because it was unable to load its ATF/UEFI and needs to
// be investigated.
async fn hack_dpu_os_to_load_atf_uefi_with_specific_versions() -> eyre::Result<()> {
    tracing::info!("attempting to verify the hack for specific versions");
    let bfvcheck_output: String = if cfg!(test) {
        let test_data_dir = PathBuf::from(crate::dpu::ARMOS_TEST_DATA_DIR);

        std::fs::read_to_string(test_data_dir.join("bfvcheck.out")).map_err(|e| {
            error!("Could not read bfvcheck.out: {e}");
            eyre::eyre!("Could not read bfvcheck.out: {}", e)
        })?
    } else {
        let mut cmd = tokio::process::Command::new("bash");
        cmd.args(vec!["-c", "bfvcheck"]);
        cmd.kill_on_drop(true);

        let cmd_str = pretty_cmd(cmd.as_std());

        // bfvcheck is taking around 11 seconds, and worse case is 30s
        // bump it to a minute just in case
        let output = tokio::time::timeout(crate::dpu::COMMAND_TIMEOUT * 6, cmd.output())
            .await
            .wrap_err_with(|| format!("Timeout while running command: {cmd_str:?}"))??;

        String::from_utf8_lossy(&output.stdout).to_string()
    };

    // The specific check is to see if we have not loaded but have a recommended ATF/UEFI is 2.9.
    // If this is the case, we have hit the "unable to load the ATF/UEFI because of the ugly bug"
    // condition, and it is the only time these commands are issued. The ATF/UEFI is immediately updated on
    // newer cards and after reboot on the older cards. Both need the reboot to properly populate the
    // redfish db as well.

    // these are colorized on bfvcheck output so instead of checking for ugly bash color codes, just
    // validate the actual strings
    if bfvcheck_output.clone().contains("WARNING: ATF VERSION DOES NOT MATCH RECOMMENDED!") &&
        bfvcheck_output.clone().contains("WARNING: UEFI VERSION DOES NOT MATCH RECOMMENDED!") &&
        // This is to ensure that the recommended is 4.9.3, meaning its only going to fix this if
        // moving to 4.9.3. This is done so that no older DPUs which may be operating under a customer
        // that have not properly updated but yet somehow became assigned. These DPUS are only in
        // this state because they are stuck in reprovisioning as part of the same release with
        // 4.9.3 included. If this check was deployed to production weeks after the update to 4.9.3,
        // there could be a problem with  assigned machines having 2.9.2 recommended but not loaded,
        // but if both releases drop at the same time, this state will only be seen during
        // reprovisioning / initial discovery.
        bfvcheck_output.clone().contains(
        "-RECOMMENDED VERSIONS-
ATF: v2.2(release):4.9.3-")
    && !cfg!(test)
    {
        tracing::info!(
            "bfvcheck output has identifed a situation in which it needs to load and \
                restart the DPU during install. This message should not print in logs multiple reboots. \
                If it does, the ATF/UEFI cannot be loaded and the card should be investigated."
        );
        let mut cmd = tokio::process::Command::new("bash");
        cmd.args(vec![
            "-c",
            "mlxbf-bootctl -s -b /lib/firmware/mellanox/boot/default.bfb -d /dev/mmcblk0",
        ]);
        cmd.kill_on_drop(true);

        let cmd_str = pretty_cmd(cmd.as_std());

        // This is not a typo, we have to run it twice as per NBU
        tokio::time::timeout(crate::dpu::COMMAND_TIMEOUT, cmd.output())
            .await
            .wrap_err_with(|| format!("Timeout while running command: {cmd_str:?}"))??;
        // This is not a typo, we have to run it twice as per NBU
        tokio::time::timeout(crate::dpu::COMMAND_TIMEOUT, cmd.output())
            .await
            .wrap_err_with(|| format!("Timeout while running command: {cmd_str:?}"))??;

        let mut cmd = tokio::process::Command::new("bash");
        cmd.args(vec!["-c", "sync"]);
        cmd.kill_on_drop(true);

        let cmd_str = pretty_cmd(cmd.as_std());
        tokio::time::timeout(crate::dpu::COMMAND_TIMEOUT, cmd.output())
            .await
            .wrap_err_with(|| format!("Timeout while running command: {cmd_str:?}"))??;

        // And now for the pièce de résistance, a reboot inline on the dpu OS, and this command
        // takes a LONG time so we will put an egregiously large reboot time
        let mut cmd = tokio::process::Command::new("bash");
        cmd.args(vec!["-c", "reboot"]);
        cmd.kill_on_drop(true);

        let cmd_str = pretty_cmd(cmd.as_std());
        tokio::time::timeout(Duration::from_secs(60 * 10), cmd.output())
            .await
            .wrap_err_with(|| format!("Timeout while running command: {cmd_str:?}"))??;
    }

    // This method will either reboot a card or just return ok.
    Ok(())
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
