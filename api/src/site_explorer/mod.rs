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

use std::{collections::HashMap, net::IpAddr, sync::Arc, time::Duration};

use mac_address::MacAddress;
use sqlx::PgPool;
use tokio::{sync::oneshot, task::JoinSet};
use tracing::Instrument;

use crate::{
    cfg::SiteExplorerConfig,
    db::{
        explored_endpoints::DbExploredEndpoint,
        explored_managed_host::DbExploredManagedHost,
        machine::Machine,
        machine_interface::MachineInterface,
        network_segment::{NetworkSegment, NetworkSegmentType},
        DatabaseError,
    },
    model::{
        config_version::ConfigVersion,
        site_explorer::{
            EndpointExplorationReport, EndpointType, ExploredEndpoint, ExploredManagedHost,
        },
    },
    CarbideError, CarbideResult,
};

mod endpoint_explorer;
pub use endpoint_explorer::EndpointExplorer;
mod metrics;
mod redfish_endpoint_explorer;
pub use redfish_endpoint_explorer::RedfishEndpointExplorer;

use self::metrics::{exploration_error_to_metric_label, SiteExplorationMetrics};

/// The SiteExplorer periodically runs [modules](machine_update_module::MachineUpdateModule) to initiate upgrades of machine components.
/// On each iteration the SiteExplorer will:
/// 1. collect the number of outstanding updates from all modules.
/// 2. if there are less than the max allowed updates each module will be told to start updates until
/// the number of updates reaches the maximum allowed.
///
/// Config from [CarbideConfig]:
/// * `max_concurrent_machine_updates` the maximum number of updates allowed across all modules
/// * `machine_update_run_interval` how often the manager calls the modules to start updates
pub struct SiteExplorer {
    database_connection: PgPool,
    enabled: bool,
    config: SiteExplorerConfig,
    instruments: Arc<metrics::SiteExplorerInstruments>,
    endpoint_explorer: Arc<dyn EndpointExplorer>,
}

impl SiteExplorer {
    const DB_LOCK_NAME: &'static str = "site_explorer_lock";
    const DB_LOCK_QUERY: &'static str =
        "SELECT pg_try_advisory_xact_lock((SELECT 'site_explorer_lock'::regclass::oid)::integer);";

    /// Create a SiteExplorer with the default modules.
    pub fn new(
        database_connection: sqlx::PgPool,
        config: Option<&SiteExplorerConfig>,
        meter: opentelemetry::metrics::Meter,
        endpoint_explorer: Arc<dyn EndpointExplorer>,
    ) -> Self {
        let instruments = Arc::new(metrics::SiteExplorerInstruments::new(&meter));

        let explorer_config = config.cloned().unwrap_or(SiteExplorerConfig {
            enabled: false,
            run_interval: 0,
            concurrent_explorations: 0,
            explorations_per_run: 0,
            create_machines: true,
        });
        SiteExplorer {
            database_connection,
            enabled: explorer_config.enabled,
            config: explorer_config,
            instruments,
            endpoint_explorer,
        }
    }

    /// Start the SiteExplorer and return a [sending channel](tokio::sync::oneshot::Sender) that will stop the SiteExplorer when dropped.
    pub fn start(self) -> eyre::Result<oneshot::Sender<i32>> {
        let (stop_sender, stop_receiver) = oneshot::channel();

        if self.enabled {
            tokio::task::Builder::new()
                .name("site_explorer")
                .spawn(async move { self.run(stop_receiver).await })?;
        }

        Ok(stop_sender)
    }

    async fn run(&self, mut stop_receiver: oneshot::Receiver<i32>) {
        loop {
            if let Err(e) = self.run_single_iteration().await {
                tracing::warn!("SiteExplorer error: {}", e);
            }

            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(self.config.run_interval)) => {},
                _ = &mut stop_receiver => {
                    tracing::info!("SiteExplorer stop was requested");
                    return;
                }
            }
        }
    }

    pub async fn run_single_iteration(&self) -> CarbideResult<()> {
        let mut metrics = SiteExplorationMetrics::new();

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::GenericError(format!("Failed to create transaction: {e}"))
        })?;

        if sqlx::query_scalar(SiteExplorer::DB_LOCK_QUERY)
            .fetch_one(&mut *txn)
            .await
            .unwrap_or(false)
        {
            tracing::trace!(
                lock = SiteExplorer::DB_LOCK_NAME,
                "SiteExplorer acquired the lock",
            );

            let span_id: String = format!("{:#x}", u64::from_le_bytes(rand::random::<[u8; 8]>()));

            let explore_site_span = tracing::span!(
                tracing::Level::INFO,
                "explore_site",
                span_id,
                start_time = format!("{:?}", chrono::Utc::now()),
                elapsed_us = tracing::field::Empty,
                otel.status_code = tracing::field::Empty,
                otel.status_message = tracing::field::Empty,
                identified_managed_hosts = tracing::field::Empty,
                endpoint_explorations = tracing::field::Empty,
                endpoint_explorations_success = tracing::field::Empty,
                endpoint_explorations_failures = tracing::field::Empty,
                endpoint_explorations_failures_by_type = tracing::field::Empty,
            );

            let res = self
                .explore_site(&mut metrics)
                .instrument(explore_site_span.clone())
                .await;
            let elapsed = metrics.start_time.elapsed();
            explore_site_span.record("elapsed_us", elapsed.as_micros());
            explore_site_span.record(
                "identified_managed_hosts",
                metrics.exploration_identified_managed_hosts,
            );
            explore_site_span.record("endpoint_explorations", metrics.endpoint_explorations);
            explore_site_span.record(
                "endpoint_explorations_success",
                metrics.endpoint_explorations_success,
            );
            explore_site_span.record(
                "endpoint_explorations_failures",
                metrics
                    .endpoint_explorations_failures_by_type
                    .values()
                    .sum::<usize>(),
            );
            explore_site_span.record(
                "endpoint_explorations_failures_by_type",
                serde_json::to_string(&metrics.endpoint_explorations_failures_by_type)
                    .unwrap_or_default(),
            );

            match &res {
                Ok(()) => {
                    explore_site_span.record("otel.status_code", "ok");
                }
                Err(e) => {
                    tracing::error!("SiteExplorer run failed due to: {:?}", e);
                    explore_site_span.record("otel.status_code", "error");
                    // Writing this field will set the span status to error
                    // Therefore we only write it on errors
                    explore_site_span.record("otel.status_message", format!("{:?}", e));
                }
            }

            self.instruments.emit(&metrics, &[]);

            res?;

            txn.commit().await.map_err(|e| {
                CarbideError::GenericError(format!("Failed to commit transaction: {e}"))
            })?;
        }

        Ok(())
    }

    async fn explore_site(&self, metrics: &mut SiteExplorationMetrics) -> CarbideResult<()> {
        self.update_explored_endpoints(metrics).await?;
        // Note/TODO:
        // Since we generate the managed-host pair in a different transaction than endpoint discovery,
        // the generation of both reports is not necessarily atomic.
        // This is improvable
        // However since host information rarely changes (we never reassign MachineInterfaces),
        // this should be ok. The most noticable effect is that ManagedHost population might be delayed a bit.
        self.update_explored_managed_hosts(metrics).await?;

        Ok(())
    }

    pub async fn create_managed_host(
        &self,
        dpu_report: &EndpointExplorationReport,
        explored_host: ExploredManagedHost,
    ) -> CarbideResult<(Machine, Machine)> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "begin load create_managed_host data", e)
        })?;

        let managed_host = dpu_report
            .create_managed_host(&mut txn, explored_host)
            .await?;

        txn.commit()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "end create_managed_host data", e))?;

        Ok(managed_host)
    }

    async fn update_explored_managed_hosts(
        &self,
        metrics: &mut SiteExplorationMetrics,
    ) -> CarbideResult<()> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "begin load update_explored_endpoints data",
                e,
            )
        })?;

        // TODO: We reload the endpoint list even though we just regenerated it
        // Could optimize this by keeping it in memory. But since the manipulations
        // are quite complicated in the previous step, this makes things much easier
        let explored_endpoints = DbExploredEndpoint::find_all(&mut txn).await?;

        let mut explored_dpus = Vec::new();
        let mut explored_hosts = Vec::new();
        for ep in explored_endpoints.into_iter() {
            if ep.report.endpoint_type != EndpointType::Bmc {
                continue;
            }
            if ep.report.is_dpu() {
                explored_dpus.push(ep);
            } else {
                explored_hosts.push(ep);
            }
        }

        // Match HOST and DPU using SerialNumber.
        // Compare DPU system.serial_number with HOST chassis.network_adapters[].serial_number
        let mut dpu_sn_to_endpoint = HashMap::new();
        for ep in explored_dpus.iter() {
            if let Some(sn) = ep
                .report
                .systems
                .get(0)
                .and_then(|system| system.serial_number.as_ref())
            {
                dpu_sn_to_endpoint.insert(sn, ep);
            }
        }

        let mut managed_hosts = Vec::new();
        'loop_hosts: for ep in explored_hosts {
            for chassis in ep.report.chassis.iter() {
                for net_adapter in chassis.network_adapters.iter() {
                    if net_adapter.serial_number.is_some() {
                        let sn = net_adapter.serial_number.as_ref().unwrap();
                        if let Some(dpu_ep) = dpu_sn_to_endpoint.get(&sn) {
                            let host_pf_mac_address = find_host_pf_mac_address(&ep, dpu_ep);
                            let explored_host = ExploredManagedHost {
                                host_bmc_ip: ep.address,
                                dpu_bmc_ip: dpu_ep.address,
                                host_pf_mac_address,
                            };
                            managed_hosts.push(explored_host.clone());

                            if self.config.create_machines {
                                if host_pf_mac_address.is_none() {
                                    tracing::warn!("Can't create managed host, since no factory MAC address for host: {:#?}", ep);
                                } else {
                                    match self
                                        .create_managed_host(&dpu_ep.report, explored_host)
                                        .await
                                    {
                                        Ok((dpu_machine, host_machine)) => {
                                            tracing::info!(
                                                "Created managed host: DPU({})<->PredictedHost({})",
                                                dpu_machine.id(),
                                                host_machine.id()
                                            );
                                        }
                                        Err(error) => {
                                            tracing::error!(%error, "Failed to create managed host");
                                        }
                                    }
                                }
                            }
                            metrics.exploration_identified_managed_hosts += 1;
                            continue 'loop_hosts;
                        }
                    }
                }
            }
        }

        DbExploredManagedHost::update(&mut txn, &managed_hosts).await?;

        txn.commit().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "end update_explored_endpoints data", e)
        })?;

        Ok(())
    }

    async fn update_explored_endpoints(
        &self,
        metrics: &mut SiteExplorationMetrics,
    ) -> CarbideResult<()> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "begin load update_explored_endpoints data",
                e,
            )
        })?;

        let underlay_segments =
            NetworkSegment::list_segment_ids(&mut txn, Some(NetworkSegmentType::Underlay)).await?;
        let interfaces = MachineInterface::find_all(&mut txn).await?;
        let explored_endpoints = DbExploredEndpoint::find_all(&mut txn).await?;
        txn.rollback().await.map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "end load update_explored_endpoints data",
                e,
            )
        })?;

        // We don't have to scan anything that is on the Tenant or Admin Segments,
        // since we know what those Segments are used for (Forge allocated the IPs on the segments
        // for a specific machine)
        let underlay_interfaces: Vec<MachineInterface> = interfaces
            .into_iter()
            .filter(|iface| underlay_segments.contains(&iface.segment_id()))
            .collect();

        let mut underlay_interfaces_by_address = HashMap::<IpAddr, &MachineInterface>::new();
        for iface in underlay_interfaces.iter() {
            for addr in iface.addresses() {
                underlay_interfaces_by_address.insert(addr.address, iface);
            }
        }

        let mut explored_endpoints_by_address = HashMap::<IpAddr, ExploredEndpoint>::new();
        for endpoint in explored_endpoints.into_iter() {
            explored_endpoints_by_address.insert(endpoint.address, endpoint);
        }

        // If a previously explored endpoint is not part of `MachineInterfaces` anymore,
        // we can delete knowledge about it. Otherwise we might try to refresh the
        // information about the endpoint
        let mut delete_endpoints = Vec::new();
        let mut update_endpoints = Vec::with_capacity(explored_endpoints_by_address.len());
        for (address, endpoint) in &explored_endpoints_by_address {
            match underlay_interfaces_by_address.get(address) {
                Some(iface) => {
                    update_endpoints.push((*address, *iface, endpoint));
                }
                None => delete_endpoints.push(*address),
            }
        }

        // The unknown endpoints can quickly be cleaned up
        if !delete_endpoints.is_empty() {
            let mut txn = self.database_connection.begin().await.map_err(|e| {
                DatabaseError::new(file!(), line!(), "begin delete unknown endpoints", e)
            })?;

            // TODO: Explore deleting all old endpoints in a single query, which would be more efficient
            // Since we practically never delete `MachineInterface`s anyway, this however isn't that important.
            for address in delete_endpoints.into_iter() {
                DbExploredEndpoint::delete(&mut txn, address).await?;
            }

            txn.commit().await.map_err(|e| {
                DatabaseError::new(file!(), line!(), "end delete unknown endpoints", e)
            })?;
        }

        // If there is a MachineInterface and no previously discovered information,
        // we need to detect it
        let mut unexplored_endpoints = Vec::with_capacity(
            underlay_interfaces_by_address
                .len()
                .saturating_sub(explored_endpoints_by_address.len()),
        );
        for (address, &iface) in &underlay_interfaces_by_address {
            if !explored_endpoints_by_address.contains_key(address) {
                unexplored_endpoints.push((*address, iface));
            }
        }

        // Now that we gathered the candidates for exploration, let's decide what
        // we are actually going to explore. The config limits the amount of explorations
        // per iteration.
        let num_explore_endpoints = (self.config.explorations_per_run as usize)
            .min(unexplored_endpoints.len() + update_endpoints.len());
        #[allow(clippy::type_complexity)]
        let mut explore_endpoint_data: Vec<(
            IpAddr,
            MachineInterface,
            Option<(ConfigVersion, EndpointExplorationReport)>,
        )> = Vec::with_capacity(num_explore_endpoints);
        // We prioritize all endpoints that we've never looked at
        for (address, iface) in unexplored_endpoints.iter().take(num_explore_endpoints) {
            explore_endpoint_data.push((*address, (*iface).clone(), None))
        }
        let remaining_explore_endpoints = num_explore_endpoints - explore_endpoint_data.len();
        // If we have any capacity available, we update knowledge about endpoints we looked at earlier on
        if remaining_explore_endpoints != 0 {
            // Sort endpoints so that we will replace the oldest report first
            update_endpoints.sort_by_key(|(_address, _machine_interface, endpoint)| {
                endpoint.report_version.timestamp()
            });
            for (address, iface, endpoint) in
                update_endpoints.iter().take(remaining_explore_endpoints)
            {
                explore_endpoint_data.push((
                    *address,
                    (*iface).clone(),
                    Some((endpoint.report_version, endpoint.report.clone())),
                ));
            }
        }

        let mut task_set = JoinSet::new();
        let concurrency_limiter = Arc::new(tokio::sync::Semaphore::new(
            self.config.concurrent_explorations as usize,
        ));

        for (address, iface, old_report) in explore_endpoint_data.into_iter() {
            let endpoint_exlorer = self.endpoint_explorer.clone();
            let concurrency_limiter = concurrency_limiter.clone();

            let _abort_handle = task_set.spawn(
                async move {
                    let start = std::time::Instant::now();

                    // Acquire a permit which will block more than `concurrent_explorations`
                    // tasks from running.
                    // Note that assigning the permit to a named variable is necessary
                    // to make it live until the end of the scope. Using `_` would
                    // immediately dispose the permit.
                    let _permit = concurrency_limiter
                        .acquire()
                        .await
                        .expect("Semaphore can't be closed");

                    let mut result = endpoint_exlorer
                        .explore_endpoint(
                            &address,
                            &iface,
                            old_report.as_ref().map(|report| &report.1),
                        )
                        .await;

                    // Try to generate a MachineId based on the retrieved data
                    if let Ok(report) = &mut result {
                        report.generate_machine_id();
                    }

                    (address, old_report, result, start.elapsed())
                }
                .in_current_span(),
            );
        }

        // We want for all tasks to run to completion here and therefore can't
        // return early until the `TaskSet` is fully consumed.
        // If we would return early then some tasks might still work on an object
        // even thought the next controller iteration already started.
        // Therefore we drain the `task_set` here completely and record all errors
        // before returning.
        let mut last_join_error: Option<tokio::task::JoinError> = None;
        let mut exploration_results = Vec::new();

        while let Some(result) = task_set.join_next().await {
            match result {
                Err(join_error) => {
                    last_join_error = Some(join_error);
                }
                Ok(result) => {
                    exploration_results.push(result);
                }
            }
        }

        // All subtasks finished. We now update the database
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "begin update endpoint information", e)
        })?;

        for (address, old_endpoint_report, result, exploration_duration) in
            exploration_results.into_iter()
        {
            metrics.endpoint_explorations += 1;
            metrics
                .endpoint_exploration_duration
                .push(exploration_duration);
            match &result {
                Ok(_) => metrics.endpoint_explorations_success += 1,
                Err(e) => {
                    *metrics
                        .endpoint_explorations_failures_by_type
                        .entry(exploration_error_to_metric_label(e))
                        .or_default() += 1;
                }
            }

            match old_endpoint_report {
                Some((old_version, mut old_report)) => {
                    match result {
                        Ok(report) => {
                            if old_report.endpoint_type == EndpointType::Unknown {
                                tracing::info!(
                                    address = %address,
                                    exploration_report = ?report,
                                    "Initial exploration of machine"
                                );
                            }
                            let _updated = DbExploredEndpoint::try_update(
                                address,
                                old_version,
                                &report,
                                &mut txn,
                            )
                            .await?;
                        }
                        Err(e) => {
                            // If an endpoint can not be explored we don't delete the known information, since it's
                            // still helpful. The failure might just be intermittent.
                            old_report.last_exploration_error = Some(e);
                            let _updated = DbExploredEndpoint::try_update(
                                address,
                                old_version,
                                &old_report,
                                &mut txn,
                            )
                            .await?;
                        }
                    }
                }
                None => {
                    match result {
                        Ok(report) => {
                            tracing::info!(
                                address = %address,
                                exploration_report = ?report,
                                "Initial exploration of machine"
                            );
                            DbExploredEndpoint::insert(address, &report, &mut txn).await?
                        }
                        Err(e) => {
                            // If an endpoint exploration failed we still track the result in the database
                            // That will avoid immmediatly retrying the exploration in the next run
                            let report = EndpointExplorationReport::new_with_error(e);
                            DbExploredEndpoint::insert(address, &report, &mut txn).await?
                        }
                    }
                }
            }
        }

        txn.commit().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "end update endpoint information", e)
        })?;

        if let Some(err) = last_join_error.take() {
            return Err(err.into());
        }

        Ok(())
    }
}

/// Identifies the MAC address that is used by the pf0 interface that
/// the DPU exposes to the host.
///
/// Note: This method uses MAC address prefix matching between a DPUs BMC
/// MAC address and any other MAC address on the system. This mechanism is not
/// necessarily 100% reliable, and might lead to incorrect results if the host
/// uses different NICs which uses similar MAC address ranges.
///
/// The method should be migrated to the DPU directly providing the
/// MAC address: https://redmine.mellanox.com/issues/3749837
fn find_host_pf_mac_address(
    host_ep: &ExploredEndpoint,
    dpu_ep: &ExploredEndpoint,
) -> Option<MacAddress> {
    let dpu_bmc_mac = match dpu_ep
        .report
        .managers
        .get(0)
        .and_then(|manager| manager.ethernet_interfaces.get(0))
        .and_then(|iface| iface.mac_address.clone())
    {
        Some(mac) => mac,
        _ => return None,
    };
    // Bmc  mac: a0:88:c2:08:80:97
    // Base mac: a0:88:c2:08:80:72
    let bmc_prefix: String = dpu_bmc_mac.chars().take(12).collect();

    for host_interface in host_ep
        .report
        .systems
        .iter()
        .flat_map(|sys| sys.ethernet_interfaces.iter())
    {
        let host_mac = match host_interface.mac_address.as_ref() {
            None => continue,
            Some(mac) => mac,
        };

        if host_mac.starts_with(bmc_prefix.as_str()) {
            match host_mac.parse::<MacAddress>() {
                Ok(mac) => return Some(mac),
                Err(_) => continue,
            };
        }
    }

    None
}
