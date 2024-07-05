/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::Arc,
};

use config_version::ConfigVersion;
use mac_address::MacAddress;
use sqlx::PgPool;
use tokio::{net::lookup_host, sync::oneshot, task::JoinSet};
use tracing::Instrument;

use crate::{
    cfg::{DpuDesc, DpuModel, SiteExplorerConfig},
    db::{
        bmc_metadata::BmcMetaDataUpdateRequest,
        expected_machine::ExpectedMachine,
        explored_endpoints::DbExploredEndpoint,
        explored_managed_host::DbExploredManagedHost,
        machine::{Machine, MachineSearchConfig},
        machine_interface::MachineInterface,
        machine_topology::MachineTopology,
        network_segment::{NetworkSegment, NetworkSegmentType},
        DatabaseError,
    },
    model::{
        bmc_info::BmcInfo,
        hardware_info::{DpuData, HardwareInfo},
        machine::{machine_id::MachineId, DpuDiscoveringState, ManagedHostState},
        site_explorer::{
            Chassis, EndpointExplorationReport, EndpointType, ExploredDpu, ExploredEndpoint,
            ExploredManagedHost, NicMode, Service,
        },
    },
    resource_pool::common::CommonPools,
    CarbideError, CarbideResult,
};

mod endpoint_explorer;
pub use endpoint_explorer::EndpointExplorer;
mod credentials;
mod metrics;
pub use metrics::SiteExplorationMetrics;
mod redfish;
mod redfish_endpoint_explorer;
pub use redfish_endpoint_explorer::RedfishEndpointExplorer;
mod identify;
pub use identify::{identify_bmc, IdentifyError};

use self::metrics::exploration_error_to_metric_label;

struct Endpoint {
    address: IpAddr,
    iface: MachineInterface,
    old_report: Option<(ConfigVersion, EndpointExplorationReport)>,
    pub(crate) expected: Option<ExpectedMachine>,
}

impl Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

impl Endpoint {
    fn new(
        address: IpAddr,
        iface: MachineInterface,
        old_report: Option<(ConfigVersion, EndpointExplorationReport)>,
    ) -> Self {
        Self {
            address,
            iface,
            old_report,
            expected: None,
        }
    }
}

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
    dpu_models: HashMap<DpuModel, DpuDesc>,
    metric_holder: Arc<metrics::MetricHolder>,
    endpoint_explorer: Arc<dyn EndpointExplorer>,
    common_pools: Arc<CommonPools>,
}

impl SiteExplorer {
    const DB_LOCK_NAME: &'static str = "site_explorer_lock";
    const DB_LOCK_QUERY: &'static str =
        "SELECT pg_try_advisory_xact_lock((SELECT 'site_explorer_lock'::regclass::oid)::integer);";

    pub fn new(
        database_connection: sqlx::PgPool,
        explorer_config: SiteExplorerConfig,
        dpu_models: &HashMap<DpuModel, DpuDesc>,
        meter: opentelemetry::metrics::Meter,
        endpoint_explorer: Arc<dyn EndpointExplorer>,
        common_pools: Arc<CommonPools>,
    ) -> Self {
        // We want to hold metrics for longer than the iteration interval, so there is continuity
        // in emitting metrics. However we want to avoid reporting outdated metrics in case
        // reporting gets stuck. Therefore round up the iteration interval by 1min.
        let hold_period = explorer_config
            .run_interval
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(meter, hold_period));
        metric_holder.register_callback();

        SiteExplorer {
            database_connection,
            enabled: explorer_config.enabled,
            config: explorer_config,
            dpu_models: dpu_models.clone(),
            metric_holder,
            endpoint_explorer,
            common_pools,
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
                _ = tokio::time::sleep(self.config.run_interval) => {},
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
                otel.status_code = tracing::field::Empty,
                otel.status_message = tracing::field::Empty,
                created_machines = tracing::field::Empty,
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
            explore_site_span.record(
                "identified_managed_hosts",
                metrics.exploration_identified_managed_hosts,
            );
            explore_site_span.record("created_machines", metrics.created_machines);
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

            // Cache all other metrics that have been captured in this iteration.
            // Those will be queried by OTEL on demand
            self.metric_holder.update_metrics(metrics);

            res?;

            txn.commit().await.map_err(|e| {
                CarbideError::GenericError(format!("Failed to commit transaction: {e}"))
            })?;
        }

        Ok(())
    }

    async fn explore_site(&self, metrics: &mut SiteExplorationMetrics) -> CarbideResult<()> {
        self.check_preconditions(metrics).await?;

        self.update_explored_endpoints(metrics).await?;
        // Note/TODO:
        // Since we generate the managed-host pair in a different transaction than endpoint discovery,
        // the generation of both reports is not necessarily atomic.
        // This is improvable
        // However since host information rarely changes (we never reassign MachineInterfaces),
        // this should be ok. The most noticable effect is that ManagedHost population might be delayed a bit.
        let identified_hosts = self.identify_managed_hosts(metrics).await?;

        if **self.config.create_machines.load() {
            self.create_machines(metrics, identified_hosts).await?;
        }

        Ok(())
    }

    /// Creates a new ManagedHost (Host `Machine` and DPU `Machine` pair)
    /// for each ManagedHost that was identified and that doesn't have a corresponding `Machine` yet
    async fn create_machines(
        &self,
        metrics: &mut SiteExplorationMetrics,
        explored_managed_hosts: Vec<ExploredManagedHost>,
    ) -> CarbideResult<()> {
        // TODO: Improve the efficiency of this method. Right now we perform 3 database transactions
        // for every identified ManagedHost even if we don't create any objects.
        // We can perform a single query upfront to identify which ManagedHosts don't yet have Machines
        for host in explored_managed_hosts {
            match self
                .create_managed_host(&host, &self.database_connection)
                .await
            {
                Ok(true) => metrics.created_machines += 1,
                Ok(false) => {}
                Err(error) => tracing::error!(%error, "Failed to create managed host"),
            }
        }

        Ok(())
    }

    /// Creates a `Machine` objects for an identified `ManagedHost` with initial states
    ///
    /// Returns `true` if new `Machine` objects have been created or `false` otherwise
    pub async fn create_managed_host(
        &self,
        explored_host: &ExploredManagedHost,
        pool: &PgPool,
    ) -> CarbideResult<bool> {
        let mut txn = pool.begin().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "begin load create_machine_pair", e)
        })?;

        let mut host_machine_id: Option<MachineId> = None;

        for (i, dpu_report) in explored_host.dpus.iter().enumerate() {
            self.can_visit(dpu_report)?;

            let dpu_machine_id = dpu_report.report.machine_id.as_ref().unwrap();

            let (dpu_machine, is_new) =
                match Machine::find_one(&mut txn, dpu_machine_id, MachineSearchConfig::default())
                    .await?
                {
                    // Do nothing if machine exists. It'll be reprovisioned via redfish
                    Some(m) => (m, false),
                    None => match Machine::create(
                        &mut txn,
                        dpu_machine_id,
                        ManagedHostState::DpuDiscoveringState {
                            discovering_state: DpuDiscoveringState::Initializing,
                        },
                    )
                    .await
                    {
                        Ok(m) => {
                            tracing::info!("Created DPU machine with id: {}", dpu_machine_id);
                            (m, true)
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Can't create Machine");
                            return Err(e);
                        }
                    },
                };
            if !is_new {
                return Ok(false);
            }

            let (mut network_config, version) = dpu_machine.network_config().clone().take();
            if network_config.loopback_ip.is_none() {
                let loopback_ip = Machine::allocate_loopback_ip(
                    &self.common_pools,
                    &mut txn,
                    &dpu_machine_id.to_string(),
                )
                .await?;
                network_config.loopback_ip = Some(loopback_ip);
            }
            network_config.use_admin_network = Some(true);
            Machine::try_update_network_config(&mut txn, dpu_machine_id, version, &network_config)
                .await
                .map_err(CarbideError::from)?;

            let serial_number = dpu_report
                .report
                .systems
                .first()
                .and_then(|system| system.serial_number.as_ref())
                .unwrap();
            let dmi_data = dpu_report
                .report
                .create_temporary_dmi_data(serial_number.as_str());

            let chassis_map = dpu_report
                .report
                .chassis
                .clone()
                .into_iter()
                .map(|x| (x.id.clone(), x))
                .collect::<HashMap<_, _>>();
            let inventory_map = dpu_report.report.get_inventory_map();

            let dpu_data = DpuData {
                factory_mac_address: dpu_report
                    .host_pf_mac_address
                    .ok_or(CarbideError::MissingArgument("Missing base mac"))?
                    .to_string(),
                part_number: chassis_map
                    .get("Card1")
                    .and_then(|value: &Chassis| value.part_number.as_ref())
                    .unwrap_or(&"".to_string())
                    .to_string(),
                part_description: chassis_map
                    .get("Card1")
                    .and_then(|value| value.model.as_ref())
                    .unwrap_or(&"".to_string())
                    .to_string(),
                firmware_version: inventory_map
                    .get("DPU_NIC")
                    .and_then(|value| value.version.as_ref())
                    .unwrap_or(&"".to_string())
                    .to_string(),
                firmware_date: inventory_map
                    .get("DPU_NIC")
                    .and_then(|value| value.release_date.as_ref())
                    .unwrap_or(&"".to_string())
                    .to_string(),
                ..Default::default()
            };

            let hardware_info = HardwareInfo {
                dmi_data: Some(dmi_data),
                dpu_info: Some(dpu_data),
                machine_type: "aarch64".to_string(),
                ..Default::default()
            };

            let _topology =
                MachineTopology::create_or_update(&mut txn, dpu_machine_id, &hardware_info).await?;

            // Forge scout will update this topology with a full information.
            MachineTopology::set_topology_update_needed(&mut txn, dpu_machine_id, true).await?;

            let bmc_info = BmcInfo {
                ip: Some(dpu_report.bmc_ip.to_string()),
                mac: dpu_report.report.managers.first().and_then(|m| {
                    m.ethernet_interfaces
                        .first()
                        .and_then(|e| e.mac_address.clone())
                }),
                firmware_version: Some(
                    inventory_map
                        .iter()
                        .find(|s| s.0.contains("BMC_Firmware"))
                        .and_then(|value| value.1.version.as_ref())
                        .unwrap_or(&"".to_string())
                        .to_lowercase()
                        .replace("bf-", ""),
                ),
                ..Default::default()
            };

            let bmc_metadata = BmcMetaDataUpdateRequest {
                machine_id: dpu_machine_id.clone(),
                bmc_info,
            };

            bmc_metadata
                .update_bmc_network_into_topologies(&mut txn)
                .await?;

            if i == 0 {
                // Create Host proactively.
                // In case host interface is created, this method will return existing one, instead
                // creating new everytime.
                let machine_interface =
                    MachineInterface::create_host_machine_interface_proactively(
                        &mut txn,
                        Some(&hardware_info),
                        dpu_machine_id,
                    )
                    .await?;

                // Create host machine with temporary ID if no machine is attached.
                if machine_interface.machine_id.is_some() {
                    return Err(CarbideError::GenericError(
                        format!(
                            "Machine id: {} attached to network interface",
                            machine_interface.machine_id.unwrap()
                        )
                        .to_string(),
                    ));
                }

                let predicted_machine_id =
                    MachineId::host_id_from_dpu_hardware_info(&hardware_info).map_err(|e| {
                        CarbideError::InvalidArgument(format!("hardware info missing: {e}"))
                    })?;
                let mi_id = machine_interface.id;
                let host_machine = Machine::create(
                    &mut txn,
                    &predicted_machine_id,
                    ManagedHostState::DpuDiscoveringState {
                        discovering_state: DpuDiscoveringState::Initializing,
                    },
                )
                .await?;
                tracing::info!(
                    ?mi_id,
                    machine_id = %host_machine.id(),
                    "Created host machine proactively in site-explorer",
                );
                host_machine_id = Some(host_machine.id().clone());

                machine_interface
                    .associate_interface_with_machine(&mut txn, host_machine.id())
                    .await?;
                let host_hardware_info = HardwareInfo::default();
                let _topology = MachineTopology::create_or_update(
                    &mut txn,
                    &predicted_machine_id,
                    &host_hardware_info,
                )
                .await?;

                // Forge scout will update this topology with a full information.
                MachineTopology::set_topology_update_needed(&mut txn, &predicted_machine_id, true)
                    .await?;

                let host_bmc_info = BmcInfo {
                    ip: Some(explored_host.host_bmc_ip.to_string()),
                    ..Default::default()
                };

                let host_bmc_metadata = BmcMetaDataUpdateRequest {
                    machine_id: predicted_machine_id.clone(),
                    bmc_info: host_bmc_info,
                };

                host_bmc_metadata
                    .update_bmc_network_into_topologies(&mut txn)
                    .await?;
            } else {
                let machine_interface =
                    MachineInterface::create_host_machine_interface_proactively(
                        &mut txn,
                        Some(&hardware_info),
                        dpu_machine_id,
                    )
                    .await?;
                machine_interface
                    .set_primary_interface(&mut txn, false)
                    .await?;
                let host_id = host_machine_id
                    .as_ref()
                    .ok_or(CarbideError::GenericError("No host machine id".to_string()))?
                    .clone();
                machine_interface
                    .associate_interface_with_machine(&mut txn, &host_id)
                    .await?;
            }
        }

        txn.commit()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "end create_machine_pair", e))?;

        Ok(true)
    }

    async fn identify_managed_hosts(
        &self,
        metrics: &mut SiteExplorationMetrics,
    ) -> CarbideResult<Vec<ExploredManagedHost>> {
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
        let explored_endpoints =
            DbExploredEndpoint::find_all_preingestion_complete(&mut txn).await?;

        let mut explored_dpus = HashMap::new();
        let mut explored_hosts = HashMap::new();
        for ep in explored_endpoints.into_iter() {
            if ep.report.endpoint_type != EndpointType::Bmc {
                continue;
            }
            if ep.report.is_dpu() {
                explored_dpus.insert(ep.address, ep);
            } else {
                explored_hosts.insert(ep.address, ep);
            }
        }

        // Match HOST and DPU using SerialNumber.
        // Compare DPU system.serial_number with HOST chassis.network_adapters[].serial_number
        let mut dpu_sn_to_endpoint = HashMap::new();
        for ep in explored_dpus.values() {
            if let Some(sn) = ep
                .report
                .systems
                .first()
                .and_then(|system| system.serial_number.as_ref())
            {
                dpu_sn_to_endpoint.insert(sn.trim(), ep);
            }
        }

        let mut managed_hosts = Vec::new();
        for ep in explored_hosts.values() {
            // the list of DPUs that the site-explorer has explored for this host
            let mut dpus_explored_for_host: Vec<ExploredDpu> = Vec::new();
            // the number of DPUs that the host reports are attached to it
            let mut expected_num_dpus_attached_to_host = 0;
            for chassis in ep.report.chassis.iter() {
                for net_adapter in chassis.network_adapters.iter() {
                    if net_adapter.is_bluefield() {
                        // is_bluefield currently returns true if a network adapter is BF2 DPU, BF3 DPU, or BF3 Super NIC
                        expected_num_dpus_attached_to_host += 1;
                    }

                    if net_adapter.serial_number.is_some() {
                        let sn = net_adapter.serial_number.as_ref().unwrap().trim();
                        if let Some(dpu_ep) = dpu_sn_to_endpoint.get(sn) {
                            // We do not want to attach bluefields that are in NIC mode as DPUs to the host
                            if dpu_ep.report.nic_mode().is_some_and(|m| m == NicMode::Nic) {
                                expected_num_dpus_attached_to_host -= 1;
                                tracing::info!(
                                    address = %dpu_ep.address,
                                    exploration_report = ?dpu_ep.report,
                                    "discovered bluefield in NIC mode attached to host {}",
                                    ep.address
                                );
                                continue;
                            }
                            let host_pf_mac_address = match find_host_pf_mac_address(dpu_ep) {
                                Ok(m) => Some(m),
                                Err(error) => {
                                    tracing::error!(%error, dpu_ip = %dpu_ep.address, "Failed to find base mac address for DPU");
                                    None
                                }
                            };
                            dpus_explored_for_host.push(ExploredDpu {
                                bmc_ip: dpu_ep.address,
                                host_pf_mac_address,
                                report: dpu_ep.report.clone(),
                            });
                        }
                    }
                }
            }

            // The site explorer should only create a managed host after exploring all of the DPUs attached to the host.
            // If a host reports that it has two DPUs, the site explorer must wait until **both** DPUs have made the DHCP request.
            // If only one of the two DPUs have made the DHCP request, the site explorer must wait until it has explored the latter DPU's BMC
            // (ensuring that the second DPU has also made the DHCP request).
            if dpus_explored_for_host.is_empty()
                || dpus_explored_for_host.len() != expected_num_dpus_attached_to_host
            {
                tracing::info!(
                    address = %ep.address,
                    exploration_report = ?ep,
                    "cannot identify managed host because the site explorer has only discovered {} out of the {} attached DPUs:\n{:#?}",
                    dpus_explored_for_host.len(), expected_num_dpus_attached_to_host, dpus_explored_for_host
                );
                continue;
            }

            dpus_explored_for_host.sort_by_key(|d| {
                d.report.systems[0]
                    .serial_number
                    .clone()
                    .unwrap_or("".to_string())
                    .to_lowercase()
            });
            managed_hosts.push(ExploredManagedHost {
                host_bmc_ip: ep.address,
                dpus: dpus_explored_for_host,
            });
            metrics.exploration_identified_managed_hosts += 1;
        }

        DbExploredManagedHost::update(&mut txn, &managed_hosts).await?;

        txn.commit().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "end update_explored_endpoints data", e)
        })?;

        Ok(managed_hosts)
    }

    /// Checks if all data that a site exploration run requires is actually configured
    ///
    /// Doing this upfront avoids the risk of trying to log into BMCs without
    /// the necessary credentials - which could trigger a lockout.
    async fn check_preconditions(&self, metrics: &mut SiteExplorationMetrics) -> CarbideResult<()> {
        self.endpoint_explorer
            .check_preconditions(metrics)
            .await
            .map_err(|e| CarbideError::GenericError(e.to_string()))
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
        let mut explore_endpoint_data = Vec::with_capacity(num_explore_endpoints);
        // We prioritize all endpoints that we've never looked at
        for (address, iface) in unexplored_endpoints.iter().take(num_explore_endpoints) {
            explore_endpoint_data.push(Endpoint::new(*address, (*iface).clone(), None))
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
                explore_endpoint_data.push(Endpoint::new(
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

        let macs = explore_endpoint_data
            .iter()
            .map(|d| d.iface.mac_address)
            .collect::<Vec<_>>();
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "begin find_many_by_bmc_mac_address", e)
        })?;
        let mut expected = ExpectedMachine::find_many_by_bmc_mac_address(&mut txn, &macs).await?;
        txn.commit().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "end find_many_by_bmc_mac_address", e)
        })?;

        for endpoint in explore_endpoint_data.iter_mut() {
            endpoint.expected = expected.remove(&endpoint.iface.mac_address);
        }

        for endpoint in explore_endpoint_data.into_iter() {
            let endpoint_explorer = self.endpoint_explorer.clone();
            let concurrency_limiter = concurrency_limiter.clone();

            let bmc_target_port = self.config.override_target_port.unwrap_or(443);
            let bmc_target_addr = match self.config.override_target_ip.as_ref() {
                Some(override_ip) => {
                    let addr = match lookup_host((override_ip.as_str(), bmc_target_port)).await {
                        Ok(mut sockaddr) => sockaddr.next(),
                        Err(e) => {
                            tracing::warn!("Could not find override addr: {e}");
                            return Err(CarbideError::GenericError(e.to_string()));
                        }
                    };
                    let Some(addr) = addr else {
                        tracing::warn!("Could not find override addr");
                        return Err(CarbideError::GenericError(
                            "Could not find override addr".to_string(),
                        ));
                    };

                    addr
                }
                None => SocketAddr::new(endpoint.address, bmc_target_port),
            };

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

                    let mut result = endpoint_explorer
                        .explore_endpoint(
                            bmc_target_addr,
                            &endpoint.iface,
                            endpoint.expected,
                            endpoint.old_report.as_ref().map(|report| &report.1),
                        )
                        .await;

                    // Try to generate a MachineId based on the retrieved data
                    if let Ok(report) = &mut result {
                        report.generate_machine_id();
                    }

                    (
                        endpoint.address,
                        endpoint.old_report,
                        result,
                        start.elapsed(),
                    )
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
                    if !**self.config.create_machines.load() {
                        // We're using manual ingestion, making preingestion updates risky.  Go ahead and skip them.
                        DbExploredEndpoint::set_preingestion_complete(address, &mut txn).await?
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

    fn can_visit(&self, explored_dpu: &ExploredDpu) -> CarbideResult<()> {
        explored_dpu.has_valid_report()?;
        explored_dpu.has_valid_firmware(&self.dpu_models)?;
        Ok(())
    }
}

pub fn get_sys_image_version(services: &[Service]) -> Result<String, String> {
    let Some(service) = services.iter().find(|s| s.id == "FirmwareInventory") else {
        return Err("Missing FirmwareInventory".to_string());
    };

    let Some(image) = service
        .inventories
        .iter()
        .find(|inv| inv.id == "DPU_SYS_IMAGE")
    else {
        return Err("Missing DPU_SYS_IMAGE".to_string());
    };

    image
        .version
        .clone()
        .ok_or("Missing DPU_SYS_IMAGE version".to_string())
}

/// Identifies the MAC address that is used by the pf0 interface that
/// the DPU exposes to the host.
///
/// According "MAC and GUID allocation and assignment" document
///
/// Ethernet only require allocation of MAC address. Similarly,
/// IB only requires GUID allocation. Yet, since Mellanox devices support RoCE,
/// NIC cards require allocation of GUID addresses. Similarly, since IB supports
/// IP traffic HCA cards require allocation of MAC addresses.
/// As both MAC addresses and GUID addresses are allocated together, there is a
/// correlation between these 2 values. Unfortunately the translation from MAC
/// address to GUID and vice-versa is inconsistent between different platforms and operating systems.
/// To assure that this will not cause future issues, it is required that future
/// devices will not rely on any conversion formulas between MAC and GUID values,
/// and that these values will be explicitly stored in the device’s nonvolatile memory.
///
/// Assumption:
/// redfish/v1/UpdateService/FirmwareInventory/DPU_SYS_IMAGE(Version)
/// is identical to
/// flint -d /dev/mst/mt*_pciconf0 q full (BASE GUID)
///
/// Details:
/// redfish/v1/UpdateService/FirmwareInventory/DPU_SYS_IMAGE
/// is taken from /sys/class/infiniband/mlx*_<port>/sys_image_guid
///
/// Example:
/// DPU_SYS_IMAGE: a088:c203:0046:0c68
/// Base GUID: a088c20300460c68
/// Base MAC:  a088c2    460c68
/// Note: 0300 in the middle looks as a constant for dpu
///
/// redfish/v1/UpdateService/FirmwareInventory/DPU_SYS_IMAGE
/// "Version": "a088:c203:0046:0c68"
///
/// ibdev2netdev -v
/// 0000:31:00.0 mlx5_0 (MT41692 - 900-9D3B6-00CV-AA0) BlueField-3 P-Series DPU 200GbE/NDR200 dual-port QSFP112,
/// PCIe Gen5.0 x16 FHHL, Crypto Enabled, 32GB DDR5, BMC, Tall Bracket  fw 32.37.1306 port 1 (DOWN  ) ==> ens3np0 (Down)
///
/// cat /sys/class/infiniband/mlx5_0/sys_image_guid
/// a088:c203:0046:0c68
///
/// ip link show ens3np0
/// 6: ens3np0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
/// link/ether a0:88:c2:46:0c:68 brd ff:ff:ff:ff:ff:ff
///
/// The method should be migrated to the DPU directly providing the
/// MAC address: https://redmine.mellanox.com/issues/3749837
fn find_host_pf_mac_address(dpu_ep: &ExploredEndpoint) -> Result<MacAddress, String> {
    let mut base_mac = get_sys_image_version(dpu_ep.report.service.as_ref())?;
    if base_mac.len() != 19 {
        return Err(format!("Invalid base_mac length: {}", base_mac.len()));
    }
    base_mac = base_mac.replace(':', "");
    if base_mac.len() != 16 {
        return Err(format!(
            "Invalid base_mac length after removing ':': {}",
            base_mac.len()
        ));
    }

    base_mac.replace_range(6..10, "");
    base_mac.insert(10, ':');
    base_mac.insert(8, ':');
    base_mac.insert(6, ':');
    base_mac.insert(4, ':');
    base_mac.insert(2, ':');

    MacAddress::from_str(base_mac.as_str())
        .map_err(|_| format!("Invalid MAC address format: {}", base_mac.as_str()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::site_explorer::PreingestionState;

    fn load_bf2_ep_report() -> EndpointExplorationReport {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/site_explorer/test_data/bf2_report.json"
        );
        let report: EndpointExplorationReport =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(!report.systems.is_empty());
        assert!(!report.managers.is_empty());
        assert!(!report.chassis.is_empty());
        assert!(!report.service.is_empty());
        report
    }

    fn load_dell_ep_report() -> EndpointExplorationReport {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/site_explorer/test_data/dell_report.json"
        );
        let report: EndpointExplorationReport =
            serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert!(!report.systems.is_empty());
        assert!(!report.managers.is_empty());
        assert!(!report.chassis.is_empty());
        assert!(report.service.is_empty());
        report
    }

    #[test]
    fn test_load_dell_report() {
        let _ = load_dell_ep_report();
    }

    #[test]
    fn test_find_host_pf_mac_address() {
        let ep_report: EndpointExplorationReport = load_bf2_ep_report();
        let ep = ExploredEndpoint {
            address: "10.217.132.202".parse().unwrap(),
            report: ep_report,
            report_version: ConfigVersion::initial(),
            preingestion_state: PreingestionState::Initial,
            waiting_for_explorer_refresh: false,
        };

        assert_eq!(
            find_host_pf_mac_address(&ep).unwrap(),
            "B8:3F:D2:90:95:F4".parse().unwrap()
        );

        // Invalid DPU_SYS_IMAGE field
        let mut ep1 = ep.clone();
        let update_service = ep1
            .report
            .service
            .iter_mut()
            .find(|s| s.id == "FirmwareInventory")
            .unwrap();
        let inv = update_service
            .inventories
            .iter_mut()
            .find(|inv| inv.id == "DPU_SYS_IMAGE")
            .unwrap();
        inv.version = Some("b83f:d203:0090:95fz".to_string());
        assert_eq!(
            find_host_pf_mac_address(&ep1),
            Err("Invalid MAC address format: b8:3f:d2:90:95:fz".to_string())
        );

        // Invalid DPU_SYS_IMAGE field
        let mut ep1 = ep.clone();
        let update_service = ep1
            .report
            .service
            .iter_mut()
            .find(|s| s.id == "FirmwareInventory")
            .unwrap();
        let inv = update_service
            .inventories
            .iter_mut()
            .find(|inv| inv.id == "DPU_SYS_IMAGE")
            .unwrap();
        inv.version = Some("abc".to_string());
        assert_eq!(
            find_host_pf_mac_address(&ep1),
            Err("Invalid base_mac length: 3".to_string())
        );

        // Missing DPU_SYS_IMAGE field
        let mut ep1 = ep.clone();
        let update_service = ep1
            .report
            .service
            .iter_mut()
            .find(|s| s.id == "FirmwareInventory")
            .unwrap();
        update_service
            .inventories
            .retain_mut(|inv| inv.id != "DPU_SYS_IMAGE");
        assert_eq!(
            find_host_pf_mac_address(&ep1),
            Err("Missing DPU_SYS_IMAGE".to_string())
        );

        // Missing FirmwareInventory field
        let mut ep1 = ep.clone();
        ep1.report
            .service
            .retain_mut(|inv| inv.id != "FirmwareInventory");
        assert_eq!(
            find_host_pf_mac_address(&ep1),
            Err("Missing FirmwareInventory".to_string())
        );
    }
}
