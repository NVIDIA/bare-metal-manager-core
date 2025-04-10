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
    collections::{HashMap, HashSet},
    fmt::Display,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use chrono::Utc;
use config_version::ConfigVersion;
use itertools::Itertools;
use libredfish::model::oem::nvidia_dpu::NicMode;
use mac_address::MacAddress;
use managed_host::ManagedHost;
use sqlx::{PgPool, Postgres, Transaction};
use tokio::{sync::oneshot, task::JoinSet};
use tracing::Instrument;

use crate::{
    CarbideError, CarbideResult,
    cfg::file::{FirmwareComponentType, FirmwareConfig, SiteExplorerConfig},
    db::{
        self, DatabaseError, ObjectFilter,
        expected_machine::ExpectedMachine,
        explored_endpoints::DbExploredEndpoint,
        explored_managed_host::DbExploredManagedHost,
        machine::MachineSearchConfig,
        machine_topology::MachineTopology,
        network_segment::{NetworkSegment, NetworkSegmentType},
    },
    model::{
        bmc_info::BmcInfo,
        hardware_info::HardwareInfo,
        machine::{
            DpuDiscoveringState, DpuDiscoveringStates, MachineInterfaceSnapshot, ManagedHostState,
            machine_id::host_id_from_dpu_hardware_info,
        },
        metadata::Metadata,
        site_explorer::{
            EndpointExplorationError, EndpointExplorationReport, EndpointType, ExploredDpu,
            ExploredEndpoint, ExploredManagedHost, MachineExpectation, PowerState,
            PreingestionState, Service, is_bf3_dpu, is_bf3_supernic, is_bluefield_model,
        },
    },
    resource_pool::common::CommonPools,
};
use forge_network::sanitized_mac;
use forge_uuid::machine::{MachineId, MachineType};

mod endpoint_explorer;
pub use endpoint_explorer::EndpointExplorer;
mod credentials;
mod metrics;
pub use metrics::SiteExplorationMetrics;
mod bmc_endpoint_explorer;
mod redfish;
pub use bmc_endpoint_explorer::BmcEndpointExplorer;

mod managed_host;
use self::metrics::exploration_error_to_metric_label;
use crate::db::predicted_machine_interface::{
    NewPredictedMachineInterface, PredictedMachineInterface,
};
use crate::db::{ObjectColumnFilter, predicted_machine_interface};
use crate::model::machine::Machine;
pub use managed_host::is_endpoint_in_managed_host;

#[derive(Debug, Clone)]
pub struct Endpoint {
    address: IpAddr,
    iface: MachineInterfaceSnapshot,
    last_redfish_bmc_reset: Option<chrono::DateTime<chrono::Utc>>,
    last_ipmitool_bmc_reset: Option<chrono::DateTime<chrono::Utc>>,
    last_redfish_reboot: Option<chrono::DateTime<chrono::Utc>>,
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
        iface: MachineInterfaceSnapshot,
        last_redfish_bmc_reset: Option<chrono::DateTime<chrono::Utc>>,
        last_ipmitool_bmc_reset: Option<chrono::DateTime<chrono::Utc>>,
        last_redfish_reboot: Option<chrono::DateTime<chrono::Utc>>,
        old_report: Option<(ConfigVersion, EndpointExplorationReport)>,
    ) -> Self {
        Self {
            address,
            iface,
            last_redfish_bmc_reset,
            last_ipmitool_bmc_reset,
            last_redfish_reboot,
            old_report,
            expected: None,
        }
    }
}

/// The SiteExplorer periodically runs [modules](machine_update_module::MachineUpdateModule) to initiate upgrades of machine components.
/// On each iteration the SiteExplorer will:
/// 1. collect the number of outstanding updates from all modules.
/// 2. if there are less than the max allowed updates each module will be told to start updates until
///    the number of updates reaches the maximum allowed.
///
/// Config from [CarbideConfig]:
/// * `max_concurrent_machine_updates` the maximum number of updates allowed across all modules
/// * `machine_update_run_interval` how often the manager calls the modules to start updates
pub struct SiteExplorer {
    database_connection: PgPool,
    enabled: bool,
    config: SiteExplorerConfig,
    metric_holder: Arc<metrics::MetricHolder>,
    endpoint_explorer: Arc<dyn EndpointExplorer>,
    firmware_config: Arc<FirmwareConfig>,
    common_pools: Arc<CommonPools>,
}

impl SiteExplorer {
    const DB_LOCK_NAME: &'static str = "site_explorer_lock";
    const DB_LOCK_QUERY: &'static str =
        "SELECT pg_try_advisory_xact_lock((SELECT 'site_explorer_lock'::regclass::oid)::integer)";

    pub fn new(
        database_connection: sqlx::PgPool,
        explorer_config: SiteExplorerConfig,
        meter: opentelemetry::metrics::Meter,
        endpoint_explorer: Arc<dyn EndpointExplorer>,
        firmware_config: Arc<FirmwareConfig>,
        common_pools: Arc<CommonPools>,
    ) -> Self {
        // We want to hold metrics for longer than the iteration interval, so there is continuity
        // in emitting metrics. However we want to avoid reporting outdated metrics in case
        // reporting gets stuck. Therefore round up the iteration interval by 1min.
        let hold_period = explorer_config
            .run_interval
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(meter, hold_period));

        SiteExplorer {
            database_connection,
            enabled: explorer_config.enabled,
            config: explorer_config,
            metric_holder,
            endpoint_explorer,
            firmware_config,
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

        let mut txn =
            self.database_connection.begin().await.map_err(|e| {
                CarbideError::internal(format!("Failed to create transaction: {e}"))
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
                CarbideError::internal(format!("Failed to commit transaction: {e}"))
            })?;
        }

        Ok(())
    }

    /// Audits and collects metrics of _all_ explored results vs. _all_ expected machines, not a single exploration cycle.
    /// Also updates the Site Explorer Health Report for all explored endpoints based on the last exploration data.
    ///
    /// * `metrics`                   - A metrics collector for accumulating and later emitting metrics.
    /// * `matched_expected_machines` - A map of expected machines that have been matched to interfaces, indexed by IP(s).
    async fn audit_exploration_results(
        &self,
        metrics: &mut SiteExplorationMetrics,
        matched_expected_machines: &HashMap<IpAddr, ExpectedMachine>,
    ) -> CarbideResult<()> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "begin load audit_exploration_results data",
                e,
            )
        })?;

        // Grab them all because we care about everything,
        // not just the subset in the current run.
        let explored_endpoints = DbExploredEndpoint::find_all(&mut txn).await?;
        let explored_managed_hosts = DbExploredManagedHost::find_all(&mut txn).await?;

        txn.rollback().await.map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "end load audit_exploration_results data",
                e,
            )
        })?;

        // Go through all the explored endpoints and collect metrics and submit
        // health reports
        for ep in explored_endpoints.into_iter() {
            if ep.report.endpoint_type != EndpointType::Bmc {
                // Skip anything that isn't a BMC.
                continue;
            }

            // We need to find the last health report for the endpoint in order to update it with latest health data
            let mut txn = self.database_connection.begin().await.map_err(|e| {
                DatabaseError::new(
                    file!(),
                    line!(),
                    "begin update SiteExplorer Health Report",
                    e,
                )
            })?;
            let machine_id = db::machine::find_id_by_bmc_ip(&mut txn, &ep.address).await?;
            let machine = match machine_id.as_ref() {
                Some(id) => db::machine::find(
                    &mut txn,
                    ObjectFilter::One(*id),
                    MachineSearchConfig {
                        include_dpus: true,
                        include_predicted_host: true,
                        ..Default::default()
                    },
                )
                .await?
                .into_iter()
                .next(),
                None => None,
            };
            let previous_health_report = machine
                .as_ref()
                .and_then(|machine| machine.site_explorer_health_report.as_ref());
            let mut new_health_report: health_report::HealthReport =
                health_report::HealthReport::empty("site-explorer".to_string());

            if let Some(ref e) = ep.report.last_exploration_error {
                metrics.increment_endpoint_explorations_failures_overall_count(
                    exploration_error_to_metric_label(e),
                );
                // Despite the last exploration failing, there might still be additional
                // endpoint information available. There might even be an ingested
                // Machine that corresponds to that endpoint.

                // The target allows to distinguish multiple DPUs which might
                // exhibit different alerts
                new_health_report
                    .alerts
                    .push(health_report::HealthProbeAlert {
                        id: "BmcExplorationFailure".parse().unwrap(),
                        target: Some(ep.address.to_string()),
                        in_alert_since: None,
                        message: format!("Endpoint exploration failed: {e}"),
                        tenant_message: None,
                        classifications: vec![
                            health_report::HealthAlertClassification::prevent_allocations(),
                        ],
                    });
            }

            for system in ep.report.systems.iter() {
                if system.power_state != PowerState::On {
                    new_health_report
                        .alerts
                        .push(health_report::HealthProbeAlert {
                            id: "PoweredOff".parse().unwrap(),
                            target: Some(ep.address.to_string()),
                            in_alert_since: None,
                            message: format!(
                                "System \"{}\" power state is \"{:?}\"",
                                system.id, system.power_state
                            ),
                            tenant_message: None,
                            classifications: vec![
                                health_report::HealthAlertClassification::prevent_allocations(),
                            ],
                        });
                    break;
                }
            }

            let expected_machine = matched_expected_machines.get(&ep.address);

            let (machine_type, expected) = match ep.report.is_dpu() {
                true => (MachineType::Dpu, MachineExpectation::NotApplicable),
                false => (MachineType::Host, expected_machine.is_some().into()),
            };

            // Track machines in a preingestion state.
            if ep.preingestion_state != PreingestionState::Complete {
                metrics.increment_endpoint_explorations_preingestions_incomplete_overall_count(
                    expected,
                    machine_type,
                );
            }

            // Increment total exploration counts
            metrics.increment_endpoint_explorations_machines_explored_overall_count(
                expected,
                machine_type,
            );

            if let Some(expected_machine) = expected_machine {
                let expected_sn = &expected_machine.serial_number;

                // Check expected vs actual serial number
                // using system serial numbers.
                // If nothing found, try again with chassis
                // serial numbers.
                if !ep
                    .report
                    .systems
                    .iter()
                    .any(|s| s.check_serial_number(expected_sn) || s.check_sku(expected_sn))
                    && !ep.report.chassis.iter().any(|s| match s.serial_number {
                        Some(ref sn) => sn == expected_sn,
                        _ => false,
                    })
                {
                    metrics
                            .increment_endpoint_explorations_expected_serial_number_mismatches_overall_count(
                                machine_type,
                            );

                    new_health_report
                        .alerts
                        .push(health_report::HealthProbeAlert {
                            id: "SerialNumberMismatch".parse().unwrap(),
                            target: Some(ep.address.to_string()),
                            in_alert_since: None,
                            message: format!(
                                "Expected serial number {expected_sn} can not be found"
                            ),
                            tenant_message: None,
                            classifications: vec![
                                health_report::HealthAlertClassification::prevent_allocations(),
                            ],
                        });
                }
            }

            new_health_report.update_in_alert_since(previous_health_report);
            if let Some(id) = machine_id.as_ref() {
                db::machine::update_site_explorer_health_report(&mut txn, id, &new_health_report)
                    .await?;
            }

            txn.commit().await.map_err(|e| {
                DatabaseError::new(file!(), line!(), "end update SiteExplorer Health Report", e)
            })?;
        }

        // Count the total number of explored managed hosts
        for explored_managed_host in explored_managed_hosts {
            metrics.increment_endpoint_explorations_identified_managed_hosts_overall_count(
                matched_expected_machines
                    .get(&explored_managed_host.host_bmc_ip)
                    .is_some()
                    .into(),
            );
        }

        Ok(())
    }

    async fn explore_site(&self, metrics: &mut SiteExplorationMetrics) -> CarbideResult<()> {
        self.check_preconditions(metrics).await?;

        let matched_expected_machines = self.update_explored_endpoints(metrics).await?;

        // Create a list of DPUs and hosts that site explorer should try to ingest. Site explorer uses the following criteria to determine whether
        // to ingest a given endpoint (creating a managed host containing the endpoint and adding it to the state machine):
        // 1) Pre-ingestion must have completed for a given endpoint
        // 2a) If the endpoint is for a DPU: make sure that site explorer can retrieve the mac address of the pf0 interface that the DPU exposes to the host.
        // If site explorer is unable to retrieve this mac address, there is no point in creating a managed host: we will not be able to configure the host appropriately.
        // 2b) If the endpoint is for a host: make sure that the host is on and that infinite boot is enabled. Otherwise, we will not be able to provision the DPU appropriately
        // once we create a managed host and add it to the state machine.
        let (explored_dpus, explored_hosts) = self.identify_machines_to_ingest().await?;

        // Note/TODO:
        // Since we generate the managed-host pair in a different transaction than endpoint discovery,
        // the generation of both reports is not necessarily atomic.
        // This is improvable
        // However since host information rarely changes (we never reassign MachineInterfaces),
        // this should be ok. The most noticable effect is that ManagedHost population might be delayed a bit.
        let identified_hosts = self
            .identify_managed_hosts(
                metrics,
                &matched_expected_machines,
                explored_dpus,
                explored_hosts,
            )
            .await?;

        if **self.config.create_machines.load() {
            let start_create_machines = std::time::Instant::now();
            let create_machines_res = self
                .create_machines(metrics, identified_hosts, &matched_expected_machines)
                .await;
            metrics.create_machines_latency = Some(start_create_machines.elapsed());
            create_machines_res?;
        }

        // Audit after everything has been explored, identified, and created.
        self.audit_exploration_results(metrics, &matched_expected_machines)
            .await?;

        Ok(())
    }

    /// Creates a new ManagedHost (Host `Machine` and DPU `Machine` pair)
    /// for each ManagedHost that was identified and that doesn't have a corresponding `Machine` yet
    async fn create_machines(
        &self,
        metrics: &mut SiteExplorationMetrics,
        explored_managed_hosts: Vec<(ExploredManagedHost, EndpointExplorationReport)>,
        matched_expected_machines: &HashMap<IpAddr, ExpectedMachine>,
    ) -> CarbideResult<()> {
        // TODO: Improve the efficiency of this method. Right now we perform 3 database transactions
        // for every identified ManagedHost even if we don't create any objects.
        // We can perform a single query upfront to identify which ManagedHosts don't yet have Machines
        for (host, report) in explored_managed_hosts {
            let expected_machine = matched_expected_machines.get(&host.host_bmc_ip);

            match self
                .create_managed_host(
                    host.clone(),
                    report,
                    expected_machine,
                    &self.database_connection,
                )
                .await
            {
                Ok(true) => {
                    metrics.created_machines += 1;
                    if metrics.created_machines as u64 == self.config.machines_created_per_run {
                        break;
                    }
                }
                Ok(false) => {}
                Err(error) => tracing::error!(%error, "Failed to create managed host {:#?}", host),
            }
        }

        Ok(())
    }

    /// Creates a `Machine` objects for an identified `ManagedHost` with initial states
    ///
    /// Returns `true` if new `Machine` objects have been created or `false` otherwise
    pub async fn create_managed_host(
        &self,
        explored_host: ExploredManagedHost,
        mut report: EndpointExplorationReport,
        expected_machine: Option<&ExpectedMachine>,
        pool: &PgPool,
    ) -> CarbideResult<bool> {
        let mut managed_host = ManagedHost::init(explored_host);
        let mut txn = pool.begin().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "begin load create_managed_host", e)
        })?;

        let metadata = match expected_machine {
            Some(m) => m.metadata.clone(),
            None => Metadata {
                name: String::new(),
                description: String::new(),
                labels: Default::default(),
            },
        };

        // Zero-dpu case: If the explored host had no DPUs, we can create the machine now
        if managed_host.explored_host.dpus.is_empty() {
            if !self.config.allow_zero_dpu_hosts {
                let error = CarbideError::NoDpusInMachine(managed_host.explored_host.host_bmc_ip);
                tracing::error!(%error, "Cannot create managed host for explored endpoint with no DPUs: Zero-dpu hosts are disallowed by config");
                return Err(error);
            }
            let did_create = self
                .create_zero_dpu_machine(&mut txn, &mut managed_host, &mut report, metadata.clone())
                .await?;
            if !did_create {
                // Site explorer has already created a machine for this endpoint previously, skip.
                return Ok(false);
            }
            tracing::info!("Created managed_host with zero DPUs");
        }

        let mut dpu_ids = vec![];
        for dpu_report in managed_host.explored_host.dpus.clone().iter() {
            // machine_id_if_valid_report makes sure that all optional fields on dpu_report are
            // actually set (like the machine-id etc) and returns the machine_id if everything
            // is valid.
            let dpu_machine_id = *dpu_report.machine_id_if_valid_report()?;
            dpu_ids.push(dpu_machine_id);

            if !self.create_dpu(&mut txn, dpu_report).await? {
                // Site explorer has already created a machine for this DPU previously.
                //
                // If the DPU's machine is not attached to its machine interface, do so here.
                // TODO (sp): is this defensive check really neccessary?
                if self.configure_dpu_interface(&mut txn, dpu_report).await? {
                    txn.commit().await.map_err(|e| {
                        DatabaseError::new(file!(), line!(), "end create_managed_host", e)
                    })?;
                }
                return Ok(false);
            }

            self.attach_dpu_to_host(&mut txn, &mut managed_host, dpu_report, metadata.clone())
                .await?;
        }

        // Now since all DPUs are created, update host and DPUs state correctly.
        let host_machine_id = managed_host
            .clone()
            .machine_id
            .ok_or(CarbideError::internal(format!(
                "Failed to get machine ID for host: {:#?}",
                managed_host
            )))?;

        db::machine::update_state(
            &mut txn,
            &host_machine_id,
            ManagedHostState::DpuDiscoveringState {
                dpu_states: DpuDiscoveringStates {
                    states: dpu_ids
                        .into_iter()
                        .map(|x| (x, DpuDiscoveringState::Initializing))
                        .collect::<HashMap<MachineId, DpuDiscoveringState>>(),
                },
            },
        )
        .await?;

        txn.commit()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "end create_managed_host", e))?;

        Ok(true)
    }

    /// identify_machines_to_ingest returns two maps.
    /// The first map returned identifies all of the DPUs that site explorer will try to ingest.
    /// The latter identifies all of the hosts the the site explorer will try to ingest.
    /// Both map from machine BMC IP address to the corresponding explored endpoint.
    async fn identify_machines_to_ingest(
        &self,
    ) -> CarbideResult<(
        HashMap<IpAddr, ExploredEndpoint>,
        HashMap<IpAddr, ExploredEndpoint>,
    )> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "load find_all_preingestion_complete data",
                e,
            )
        })?;

        // TODO: We reload the endpoint list even though we just regenerated it
        // Could optimize this by keeping it in memory. But since the manipulations
        // are quite complicated in the previous step, this makes things much easier
        let explored_endpoints =
            DbExploredEndpoint::find_all_preingestion_complete(&mut txn).await?;

        txn.commit().await.map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "end find_all_preingestion_complete data",
                e,
            )
        })?;

        let mut explored_dpus = HashMap::new();
        let mut explored_hosts = HashMap::new();
        for ep in explored_endpoints.into_iter() {
            if ep.report.endpoint_type != EndpointType::Bmc {
                continue;
            }

            if ep.report.is_dpu() {
                if self.can_ingest_dpu_endpoint(&ep).await? {
                    explored_dpus.insert(ep.address, ep);
                }
            } else if self.can_ingest_host_endpoint(&ep).await? {
                explored_hosts.insert(ep.address, ep);
            }
        }

        Ok((explored_dpus, explored_hosts))
    }

    async fn identify_managed_hosts(
        &self,
        metrics: &mut SiteExplorationMetrics,
        matched_expected_machines: &HashMap<IpAddr, ExpectedMachine>,
        explored_dpus: HashMap<IpAddr, ExploredEndpoint>,
        explored_hosts: HashMap<IpAddr, ExploredEndpoint>,
    ) -> CarbideResult<Vec<(ExploredManagedHost, EndpointExplorationReport)>> {
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

        let is_dpu_in_nic_mode = |dpu_ep: &&ExploredEndpoint, host_ep: &ExploredEndpoint| -> bool {
            let nic_mode = dpu_ep.report.nic_mode().is_some_and(|m| m == NicMode::Nic);
            if nic_mode {
                tracing::info!(
                    address = %dpu_ep.address,
                    // exploration_report = ?dpu_ep.report,
                    "discovered bluefield in NIC mode attached to host {}",
                    host_ep.address
                );
            }
            nic_mode
        };

        let get_host_pf_mac_address = |dpu_ep: &ExploredEndpoint| -> Option<MacAddress> {
            match find_host_pf_mac_address(dpu_ep) {
                Ok(m) => Some(m),
                Err(error) => {
                    tracing::error!(%error, dpu_ip = %dpu_ep.address, "Failed to find base mac address for DPU");
                    None
                }
            }
        };

        for ep in explored_hosts.values() {
            // the list of DPUs that the site-explorer has explored for this host
            let mut dpus_explored_for_host: Vec<ExploredDpu> = Vec::new();
            // the number of DPUs that the host reports are attached to it
            let mut expected_num_dpus_attached_to_host = 0;
            let mut all_dpus_configured_properly_in_host = true;
            for system in ep.report.systems.iter() {
                for pcie_device in system.pcie_devices.iter() {
                    if pcie_device.is_bluefield() {
                        // is_bluefield currently returns true if a network adapter is BF2 DPU, BF3 DPU, or BF3 Super NIC
                        expected_num_dpus_attached_to_host += 1;
                    }

                    if pcie_device.serial_number.is_some() {
                        let sn = pcie_device.serial_number.as_ref().unwrap().trim();
                        if let Some(dpu_ep) = dpu_sn_to_endpoint.get(sn) {
                            if let Some(model) = pcie_device.part_number.as_ref() {
                                match self
                                    .check_and_configure_dpu_mode(
                                        (**dpu_ep).to_owned(),
                                        model.to_string(),
                                    )
                                    .await
                                {
                                    Ok(is_dpu_mode_configured_correctly) => {
                                        if !is_dpu_mode_configured_correctly {
                                            all_dpus_configured_properly_in_host = false;
                                            // we do not want to ingest a host with an incorrectly configured DPU
                                            continue;
                                        }
                                    }
                                    Err(err) => {
                                        tracing::warn!(
                                            "failed to check DPU mode against {}: {err}",
                                            dpu_ep.address
                                        );
                                        continue;
                                    }
                                };
                            }

                            // We do not want to attach bluefields that are in NIC mode as DPUs to the host
                            if is_dpu_in_nic_mode(dpu_ep, ep) {
                                expected_num_dpus_attached_to_host -= 1;
                                continue;
                            }

                            dpus_explored_for_host.push(ExploredDpu {
                                bmc_ip: dpu_ep.address,
                                host_pf_mac_address: get_host_pf_mac_address(dpu_ep),
                                report: dpu_ep.report.clone(),
                            });
                        }
                    }
                }
            }

            if expected_num_dpus_attached_to_host == 0 {
                for chassis in ep.report.chassis.iter() {
                    for network_adapter in chassis.network_adapters.iter() {
                        if let Some(model) = network_adapter.part_number.as_ref() {
                            if is_bluefield_model(model.trim()) {
                                expected_num_dpus_attached_to_host += 1;
                            }
                        }

                        if let Some(sn) = network_adapter.serial_number.as_ref() {
                            if let Some(dpu_ep) = dpu_sn_to_endpoint.get(sn.trim()) {
                                if let Some(model) = network_adapter.part_number.as_ref() {
                                    match self
                                        .check_and_configure_dpu_mode(
                                            (**dpu_ep).to_owned(),
                                            model.to_string(),
                                        )
                                        .await
                                    {
                                        Ok(is_dpu_mode_configured_correctly) => {
                                            if !is_dpu_mode_configured_correctly {
                                                all_dpus_configured_properly_in_host = false;
                                                // we do not want to ingest a host with an incorrectly configured DPU
                                                continue;
                                            }
                                        }
                                        Err(err) => {
                                            tracing::warn!(
                                                "failed to check DPU mode against {}: {err}",
                                                dpu_ep.address
                                            );
                                            continue;
                                        }
                                    };
                                }

                                // We do not want to attach bluefields that are in NIC mode as DPUs to the host
                                if is_dpu_in_nic_mode(dpu_ep, ep) {
                                    expected_num_dpus_attached_to_host -= 1;
                                    continue;
                                }
                                dpus_explored_for_host.push(ExploredDpu {
                                    bmc_ip: dpu_ep.address,
                                    host_pf_mac_address: get_host_pf_mac_address(dpu_ep),
                                    report: dpu_ep.report.clone(),
                                });
                            }
                        }
                    }
                }
            }

            if dpus_explored_for_host.is_empty()
                || dpus_explored_for_host.len() != expected_num_dpus_attached_to_host
            {
                // Check if there are dpu serial(s) specified in expected_machine table for this host
                // Lets assume for now that if a DPU is specific in the expected machine table for the host
                // it has been configured properly (DPU vs NIC mode).
                let mut dpu_added = false;
                if let Some(expected_machine) = matched_expected_machines.get(&ep.address) {
                    for dpu_sn in expected_machine.fallback_dpu_serial_numbers.clone() {
                        if let Some(dpu_ep) = dpu_sn_to_endpoint.get(dpu_sn.as_str()) {
                            // We do not want to attach bluefields that are in NIC mode as DPUs to the host
                            if is_dpu_in_nic_mode(dpu_ep, ep)
                                && expected_num_dpus_attached_to_host > 0
                            {
                                expected_num_dpus_attached_to_host -= 1;
                                continue;
                            }
                            dpu_added = true;
                            dpus_explored_for_host.push(ExploredDpu {
                                bmc_ip: dpu_ep.address,
                                host_pf_mac_address: get_host_pf_mac_address(dpu_ep),
                                report: dpu_ep.report.clone(),
                            });
                        }
                    }
                }
                // The site explorer should only create a managed host after exploring all of the DPUs attached to the host.
                // If a host reports that it has two DPUs, the site explorer must wait until **both** DPUs have made the DHCP request.
                // If only one of the two DPUs have made the DHCP request, the site explorer must wait until it has explored the latter DPU's BMC
                // (ensuring that the second DPU has also made the DHCP request).
                if !dpu_added {
                    if expected_num_dpus_attached_to_host > 0 {
                        tracing::warn!(
                            address = %ep.address,
                            exploration_report = ?ep,
                            "cannot identify managed host because the site explorer has only discovered {} out of the {} attached DPUs (all_dpus_configured_properly_in_host={all_dpus_configured_properly_in_host}):\n{:#?}",
                            dpus_explored_for_host.len(), expected_num_dpus_attached_to_host, dpus_explored_for_host
                        );

                        if !all_dpus_configured_properly_in_host {
                            if ep.report.vendor.is_some_and(|vendor| vendor.is_dell()) {
                                tracing::warn!(
                                    "power cycling Dell {} to apply nic mode change for its incorrectly configured DPUs",
                                    ep.address,
                                );

                                let time_since_redfish_powercycle = Utc::now()
                                    .signed_duration_since(
                                        ep.last_redfish_powercycle.unwrap_or_default(),
                                    );
                                if time_since_redfish_powercycle > self.config.reset_rate_limit {
                                    let _ = self.redfish_powercycle(
                                            ep.address,
                                        )
                                        .await.inspect_err(|err| tracing::warn!("site explorer failed to power cycle host {} to apply DPU mode changes: {err}", ep.address));
                                }
                            } else {
                                tracing::warn!(
                                    "wait for manual power cycle of host {}; site explorer doesn't support power cycling vendor {:#?}",
                                    ep.address,
                                    ep.report.vendor
                                );
                            }
                        }

                        continue;
                    } else if !self.config.allow_zero_dpu_hosts {
                        tracing::warn!(
                            address = %ep.address,
                            exploration_report = ?ep,
                            "cannot identify managed host because the site explorer does not see any DPUs on this host, and zero-DPU hosts are not allowed by configuration; expected_num_dpus_attached_to_host: {expected_num_dpus_attached_to_host}; dpus_explored_for_host: {dpus_explored_for_host:#?}",
                        );
                        continue;
                    }
                }
            }

            // If we know the booting interface of the host, we should use this for deciding
            // primary interface.
            let mut is_sorted = false;
            if let Some(mac_address) = ep
                .report
                .fetch_host_primary_interface_mac(&dpus_explored_for_host)
            {
                let primary_dpu_position = dpus_explored_for_host
                    .iter()
                    .position(|x| x.host_pf_mac_address.unwrap_or_default() == mac_address);

                if let Some(primary_dpu_position) = primary_dpu_position {
                    if primary_dpu_position != 0 {
                        let dpu = dpus_explored_for_host.remove(primary_dpu_position);
                        dpus_explored_for_host.insert(0, dpu);
                    }
                    is_sorted = true;
                } else if !dpus_explored_for_host.is_empty() {
                    let all_mac = dpus_explored_for_host
                        .iter()
                        .map(|x| {
                            x.host_pf_mac_address
                                .map(|x| x.to_string())
                                .unwrap_or_default()
                        })
                        .collect_vec()
                        .join(",");

                    tracing::error!(
                        "Could not find mac_address {mac_address} in discovered DPU's list {all_mac}, host bmc: {}.",
                        ep.address
                    );
                    continue;
                }
            }

            if !is_sorted {
                // Sort using usual way.
                dpus_explored_for_host.sort_by_key(|d| {
                    d.report.systems[0]
                        .serial_number
                        .clone()
                        .unwrap_or("".to_string())
                        .to_lowercase()
                });
            }

            managed_hosts.push((
                ExploredManagedHost {
                    host_bmc_ip: ep.address,
                    dpus: dpus_explored_for_host,
                },
                ep.report.clone(),
            ));
            metrics.exploration_identified_managed_hosts += 1;
        }

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "begin load update_explored_endpoints data",
                e,
            )
        })?;

        DbExploredManagedHost::update(
            &mut txn,
            managed_hosts
                .iter()
                .map(|h| h.0.clone())
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .await?;

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
            .map_err(|e| CarbideError::internal(e.to_string()))
    }

    async fn update_explored_endpoints(
        &self,
        metrics: &mut SiteExplorationMetrics,
    ) -> CarbideResult<HashMap<IpAddr, ExpectedMachine>> {
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
        let interfaces = db::machine_interface::find_all(&mut txn).await?;
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
        // for a specific machine).
        // We also can skip scanning IPs which are knowingly used as DPU OOB interfaces,
        // since those will not speak redfish.
        // Note: As a side effect of this, OOB interfaces might for a short time be scanned,
        // until the machine is ingested. At that point in time this filter will remove them
        // from the to-be-scanned list.
        let underlay_interfaces: Vec<MachineInterfaceSnapshot> = interfaces
            .into_iter()
            .filter(|iface| {
                underlay_segments.contains(&iface.segment_id) && iface.machine_id.is_none()
            })
            .collect();

        // We'll be returning a hashmap of all expected machines by IP
        // for later auditing, but the list of expected machines is also used for
        // identifying managed hosts in identify_managed_hosts based on matching
        // interfaces, so we'll need by-mac to filter the list of expected machines
        // we pull from the DB.
        let mut underlay_interfaces_by_mac =
            HashMap::<MacAddress, &MachineInterfaceSnapshot>::new();
        let mut underlay_interfaces_by_address =
            HashMap::<IpAddr, &MachineInterfaceSnapshot>::new();
        for iface in underlay_interfaces.iter() {
            for addr in iface.addresses.iter() {
                underlay_interfaces_by_address.insert(*addr, iface);
                underlay_interfaces_by_mac.insert(iface.mac_address, iface);
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
        let mut priority_update_endpoints = Vec::new();
        let mut update_endpoints = Vec::with_capacity(explored_endpoints_by_address.len());
        for (address, endpoint) in &explored_endpoints_by_address {
            match underlay_interfaces_by_address.get(address) {
                Some(iface) => {
                    if endpoint.exploration_requested {
                        priority_update_endpoints.push((*address, *iface, endpoint));
                    } else {
                        update_endpoints.push((*address, *iface, endpoint));
                    }
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

        // We prioritize existing endpoints which have the `exploration_requested` flag set
        for (address, iface, endpoint) in
            priority_update_endpoints.iter().take(num_explore_endpoints)
        {
            explore_endpoint_data.push(Endpoint::new(
                *address,
                (*iface).clone(),
                endpoint.last_redfish_bmc_reset,
                endpoint.last_ipmitool_bmc_reset,
                endpoint.last_redfish_reboot,
                Some((endpoint.report_version, endpoint.report.clone())),
            ));
        }

        // Next priority are all endpoints that we've never looked at
        let remaining_explore_endpoints = num_explore_endpoints - explore_endpoint_data.len();
        for (address, iface) in unexplored_endpoints
            .iter()
            .take(remaining_explore_endpoints)
        {
            explore_endpoint_data.push(Endpoint::new(
                *address,
                (*iface).clone(),
                None,
                None,
                None,
                None,
            ))
        }

        // If we have any capacity available, we update knowledge about endpoints we looked at earlier on
        let remaining_explore_endpoints = num_explore_endpoints - explore_endpoint_data.len();
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
                    endpoint.last_redfish_bmc_reset,
                    endpoint.last_ipmitool_bmc_reset,
                    endpoint.last_redfish_reboot,
                    Some((endpoint.report_version, endpoint.report.clone())),
                ));
            }
        }

        let mut task_set = JoinSet::new();
        let concurrency_limiter = Arc::new(tokio::sync::Semaphore::new(
            self.config.concurrent_explorations as usize,
        ));

        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "begin find_all", e))?;
        let expected = ExpectedMachine::find_all(&mut txn).await?;
        txn.commit()
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "end find_all", e))?;

        let expected_count = expected.len();
        let mut unique_matched_expected_machines: HashSet<MacAddress> = HashSet::new();

        let mut matched_expected_machines: HashMap<IpAddr, ExpectedMachine> = HashMap::new();
        let mut expected_machines_by_mac: HashMap<MacAddress, ExpectedMachine> = HashMap::new();
        for expected_machine in expected {
            expected_machines_by_mac
                .insert(expected_machine.bmc_mac_address, expected_machine.clone());
            if let Some(iface) = underlay_interfaces_by_mac.get(&expected_machine.bmc_mac_address) {
                unique_matched_expected_machines.insert(expected_machine.bmc_mac_address);
                for addr in iface.addresses.iter() {
                    matched_expected_machines.insert(*addr, expected_machine.clone());
                }
            }
        }

        // Record the difference between the total expected machine count and
        // the number of expected machines we've actually "seen."
        metrics.endpoint_explorations_expected_machines_missing_overall_count =
            expected_count - unique_matched_expected_machines.len();

        for endpoint in explore_endpoint_data.iter_mut() {
            endpoint.expected = expected_machines_by_mac.remove(&endpoint.iface.mac_address);
        }

        for endpoint in explore_endpoint_data.into_iter() {
            let endpoint_explorer = self.endpoint_explorer.clone();
            let concurrency_limiter = concurrency_limiter.clone();

            let bmc_target_port = self.config.override_target_port.unwrap_or(443);
            let bmc_target_addr = SocketAddr::new(endpoint.address, bmc_target_port);
            let firmware_config = self.firmware_config.clone();

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
                            endpoint.expected.clone(),
                            endpoint.old_report.as_ref().map(|report| &report.1),
                        )
                        .await;

                    if let Err(error) = result.clone() {
                        tracing::info!(%error, "Failed to explore {}: {}",bmc_target_addr , error);
                    }

                    // Try to generate a MachineId and parsed version info based on the retrieved data
                    if let Ok(report) = &mut result {
                        if let Err(error) = report.generate_machine_id(false) {
                            tracing::error!(%error, "Can not generate MachineId for explored endpoint");
                        }
                        if let Some(fw_info) = firmware_config.find_fw_info_for_host_report(report)
                        {
                            report.parse_versions(&fw_info);
                            } else {
                            // It's possible that we knew about this host type before but do not now, so make sure we
                            // do not keep stale data.
                            report.versions = HashMap::default();
                        }
                        report.model = report.model();
                    }

                    (endpoint, result, start.elapsed())
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

        for (endpoint, result, exploration_duration) in exploration_results.into_iter() {
            let address = endpoint.address;

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

                    if e.is_redfish() {
                        self.handle_redfish_error(endpoint.clone(), metrics, e)
                            .await;
                    }
                }
            }

            // Update possible stale machine versions
            if let Ok(report) = &result {
                if let Some(bmc_version) = report.versions.get(&FirmwareComponentType::Bmc) {
                    if let Some(uefi_version) = report.versions.get(&FirmwareComponentType::Uefi) {
                        MachineTopology::update_firmware_version_by_bmc_address(
                            &mut txn,
                            &address,
                            bmc_version,
                            uefi_version,
                        )
                        .await?;
                    }
                }
            }

            match endpoint.old_report {
                Some((old_version, mut old_report)) => {
                    match result {
                        Ok(mut report) => {
                            report.last_exploration_latency = Some(exploration_duration);
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
                            old_report.last_exploration_latency = Some(exploration_duration);
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
                        Ok(mut report) => {
                            report.last_exploration_latency = Some(exploration_duration);
                            tracing::info!(
                                address = %address,
                                exploration_report = ?report,
                                "Initial exploration of machine"
                            );
                            DbExploredEndpoint::insert(address, &report, &mut txn).await?;
                        }
                        Err(e) => {
                            // If an endpoint exploration failed we still track the result in the database
                            // That will avoid immmediatly retrying the exploration in the next run
                            let mut report = EndpointExplorationReport::new_with_error(e);
                            report.last_exploration_latency = Some(exploration_duration);
                            DbExploredEndpoint::insert(address, &report, &mut txn).await?;
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

        Ok(matched_expected_machines)
    }

    // create_dpu does everything needed to create a DPU as part of a newly discovered managed host.
    // If the DPU does not exist in the machines table, the function creates a new DPU machine and configures it appropriately. create_dpu returns true.
    // If the DPU already exists in the machines table, this is a no-op. create_dpu returns false.
    async fn create_dpu(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        explored_dpu: &ExploredDpu,
    ) -> CarbideResult<bool> {
        if let Some(dpu_machine) = self.create_dpu_machine(txn, explored_dpu).await? {
            self.configure_dpu_interface(txn, explored_dpu).await?;
            self.update_dpu_network_config(txn, &dpu_machine).await?;
            let dpu_machine_id: &MachineId = explored_dpu.report.machine_id.as_ref().unwrap();
            let dpu_bmc_info = explored_dpu.bmc_info();
            let dpu_hw_info = explored_dpu.hardware_info()?;
            self.update_machine_topology(txn, dpu_machine_id, dpu_bmc_info, dpu_hw_info)
                .await?;
            return Ok(true);
        }
        Ok(false)
    }

    async fn create_zero_dpu_machine(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        managed_host: &mut ManagedHost,
        report: &mut EndpointExplorationReport,
        metadata: Metadata,
    ) -> CarbideResult<bool> {
        // If there's already a machine with the same MAC address as this endpoint, return false. We
        // can't rely on matching the machine_id, as it may have migrated to a stable MachineID
        // already.
        let mac_addresses = report.all_mac_addresses();
        for mac_address in &mac_addresses {
            if db::machine::find_by_mac_address(txn, mac_address)
                .await?
                .is_some()
            {
                return Ok(false);
            }

            // If we already minted this machine and it hasn't DHCP'd yet, there will be an
            // predicted_machine_interface with this MAC address. If so, also skip.
            if !PredictedMachineInterface::find_by(
                txn,
                ObjectColumnFilter::One(predicted_machine_interface::MacAddressColumn, mac_address),
            )
            .await?
            .is_empty()
            {
                return Ok(false);
            }
        }

        let machine_id = match managed_host.machine_id.as_ref() {
            Some(machine_id) => machine_id,
            None => {
                // Mint a predicted-host machine_id from the exploration report
                report.generate_machine_id(true)?.unwrap()
            }
        };

        tracing::info!(%machine_id, "Minted predicted host ID for zero-DPU machine");

        let existing_machine = db::machine::find_one(
            txn,
            machine_id,
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?;

        if let Some(existing_machine) = existing_machine {
            // There's already a machine with this ID, but we already looked above for machines with
            // the same MAC address as this one, so something's weird here. Log this host's mac
            // addresses and the ones from the colliding hosts to help in diagnosis.
            let existing_macs = existing_machine
                .hardware_info
                .as_ref()
                .map(|hw| hw.all_mac_addresses())
                .unwrap_or_default();
            tracing::warn!(
                %machine_id,
                ?existing_macs,
                predicted_host_macs=?mac_addresses,
                "Predicted host already exists, with different mac addresses from this one. Potentially multiple machines with same serial number?"
            );
            return Ok(false);
        }

        self.create_machine_from_explored_managed_host(txn, managed_host, machine_id, metadata)
            .await?;

        let machine_id = *machine_id; // 🦀 end the borrow so we can write to managed_host.machine_id
        managed_host.machine_id = Some(machine_id);

        // Create and attach a non-DPU machine_interface to the host for every MAC address we see in
        // the exploration report
        for mac_address in mac_addresses {
            if let Some(machine_interface) =
                db::machine_interface::find_by_mac_address(txn, mac_address)
                    .await?
                    .into_iter()
                    .next()
            {
                // There's already a machine_interface with this MAC...
                if let Some(existing_machine_id) = machine_interface.machine_id {
                    // ...If it has a MachineId, something's gone wrong. We already checked db::machine::find_by_mac()
                    // above for all mac addresses, and returned Ok(false) if any were found. Finding an interface
                    // with this MAC with a non-nil machine_id is a contradiction.
                    tracing::error!(
                        %mac_address,
                        %machine_id,
                        %existing_machine_id,
                        "BUG! Found existing machine_interface with this MAC address, we should not have gotten here!"
                    );
                    return Err(CarbideError::AlreadyFoundError {
                        kind: "MachineInterface",
                        id: mac_address.to_string(),
                    });
                } else {
                    // ...If it has no MachineId, the host must have DHCP'd before site-explorer ran. Set it to the new machine ID.
                    tracing::info!(%mac_address, %machine_id, "Migrating unowned machine_interface to new managed host");
                    db::machine_interface::associate_interface_with_machine(
                        &machine_interface.id,
                        &machine_id,
                        txn,
                    )
                    .await?;
                }
            } else {
                NewPredictedMachineInterface {
                    machine_id: &machine_id,
                    mac_address,
                    expected_network_segment_type: NetworkSegmentType::HostInband,
                }
                .create(txn)
                .await?;
            }
        }

        Ok(true)
    }

    // configure_dpu_interface checks the machine_interfaces table to see if the DPU's machine interface has its machine id set.
    // If the machine ID is already configured appropriately for the DPU's machine interface, configure_dpu_interface will return false
    // If the DPU's machine interface was missing the machine ID in the table, configure_dpu_interface will set the machine ID and return true.
    async fn configure_dpu_interface(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        explored_dpu: &ExploredDpu,
    ) -> CarbideResult<bool> {
        let dpu_machine_id: &MachineId = explored_dpu.report.machine_id.as_ref().unwrap();
        let oob_net0_mac = explored_dpu.report.systems.iter().find_map(|x| {
            x.ethernet_interfaces.iter().find_map(|x| {
                if x.id == Some("oob_net0".to_string()) {
                    x.mac_address
                } else {
                    None
                }
            })
        });

        // If machine_interface exists for the DPU and machine_id is not updated, do it now.
        if let Some(oob_net0_mac) = oob_net0_mac {
            let mi = db::machine_interface::find_by_mac_address(txn, oob_net0_mac).await?;

            if let Some(interface) = mi.first() {
                if interface.machine_id.is_none() {
                    tracing::info!(
                        "Updating machine interface {} with machine id {dpu_machine_id}.",
                        interface.id
                    );
                    db::machine_interface::associate_interface_with_machine(
                        &interface.id,
                        dpu_machine_id,
                        txn,
                    )
                    .await?;
                    db::machine_interface::associate_interface_with_dpu_machine(
                        &interface.id,
                        dpu_machine_id,
                        txn,
                    )
                    .await?;
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    // create_dpu_machine creates a machine for the DPU as specified by dpu_machine_id. Returns an Optional Machine indicating whether the function created a new machine (returns None if a machine already existed for this DPU).
    // if an entry exists in the machines table with a machine ID which matches dpu_machine_id, a machine has already been created for this DPU. Returns None.
    // if an entry doesnt exist in the machine table, the site explorer will add an entry in the machines table for the DPU and update its network config appropriately (allocating a loop ip address etc). Return the newly created machine.
    async fn create_dpu_machine(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        explored_dpu: &ExploredDpu,
    ) -> CarbideResult<Option<Machine>> {
        let dpu_machine_id = explored_dpu.report.machine_id.as_ref().unwrap();
        match db::machine::find_one(txn, dpu_machine_id, MachineSearchConfig::default()).await? {
            // Do nothing if machine exists. It'll be reprovisioned via redfish
            Some(_existing_machine) => Ok(None),
            None => match db::machine::create(
                txn,
                Some(&self.common_pools),
                dpu_machine_id,
                ManagedHostState::Created,
                &Metadata {
                    name: dpu_machine_id.to_string(),
                    ..Default::default()
                },
            )
            .await
            {
                Ok(machine) => {
                    tracing::info!("Created DPU machine with id: {}", dpu_machine_id);
                    Ok(Some(machine))
                }
                Err(e) => {
                    tracing::error!(error = %e, "Can't create DPU machine");
                    Err(e)
                }
            },
        }
    }

    async fn update_dpu_network_config(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        dpu_machine: &Machine,
    ) -> CarbideResult<()> {
        let (mut network_config, version) = dpu_machine.network_config.clone().take();
        if network_config.loopback_ip.is_none() {
            let loopback_ip = db::machine::allocate_loopback_ip(
                &self.common_pools,
                txn,
                &dpu_machine.id.to_string(),
            )
            .await?;
            network_config.loopback_ip = Some(loopback_ip);
        }
        network_config.use_admin_network = Some(true);
        db::machine::try_update_network_config(txn, &dpu_machine.id, version, &network_config)
            .await
            .map_err(CarbideError::from)?;

        Ok(())
    }

    async fn attach_dpu_to_host(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        explored_host: &mut ManagedHost,
        explored_dpu: &ExploredDpu,
        metadata: Metadata,
    ) -> CarbideResult<()> {
        let dpu_hw_info = explored_dpu.hardware_info()?;
        // Create Host proactively.
        // In case host interface is created, this method will return existing one, instead
        // creating new everytime.
        let host_machine_interface =
            db::machine_interface::create_host_machine_dpu_interface_proactively(
                txn,
                Some(&dpu_hw_info),
                explored_dpu.report.machine_id.as_ref().unwrap(),
            )
            .await?;

        if host_machine_interface.machine_id.is_some() {
            return Err(CarbideError::internal(format!(
                "The host's machine interface for DPU {} already has the machine ID set--something is wrong: {:#?}",
                explored_dpu.report.machine_id.as_ref().unwrap(),
                host_machine_interface
            )));
        }

        self.configure_host_machine(
            txn,
            explored_host,
            &host_machine_interface,
            explored_dpu,
            metadata,
        )
        .await?;

        // configure_host_machine should have setup the machine_id for the host
        let host_machine_id = explored_host
            .clone()
            .machine_id
            .ok_or(CarbideError::internal(format!(
                "Failed to set machine ID for host: {:#?}",
                explored_host
            )))?;

        db::machine_interface::associate_interface_with_machine(
            &host_machine_interface.id,
            &host_machine_id,
            txn,
        )
        .await?;

        Ok(())
    }

    // configure_host_machine configures the host's machine with the specific interface. It returns the host's machine ID.
    //
    // Normally, a host will have a single machine interface because the majority of hosts (for now) have a single DPU.
    // If a host has multiple DPUs, the host machine will have a machine interface for each DPU.
    // However, all of the host machine interfaces must be attached to the same host machine (and host machine-id).
    // Until this point, all of these interfaces will be marked as the "primary" interface by default.
    //
    // configure_host_machine handles two cases:
    // 1) host_machine_interface is the primary interface for this host: generate the machine ID for this host and use it to actually create the machine for the host.
    // 2) host_machine_interface is *not* the primary interface for this host: set "primary_interface" to false for this machine interface. Return the host ID generated from (1)
    //
    // The first DPU that we attach to the host is designated as the primary DPU; the associate host machine interface is designated is the primary interface.
    // Therefore, the primary interface is guaranteed to be configured prior to any secondary interface.
    async fn configure_host_machine(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        explored_host: &mut ManagedHost,
        host_machine_interface: &MachineInterfaceSnapshot,
        explored_dpu: &ExploredDpu,
        metadata: Metadata,
    ) -> CarbideResult<MachineId> {
        match &explored_host.machine_id {
            Some(host_machine_id) => {
                // This is not the primary interface for this host
                // The primary interface *must* have already been created for this host (otherwise something very bad has happened)
                db::machine_interface::set_primary_interface(
                    &host_machine_interface.id,
                    false,
                    txn,
                )
                .await?;
                Ok(*host_machine_id)
            }
            None => {
                // This is the primary interface for the host.
                // 1. Generate the ID for the host from *this* DPU's hw info
                // 2. Add an entry for this host in the machines table (with a machine-id from (1)).
                let host_machine_id = self
                    .create_host_from_dpu_hw_info(
                        txn,
                        &explored_host.explored_host,
                        explored_dpu,
                        metadata,
                    )
                    .await?;

                tracing::info!(
                    ?host_machine_interface.id,
                    machine_id = %host_machine_id,
                    "Created host machine proactively in site-explorer",
                );

                explored_host.machine_id = Some(host_machine_id);
                db::machine_interface::set_primary_interface(&host_machine_interface.id, true, txn)
                    .await?;
                Ok(host_machine_id)
            }
        }
    }

    // 1) Generate the host's machine ID from the DPU's hardware info
    // 2) Create a machine for this host using the machine ID from (1)
    // 3) Update the "machine_topologies" table with the bmc info for this host
    async fn create_host_from_dpu_hw_info(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        explored_host: &ExploredManagedHost,
        explored_dpu: &ExploredDpu,
        mut metadata: Metadata,
    ) -> CarbideResult<MachineId> {
        let dpu_hw_info = explored_dpu.hardware_info()?;
        let predicted_machine_id = host_id_from_dpu_hardware_info(&dpu_hw_info)
            .map_err(|e| CarbideError::InvalidArgument(format!("hardware info missing: {e}")))?;

        if metadata.name.is_empty() {
            metadata.name = predicted_machine_id.to_string();
        }

        let _host_machine = db::machine::create(
            txn,
            Some(&self.common_pools),
            &predicted_machine_id,
            ManagedHostState::Created,
            &metadata,
        )
        .await?;

        let host_bmc_info = explored_host.bmc_info();
        let host_hardware_info = HardwareInfo::default();
        self.update_machine_topology(
            txn,
            &predicted_machine_id,
            host_bmc_info,
            host_hardware_info,
        )
        .await?;

        Ok(predicted_machine_id)
    }

    // 1) Create a machine for this host using the passed machine_id
    // 2) Update the "machine_topologies" table with the bmc info for this host
    async fn create_machine_from_explored_managed_host(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        managed_host: &ManagedHost,
        predicted_machine_id: &MachineId,
        mut metadata: Metadata,
    ) -> CarbideResult<()> {
        if metadata.name.is_empty() {
            metadata.name = predicted_machine_id.to_string();
        }

        _ = db::machine::create(
            txn,
            Some(&self.common_pools),
            predicted_machine_id,
            ManagedHostState::Created,
            &metadata,
        )
        .await?;
        let hardware_info = HardwareInfo::default();
        self.update_machine_topology(
            txn,
            predicted_machine_id,
            managed_host.explored_host.bmc_info(),
            hardware_info,
        )
        .await
    }

    async fn update_machine_topology(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        mut bmc_info: BmcInfo,
        hardware_info: HardwareInfo,
    ) -> CarbideResult<()> {
        let _topology = MachineTopology::create_or_update(txn, machine_id, &hardware_info).await?;

        // Forge scout will update this topology with a full information.
        MachineTopology::set_topology_update_needed(txn, machine_id, true).await?;

        // call enrich_mac_address to fill the MAC address info from the machine_interfaces table
        db::bmc_metadata::enrich_mac_address(
            &mut bmc_info,
            "SiteExplorer::update_machine_topology".to_string(),
            txn,
            machine_id,
            true,
        )
        .await?;

        db::bmc_metadata::update_bmc_network_into_topologies(txn, machine_id, &bmc_info).await?;

        Ok(())
    }

    pub async fn handle_redfish_error(
        &self,
        endpoint: Endpoint,
        metrics: &mut SiteExplorationMetrics,
        error: &EndpointExplorationError,
    ) {
        // If site explorer cant log in, theres nothing we can do.
        if !self
            .endpoint_explorer
            .have_credentials(&endpoint.iface)
            .await
        {
            return;
        }

        match self
            .is_managed_host_created_for_endpoint(endpoint.address)
            .await
        {
            Ok(managed_host_exists) => {
                if managed_host_exists {
                    tracing::info!(
                        "Site explorer will not remediate error for {endpoint} because a managed host has already been created for this endpoint: {error}"
                    );
                    return;
                }
            }
            Err(e) => {
                tracing::error!(%e, "failed to retrieve whether managed host was created for endpoint: {endpoint}");
                return;
            }
        };

        // Dont let site explorer issue either a force-restart or bmc-reset more than the rate limit.
        let reset_rate_limit = self.config.reset_rate_limit;
        let min_time_since_last_action_mins = 20;
        let start = Utc::now();
        let time_since_redfish_reboot =
            start.signed_duration_since(endpoint.last_redfish_reboot.unwrap_or_default());
        let time_since_redfish_bmc_reset =
            start.signed_duration_since(endpoint.last_redfish_bmc_reset.unwrap_or_default());
        let time_since_ipmitool_bmc_reset =
            start.signed_duration_since(endpoint.last_ipmitool_bmc_reset.unwrap_or_default());

        if time_since_redfish_reboot.num_minutes() < min_time_since_last_action_mins
            || time_since_redfish_bmc_reset.num_minutes() < min_time_since_last_action_mins
            || time_since_ipmitool_bmc_reset.num_minutes() < min_time_since_last_action_mins
        {
            tracing::info!(
                "waiting to remediate error {error} for {endpoint}; time_since_redfish_reboot: {time_since_redfish_reboot}; time_since_redfish_bmc_reset: {time_since_redfish_bmc_reset}; time_since_ipmitool_bmc_reset: {time_since_ipmitool_bmc_reset}"
            );
            return;
        }

        tracing::info!(
            "Site explorer captured an error for {endpoint}: {error};\n time_since_redfish_reboot: {time_since_redfish_reboot}; time_since_redfish_bmc_reset: {time_since_redfish_bmc_reset}; time_since_ipmitool_bmc_reset: {time_since_ipmitool_bmc_reset}'"
        );

        // If the endpoint is a DPU, and the error is that the BIOS attributes are coming up as empty for this DPU,
        // reboot the DPU as our first course of action. This is the official workaround from the DPU redfish team to mitigate empty UEFI attributes
        // until https://redmine.mellanox.com/issues/3746477 is fixed.
        //
        // If this fails, and we continue seeing the BIOS attributes come up as empty after twenty minutes (providing plenty of time)
        // for the DPU to come back up after the reboot, lets try resetting the BMC to see if it helps.

        if (error.is_dpu_redfish_bios_response_invalid())
            && time_since_redfish_reboot > reset_rate_limit
            && self
                .force_restart(&endpoint)
                .await
                .map_err(|err| {
                    tracing::error!(
                        "Site Explorer failed to reboot {}: {}",
                        endpoint.address,
                        err
                    )
                })
                .is_ok()
        {
            metrics.bmc_reboot_count += 1;
            return;
        }

        if self.is_viking_bmc(&endpoint).await && time_since_redfish_reboot > reset_rate_limit {
            match self.clear_nvram(&endpoint).await {
                Ok(_) => {
                    metrics.bmc_reboot_count += 1;
                    return;
                }
                Err(e) => {
                    tracing::error!(
                        "Site Explorer failed to clear nvram {}: {}",
                        endpoint.address,
                        e
                    )
                }
            }
        }

        if time_since_redfish_bmc_reset > reset_rate_limit
            && self
                .redfish_reset_bmc(&endpoint)
                .await
                .map_err(|err| {
                    tracing::error!(
                        "Site Explorer failed to reset BMC {} through redfish: {}",
                        endpoint.address,
                        err
                    )
                })
                .is_ok()
        {
            metrics.bmc_reset_count += 1;
            return;
        }

        if time_since_ipmitool_bmc_reset > reset_rate_limit {
            let _ = self.ipmitool_reset_bmc(&endpoint).await.map_err(|err| {
                tracing::error!(
                    "Site Explorer failed to reset BMC {} through ipmitool: {}",
                    endpoint.address,
                    err
                )
            });
            metrics.bmc_reset_count += 1;
        }
    }

    pub async fn ipmitool_reset_bmc(&self, endpoint: &Endpoint) -> CarbideResult<()> {
        tracing::info!(
            "SiteExplorer is initiating a cold BMC reset through IPMI to IP {}",
            endpoint.address
        );

        let bmc_target_port = self.config.override_target_port.unwrap_or(443);
        let bmc_target_addr = SocketAddr::new(endpoint.address, bmc_target_port);
        match self
            .endpoint_explorer
            .ipmitool_reset_bmc(bmc_target_addr, &endpoint.iface)
            .await
        {
            Ok(_) => {
                let mut txn = self.database_connection.begin().await.map_err(|e| {
                    DatabaseError::new(file!(), line!(), "begin set_last_ipmitool_bmc_reset", e)
                })?;

                DbExploredEndpoint::set_last_ipmitool_bmc_reset(endpoint.address, &mut txn).await?;

                txn.commit().await.map_err(|e| {
                    DatabaseError::new(file!(), line!(), "end set_last_ipmitool_bmc_reset", e)
                })?;

                Ok(())
            }
            Err(e) => Err(CarbideError::internal(format!(
                "site-explorer failed to cold reset bmc through ipmitool {}: {:#?}",
                endpoint.address, e
            ))),
        }
    }

    pub async fn redfish_reset_bmc(&self, endpoint: &Endpoint) -> CarbideResult<()> {
        tracing::info!(
            "SiteExplorer is initiating a BMC reset through Redfish to IP {}",
            endpoint.address
        );
        let bmc_target_port = self.config.override_target_port.unwrap_or(443);
        let bmc_target_addr = SocketAddr::new(endpoint.address, bmc_target_port);
        match self
            .endpoint_explorer
            .redfish_reset_bmc(bmc_target_addr, &endpoint.iface)
            .await
        {
            Ok(_) => {
                let mut txn = self.database_connection.begin().await.map_err(|e| {
                    DatabaseError::new(file!(), line!(), "begin set_last_redfish_bmc_reset", e)
                })?;

                DbExploredEndpoint::set_last_redfish_bmc_reset(endpoint.address, &mut txn).await?;

                txn.commit().await.map_err(|e| {
                    DatabaseError::new(file!(), line!(), "end set_last_redfish_bmc_reset", e)
                })?;

                Ok(())
            }
            Err(e) => Err(CarbideError::internal(format!(
                "site-explorer failed to reset bmc through redfish {}: {:#?}",
                endpoint.address, e
            ))),
        }
    }

    pub async fn is_viking_bmc(&self, endpoint: &Endpoint) -> bool {
        let bmc_target_port = self.config.override_target_port.unwrap_or(443);
        let bmc_target_addr = SocketAddr::new(endpoint.address, bmc_target_port);
        match self
            .endpoint_explorer
            .is_viking(bmc_target_addr, &endpoint.iface)
            .await
        {
            Ok(is_viking) => is_viking,
            Err(e) => {
                tracing::warn!("could not retrieve vendor for {}: {e}", endpoint.address);
                false
            }
        }
    }
    pub async fn clear_nvram(&self, endpoint: &Endpoint) -> CarbideResult<()> {
        tracing::info!(
            "SiteExplorer is issuing a clean_nvram through Redfish to IP {}",
            endpoint.address
        );
        let bmc_target_port = self.config.override_target_port.unwrap_or(443);
        let bmc_target_addr = SocketAddr::new(endpoint.address, bmc_target_port);

        self.endpoint_explorer
            .clear_nvram(bmc_target_addr, &endpoint.iface)
            .await
            .map_err(|err| {
                CarbideError::internal(format!(
                    "site-explorer failed to clear nvram {}: {:#?}",
                    endpoint.address, err
                ))
            })?;

        self.force_restart(endpoint).await
    }

    pub async fn force_restart(&self, endpoint: &Endpoint) -> CarbideResult<()> {
        tracing::info!(
            "SiteExplorer is initiating a reboot through Redfish to IP {}",
            endpoint.address
        );
        let bmc_target_port = self.config.override_target_port.unwrap_or(443);
        let bmc_target_addr = SocketAddr::new(endpoint.address, bmc_target_port);
        match self
            .endpoint_explorer
            .redfish_power_control(
                bmc_target_addr,
                &endpoint.iface,
                libredfish::SystemPowerControl::ForceRestart,
            )
            .await
        {
            Ok(()) => {
                let mut txn = self.database_connection.begin().await.map_err(|e| {
                    DatabaseError::new(file!(), line!(), "begin set_last_redfish_reboot", e)
                })?;

                DbExploredEndpoint::set_last_redfish_reboot(endpoint.address, &mut txn).await?;

                txn.commit().await.map_err(|e| {
                    DatabaseError::new(file!(), line!(), "end set_last_redfish_reboot", e)
                })?;

                Ok(())
            }
            Err(e) => Err(CarbideError::internal(format!(
                "site-explorer failed to reboot {}: {:#?}",
                endpoint.address, e
            ))),
        }
    }

    async fn is_managed_host_created_for_endpoint(
        &self,
        bmc_ip_address: IpAddr,
    ) -> CarbideResult<bool> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "begin is_managed_host_created_for_endpoint",
                e,
            )
        })?;

        let is_endpoint_in_managed_host =
            is_endpoint_in_managed_host(bmc_ip_address, &mut txn).await?;

        txn.commit().await.map_err(|e| {
            DatabaseError::new(
                file!(),
                line!(),
                "end is_managed_host_created_for_endpoint",
                e,
            )
        })?;

        Ok(is_endpoint_in_managed_host)
    }

    /// can_ingest_dpu_endpoint returns a boolean indicating whether the site explorer should continue ingesting a DPU endpoint.
    /// it will always return true for a DPU that has already been ingested.
    async fn can_ingest_dpu_endpoint(
        &self,
        dpu_endpoint: &ExploredEndpoint,
    ) -> CarbideResult<bool> {
        let is_managed_host_created_for_endpoint = match self
            .is_managed_host_created_for_endpoint(dpu_endpoint.address)
            .await
        {
            Ok(managed_host_exists) => managed_host_exists,
            Err(e) => {
                tracing::error!(%e, "failed to retrieve whether managed host was created for DPU endpoint: {dpu_endpoint}");
                // return true by default
                true
            }
        };

        if is_managed_host_created_for_endpoint {
            // this dpu has already been ingested
            return Ok(true);
        }

        if let Some(nic_mode) = dpu_endpoint.report.nic_mode() {
            // DPU's in NIC mode do not have full redfish functionality,
            // for example, we will not be able to retrieve the base GUID
            // from the redfish response. Skip the next check because the DPUs
            // in NIC mode will not expose a pf0 interface to the host.
            if nic_mode == NicMode::Nic {
                tracing::info!(
                    "Site explorer found an uningested DPU (bmc ip: {}) in NIC mode",
                    dpu_endpoint.address
                );
                return Ok(true);
            }
        } else {
            tracing::error!(
                "Site explorer found an uningested DPU (bmc ip: {}) without being able to determine if it is in NIC mode",
                dpu_endpoint.address
            );
            return Ok(false);
        }

        // This is a bluefield in DPU mode
        match find_host_pf_mac_address(dpu_endpoint) {
            Ok(_) => Ok(true),
            Err(error) => {
                tracing::error!(%error, "Site explorer found an uningested DPU (bmc ip: {}): failed to find the MAC address of the pf0 interface that the DPU exposes to the host", dpu_endpoint.address);
                Ok(false)
            }
        }
    }

    async fn set_nic_mode(
        &self,
        dpu_endpoint: ExploredEndpoint,
        mode: NicMode,
    ) -> CarbideResult<()> {
        let bmc_target_port = self.config.override_target_port.unwrap_or(443);
        let bmc_target_addr = SocketAddr::new(dpu_endpoint.address, bmc_target_port);

        let interface = self
            .find_machine_interface_for_ip(dpu_endpoint.address)
            .await?;

        self.endpoint_explorer
            .set_nic_mode(bmc_target_addr, &interface, mode)
            .await
            .map_err(|err| CarbideError::EndpointExplorationError {
                action: "set_nic_mode",
                err,
            })
    }

    async fn redfish_power_control(
        &self,
        bmc_ip_address: IpAddr,
        action: libredfish::SystemPowerControl,
    ) -> CarbideResult<()> {
        let bmc_target_port = self.config.override_target_port.unwrap_or(443);
        let bmc_target_addr = SocketAddr::new(bmc_ip_address, bmc_target_port);

        let interface = self.find_machine_interface_for_ip(bmc_ip_address).await?;

        self.endpoint_explorer
            .redfish_power_control(bmc_target_addr, &interface, action)
            .await
            .map_err(|err| CarbideError::EndpointExplorationError {
                action: "redfish_power_control",
                err,
            })
    }

    async fn redfish_powercycle(&self, bmc_ip_address: IpAddr) -> CarbideResult<()> {
        self.redfish_power_control(bmc_ip_address, libredfish::SystemPowerControl::PowerCycle)
            .await?;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "begin set_last_redfish_powercycle", e)
        })?;

        DbExploredEndpoint::set_last_redfish_powercycle(bmc_ip_address, &mut txn).await?;

        txn.commit().await.map_err(|e| {
            CarbideError::DBError(DatabaseError::new(
                file!(),
                line!(),
                "end set_last_redfish_powercycle",
                e,
            ))
        })
    }

    async fn find_machine_interface_for_ip(
        &self,
        ip_address: IpAddr,
    ) -> CarbideResult<MachineInterfaceSnapshot> {
        let mut txn = self.database_connection.begin().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "begin find_machine_interface_for_ip", e)
        })?;

        let machine_interface = db::machine_interface::find_by_ip(&mut txn, ip_address).await?;

        txn.commit().await.map_err(|e| {
            DatabaseError::new(file!(), line!(), "end find_machine_interface_for_ip", e)
        })?;

        match machine_interface {
            Some(interface) => Ok(interface),
            None => Err(CarbideError::NotFoundError {
                kind: "machine_interface",
                id: format!("remote_ip={ip_address:?}"),
            }),
        }
    }

    //// can_ingest_host_endpoint will return true if the site explorer should proceed with ingesting a given host endpoint.
    /// It will always return true for a host that has already been ingested.
    ///
    /// If the host has not been ingested, and is not on, the function will try to turn the host on and return false.
    /// If the host has not been ingested, is a Lenovo,  and infinite boot is disabled, the function will try to enable
    /// infinite boot and return false.
    /// Otherwise, the function will return true.
    async fn can_ingest_host_endpoint(
        &self,
        host_endpoint: &ExploredEndpoint,
    ) -> CarbideResult<bool> {
        let is_managed_host_created_for_endpoint = match self
            .is_managed_host_created_for_endpoint(host_endpoint.address)
            .await
        {
            Ok(managed_host_exists) => managed_host_exists,
            Err(e) => {
                tracing::error!(%e, "failed to retrieve whether managed host was created for Host endpoint: {host_endpoint}");
                // return true by default
                true
            }
        };

        if is_managed_host_created_for_endpoint {
            // this host has already been ingested
            return Ok(true);
        }

        let bmc_target_port = self.config.override_target_port.unwrap_or(443);
        let bmc_target_addr = SocketAddr::new(host_endpoint.address, bmc_target_port);
        let Some(system) = host_endpoint.report.systems.first() else {
            tracing::warn!(
                "Site Explorer could not find the system report for a host (bmc_ip_address: {})",
                host_endpoint.address,
            );

            return Ok(false);
        };

        let mut ingest_host = true;

        if !matches!(system.power_state, PowerState::On) {
            tracing::warn!(
                "Site Explorer found an uningested host (bmc_ip_address: {}) that isnt on: {:#?}",
                host_endpoint.address,
                system.power_state
            );

            let interface = self
                .find_machine_interface_for_ip(host_endpoint.address)
                .await?;

            let _ = self.endpoint_explorer
                .redfish_power_control(
                    bmc_target_addr,
                    &interface.clone(),
                    libredfish::SystemPowerControl::On,
                )
                .await
                .map_err(|err| {
                    tracing::error!(
                        "Site Explorer failed to turn on host (bmc_ip_address: {}) through redfish: {}",
                        host_endpoint.address,
                        err
                    )
                });

            ingest_host = false;
        }

        if host_endpoint.report.vendor.unwrap_or_default().is_lenovo()
            && system
                .attributes
                .is_infinite_boot_enabled
                .is_some_and(|status| !status)
        {
            tracing::warn!(
                "Site Explorer found an uningested Lenovo (bmc_ip_address: {}) without infinite boot enabled; System Report: {:#?}",
                host_endpoint.address,
                system.attributes
            );

            let interface = self
                .find_machine_interface_for_ip(bmc_target_addr.ip())
                .await?;

            let _ = self.endpoint_explorer
                .forge_setup(bmc_target_addr, &interface.clone(), None)
                .await
                .map_err(|err| {
                    tracing::error!(
                        "Site Explorer failed to call forge_setup against Lenovo (bmc_ip_address: {}): {}",
                        host_endpoint.address,
                        err
                    )
                });

            let _ = self.endpoint_explorer
                .redfish_power_control(
                    bmc_target_addr,
                    &interface,
                    libredfish::SystemPowerControl::ForceRestart,
                )
                .await
                .map_err(|err| {
                    tracing::error!(
                        "Site Explorer failed to restart Lenovo (bmc_ip_address: {}) after calling forge_setup: {}",
                        host_endpoint.address,
                        err
                    )
                });

            ingest_host = false;
        }

        Ok(ingest_host)
    }

    // check_and_configure_dpu_mode returns a boolean indicating whether a DPU is configured correctly.
    // check_and_configure_dpu_mode will always return true for BF2s
    // check_and_configure_dpu_mode will return false if a BF3 SuperNIC is configured in DPU mode or if a BF3 DPU is configured in NIC mode. Otherwise, it will return true.
    // if check_and_configure_dpu_mode returns false, it will try to configure the DPU appropriately (put a BF3 SuperNIC in NIC mode or put a BF3 DPU in DPU mode)
    async fn check_and_configure_dpu_mode(
        &self,
        dpu_ep: ExploredEndpoint,
        dpu_model: String,
    ) -> CarbideResult<bool> {
        match dpu_ep.report.nic_mode() {
            Some(NicMode::Dpu) => {
                if is_bf3_supernic(&dpu_model) {
                    tracing::warn!(
                        "site explorer found a BF3 SuperNIC ({}) that is in DPU mode; will try setting it into NIC mode",
                        dpu_ep.address
                    );
                    self.set_nic_mode(dpu_ep.clone(), NicMode::Nic).await?;
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
            Some(NicMode::Nic) => {
                if is_bf3_dpu(&dpu_model) {
                    tracing::warn!(
                        "site explorer found a BF3 DPU ({}) that is in NIC mode; will try setting it into DPU mode",
                        dpu_ep.address
                    );
                    self.set_nic_mode(dpu_ep.clone(), NicMode::Dpu).await?;
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
            None => {
                tracing::warn!(
                    "Site explorer cannot determine this DPU's mode {}: {:#?}",
                    dpu_ep.address,
                    dpu_ep.report
                );
                Ok(true)
            }
        }
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

/// get_base_mac_from_sys_image_version returns a base MAC address
/// for a given sys image version/ See comments below about how the
/// DPU derives a MAC from a DPU_SYS_IMAGE, but ultimately, a
/// DPU_SYS_IMAGE of a088:c203:0046:0c68 means you just take out
/// chars 6-10, and you get a MAC of a0:88:c2:46:0c:68.
fn get_base_mac_from_sys_image_version(sys_image_version: String) -> Result<String, String> {
    // The DPU_SYS_IMAGE is always 19 characters long. Well, until
    // it isn't, but for now, the DPU_SYS_IMAGE is 19 characters
    // long.
    if sys_image_version.len() != 19 {
        return Err(format!(
            "Invalid sys_image_version length: {} ({})",
            sys_image_version.len(),
            sys_image_version,
        ));
    }

    // First, strip out the colons, and make sure we're
    // left with 16 [what should be hex-friendly] characters.
    let mut base_mac = sys_image_version.replace(':', "");
    if base_mac.len() != 16 {
        return Err(format!(
            "Invalid base_mac length from sys_image_version after removing ':': {}",
            base_mac.len()
        ));
    }

    // And now drop range 6-10, leaving us with what
    // should be the 12 characters for the MAC address.
    base_mac.replace_range(6..10, "");

    Ok(base_mac)
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
    // First, try to grab a MAC from explored Redfish data,
    // which lives under ComputerSystem. Otherwise, just fall
    // back to the legacy method via get_sys_image_version.
    //
    // This returns the source MAC for the given source type,
    // as well as String for the "source type", making it a
    // little easier to debug in the event something fails.
    let (source_mac, source_type) = if let Some(system_mac) = dpu_ep
        .report
        .systems
        .first()
        .and_then(|s| s.base_mac.clone())
    {
        (system_mac, "explored/computer-system".to_string())
    } else {
        (
            get_base_mac_from_sys_image_version(get_sys_image_version(
                dpu_ep.report.service.as_ref(),
            )?)?,
            "legacy/service".to_string(),
        )
    };

    // Once we've got a some unsanitized MAC value, from whatever source,
    // sanitize it (stripping out garbage like spaces, double quotes, etc),
    // and return a sanitized MA:CA:DD:RE:SS as a MacAddress.
    sanitized_mac(source_mac.clone()).map_err(|e| {
        format!(
            "Failed to build sanitized MAC from {} MAC: {} (source_mac: {})",
            source_type, e, source_mac
        )
    })
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
            exploration_requested: false,
            last_redfish_bmc_reset: None,
            last_ipmitool_bmc_reset: None,
            last_redfish_reboot: None,
            last_redfish_powercycle: None,
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
            Err("Failed to build sanitized MAC from legacy/service MAC: Invalid stripped MAC length: 11 (input: b83fd29095fz, output: b83fd29095f) (source_mac: b83fd29095fz)".to_string())
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
            Err("Invalid sys_image_version length: 3 (abc)".to_string())
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
