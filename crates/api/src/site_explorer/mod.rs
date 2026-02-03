/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt::Display;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::panic::Location;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use carbide_uuid::machine::MachineType;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::power_shelf::{PowerShelfIdSource, PowerShelfType};
use carbide_uuid::switch::{SwitchIdSource, SwitchType};
use chrono::Utc;
use config_version::ConfigVersion;
use db::{
    self, DatabaseError, ObjectFilter, Transaction, machine, network_segment as db_network_segment,
    power_shelf as db_power_shelf, switch as db_switch,
};
use forge_network::sanitized_mac;
use futures_util::stream::FuturesUnordered;
use futures_util::{StreamExt, TryFutureExt};
use itertools::Itertools;
use libredfish::model::oem::nvidia_dpu::NicMode;
use mac_address::MacAddress;
use model::expected_power_shelf::ExpectedPowerShelf;
use model::expected_switch::ExpectedSwitch;
use model::machine::MachineInterfaceSnapshot;
use model::machine::machine_search_config::MachineSearchConfig;
use model::power_shelf::{NewPowerShelf, PowerShelfConfig};
use model::resource_pool::common::CommonPools;
use model::site_explorer::{
    EndpointExplorationError, EndpointExplorationReport, EndpointType, ExploredDpu,
    ExploredEndpoint, ExploredManagedHost, MachineExpectation, PowerState, PreingestionState,
    Service, is_bf3_dpu, is_bf3_supernic, is_bluefield_model,
};
use model::switch::{NewSwitch, SwitchConfig};
use sqlx::PgPool;
use tokio::sync::oneshot;
use tracing::Instrument;
use version_compare::Cmp;

use crate::cfg::file::{FirmwareConfig, SiteExplorerConfig};
use crate::rack::rms_client::{RmsApi, RmsNodeType};
use crate::{CarbideError, CarbideResult};

mod endpoint_explorer;
pub use endpoint_explorer::EndpointExplorer;
mod credentials;
mod metrics;
pub use metrics::SiteExplorationMetrics;
mod bmc_endpoint_explorer;
mod redfish;
mod rms;
pub use bmc_endpoint_explorer::BmcEndpointExplorer;
mod boot_order_tracker;
use boot_order_tracker::BootOrderTracker;

mod machine_creator;
pub use machine_creator::MachineCreator;
pub mod explored_endpoint_index;
mod managed_host;

use db::ObjectColumnFilter;
use db::work_lock_manager::WorkLockManagerHandle;
pub use managed_host::is_endpoint_in_managed_host;
use model::expected_machine::ExpectedMachine;
use model::firmware::FirmwareComponentType;
use model::machine_interface_address::MachineInterfaceAssociation;
use model::network_segment::NetworkSegmentType;

use self::metrics::{PairingBlockerReason, exploration_error_to_metric_label};
use crate::site_explorer::explored_endpoint_index::ExploredEndpointIndex;

#[derive(Debug)]
pub struct Endpoint<'a> {
    address: IpAddr,
    iface: &'a MachineInterfaceSnapshot,
    last_redfish_bmc_reset: Option<chrono::DateTime<chrono::Utc>>,
    last_ipmitool_bmc_reset: Option<chrono::DateTime<chrono::Utc>>,
    last_redfish_reboot: Option<chrono::DateTime<chrono::Utc>>,
    old_report: Option<(ConfigVersion, &'a EndpointExplorationReport)>,
    pub(crate) expected: Option<&'a ExpectedMachine>,
    pub(crate) expected_power_shelf: Option<&'a ExpectedPowerShelf>,
    pub(crate) expected_switch: Option<&'a ExpectedSwitch>,
    pause_remediation: bool,
    boot_interface_mac: Option<MacAddress>,
}

impl Display for Endpoint<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.address)
    }
}

pub type SiteIdentifiedHosts = Vec<(ExploredManagedHost, EndpointExplorationReport)>;

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
    work_lock_manager_handle: WorkLockManagerHandle,
    machine_creator: MachineCreator,
    boot_order_tracker: BootOrderTracker,
    rms_client: Option<Arc<dyn RmsApi>>,
}

impl SiteExplorer {
    const ITERATION_WORK_KEY: &'static str = "SiteExplorer::run_single_iteration";

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        database_connection: sqlx::PgPool,
        explorer_config: SiteExplorerConfig,
        meter: opentelemetry::metrics::Meter,
        endpoint_explorer: Arc<dyn EndpointExplorer>,
        firmware_config: Arc<FirmwareConfig>,
        common_pools: Arc<CommonPools>,
        work_lock_manager_handle: WorkLockManagerHandle,
        rms_client: Option<Arc<dyn RmsApi>>,
    ) -> Self {
        // We want to hold metrics for longer than the iteration interval, so there is continuity
        // in emitting metrics. However we want to avoid reporting outdated metrics in case
        // reporting gets stuck. Therefore round up the iteration interval by 1min.
        let hold_period = explorer_config
            .run_interval
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(meter, hold_period));

        SiteExplorer {
            machine_creator: MachineCreator::new(
                database_connection.clone(),
                explorer_config.clone(),
                common_pools,
            ),
            database_connection,
            enabled: explorer_config.enabled,
            config: explorer_config,
            metric_holder,
            endpoint_explorer,
            firmware_config,
            work_lock_manager_handle,
            boot_order_tracker: BootOrderTracker::default(),
            rms_client,
        }
    }

    /// Start the SiteExplorer and return a [sending channel](tokio::sync::oneshot::Sender) that will stop the SiteExplorer when dropped.
    pub fn start(mut self) -> eyre::Result<oneshot::Sender<i32>> {
        let (stop_sender, stop_receiver) = oneshot::channel();

        if self.enabled {
            tokio::task::Builder::new()
                .name("site_explorer")
                .spawn(async move { self.run(stop_receiver).await })?;
        }

        Ok(stop_sender)
    }

    async fn run(&mut self, mut stop_receiver: oneshot::Receiver<i32>) {
        loop {
            match self.run_single_iteration().await {
                Ok(identified_hosts) => self
                    .boot_order_tracker
                    .track_hosts(Instant::now(), &identified_hosts),
                Err(e) => {
                    tracing::warn!("SiteExplorer error: {}", e);
                }
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

    // This function can just async when
    // https://github.com/rust-lang/rust/issues/110011 will be
    // implemented
    #[track_caller]
    fn txn_begin(&self) -> impl Future<Output = CarbideResult<db::Transaction<'_>>> {
        let loc = Location::caller();
        db::Transaction::begin_with_location(&self.database_connection, loc).map_err(Into::into)
    }

    pub async fn run_single_iteration(&self) -> CarbideResult<SiteIdentifiedHosts> {
        let mut metrics = SiteExplorationMetrics::new();

        let _work_lock = match self
            .work_lock_manager_handle
            .try_acquire_lock(Self::ITERATION_WORK_KEY.into())
            .await
        {
            Ok(lock) => lock,
            Err(e) => {
                return Err(CarbideError::internal(format!(
                    "Failed to acquire connection: {e}"
                )));
            }
        };

        tracing::trace!(
            lock = SiteExplorer::ITERATION_WORK_KEY,
            "SiteExplorer acquired the lock",
        );

        let span_id: String = format!("{:#x}", u64::from_le_bytes(rand::random::<[u8; 8]>()));

        let explore_site_span = tracing::span!(
            parent: None,
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
            Ok(_) => {
                explore_site_span.record("otel.status_code", "ok");
            }
            Err(e) => {
                tracing::error!("SiteExplorer run failed due to: {:?}", e);
                explore_site_span.record("otel.status_code", "error");
                // Writing this field will set the span status to error
                // Therefore we only write it on errors
                explore_site_span.record("otel.status_message", format!("{e:?}"));
            }
        }

        // Cache all other metrics that have been captured in this iteration.
        // Those will be queried by OTEL on demand
        self.metric_holder.update_metrics(metrics);

        res
    }

    /// Audits and collects metrics of _all_ explored results vs. _all_ expected machines, not a single exploration cycle.
    /// Also updates the Site Explorer Health Report for all explored endpoints based on the last exploration data.
    ///
    /// * `metrics`                   - A metrics collector for accumulating and later emitting metrics.
    /// * `matched_expected_machines` - A map of expected machines that have been matched to interfaces, indexed by IP(s).
    async fn audit_exploration_results(
        &self,
        metrics: &mut SiteExplorationMetrics,
        expected_endpoint_index: &ExploredEndpointIndex,
    ) -> CarbideResult<()> {
        let mut txn = self.txn_begin().await?;

        // Grab them all because we care about everything,
        // not just the subset in the current run.
        let explored_endpoints = db::explored_endpoints::find_all(&mut txn).await?;
        let explored_managed_hosts = db::explored_managed_host::find_all(&mut txn).await?;

        txn.rollback().await?;

        // Go through all the explored endpoints and collect metrics and submit
        // health reports
        for ep in explored_endpoints.into_iter() {
            if ep.report.endpoint_type != EndpointType::Bmc {
                // Skip anything that isn't a BMC.
                continue;
            }

            // We need to find the last health report for the endpoint in order to update it with latest health data
            let mut txn = self.txn_begin().await?;
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

            let expected_machine = expected_endpoint_index.matched_expected_machine(&ep.address);

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
                let expected_sn = &expected_machine.data.serial_number;

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

            txn.commit().await?;
        }

        // Count the total number of explored managed hosts
        for explored_managed_host in explored_managed_hosts {
            metrics.increment_endpoint_explorations_identified_managed_hosts_overall_count(
                expected_endpoint_index
                    .matched_expected_machine(&explored_managed_host.host_bmc_ip)
                    .is_some()
                    .into(),
            );
        }

        Ok(())
    }

    async fn explore_site(
        &self,
        metrics: &mut SiteExplorationMetrics,
    ) -> CarbideResult<SiteIdentifiedHosts> {
        self.check_preconditions(metrics).await?;
        let expected_endpoint_index = self.update_explored_endpoints(metrics).await?;

        // Create a list of DPUs and hosts that site explorer should try to ingest. Site explorer uses the following criteria to determine whether
        // to ingest a given endpoint (creating a managed host containing the endpoint and adding it to the state machine):
        // 1) Pre-ingestion must have completed for a given endpoint
        // 2a) If the endpoint is for a DPU: make sure that site explorer can retrieve the mac address of the pf0 interface that the DPU exposes to the host.
        // If site explorer is unable to retrieve this mac address, there is no point in creating a managed host: we will not be able to configure the host appropriately.
        // 2b) If the endpoint is for a host: make sure that the host is on and that infinite boot is enabled. Otherwise, we will not be able to provision the DPU appropriately
        // once we create a managed host and add it to the state machine.
        let (explored_dpus, explored_hosts) = self.identify_machines_to_ingest(metrics).await?;

        // Note/TODO:
        // Since we generate the managed-host pair in a different transaction than endpoint discovery,
        // the generation of both reports is not necessarily atomic.
        // This is improvable
        // However since host information rarely changes (we never reassign MachineInterfaces),
        // this should be ok. The most noticable effect is that ManagedHost population might be delayed a bit.
        let mut identified_hosts = self
            .identify_managed_hosts(
                metrics,
                &expected_endpoint_index,
                explored_dpus,
                explored_hosts,
            )
            .await?;

        if self.config.create_machines.load(Ordering::Relaxed) {
            let start_create_machines = std::time::Instant::now();
            let create_machines_res = self
                .machine_creator
                .create_machines(metrics, &mut identified_hosts, &expected_endpoint_index)
                .await;
            metrics.create_machines_latency = Some(start_create_machines.elapsed());
            create_machines_res?;
        }

        // Identify and create power shelves
        let explored_power_shelves = self.identify_power_shelves_to_ingest().await?;

        if self.config.create_power_shelves.load(Ordering::Relaxed) {
            let start_create_power_shelves = std::time::Instant::now();
            let create_power_shelves_res: Result<(), CarbideError> = self
                .create_power_shelves(metrics, explored_power_shelves, &expected_endpoint_index)
                .await;
            metrics.create_power_shelves_latency = Some(start_create_power_shelves.elapsed());
            create_power_shelves_res?;
        }

        // Identify and create switches
        let explored_switches = self
            .identify_switches_to_ingest(&expected_endpoint_index)
            .await?;

        if self.config.create_switches.load(Ordering::Relaxed) {
            let start_create_switches = std::time::Instant::now();
            let create_switches_res: Result<(), CarbideError> =
                self.create_switches(metrics, explored_switches).await;
            metrics.create_switches_latency = Some(start_create_switches.elapsed());
            create_switches_res?;
        }

        // Audit after everything has been explored, identified, and created.
        self.audit_exploration_results(metrics, &expected_endpoint_index)
            .await?;

        Ok(identified_hosts)
    }

    async fn create_power_shelves(
        &self,
        metrics: &mut SiteExplorationMetrics,
        explored_power_shelves: Vec<(ExploredEndpoint, EndpointExplorationReport)>,
        expected_endpoint_index: &ExploredEndpointIndex,
    ) -> CarbideResult<()> {
        for (endpoint, report) in explored_power_shelves {
            let address = endpoint.address;
            let Some(expected_power_shelf) =
                expected_endpoint_index.matched_expected_power_shelf(&endpoint.address)
            else {
                tracing::info!(
                    "No expected power shelf found for endpoint {:#?}",
                    endpoint.address
                );
                continue;
            };

            match self
                .create_power_shelf(
                    endpoint,
                    report,
                    expected_power_shelf,
                    &self.database_connection,
                )
                .await
            {
                Ok(true) => {
                    metrics.created_power_shelves_count += 1;
                    if metrics.created_power_shelves_count as u64
                        == self.config.power_shelves_created_per_run
                    {
                        break;
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(%error, "Failed to create power shelf {:#?}", address)
                }
            }
        }

        Ok(())
    }

    /// Creates a `Switch` object for an identified switch endpoint with initial states
    async fn create_switches(
        &self,
        metrics: &mut SiteExplorationMetrics,
        explored_switches: Vec<(ExploredEndpoint, &ExpectedSwitch)>,
    ) -> CarbideResult<()> {
        for (endpoint, expected_switch) in explored_switches {
            let address = endpoint.address;
            match self
                .create_switch(endpoint, expected_switch, &self.database_connection)
                .await
            {
                Ok(true) => {
                    metrics.created_switches_count += 1;
                    if metrics.created_switches_count as u64 == self.config.switches_created_per_run
                    {
                        break;
                    }
                }
                Ok(false) => {}
                Err(error) => {
                    tracing::error!(%error, "Failed to create switch {:#?}", address)
                }
            }
        }

        Ok(())
    }

    pub async fn create_power_shelf(
        &self,
        explored_endpoint: ExploredEndpoint,
        report: EndpointExplorationReport,
        expected_shelf: &ExpectedPowerShelf,
        pool: &PgPool,
    ) -> CarbideResult<bool> {
        let mut txn = pool
            .begin()
            .await
            .map_err(|e| DatabaseError::new("begin load create_power_shelf", e))?;

        tracing::info!(
            "creating power shelf for endpoint: {} ",
            explored_endpoint.address
        );

        // Check if a power shelf with the same name already exists
        if !expected_shelf.metadata.name.is_empty() {
            let existing_power_shelves = db_power_shelf::find_by(
                &mut txn,
                ObjectColumnFilter::All::<db::power_shelf::NameColumn>,
                db_power_shelf::PowerShelfSearchConfig::default(),
            )
            .await?;

            // Check if any existing power shelf has the same name
            for existing_ps in &existing_power_shelves {
                if existing_ps.config.name == expected_shelf.metadata.name {
                    tracing::info!(
                        "Power shelf with name '{}' already exists, skipping creation for endpoint {}",
                        &expected_shelf.metadata.name,
                        explored_endpoint.address
                    );
                    txn.rollback()
                        .await
                        .map_err(|e| DatabaseError::new("rollback create_power_shelf", e))?;
                    return Ok(false);
                }
            }
        }

        // Create a new power shelf
        // Generate power_shelf_id similar to machine_id using deterministic hashing
        // Extract power shelf metadata similar to how machine_id extracts hardware info
        //TODO fetch these from chassis
        let power_shelf_serial = expected_shelf.metadata.name.as_str();
        let power_shelf_vendor = "NVIDIA"; // Default vendor for power shelves
        let power_shelf_model = "PowerShelf"; // Default model identifier
        // TODO: Fetch power shelf location from chassis metadata or configuration
        // NOTE: Metadata does not have a 'location' field, so use a default for now.

        let power_shelf_id = match model::power_shelf::power_shelf_id::from_hardware_info(
            power_shelf_serial,
            power_shelf_vendor,
            power_shelf_model,
            PowerShelfIdSource::ProductBoardChassisSerial,
            PowerShelfType::Rack,
        ) {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(%e, "Failed to create power shelf ID");
                return Err(CarbideError::InvalidArgument(format!(
                    "Failed to create power shelf ID: {e}"
                )));
            }
        };

        let config = PowerShelfConfig {
            name: expected_shelf.metadata.name.clone(),
            capacity: Some(100),
            voltage: Some(240),
            location: Some("US/CA/DC/San Jose/1000 N Mathilda Ave".to_string()),
        };

        let new_power_shelf = NewPowerShelf {
            id: power_shelf_id,
            config,
        };

        db_power_shelf::create(&mut txn, &new_power_shelf).await?;

        let mac_addresses = report.all_mac_addresses();
        for mac_address in mac_addresses {
            let mi = db::machine_interface::find_by_mac_address(&mut txn, mac_address).await?;
            if let Some(interface) = mi.first() {
                db::machine_interface::associate_interface_with_machine(
                    &interface.id,
                    MachineInterfaceAssociation::PowerShelf(power_shelf_id),
                    &mut txn,
                )
                .await?;
            }
        }

        let mac_addresses = report.all_mac_addresses();
        for mac_address in mac_addresses {
            let mi = db::machine_interface::find_by_mac_address(&mut txn, mac_address).await?;
            if let Some(interface) = mi.first() {
                db::machine_interface::associate_interface_with_machine(
                    &interface.id,
                    MachineInterfaceAssociation::PowerShelf(power_shelf_id),
                    &mut txn,
                )
                .await?;
            }
        }

        if let Some(rack_id) = expected_shelf.rack_id {
            let rack = match db::rack::get(&mut txn, rack_id).await {
                Ok(rack) => rack,
                Err(_) => db::rack::create(
                    &mut txn,
                    rack_id,
                    vec![],
                    vec![],
                    vec![expected_shelf.bmc_mac_address],
                )
                .await
                .map_err(CarbideError::from)?,
            };
            let mut config = rack.config.clone();
            config.power_shelves.push(power_shelf_id);
            db::rack::update(&mut txn, rack_id, &config)
                .await
                .map_err(CarbideError::from)?;
        }
        // No need to update the power shelf name again; it was already set in config above.
        txn.commit()
            .await
            .map_err(|e| DatabaseError::new("end create_power_shelf", e))?;

        tracing::info!(
            "Created power shelf {} for endpoint {}",
            power_shelf_id,
            explored_endpoint.address
        );

        // Register the power shelf with Rack Manager if RMS client is available
        if let Some(rms_client) = &self.rms_client {
            if let Some(rack_id) = expected_shelf.rack_id {
                if let Err(e) = rms::add_node_to_rms(
                    rms_client.as_ref(),
                    rack_id,
                    power_shelf_id.to_string(),
                    explored_endpoint.address.to_string(),
                    443,
                    expected_shelf.bmc_mac_address,
                    RmsNodeType::PowerShelf,
                )
                .await
                {
                    tracing::warn!(
                        "Failed to add power shelf {} to Rack Manager: {}",
                        power_shelf_id,
                        e
                    );
                } else {
                    tracing::info!(
                        "Added power shelf {} to Rack Manager for endpoint {}",
                        power_shelf_id,
                        explored_endpoint.address,
                    );
                }
            } else {
                tracing::warn!(
                    "Cannot add power shelf {} to Rack Manager: rack_id is missing",
                    power_shelf_id
                );
            }
        }

        Ok(true)
    }

    pub async fn create_switch(
        &self,
        explored_endpoint: ExploredEndpoint,
        expected_switch: &ExpectedSwitch,
        pool: &PgPool,
    ) -> CarbideResult<bool> {
        let mut txn = pool
            .begin()
            .await
            .map_err(|e| DatabaseError::new("begin load create_switch", e))?;

        // Generate switch_id similar to machine_id using deterministic hashing
        // Extract switch metadata similar to how machine_id extracts hardware info
        //TODO fetch these from chassis
        let switch_serial = expected_switch.serial_number.as_str();
        let switch_vendor = "NVIDIA"; // Default vendor for switches
        let switch_model = "Switch"; // Default model identifier

        let switch_id = match model::switch::switch_id::from_hardware_info(
            switch_serial,
            switch_vendor,
            switch_model,
            SwitchIdSource::ProductBoardChassisSerial,
            SwitchType::NvLink,
        ) {
            Ok(id) => id,
            Err(e) => {
                tracing::error!(%e, "Failed to create switch ID");
                return Err(CarbideError::InvalidArgument(format!(
                    "Failed to create switch ID: {e}"
                )));
            }
        };

        // TODO: review
        // Check if a switch with the same SwitchId already exists
        if let Some(_existing_switch) = db_switch::find_by_id(&mut txn, &switch_id).await? {
            tracing::info!(
                "Switch with ID '{}' already exists, skipping creation for endpoint {}",
                switch_id,
                explored_endpoint.address
            );
            txn.rollback()
                .await
                .map_err(|e| DatabaseError::new("rollback create_switch", e))?;
            return Ok(false);
        }

        let config = SwitchConfig {
            name: switch_serial.to_string(), // TODO: use metadata.name if it is not empty
            enable_nmxc: false,
            fabric_manager_config: None,
            location: Some("US/CA/DC/San Jose/1000 N Mathilda Ave".to_string()),
        };

        let new_switch = NewSwitch {
            id: switch_id,
            config,
        };

        db_switch::create(&mut txn, &new_switch).await?;

        let mac_addresses = explored_endpoint.report.all_mac_addresses();
        for mac_address in mac_addresses {
            let mi = db::machine_interface::find_by_mac_address(&mut txn, mac_address).await?;
            if let Some(interface) = mi.first() {
                db::machine_interface::associate_interface_with_machine(
                    &interface.id,
                    MachineInterfaceAssociation::Switch(switch_id),
                    &mut txn,
                )
                .await?;
            }
        }

        // No need to update the switch name again; it was already set in config above.
        txn.commit()
            .await
            .map_err(|e| DatabaseError::new("end create_switch", e))?;

        tracing::info!(
            "Created switch {} for endpoint {}",
            switch_id,
            explored_endpoint.address,
        );

        // Register the switch with Rack Manager if RMS client is available
        if let Some(rms_client) = &self.rms_client {
            if let Some(rack_id) = expected_switch.rack_id {
                if let Err(e) = rms::add_node_to_rms(
                    rms_client.as_ref(),
                    rack_id,
                    switch_id.to_string(),
                    explored_endpoint.address.to_string(),
                    443,
                    expected_switch.bmc_mac_address,
                    RmsNodeType::Switch,
                )
                .await
                {
                    tracing::warn!("Failed to add switch {} to Rack Manager: {}", switch_id, e);
                } else {
                    tracing::info!(
                        "Added switch {} to Rack Manager for endpoint {}",
                        switch_id,
                        explored_endpoint.address,
                    );
                }
            } else {
                tracing::warn!(
                    "Cannot add switch {} to Rack Manager: rack_id is missing",
                    switch_id
                );
            }
        }

        Ok(true)
    }

    /// identify_machines_to_ingest returns two maps.
    /// The first map returned identifies all of the DPUs that site explorer will try to ingest.
    /// The latter identifies all of the hosts the the site explorer will try to ingest.
    /// Both map from machine BMC IP address to the corresponding explored endpoint.
    async fn identify_machines_to_ingest(
        &self,
        metrics: &mut SiteExplorationMetrics,
    ) -> CarbideResult<(
        HashMap<IpAddr, ExploredEndpoint>,
        HashMap<IpAddr, ExploredEndpoint>,
    )> {
        let mut txn = self.txn_begin().await?;

        // TODO: We reload the endpoint list even though we just regenerated it
        // Could optimize this by keeping it in memory. But since the manipulations
        // are quite complicated in the previous step, this makes things much easier
        let explored_endpoints =
            db::explored_endpoints::find_all_preingestion_complete(&mut txn).await?;

        txn.commit().await?;

        let mut explored_dpus = HashMap::new();
        let mut explored_hosts = HashMap::new();
        for ep in explored_endpoints.into_iter() {
            if ep.report.endpoint_type != EndpointType::Bmc {
                continue;
            }

            if ep.report.is_power_shelf() {
                continue;
            }

            if ep.report.is_switch() {
                continue;
            }

            if ep.report.is_dpu() {
                // Ignore the DPU if we are using the host NIC instead of the DPU NIC.
                if self.config.use_onboard_nic.load(Ordering::Relaxed) {
                    continue;
                }
                if self.can_ingest_dpu_endpoint(metrics, &ep).await? {
                    explored_dpus.insert(ep.address, ep);
                }
            } else if self.can_ingest_host_endpoint(metrics, &ep).await? {
                explored_hosts.insert(ep.address, ep);
            }
        }

        Ok((explored_dpus, explored_hosts))
    }

    async fn identify_managed_hosts(
        &self,
        metrics: &mut SiteExplorationMetrics,
        expected_explored_endpoint_index: &ExploredEndpointIndex,
        explored_dpus: HashMap<IpAddr, ExploredEndpoint>,
        explored_hosts: HashMap<IpAddr, ExploredEndpoint>,
    ) -> CarbideResult<Vec<(ExploredManagedHost, EndpointExplorationReport)>> {
        if self.config.use_onboard_nic.load(Ordering::Relaxed) {
            // Ignore the DPU and ingest the machine as a managed host
            return Ok(explored_hosts
                .values()
                .map(|ep| {
                    (
                        ExploredManagedHost {
                            host_bmc_ip: ep.address,
                            dpus: vec![],
                        },
                        ep.report.clone(),
                    )
                })
                .collect());
        }
        // Match HOST and DPU using SerialNumber.
        // Compare DPU system.serial_number with HOST chassis.network_adapters[].serial_number
        let mut dpu_sn_to_endpoint = HashMap::new();
        for (_, ep) in explored_dpus {
            if let Some(sn) = ep
                .report
                .systems
                .first()
                .and_then(|system| system.serial_number.as_ref())
            {
                dpu_sn_to_endpoint.insert(sn.trim().to_string(), ep);
            }
        }

        let mut managed_hosts = Vec::new();
        let mut boot_interface_macs: Vec<(IpAddr, MacAddress)> = Vec::new();

        let is_dpu_in_nic_mode = |dpu_ep: &ExploredEndpoint, host_ep: &ExploredEndpoint| -> bool {
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

        for (_, ep) in explored_hosts {
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

                    if let Some(sn) = pcie_device.serial_number.as_ref().map(|sn| sn.trim())
                        && let Entry::Occupied(dpu_ep_entry) =
                            dpu_sn_to_endpoint.entry(sn.to_string())
                    {
                        let dpu_ep = dpu_ep_entry.get();
                        if let Some(model) = pcie_device.part_number.as_ref() {
                            match self
                                .check_and_configure_dpu_mode(dpu_ep, model.to_string())
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
                        if is_dpu_in_nic_mode(dpu_ep, &ep) {
                            expected_num_dpus_attached_to_host -= 1;
                            continue;
                        }

                        // TODO: we can use dpu_ep_entry.remove() here but we need to
                        // make sure that it will not affect fallback_dpu_serial_numbers logic.
                        let dpu_ep = dpu_ep_entry.get().clone();
                        dpus_explored_for_host.push(ExploredDpu {
                            bmc_ip: dpu_ep.address,
                            host_pf_mac_address: get_host_pf_mac_address(&dpu_ep),
                            report: dpu_ep.report.into(),
                        });
                    }
                }
            }

            if expected_num_dpus_attached_to_host == 0 {
                for chassis in ep.report.chassis.iter() {
                    for network_adapter in chassis.network_adapters.iter() {
                        if let Some(model) = network_adapter.part_number.as_ref()
                            && is_bluefield_model(model.trim())
                        {
                            expected_num_dpus_attached_to_host += 1;
                        }

                        if let Some(sn) = network_adapter.serial_number.as_ref().map(|sn| sn.trim())
                            && let Entry::Occupied(dpu_ep_entry) =
                                dpu_sn_to_endpoint.entry(sn.to_string())
                        {
                            let dpu_ep = dpu_ep_entry.get();
                            if let Some(model) = network_adapter.part_number.as_ref() {
                                match self
                                    .check_and_configure_dpu_mode(dpu_ep, model.to_string())
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
                            if is_dpu_in_nic_mode(dpu_ep, &ep) {
                                expected_num_dpus_attached_to_host -= 1;
                                continue;
                            }

                            // TODO: we can use dpu_ep_entry.remove() insted of clone here but we need to
                            // make sure that it will not affect fallback_dpu_serial_numbers logic.
                            let dpu_ep = dpu_ep_entry.get().clone();
                            dpus_explored_for_host.push(ExploredDpu {
                                bmc_ip: dpu_ep.address,
                                host_pf_mac_address: get_host_pf_mac_address(&dpu_ep),
                                report: dpu_ep.report.into(),
                            });
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
                if let Some(expected_machine) =
                    expected_explored_endpoint_index.matched_expected_machine(&ep.address)
                {
                    for dpu_sn in &expected_machine.data.fallback_dpu_serial_numbers {
                        if let Some(dpu_ep) = dpu_sn_to_endpoint.remove(dpu_sn.as_str()) {
                            // We do not want to attach bluefields that are in NIC mode as DPUs to the host
                            if is_dpu_in_nic_mode(&dpu_ep, &ep)
                                && expected_num_dpus_attached_to_host > 0
                            {
                                expected_num_dpus_attached_to_host -= 1;
                                continue;
                            }

                            // we found at least one DPU from expected machines for this host
                            // assume that the expected machines is the source of truth. Clear the
                            // contents of dpus_explored_for_host to discard the previous results of
                            // iterating over the hosts pcie devices.
                            if !dpu_added {
                                dpus_explored_for_host.clear();
                            }

                            dpu_added = true;
                            dpus_explored_for_host.push(ExploredDpu {
                                bmc_ip: dpu_ep.address,
                                host_pf_mac_address: get_host_pf_mac_address(&dpu_ep),
                                report: dpu_ep.report.into(),
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
                                let time_since_redfish_powercycle = Utc::now()
                                    .signed_duration_since(
                                        ep.last_redfish_powercycle.unwrap_or_default(),
                                    );
                                if time_since_redfish_powercycle > self.config.reset_rate_limit {
                                    tracing::warn!(
                                        "power cycling Dell {} to apply nic mode change for its incorrectly configured DPUs; time since last powercycle: {time_since_redfish_powercycle}",
                                        ep.address,
                                    );

                                    self.redfish_powercycle(
                                        ep.address,
                                    )
                                        .await.inspect_err(|err| tracing::warn!("site explorer failed to power cycle host {} to apply DPU mode changes: {err}", ep.address)).ok();
                                }
                            } else {
                                tracing::warn!(
                                    "wait for manual power cycle of host {}; site explorer doesn't support power cycling vendor {:#?}",
                                    ep.address,
                                    ep.report.vendor
                                );
                                metrics.increment_host_dpu_pairing_blocker(
                                    PairingBlockerReason::ManualPowerCycleRequired,
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
                        metrics.increment_host_dpu_pairing_blocker(
                            PairingBlockerReason::NoDpuReportedByHost,
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
                boot_interface_macs.push((ep.address, mac_address));

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
                    metrics.increment_host_dpu_pairing_blocker(
                        PairingBlockerReason::BootInterfaceMacMismatch,
                    );
                    continue;
                }
            }

            if !is_sorted {
                // Sort using usual way.
                dpus_explored_for_host.sort_by_key(|d| {
                    d.report.systems[0]
                        .serial_number
                        .as_deref()
                        .unwrap_or("")
                        .to_lowercase()
                });
            }

            managed_hosts.push((
                ExploredManagedHost {
                    host_bmc_ip: ep.address,
                    dpus: dpus_explored_for_host,
                },
                ep.report,
            ));
            metrics.exploration_identified_managed_hosts += 1;
        }

        let mut txn = self.txn_begin().await?;

        db::explored_managed_host::update(
            &mut txn,
            managed_hosts
                .iter()
                .map(|(h, _)| h)
                .collect::<Vec<_>>()
                .as_slice(),
        )
        .await?;

        // Persist boot interface MACs for host endpoints
        for (address, mac) in &boot_interface_macs {
            db::explored_endpoints::set_boot_interface_mac(*address, *mac, &mut txn).await?;
        }

        txn.commit().await?;

        Ok(managed_hosts)
    }

    async fn identify_power_shelves_to_ingest(
        &self,
    ) -> CarbideResult<Vec<(ExploredEndpoint, EndpointExplorationReport)>> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| DatabaseError::new("load find_all_preingestion_complete data", e))?;

        let explored_endpoints =
            db::explored_endpoints::find_all_preingestion_complete(&mut txn).await?;

        txn.commit()
            .await
            .map_err(|e| DatabaseError::new("end find_all_preingestion_complete data", e))?;

        let mut explored_power_shelves = Vec::new();
        for ep in explored_endpoints.into_iter() {
            if ep.report.endpoint_type != EndpointType::Bmc {
                continue;
            }
            if ep.report.is_power_shelf() {
                explored_power_shelves.push((ep.clone(), ep.report.clone()));
            }
            //ignore other endpoints
        }

        Ok(explored_power_shelves)
    }

    async fn identify_switches_to_ingest<'a>(
        &self,
        expected_endpoint_index: &'a ExploredEndpointIndex,
    ) -> CarbideResult<Vec<(ExploredEndpoint, &'a ExpectedSwitch)>> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| DatabaseError::new("load find_all_preingestion_complete data", e))?;

        let explored_endpoints =
            db::explored_endpoints::find_all_preingestion_complete(&mut txn).await?;

        txn.commit()
            .await
            .map_err(|e| DatabaseError::new("end find_all_preingestion_complete data", e))?;

        Ok(explored_endpoints
            .into_iter()
            .filter_map(|ep| {
                if ep.report.endpoint_type == EndpointType::Bmc
                    && let Some(expected_switch) =
                        expected_endpoint_index.matched_expected_switch(&ep.address)
                {
                    Some((ep, expected_switch))
                } else {
                    None
                }
            })
            .collect())
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
    ) -> CarbideResult<ExploredEndpointIndex> {
        let mut txn = self.txn_begin().await?;

        let underlay_segments =
            db::network_segment::list_segment_ids(&mut txn, Some(NetworkSegmentType::Underlay))
                .await?;
        let interfaces = db::machine_interface::find_all(&mut txn).await?;
        let explored_endpoints = db::explored_endpoints::find_all(&mut txn).await?;
        let expected_switches = db::expected_switch::find_all(&mut txn).await?;
        let expected_machines = db::expected_machine::find_all(&mut txn).await?;
        let expected_power_shelves = db::expected_power_shelf::find_all(&mut txn).await?;

        let explore_power_shelves_from_static_ip = self
            .config
            .explore_power_shelves_from_static_ip
            .load(Ordering::Relaxed);

        // Load SKU information for expected machines to record metrics
        let sku_ids: Vec<&str> = expected_machines
            .iter()
            .filter_map(|em| em.data.sku_id.as_deref())
            .collect();
        let skus = db::sku::find(&mut txn, &sku_ids).await?;

        txn.commit().await?;

        // Create a map of sku_id -> device_type for quick lookup
        let sku_device_types: HashMap<String, Option<String>> = skus
            .into_iter()
            .map(|sku| (sku.id, sku.device_type))
            .collect();

        // Record expected machine metrics
        for expected_machine in &expected_machines {
            let device_type = expected_machine
                .data
                .sku_id
                .as_ref()
                .and_then(|sku_id| sku_device_types.get(sku_id))
                .and_then(|dt| dt.as_deref());
            metrics.increment_expected_machines_sku_count(
                expected_machine.data.sku_id.as_deref(),
                device_type,
            );
        }

        let expected_count = expected_machines.len();

        // We don't have to scan anything that is on the Tenant or Admin Segments,
        // since we know what those Segments are used for (Forge allocated the IPs on the segments
        // for a specific machine).
        // We also can skip scanning IPs which are knowingly used as DPU OOB interfaces,
        // since those will not speak redfish.
        // Note: As a side effect of this, OOB interfaces might for a short time be scanned,
        // until the machine is ingested. At that point in time this filter will remove them
        // from the to-be-scanned list.
        let underlay_interfaces: Vec<MachineInterfaceSnapshot> = {
            // Get all underlay interfaces from the database
            let underlay_interfaces = interfaces.into_iter().filter(|iface| {
                underlay_segments.contains(&iface.segment_id) && iface.machine_id.is_none()
            });

            // For power shelves, currently adding a bogus static IP as an underlay interface if
            // configured to do so.
            if explore_power_shelves_from_static_ip {
                let underlay_segment_id = self.get_underlay_segment_id().await?;
                underlay_interfaces
                    .chain(expected_power_shelves.iter().map(|expected_power_shelf| {
                        let fake_ip = self.get_static_ip_for_power_shelf(
                            &expected_power_shelf.bmc_mac_address,
                            expected_power_shelf.ip_address,
                        );
                        // Create a fake machine interface for the power shelf
                        let mut fake_interface = MachineInterfaceSnapshot::mock_with_mac(
                            expected_power_shelf.bmc_mac_address,
                        );
                        fake_interface.hostname =
                            format!("power-shelf-{}", expected_power_shelf.serial_number);
                        fake_interface.segment_id = underlay_segment_id;
                        fake_interface.addresses = vec![fake_ip];
                        fake_interface.network_segment_type = Some(NetworkSegmentType::Underlay);
                        fake_interface.vendors = vec!["PowerShelf".to_string()];
                        fake_interface
                    }))
                    .collect()
            } else {
                underlay_interfaces.collect()
            }
        };

        // Start an index of all underlay interfaces, expected machines, expected power shelves, and expected switches.
        let index = ExploredEndpointIndex::builder(explored_endpoints, underlay_interfaces)
            .with_expected_machines(expected_machines)
            .with_expected_switches(expected_switches)
            .with_expected_power_shelves(expected_power_shelves)
            .build();

        // If a previously explored endpoint is not part of `MachineInterfaces` anymore,
        // we can delete knowledge about it. Otherwise we might try to refresh the
        // information about the endpoint
        let mut delete_endpoints = Vec::new();
        let mut priority_update_endpoints = Vec::new();
        let mut update_endpoints = Vec::with_capacity(index.explored_endpoints().len());
        for (address, endpoint) in index.explored_endpoints() {
            match index.underlay_interface(address) {
                Some(iface) => {
                    if endpoint.exploration_requested {
                        priority_update_endpoints.push((*address, iface, endpoint));
                    } else {
                        update_endpoints.push((*address, iface, endpoint));
                    }
                }
                None => {
                    if endpoint.report.is_power_shelf() && explore_power_shelves_from_static_ip {
                        tracing::info!(%address, "Not deleting power shelf endpoint from database, as we are sourcing power shelves from static IP's")
                    } else {
                        delete_endpoints.push(*address)
                    }
                }
            }
        }

        // The unknown endpoints can quickly be cleaned up
        if !delete_endpoints.is_empty() {
            let mut txn = self.txn_begin().await?;
            db::explored_endpoints::delete_many(&mut txn, &delete_endpoints).await?;
            txn.commit().await?;
        }

        // If there is a MachineInterface and no previously discovered information,
        // we need to detect it. This includes both regular machines, PowerShelves
        // and Switches.
        let unexplored_endpoints = index.get_unexplored_endpoints();

        // Now that we gathered the candidates for exploration, let's decide what
        // we are actually going to explore. The config limits the amount of explorations
        // per iteration.
        let num_explore_endpoints = (self.config.explorations_per_run as usize)
            .min(unexplored_endpoints.len() + update_endpoints.len());

        let mut explore_endpoint_data = Vec::with_capacity(num_explore_endpoints);

        // We prioritize existing endpoints which have the `exploration_requested` flag set
        for (address, iface, endpoint) in priority_update_endpoints
            .into_iter()
            .take(num_explore_endpoints)
        {
            explore_endpoint_data.push(Endpoint {
                address,
                iface,
                last_redfish_bmc_reset: endpoint.last_redfish_bmc_reset,
                last_ipmitool_bmc_reset: endpoint.last_ipmitool_bmc_reset,
                last_redfish_reboot: endpoint.last_redfish_reboot,
                old_report: Some((endpoint.report_version, &endpoint.report)),
                pause_remediation: endpoint.pause_remediation,
                boot_interface_mac: endpoint.boot_interface_mac,
                expected_switch: index.matched_expected_switch(&address),
                expected_power_shelf: index.matched_expected_power_shelf(&address),
                expected: index.matched_expected_machine(&address),
            });
        }

        // Next priority are all endpoints that we've never looked at
        let remaining_explore_endpoints = num_explore_endpoints - explore_endpoint_data.len();
        for (address, iface) in unexplored_endpoints
            .iter()
            .take(remaining_explore_endpoints)
        {
            explore_endpoint_data.push(Endpoint {
                address: *address,
                iface,
                last_redfish_bmc_reset: None,
                last_ipmitool_bmc_reset: None,
                last_redfish_reboot: None,
                old_report: None,
                expected_switch: index.matched_expected_switch(address),
                expected_power_shelf: index.matched_expected_power_shelf(address),
                expected: index.matched_expected_machine(address),
                pause_remediation: false, // New endpoints haven't been explored yet, so pause_remediation defaults to false
                boot_interface_mac: None, // boot_interface_mac not yet discovered for new endpoints
            });
        }

        // If we have any capacity available, we update knowledge about endpoints we looked at earlier on
        let remaining_explore_endpoints = num_explore_endpoints - explore_endpoint_data.len();
        if remaining_explore_endpoints != 0 {
            // Sort endpoints so that we will replace the oldest report first
            update_endpoints.sort_by_key(|(_address, _machine_interface, endpoint)| {
                endpoint.report_version.timestamp()
            });
            for (address, iface, endpoint) in update_endpoints
                .into_iter()
                .take(remaining_explore_endpoints)
            {
                explore_endpoint_data.push(Endpoint {
                    address,
                    iface,
                    last_redfish_bmc_reset: endpoint.last_redfish_bmc_reset,
                    last_ipmitool_bmc_reset: endpoint.last_ipmitool_bmc_reset,
                    last_redfish_reboot: endpoint.last_redfish_reboot,
                    old_report: Some((endpoint.report_version, &endpoint.report)),
                    expected: index.matched_expected_machine(&address),
                    expected_power_shelf: index.matched_expected_power_shelf(&address),
                    expected_switch: index.matched_expected_switch(&address),
                    pause_remediation: endpoint.pause_remediation,
                    boot_interface_mac: endpoint.boot_interface_mac,
                });
            }
        }

        let task_set = FuturesUnordered::new();
        let concurrency_limiter = Arc::new(tokio::sync::Semaphore::new(
            self.config.concurrent_explorations as usize,
        ));

        // Record the difference between the total expected machine count and
        // the number of expected machines we've actually "seen."
        metrics.endpoint_explorations_expected_machines_missing_overall_count =
            expected_count - index.all_matched_expected_machines().len();

        for endpoint in explore_endpoint_data.into_iter() {
            let endpoint_explorer = self.endpoint_explorer.clone();
            let concurrency_limiter = concurrency_limiter.clone();

            let bmc_target_port = self.config.override_target_port.unwrap_or(443);
            let bmc_target_addr = SocketAddr::new(endpoint.address, bmc_target_port);
            let firmware_config = self.firmware_config.clone();
            let database_connection = self.database_connection.clone();

            task_set.push(
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
                            endpoint.iface,
                            endpoint.expected,
                            endpoint.expected_power_shelf,
                            endpoint.expected_switch,
                            endpoint.old_report.map(|report| report.1),
                            endpoint.boot_interface_mac,
                        )
                        .await;

                    if let Err(error) = &result {
                        // For logging purposes
                        let machine_state = match get_machine_state_by_bmc_ip(
                            &database_connection,
                            &endpoint.address.to_string(),
                        )
                            .await
                        {
                            Ok(state) if !state.is_empty() => format!(" (state: {state})"),
                            _ => String::new(),
                        };
                        tracing::info!(%error, "Failed to explore {}: {}{}", bmc_target_addr, error, machine_state);
                    }

                    // Try to generate a MachineId and parsed version info based on the retrieved data
                    if let Ok(report) = &mut result {
                        if !report.is_power_shelf() {
                            tracing::info!("Generating MachineId for machine");
                            if let Err(error) = report.generate_machine_id(false) {
                                tracing::error!(%error, "Can not generate MachineId for explored endpoint");
                            }
                            report.model = report.model();
                            if let Some(fw_info) = firmware_config.find_fw_info_for_host_report(report)
                            {
                                let components_without_version = report.parse_versions(&fw_info);
                                if !components_without_version.is_empty() {
                                    tracing::debug!("Can not find firmware version for component(s): {:?}", components_without_version);
                                }
                            } else {
                                // It's possible that we knew about this host type before but do not now, so make sure we
                                // do not keep stale data.
                                report.versions = HashMap::default();
                                tracing::debug!("Can not find fimware info for: vendor: {:?}; model: {:?}", report.vendor, report.model());
                            }

                            // Go through the chassis entries and get what at least one of them says
                            report.parse_position_info()
                        } else {
                            tracing::info!("Generating PowerShelfId for power shelf");
                            if let Err(error) = report.generate_power_shelf_id() {
                                tracing::error!(%error, "Can not generate PowerShelfId for explored power shelf endpoint");
                            }
                            report.versions = HashMap::default();
                        }
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
        let exploration_results = task_set.collect::<Vec<_>>().await;

        // All subtasks finished. We now update the database
        let mut txn = self.txn_begin().await?;

        let mut redfish_errors = Vec::new();

        for (mut endpoint, result, exploration_duration) in exploration_results.into_iter() {
            let address = endpoint.address;
            let mut redfish_error = None;

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
                        redfish_error = Some(e.clone());
                    }
                }
            }

            // Update possible stale machine versions
            if let Ok(report) = &result
                && let Some(bmc_version) = report.versions.get(&FirmwareComponentType::Bmc)
                && let Some(uefi_version) = report.versions.get(&FirmwareComponentType::Uefi)
            {
                db::machine_topology::update_firmware_version_by_bmc_address(
                    &mut txn,
                    &address,
                    bmc_version,
                    uefi_version,
                )
                .await?;
            }

            match endpoint.old_report {
                Some((old_version, ref mut old_report)) => {
                    match result {
                        Ok(mut report) => {
                            report.last_exploration_latency = Some(exploration_duration);
                            if old_report.endpoint_type == EndpointType::Unknown {
                                tracing::info!(
                                    address = %address,
                                    exploration_report = ?report,
                                    "Initial exploration of endpoint"
                                );
                            }
                            db::explored_endpoints::try_update(
                                address,
                                old_version,
                                &report,
                                false,
                                &mut txn,
                            )
                            .await?;
                        }
                        Err(e) => {
                            // If an endpoint can not be explored we don't delete the known information, since it's
                            // still helpful. The failure might just be intermittent.
                            let mut old_report = old_report.clone();
                            old_report.last_exploration_error = Some(e);
                            old_report.last_exploration_latency = Some(exploration_duration);
                            db::explored_endpoints::try_update(
                                address,
                                old_version,
                                &old_report,
                                true,
                                &mut txn,
                            )
                            .await?;
                        }
                    }
                }
                None => {
                    let should_pause_ingestion_and_poweron = pause_ingestion_and_poweron(
                        index.expected_machines(),
                        &endpoint.iface.mac_address,
                    );
                    match result {
                        Ok(mut report) => {
                            report.last_exploration_latency = Some(exploration_duration);
                            tracing::info!(
                                address = %address,
                                exploration_report = ?report,
                                "Initial exploration of endpoint"
                            );
                            db::explored_endpoints::insert(
                                address,
                                &report,
                                should_pause_ingestion_and_poweron,
                                &mut txn,
                            )
                            .await?;
                        }
                        Err(e) => {
                            // If an endpoint exploration failed we still track the result in the database
                            // That will avoid immmediatly retrying the exploration in the next run
                            let mut report = EndpointExplorationReport::new_with_error(e);
                            report.last_exploration_latency = Some(exploration_duration);
                            db::explored_endpoints::insert(
                                address,
                                &report,
                                should_pause_ingestion_and_poweron,
                                &mut txn,
                            )
                            .await?;
                        }
                    }

                    let power_shelf_manual_ingestion = endpoint.expected_power_shelf.is_some()
                        && explore_power_shelves_from_static_ip;

                    if !self.config.create_machines.load(Ordering::Relaxed)
                        || power_shelf_manual_ingestion
                    {
                        // We're using manual ingestion, making preingestion updates risky.  Go ahead and skip them.
                        db::explored_endpoints::set_preingestion_complete(address, &mut txn).await?
                    }
                }
            }

            // We wait until the end to add it to redfish_errors so we can move endpoint safely
            if let Some(e) = redfish_error {
                redfish_errors.push((e, endpoint));
            }
        }

        txn.commit().await?;

        // We handle redfish errors after committing the transaction, to avoid holding the
        // transaction while issuing expensive redfish calls.
        for (e, endpoint) in redfish_errors {
            self.handle_redfish_error(&endpoint, metrics, &e).await;
        }

        Ok(index)
    }

    // TODO(chet): Follow up with RMS team re: code cleanup, or
    // just take care of it myself (import/merge feedback).
    fn get_static_ip_for_power_shelf(
        &self,
        _mac_address: &MacAddress,
        ip_address: Option<IpAddr>,
    ) -> IpAddr {
        // Convert MAC address to a deterministic IP address
        // We'll use a private IP range (192.168.0.0/16) and derive the IP from MAC
        //TODO will check this later needd better logic
        // let mac_bytes = mac_address.bytes();
        // let ip_bytes = [192, 168, mac_bytes[4], mac_bytes[5]];
        // IpAddr::V4(std::net::Ipv4Addr::new(
        //     ip_bytes[0],
        //     ip_bytes[1],
        //     ip_bytes[2],
        //     ip_bytes[3],
        // ));
        // if ip_address.is_some() {
        //     return ip_address.unwrap();
        // }
        ip_address.unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
    }

    /// Get the underlay segment ID for power shelf interfaces
    async fn get_underlay_segment_id(&self) -> CarbideResult<NetworkSegmentId> {
        let mut txn = self
            .database_connection
            .begin()
            .await
            .map_err(|e| DatabaseError::new("begin get underlay segment id", e))?;

        let underlay_segments =
            db_network_segment::list_segment_ids(&mut txn, Some(NetworkSegmentType::Underlay))
                .await?;
        txn.rollback()
            .await
            .map_err(|e| DatabaseError::new("end get underlay segment id", e))?;

        // Return the first underlay segment, or create a default one if none exist
        underlay_segments
            .first()
            .copied()
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "underlay_segment",
                id: "no_underlay_segments_found".to_string(),
            })
    }

    pub async fn handle_redfish_error(
        &self,
        endpoint: &Endpoint<'_>,
        metrics: &mut SiteExplorationMetrics,
        error: &EndpointExplorationError,
    ) {
        // Check if remediation is paused for this endpoint first
        if endpoint.pause_remediation {
            tracing::info!(
                "Site explorer will not remediate error for {endpoint} because remediation is paused for this endpoint: {error}"
            );
            return;
        }

        // If site explorer cant log in, theres nothing we can do.
        if !self
            .endpoint_explorer
            .have_credentials(endpoint.iface)
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
                .force_restart(endpoint)
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

        if self.is_viking_bmc(endpoint).await && time_since_redfish_reboot > reset_rate_limit {
            match self.clear_nvram(endpoint).await {
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
                .redfish_reset_bmc(endpoint)
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
            self.ipmitool_reset_bmc(endpoint)
                .await
                .map_err(|err| {
                    tracing::error!(
                        "Site Explorer failed to reset BMC {} through ipmitool: {}",
                        endpoint.address,
                        err
                    )
                })
                .ok();
            metrics.bmc_reset_count += 1;
        }
    }

    pub async fn ipmitool_reset_bmc(&self, endpoint: &Endpoint<'_>) -> CarbideResult<()> {
        tracing::info!(
            "SiteExplorer is initiating a cold BMC reset through IPMI to IP {}",
            endpoint.address
        );

        let bmc_target_port = self.config.override_target_port.unwrap_or(443);
        let bmc_target_addr = SocketAddr::new(endpoint.address, bmc_target_port);
        match self
            .endpoint_explorer
            .ipmitool_reset_bmc(bmc_target_addr, endpoint.iface)
            .await
        {
            Ok(_) => {
                let mut txn = self.txn_begin().await?;

                db::explored_endpoints::set_last_ipmitool_bmc_reset(endpoint.address, &mut txn)
                    .await?;

                txn.commit().await?;

                Ok(())
            }
            Err(e) => Err(CarbideError::internal(format!(
                "site-explorer failed to cold reset bmc through ipmitool {}: {:#?}",
                endpoint.address, e
            ))),
        }
    }

    pub async fn redfish_reset_bmc(&self, endpoint: &Endpoint<'_>) -> CarbideResult<()> {
        tracing::info!(
            "SiteExplorer is initiating a BMC reset through Redfish to IP {}",
            endpoint.address
        );
        let bmc_target_port = self.config.override_target_port.unwrap_or(443);
        let bmc_target_addr = SocketAddr::new(endpoint.address, bmc_target_port);
        match self
            .endpoint_explorer
            .redfish_reset_bmc(bmc_target_addr, endpoint.iface)
            .await
        {
            Ok(_) => {
                let mut txn = self.txn_begin().await?;

                db::explored_endpoints::set_last_redfish_bmc_reset(endpoint.address, &mut txn)
                    .await?;

                txn.commit().await?;

                Ok(())
            }
            Err(e) => Err(CarbideError::internal(format!(
                "site-explorer failed to reset bmc through redfish {}: {:#?}",
                endpoint.address, e
            ))),
        }
    }

    pub async fn is_viking_bmc(&self, endpoint: &Endpoint<'_>) -> bool {
        let bmc_target_port = self.config.override_target_port.unwrap_or(443);
        let bmc_target_addr = SocketAddr::new(endpoint.address, bmc_target_port);
        match self
            .endpoint_explorer
            .is_viking(bmc_target_addr, endpoint.iface)
            .await
        {
            Ok(is_viking) => is_viking,
            Err(e) => {
                tracing::warn!("could not retrieve vendor for {}: {e}", endpoint.address);
                false
            }
        }
    }
    pub async fn clear_nvram(&self, endpoint: &Endpoint<'_>) -> CarbideResult<()> {
        tracing::info!(
            "SiteExplorer is issuing a clean_nvram through Redfish to IP {}",
            endpoint.address
        );
        let bmc_target_port = self.config.override_target_port.unwrap_or(443);
        let bmc_target_addr = SocketAddr::new(endpoint.address, bmc_target_port);

        self.endpoint_explorer
            .clear_nvram(bmc_target_addr, endpoint.iface)
            .await
            .map_err(|err| {
                CarbideError::internal(format!(
                    "site-explorer failed to clear nvram {}: {:#?}",
                    endpoint.address, err
                ))
            })?;

        self.force_restart(endpoint).await
    }

    pub async fn force_restart(&self, endpoint: &Endpoint<'_>) -> CarbideResult<()> {
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
                endpoint.iface,
                libredfish::SystemPowerControl::ForceRestart,
            )
            .await
        {
            Ok(()) => {
                let mut txn = self.txn_begin().await?;

                db::explored_endpoints::set_last_redfish_reboot(endpoint.address, &mut txn).await?;

                txn.commit().await?;

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
        let mut txn = self.txn_begin().await?;

        let is_endpoint_in_managed_host =
            is_endpoint_in_managed_host(bmc_ip_address, &mut txn).await?;

        txn.commit().await?;

        Ok(is_endpoint_in_managed_host)
    }

    /// can_ingest_dpu_endpoint returns a boolean indicating whether the site explorer should continue ingesting a DPU endpoint.
    /// it will always return true for a DPU that has already been ingested.
    async fn can_ingest_dpu_endpoint(
        &self,
        metrics: &mut SiteExplorationMetrics,
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
            metrics.increment_host_dpu_pairing_blocker(PairingBlockerReason::DpuNicModeUnknown);
            return Ok(false);
        }

        // This is a bluefield in DPU mode
        match find_host_pf_mac_address(dpu_endpoint) {
            Ok(_) => Ok(true),
            Err(error) => {
                tracing::error!(%error, "Site explorer found an uningested DPU (bmc ip: {}): failed to find the MAC address of the pf0 interface that the DPU exposes to the host", dpu_endpoint.address);
                metrics.increment_host_dpu_pairing_blocker(PairingBlockerReason::DpuPf0MacMissing);
                Ok(false)
            }
        }
    }

    async fn set_nic_mode(
        &self,
        dpu_endpoint: &ExploredEndpoint,
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

        let mut txn = self.txn_begin().await?;

        db::explored_endpoints::set_last_redfish_powercycle(bmc_ip_address, &mut txn).await?;

        Ok(txn.commit().await?)
    }

    async fn find_machine_interface_for_ip(
        &self,
        ip_address: IpAddr,
    ) -> CarbideResult<MachineInterfaceSnapshot> {
        let mut txn = self.txn_begin().await?;

        let machine_interface = db::machine_interface::find_by_ip(&mut txn, ip_address).await?;

        txn.commit().await?;

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
        metrics: &mut SiteExplorationMetrics,
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
            metrics
                .increment_host_dpu_pairing_blocker(PairingBlockerReason::HostSystemReportMissing);
            return Ok(false);
        };

        // if we are explicitly forbidden from powering on in the expected_machines,
        // then don't do it
        if host_endpoint.pause_ingestion_and_poweron {
            tracing::warn!(
                "Host with bmc_ip_address: {} is configured to pause on ingestion",
                host_endpoint.address
            );
            return Ok(false);
        }

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

            self.endpoint_explorer
                .redfish_power_control(
                    bmc_target_addr,
                    &interface,
                    libredfish::SystemPowerControl::On,
                )
                .await
                .map_err(|err| {
                    tracing::error!(
                        "Site Explorer failed to turn on host (bmc_ip_address: {}) through redfish: {}",
                        host_endpoint.address,
                        err
                    )
                }).ok();

            ingest_host = false;
        }

        if host_endpoint.report.vendor.unwrap_or_default().is_nvidia() {
            let Some(manager) = host_endpoint.report.managers.first() else {
                tracing::warn!(
                    "Site Explorer could not find the system report for a Nvidia host (bmc_ip_address: {})",
                    host_endpoint.address,
                );

                return Ok(false);
            };

            // Viking
            if system.id == "DGX" && manager.id == "BMC" {
                for service in host_endpoint.report.service.iter() {
                    if let Some(cpldmb_0_inventory) =
                        service.inventories.iter().find(|&x| x.id == "CPLDMB_0")
                    {
                        let current_cpldmb_0_version =
                            cpldmb_0_inventory.version.clone().unwrap_or_default();
                        let expected_cpldmb_0_version = "0.2.1.9";
                        match version_compare::compare_to(
                            &current_cpldmb_0_version,
                            expected_cpldmb_0_version,
                            Cmp::Eq,
                        ) {
                            Ok(is_cpldmb_version_at_expected) => {
                                if !is_cpldmb_version_at_expected {
                                    tracing::warn!(
                                        "Site Explorer found a Viking (bmc_ip_address: {}) with a CPLDMB_0 version of {current_cpldmb_0_version}, which is less than the expected version of {expected_cpldmb_0_version}. A DC Power Cycle may be needed",
                                        host_endpoint.address,
                                    );
                                    metrics.increment_host_dpu_pairing_blocker(
                                        PairingBlockerReason::VikingCpldVersionIssue,
                                    );
                                    return Ok(false);
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "Site Explorer found a Viking (bmc_ip_address: {}) with a CPLDMB_0 version of {current_cpldmb_0_version} and could not compare it to the current CPLDMB_0 version of {expected_cpldmb_0_version}: {e:#?}",
                                    host_endpoint.address,
                                );
                                metrics.increment_host_dpu_pairing_blocker(
                                    PairingBlockerReason::VikingCpldVersionIssue,
                                );
                                return Ok(false);
                            }
                        }
                    } else {
                        tracing::warn!(
                            "Site Explorer could not find the CPLDMB_0 inventory for a Viking (bmc_ip_address: {})",
                            host_endpoint.address,
                        );
                        metrics.increment_host_dpu_pairing_blocker(
                            PairingBlockerReason::VikingCpldVersionIssue,
                        );
                        return Ok(false);
                    };
                }
            }
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

            self.endpoint_explorer
                .machine_setup(bmc_target_addr, &interface, None)
                .await
                .inspect_err(|err| {
                    tracing::error!(
                        "Site Explorer failed to call machine_setup against Lenovo (bmc_ip_address: {}): {}",
                        host_endpoint.address,
                        err
                    )
                }).ok();

            self.endpoint_explorer
                .redfish_power_control(
                    bmc_target_addr,
                    &interface,
                    libredfish::SystemPowerControl::ForceRestart,
                )
                .await
                .inspect_err(|err| {
                    tracing::error!(
                        "Site Explorer failed to restart Lenovo (bmc_ip_address: {}) after calling machine_setup: {}",
                        host_endpoint.address,
                        err
                    )
                }).ok();

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
        dpu_ep: &ExploredEndpoint,
        dpu_model: String,
    ) -> CarbideResult<bool> {
        match dpu_ep.report.nic_mode() {
            Some(NicMode::Dpu) => {
                if is_bf3_supernic(&dpu_model) {
                    tracing::warn!(
                        "site explorer found a BF3 SuperNIC ({}) that is in DPU mode; will try setting it into NIC mode",
                        dpu_ep.address
                    );
                    self.set_nic_mode(dpu_ep, NicMode::Nic).await?;
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
                    self.set_nic_mode(dpu_ep, NicMode::Dpu).await?;
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

pub fn get_sys_image_version(services: &[Service]) -> Result<&String, String> {
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
        .as_ref()
        .ok_or("Missing DPU_SYS_IMAGE version".to_string())
}

/// get_base_mac_from_sys_image_version returns a base MAC address
/// for a given sys image version/ See comments below about how the
/// DPU derives a MAC from a DPU_SYS_IMAGE, but ultimately, a
/// DPU_SYS_IMAGE of a088:c203:0046:0c68 means you just take out
/// chars 6-10, and you get a MAC of a0:88:c2:46:0c:68.
fn get_base_mac_from_sys_image_version(sys_image_version: &String) -> Result<String, String> {
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
/// and that these values will be explicitly stored in the device's nonvolatile memory.
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

    // Try the explored computer-system base_mac first
    if let Some(system_mac) = dpu_ep
        .report
        .systems
        .first()
        .and_then(|s| s.base_mac.clone())
    {
        // Once we've got some unsanitized MAC value,
        // sanitize it (stripping out garbage like spaces, double quotes, etc),
        // and return a sanitized MA:CA:DD:RE:SS as a MacAddress.
        match sanitized_mac(&system_mac) {
            Ok(mac) => return Ok(mac),
            Err(e) => {
                tracing::warn!(
                    "Failed to sanitize ComputerSystem base_mac, falling back to legacy method: {} (source_mac: {})",
                    e,
                    system_mac
                );
            }
        }
    }

    let legacy_mac = get_base_mac_from_sys_image_version(get_sys_image_version(
        dpu_ep.report.service.as_ref(),
    )?)?;

    // Sanitize the legacy MAC and return it
    sanitized_mac(&legacy_mac).map_err(|e| {
        format!(
            "Failed to build sanitized MAC from legacy/service MAC: {e} (source_mac: {legacy_mac})"
        )
    })
}

pub async fn get_machine_state_by_bmc_ip(
    database_connection: &PgPool,
    bmc_ip: &str,
) -> Result<String, DatabaseError> {
    let mut txn = Transaction::begin(database_connection).await?;

    let state = match db::machine_topology::find_machine_id_by_bmc_ip(&mut txn, bmc_ip).await? {
        Some(machine_id) => {
            match machine::find_one(&mut txn, &machine_id, MachineSearchConfig::default()).await? {
                Some(machine) => machine.current_state().to_string(),
                None => String::new(),
            }
        }
        None => String::new(),
    };

    txn.commit().await?;

    Ok(state)
}

fn pause_ingestion_and_poweron(
    expected_machines_by_mac: &HashMap<MacAddress, ExpectedMachine>,
    mac_address: &mac_address::MacAddress,
) -> bool {
    if let Some(expected_machine) = expected_machines_by_mac.get(mac_address) {
        return expected_machine
            .data
            .default_pause_ingestion_and_poweron
            .unwrap_or(false);
    }

    false
}

#[cfg(test)]
mod tests {
    use model::site_explorer::PreingestionState;

    use super::*;

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
            pause_ingestion_and_poweron: false,
            pause_remediation: false,
            boot_interface_mac: None,
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
        let mut ep1 = ep;
        ep1.report
            .service
            .retain_mut(|inv| inv.id != "FirmwareInventory");
        assert_eq!(
            find_host_pf_mac_address(&ep1),
            Err("Missing FirmwareInventory".to_string())
        );
    }
}
