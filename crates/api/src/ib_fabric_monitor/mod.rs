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

mod metrics;

use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::sync::Arc;
use std::time::Duration;

use carbide_uuid::infiniband::IBPartitionId;
use carbide_uuid::machine::MachineId;
use chrono::Utc;
use db::ib_partition::IBPartition;
use db::work_lock_manager::WorkLockManagerHandle;
use db::{self, DatabaseError};
use health_report::OverrideMode;
use metrics::{
    AppliedChange, FabricMetrics, IbFabricMonitorMetrics, UfmOperation, UfmOperationStatus,
};
use model::ib::{IBNetwork, IBPort, IBPortMembership, IBPortState};
use model::ib_partition::PartitionKey;
use model::machine::infiniband::{
    MachineIbInterfaceStatusObservation, MachineInfinibandStatusObservation,
};
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{HostHealthConfig, LoadSnapshotOptions, ManagedHostStateSnapshot};
use rpc::forge::IbPartitionSearchFilter;
use sqlx::{PgConnection, PgPool};
use tokio::sync::oneshot;
use tracing::Instrument;

use crate::cfg::file::{CarbideConfig, IbFabricDefinition};
use crate::ib::{GetPartitionOptions, IBFabricManager, IBFabricManagerType};
use crate::periodic_timer::PeriodicTimer;
use crate::{CarbideError, CarbideResult};

/// `IbFabricMonitor` monitors the health of all connected InfiniBand fabrics in periodic intervals
pub struct IbFabricMonitor {
    db_pool: PgPool,

    fabrics: HashMap<String, IbFabricDefinition>,
    metric_holder: Arc<metrics::MetricHolder>,
    /// API for interaction with Forge IBFabricManager
    fabric_manager: Arc<dyn IBFabricManager>,

    host_health: HostHealthConfig,
    work_lock_manager_handle: WorkLockManagerHandle,
}

impl IbFabricMonitor {
    const ITERATION_WORK_KEY: &'static str = "IbFabricMonitor::run_single_iteration";

    /// Create a IbFabricMonitor
    pub fn new(
        db_pool: PgPool,
        fabrics: HashMap<String, IbFabricDefinition>,
        meter: opentelemetry::metrics::Meter,
        fabric_manager: Arc<dyn IBFabricManager>,
        config: Arc<CarbideConfig>,
        work_lock_manager_handle: WorkLockManagerHandle,
    ) -> Self {
        // We want to hold metrics for longer than the iteration interval, so there is continuity
        // in emitting metrics. However we want to avoid reporting outdated metrics in case
        // reporting gets stuck. Therefore round up the iteration interval by 1min.
        let hold_period = fabric_manager
            .get_config()
            .fabric_manager_run_interval
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(
            meter,
            hold_period,
            &fabrics
                .keys()
                .map(|fab| fab.as_str())
                .collect::<Vec<&str>>(),
        ));

        IbFabricMonitor {
            db_pool,
            fabrics,
            metric_holder,
            fabric_manager,
            host_health: config.host_health,
            work_lock_manager_handle,
        }
    }

    /// Start the IbFabricMonitor and return a [sending channel](tokio::sync::oneshot::Sender) that will stop the IbFabricMonitor when dropped.
    pub fn start(self) -> eyre::Result<oneshot::Sender<i32>> {
        let (stop_sender, stop_receiver) = oneshot::channel();

        if self.fabric_manager.get_config().manager_type != IBFabricManagerType::Disable {
            tokio::task::Builder::new()
                .name("ib_fabric_monitor")
                .spawn(async move { self.run(stop_receiver).await })?;
        }

        Ok(stop_sender)
    }

    async fn run(&self, mut stop_receiver: oneshot::Receiver<i32>) {
        let run_interval = self.fabric_manager.get_config().fabric_manager_run_interval;
        let timer = PeriodicTimer::new(run_interval);

        loop {
            let mut tick = timer.tick();
            match self.run_single_iteration().await {
                Ok(num_changes) => {
                    if num_changes > 0 {
                        // If any change has been applied to the IB fabric,
                        // the status that has been collected in the last iteration is already outdated
                        // Therefore run again as soon as possible.
                        tick.set_interval(Duration::from_millis(1000));
                    }
                }
                Err(e) => {
                    tracing::warn!("IbFabricMonitor error: {}", e);
                }
            }

            tokio::select! {
                _ = tick.sleep() => {},
                _ = &mut stop_receiver => {
                    tracing::info!("IbFabricMonitor stop was requested");
                    return;
                }
            }
        }
    }

    pub async fn run_single_iteration(&self) -> CarbideResult<usize> {
        let mut metrics = IbFabricMonitorMetrics::new();

        let num_changes = if let Ok(_lock) = self
            .work_lock_manager_handle
            .try_acquire_lock(Self::ITERATION_WORK_KEY.into())
            .await
        {
            tracing::trace!(
                lock = Self::ITERATION_WORK_KEY,
                "IbFabricMonitor acquired the lock",
            );

            let span_id: String = format!("{:#x}", u64::from_le_bytes(rand::random::<[u8; 8]>()));

            let check_ib_fabrics_span = tracing::span!(
                parent: None,
                tracing::Level::INFO,
                "check_ib_fabrics_and_apply_changes",
                span_id,
                otel.status_code = tracing::field::Empty,
                otel.status_message = tracing::field::Empty,
                num_fabrics = 0,
                fabric_metrics = tracing::field::Empty,
            );

            let res = self
                .check_ib_fabrics_and_apply_changes(&mut metrics)
                .instrument(check_ib_fabrics_span.clone())
                .await;
            check_ib_fabrics_span.record("num_fabrics", metrics.num_fabrics);
            check_ib_fabrics_span.record(
                "fabric_metrics",
                serde_json::to_string(&metrics.fabrics).unwrap_or_default(),
            );

            let num_changes = match &res {
                Ok(num_changes) => {
                    check_ib_fabrics_span.record("otel.status_code", "ok");
                    *num_changes
                }
                Err(e) => {
                    tracing::error!("IbFabricMonitor run failed due to: {:?}", e);
                    check_ib_fabrics_span.record("otel.status_code", "error");
                    // Writing this field will set the span status to error
                    // Therefore we only write it on errors
                    check_ib_fabrics_span.record("otel.status_message", format!("{e:?}"));
                    0
                }
            };

            // Cache all other metrics that have been captured in this iteration.
            // Those will be queried by OTEL on demand
            self.metric_holder.update_metrics(metrics);

            res?;

            num_changes
        } else {
            0
        };

        Ok(num_changes)
    }

    async fn check_ib_fabrics_and_apply_changes(
        &self,
        metrics: &mut IbFabricMonitorMetrics,
    ) -> CarbideResult<usize> {
        if self.fabric_manager.get_config().manager_type == IBFabricManagerType::Disable {
            return Ok(0);
        }

        let mut conn = self
            .db_pool
            .acquire()
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new("acquire connection", e)))?;
        let snapshots = match self.get_all_snapshots(&mut conn).await {
            Ok(snapshots) => snapshots,
            Err(e) => {
                tracing::error!(error = %e, "Failed to load ManagedHost snapshots in IbFabricMonitor");
                // Record the same error for all fabrics, so that the problem is at least visible on dashboards
                for (fabric, _fabric_definition) in self.fabrics.iter() {
                    metrics.num_fabrics += 1;
                    let fabric_metrics = metrics.fabrics.entry(fabric.to_string()).or_default();
                    fabric_metrics.fabric_error = "ManagedHostSnapshotLoadingError".to_string();
                }
                return Err(e);
            }
        };

        let tenant_partitions = match get_tenant_partitions(&mut conn).await {
            Ok(snapshots) => snapshots,
            Err(e) => {
                tracing::error!(error = %e, "Failed to load Partition data in IbFabricMonitor");
                // Record the same error for all fabrics, so that the problem is at least visible on dashboards
                for (fabric, _fabric_definition) in self.fabrics.iter() {
                    metrics.num_fabrics += 1;
                    let fabric_metrics = metrics.fabrics.entry(fabric.to_string()).or_default();
                    fabric_metrics.fabric_error = "ManagedHostSnapshotLoadingError".to_string();
                }
                return Err(e);
            }
        };
        drop(conn); // Don't reuse the postgres connection later on. It might be stale

        // Create a reverse mapping from pkeys to partition IDs
        // That makes the lookup of which partition ID is associated with GUIDs
        // more efficient
        let mut partition_ids_by_pkey = HashMap::new();
        for (id, partition) in tenant_partitions.iter() {
            if let Some(pkey) = partition.status.as_ref().and_then(|s| s.pkey) {
                partition_ids_by_pkey.insert(pkey, *id);
            }
        }

        let mut fabric_data: HashMap<String, FabricData> = HashMap::new();
        for (fabric, fabric_definition) in self.fabrics.iter() {
            let fabric_data = fabric_data.entry(fabric.to_string()).or_default();

            metrics.num_fabrics += 1;
            let fabric_metrics = metrics.fabrics.entry(fabric.to_string()).or_default();
            if let Err(e) = check_ib_fabric(
                self.fabric_manager.as_ref(),
                fabric,
                fabric_definition,
                fabric_metrics,
            )
            .await
            {
                tracing::error!(fabric, endpoints = fabric_definition.endpoints.join(","), error = %e, "IB fabric health check failed");
                // TODO: This isn't efficient because we will get a lot of different dimensions
                // We need to have better defined errors from the UFM APIs, so we can convert
                // those into a smaller set of labels
                fabric_metrics.fabric_error = e.to_string();
                // There's no point in loading other information case the fabric is down
                continue;
            }

            match get_ports_information(self.fabric_manager.as_ref(), fabric, fabric_metrics).await
            {
                Ok(ports) => {
                    fabric_data.ports_by_guid = Some(ports);
                }
                Err(e) => {
                    tracing::error!(fabric, endpoints = fabric_definition.endpoints.join(","), error = %e, "Loading port information failed");
                    // TODO: This isn't efficient because we will get a lot of different dimensions
                    // We need to have better defined errors from the UFM APIs, so we can convert
                    // those into a smaller set of labels
                    fabric_metrics.fabric_error = e.to_string();
                    // There's no point in loading other information case the fabric is down
                    continue;
                }
            }

            match get_partition_information(self.fabric_manager.as_ref(), fabric, fabric_metrics)
                .await
            {
                Ok(partitions) => {
                    fabric_data.partitions = Some(partitions);
                }
                Err(e) => {
                    tracing::error!(fabric, endpoints = fabric_definition.endpoints.join(","), error = %e, "Loading partition information failed");
                    // TODO: This isn't efficient because we will get a lot of different dimensions
                    // We need to have better defined errors from the UFM APIs, so we can convert
                    // those into a smaller set of labels
                    fabric_metrics.fabric_error = e.to_string();
                    // There's no point in loading other information case the fabric is down
                    continue;
                }
            }

            // Derive Partitions by GUID
            fabric_data.derive_partitions_by_guid();
        }

        let mut reports = Vec::new();
        for (machine, snapshot) in &snapshots {
            let mut snapshot_clone = snapshot.clone();
            match record_machine_infiniband_status_observation(
                &self.db_pool,
                &mut snapshot_clone,
                &tenant_partitions,
                &partition_ids_by_pkey,
                &fabric_data,
                metrics,
            )
            .await
            {
                Ok(report) => {
                    reports.push(report);
                }
                Err(e) => {
                    tracing::error!(error = %e, machine_id = %machine, "Failed to update IB Status observation");
                }
            }
        }

        let mut num_changes = 0;

        for report in reports {
            for (fabric, guid, pkey) in report.missing_guid_pkeys {
                let Some(partition_id) = partition_ids_by_pkey.get(&pkey) else {
                    tracing::warn!("Missing pkey {pkey} does not map to a Partition ID");
                    continue;
                };
                let Some(partition) = tenant_partitions.get(partition_id) else {
                    tracing::warn!("Missing pkey {pkey} does not map to a Partition");
                    continue;
                };

                let conn = self.fabric_manager.new_client(&fabric).await?;
                let status = match conn
                    .bind_ib_ports(partition.into(), vec![guid.clone()])
                    .await
                {
                    Ok(()) => {
                        num_changes += 1;
                        UfmOperationStatus::Ok
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to bind {guid} to pkey {pkey} on fabric {fabric}: {e}"
                        );
                        UfmOperationStatus::Error
                    }
                };

                *metrics
                    .applied_changes
                    .entry(AppliedChange {
                        fabric,
                        operation: UfmOperation::BindGuidToPkey,
                        status,
                    })
                    .or_default() += 1;
            }

            for (fabric, guid, pkey) in report.unexpected_guid_pkeys {
                // Only unbind pkeys that are within this Carbide's managed range.
                // Pkeys outside the configured range should be left alone.
                // Note: We only enforce expected pkeys for GUIDs configured on the instance.
                // Unconfigured GUIDs with out-of-range pkeys will be ignored.
                let managed_pkey = self
                    .fabrics
                    .get(&fabric)
                    .map(|f| is_pkey_in_managed_range(pkey, f))
                    .unwrap_or(false);

                if !managed_pkey {
                    tracing::debug!(
                        %fabric,
                        %guid,
                        %pkey,
                        "Skipping unbind for pkey outside managed range"
                    );
                    continue;
                }

                let conn = self.fabric_manager.new_client(&fabric).await?;
                let status = match conn.unbind_ib_ports(pkey.into(), vec![guid.clone()]).await {
                    Ok(()) => {
                        num_changes += 1;
                        UfmOperationStatus::Ok
                    }
                    Err(e) => {
                        tracing::error!(
                            "Failed to unbind {guid} from pkey {pkey} on fabric {fabric}: {e}"
                        );
                        UfmOperationStatus::Error
                    }
                };

                *metrics
                    .applied_changes
                    .entry(AppliedChange {
                        fabric,
                        operation: UfmOperation::UnbindGuidFromPkey,
                        status,
                    })
                    .or_default() += 1;
            }
        }

        Ok(num_changes)
    }

    async fn get_all_snapshots(
        &self,
        txn: &mut PgConnection,
    ) -> CarbideResult<HashMap<MachineId, ManagedHostStateSnapshot>> {
        let machine_ids = db::machine::find_machine_ids(
            &mut *txn,
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?;
        db::managed_host::load_by_machine_ids(
            txn,
            &machine_ids,
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: true,
                host_health_config: self.host_health,
            },
        )
        .await
        .map_err(Into::into)
    }
}

/// Checks the status of a single IB fabric
async fn check_ib_fabric(
    fabric_manager: &dyn IBFabricManager,
    fabric: &str,
    fabric_definition: &IbFabricDefinition,
    metrics: &mut FabricMetrics,
) -> Result<(), CarbideError> {
    metrics.endpoints = fabric_definition.endpoints.clone();
    metrics.allow_insecure_fabric_configuration = fabric_manager
        .get_config()
        .allow_insecure_fabric_configuration;

    let conn = fabric_manager.new_client(fabric).await?;
    let version = conn.versions().await?;
    metrics.ufm_version = version.ufm_version;

    let config = conn.get_fabric_config().await?;
    metrics.subnet_prefix = config.subnet_prefix;
    metrics.m_key = config.m_key;
    metrics.sm_key = config.sm_key;
    metrics.sa_key = config.sa_key;
    metrics.m_key_per_port = config.m_key_per_port;

    // Check if any of the expected security settings is not configured
    // TODO: We are not checking whether the default partition is in restricted mode
    metrics.insecure_fabric_configuration = false;
    if parse_num(&metrics.m_key) == Some(0)
        || parse_num(&metrics.sm_key) == Some(1)
        || parse_num(&metrics.sa_key) == Some(1)
        || !metrics.m_key_per_port
    {
        metrics.insecure_fabric_configuration = true;
    }

    // Check if the default partition is in restricted mode
    let default_partition = conn
        .get_ib_network(
            PartitionKey::for_default_partition().into(),
            GetPartitionOptions {
                include_guids_data: true,
                include_qos_conf: true,
            },
        )
        .await?;
    if let Some(membership) = default_partition.membership {
        metrics.default_partition_membership = Some(membership.to_string());
        if membership == IBPortMembership::Full {
            metrics.insecure_fabric_configuration = true;
        }
    }

    Ok(())
}

#[derive(Debug, Default)]
struct FabricData {
    /// Ports by GUID. `None` if port data could not be loaded
    ports_by_guid: Option<HashMap<String, IBPort>>,
    /// Partitions by pkey. `None` if partition data could not be loaded
    partitions: Option<HashMap<u16, IBNetwork>>,
    /// Partitions associated with a single guid
    partition_ids_by_guid: Option<HashMap<String, HashSet<u16>>>,
}

impl FabricData {
    pub fn derive_partitions_by_guid(&mut self) {
        let Some(partitions) = self.partitions.as_ref() else {
            self.partition_ids_by_guid = None;
            return;
        };

        let mut partitions_by_guid: HashMap<String, HashSet<u16>> = HashMap::new();
        for (pkey, partition) in partitions.iter() {
            let Some(associated_guids) = partition.associated_guids.as_ref() else {
                // We can not correctly calculate partition_ids_by_guid if any partition has
                // incomplete GUID data
                self.partition_ids_by_guid = None;
                return;
            };

            for guid in associated_guids.iter() {
                let guid_partitions = partitions_by_guid.entry(guid.clone()).or_default();
                guid_partitions.insert(*pkey);
            }
        }

        self.partition_ids_by_guid = Some(partitions_by_guid);
    }
}

/// Return port information within a single IB fabric
async fn get_ports_information(
    fabric_manager: &dyn IBFabricManager,
    fabric: &str,
    metrics: &mut FabricMetrics,
) -> Result<HashMap<String, IBPort>, CarbideError> {
    let conn = fabric_manager.new_client(fabric).await?;

    let ports = conn.find_ib_port(None).await?;
    let mut ports_by_state = HashMap::new();
    let mut ports_by_guid = HashMap::new();
    for port in ports.into_iter() {
        let state = match port.state.as_ref() {
            Some(state) => format!("{state:?}"),
            None => "unknown".to_string(),
        };
        *ports_by_state.entry(state).or_default() += 1;
        ports_by_guid.insert(port.guid.clone(), port);
    }
    metrics.ports_by_state = Some(ports_by_state);

    Ok(ports_by_guid)
}

/// Return partitioning information within a single IB fabric
async fn get_partition_information(
    fabric_manager: &dyn IBFabricManager,
    fabric: &str,
    metrics: &mut FabricMetrics,
) -> Result<HashMap<u16, IBNetwork>, CarbideError> {
    let conn = fabric_manager.new_client(fabric).await?;

    // Due to the UFM bug we need to first get partition IDs and then query
    // each partition individually for additional data
    let partitions = conn
        .get_ib_networks(GetPartitionOptions {
            include_guids_data: false,
            include_qos_conf: true,
        })
        .await?;
    metrics.num_partitions = Some(partitions.len());

    let mut result = HashMap::new();
    for &pkey in partitions.keys() {
        match conn
            .get_ib_network(
                pkey,
                GetPartitionOptions {
                    include_guids_data: true,
                    include_qos_conf: true,
                },
            )
            .await
        {
            Ok(partition) => {
                result.insert(pkey, partition);
            }
            Err(CarbideError::NotFoundError { .. }) => continue, // Partition might have been deleted
            Err(e) => return Err(e),
        }
    }

    Ok(result)
}

/// Find all active partitions in order to determine pkeys
async fn get_tenant_partitions(
    txn: &mut PgConnection,
) -> Result<HashMap<IBPartitionId, IBPartition>, CarbideError> {
    let partition_ids = db::ib_partition::find_ids(
        &mut *txn,
        IbPartitionSearchFilter {
            tenant_org_id: None,
            name: None,
        },
    )
    .await?;

    const PAGE_SIZE: usize = 100;
    let mut result = HashMap::new();
    let mut offset = 0;
    while offset != partition_ids.len() {
        let page_size = PAGE_SIZE.min(partition_ids.len() - offset);
        let next_ids = &partition_ids[offset..offset + page_size];
        let partition_data = db::ib_partition::find_by(
            &mut *txn,
            db::ObjectColumnFilter::List(db::ib_partition::IdColumn, next_ids),
        )
        .await?;

        for partition in partition_data {
            result.insert(partition.id, partition);
        }

        offset += page_size;
    }

    Ok(result)
}

/// These are the GUID/Pkey combinations where changes are required
#[derive(Debug, Clone, Default)]
struct MachineIbStatusEvaluation {
    missing_guid_pkeys: Vec<(String, String, PartitionKey)>,
    unexpected_guid_pkeys: Vec<(String, String, PartitionKey)>,
    unknown_guid_pkeys: Vec<(String, String, PartitionKey)>,
    down_port_guids: Vec<String>,
}

async fn record_machine_infiniband_status_observation(
    db_pool: &PgPool,
    mh_snapshot: &mut ManagedHostStateSnapshot,
    tenant_partitions: &HashMap<IBPartitionId, IBPartition>,
    tenant_partition_ids_by_pkey: &HashMap<PartitionKey, IBPartitionId>,
    data_by_fabric: &HashMap<String, FabricData>,
    metrics: &mut IbFabricMonitorMetrics,
) -> Result<MachineIbStatusEvaluation, CarbideError> {
    let mut result = MachineIbStatusEvaluation::default();

    if mh_snapshot.host_snapshot.hardware_info.is_none() {
        // Skip status update while hardware info is not available
        *metrics
            .num_machines_by_port_states
            .entry((0, 0))
            .or_default() += 1;
        *metrics
            .num_machines_by_ports_with_partitions
            .entry(0)
            .or_default() += 1;
        return Ok(result);
    }

    let machine_id = &mh_snapshot.host_snapshot.id;
    let ib_hw_info = &mh_snapshot
        .host_snapshot
        .hardware_info
        .as_ref()
        .unwrap()
        .infiniband_interfaces;

    // Determine what the expected configuration for each port on the host is
    // That is derived by the instance configuration
    // If there is no instance, then each interface should not have an associated partition
    let expected_ib_config = mh_snapshot
        .instance
        .as_ref()
        .map(|instance| &instance.config.infiniband);
    let mut expected_pkeys = HashMap::new();

    let mut use_admin_network = false;
    for dpu in mh_snapshot.dpu_snapshots.iter() {
        use_admin_network |= dpu.network_config.use_admin_network.unwrap_or(true);
    }
    // If we are on the tenant network, then the pkey configuration is the instances
    // network configuration.
    // If not - e.g. during Instance termination - there are no pkeys expected on any
    // interface
    let use_tenant_network = !use_admin_network;
    if use_tenant_network && let Some(expected_ib_config) = expected_ib_config {
        for iface in expected_ib_config.ib_interfaces.iter() {
            let Some(guid) = iface.guid.as_ref() else {
                continue;
            };
            let Some(partition_data) = tenant_partitions.get(&iface.ib_partition_id) else {
                continue;
            };
            let Some(expected_pkey) = partition_data.status.as_ref().and_then(|s| s.pkey) else {
                continue;
            };
            expected_pkeys.insert(guid.clone(), expected_pkey);
        }
    }

    // SKU defines which ports are intentionally disconnected/inactive by hardware design
    // Returns None if no SKU or SKU has no IB devices (skip monitoring in those cases)
    let expected_inactive_devices = get_expected_inactive_devices(
        db_pool,
        mh_snapshot.host_snapshot.hw_sku.as_deref(),
    )
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(
            machine_id = %machine_id,
            error = %e,
            "Failed to load expected inactive devices from SKU, will skip IB port monitoring"
        );
        None
    });

    // Use GUID as secondary key for stable ordering when slots are identical
    let mut sorted_ib_interfaces = ib_hw_info.to_vec();
    sorted_ib_interfaces.sort_by_key(|iface| {
        (
            iface
                .pci_properties
                .as_ref()
                .and_then(|p| p.slot.clone())
                .unwrap_or_default(),
            iface.guid.clone(), // Stable tie-breaker
        )
    });

    // Build GUID to index mapping (index matches SKU's inactive_devices indices)
    let guid_to_index: HashMap<String, u32> = sorted_ib_interfaces
        .iter()
        .enumerate()
        .map(|(idx, iface)| (iface.guid.clone(), idx as u32))
        .collect();

    // Note: If instance has empty ib_interfaces, we get Some(empty set), which means
    // no ports will be tracked as down - this is intentional for tenant isolation
    let instance_guids: Option<HashSet<String>> = mh_snapshot.instance.as_ref().map(|instance| {
        instance
            .config
            .infiniband
            .ib_interfaces
            .iter()
            .filter_map(|iface| iface.guid.as_ref().map(|g| g.to_lowercase()))
            .collect()
    });

    // The list of GUIDs that are part of this Machine
    let mut guids: Vec<String> = Vec::new();
    for ib_interface in ib_hw_info.iter() {
        guids.push(ib_interface.guid.clone());
    }

    let mut prev = mh_snapshot
        .host_snapshot
        .infiniband_status_observation
        .clone()
        .unwrap_or_default();

    let mut ib_interfaces_status: Vec<MachineIbInterfaceStatusObservation> =
        Vec::with_capacity(guids.len());

    let mut active_ports = 0;
    let mut ports_with_partitions = 0;

    for guid in guids.iter() {
        // Search for the GUID in all fabrics. Record the fabric where we found it, plus the actual data
        // Note: This only works since GUIDs are globally unique
        let mut found_port_data = None;
        for (fabric_id, fabric_data) in data_by_fabric.iter() {
            if let Some(port_data) = fabric_data
                .ports_by_guid
                .as_ref()
                .and_then(|ports_by_guid| ports_by_guid.get(guid))
            {
                found_port_data = Some((fabric_id, fabric_data, port_data));
                break;
            }
        }

        let (fabric_id, lid, associated_pkeys, associated_partition_ids) = match found_port_data {
            Some((fabric_id, fabric_data, port_data)) => {
                // Port was found. Now try to look up associated pkeys
                // If there's no associated pkeys found, don't return any potentially invalid or empty
                // pkey list. Instead opt for a safe result and return `None` (we don't know).
                let associated_pkeys = match fabric_data.partition_ids_by_guid.as_ref() {
                    Some(partition_ids_by_guid) => match partition_ids_by_guid.get(guid) {
                        Some(partition_ids) => {
                            let mut ids = HashSet::new();
                            for id in partition_ids {
                                if let Ok(id) = PartitionKey::try_from(*id) {
                                    ids.insert(id);
                                }
                            }
                            Some(ids)
                        }
                        None => Some(HashSet::new()),
                    },
                    None => None,
                };

                let associated_partition_ids = match associated_pkeys.as_ref() {
                    Some(pkeys) => {
                        if !pkeys.is_empty() {
                            ports_with_partitions += 1;
                        }

                        // Translate associated_pkeys into associated_partition_ids
                        let mut associated_partition_ids = HashSet::new();
                        for pkey in pkeys {
                            match tenant_partition_ids_by_pkey.get(pkey) {
                                Some(partition_id) => {
                                    associated_partition_ids.insert(*partition_id);
                                }
                                None => {
                                    result.unknown_guid_pkeys.push((
                                        fabric_id.to_string(),
                                        guid.to_string(),
                                        *pkey,
                                    ));
                                }
                            }
                        }

                        // Determine which keys need to get added or removed
                        match expected_pkeys.get(guid) {
                            Some(expected_pkey) => {
                                // GUID should be associated with `expected_pkey`
                                if !pkeys.contains(expected_pkey) {
                                    result.missing_guid_pkeys.push((
                                        fabric_id.to_string(),
                                        guid.to_string(),
                                        *expected_pkey,
                                    ));
                                }
                                // Everything else is unexpected
                                for pkey in pkeys {
                                    if pkey != expected_pkey {
                                        result.unexpected_guid_pkeys.push((
                                            fabric_id.to_string(),
                                            guid.to_string(),
                                            *pkey,
                                        ));
                                    }
                                }
                            }
                            None => {
                                // All GUIDs are unexpected
                                for pkey in pkeys {
                                    result.unexpected_guid_pkeys.push((
                                        fabric_id.to_string(),
                                        guid.to_string(),
                                        *pkey,
                                    ));
                                }
                            }
                        }

                        Some(associated_partition_ids)
                    }
                    None => {
                        // We don't know what is associated, therefore we can't make
                        // a great decision about whether pkeys are missing or unexpected
                        None
                    }
                };

                let (lid, is_down) = if port_data.state == Some(IBPortState::Active) {
                    active_ports += 1;
                    (port_data.lid as u16, false)
                } else {
                    // Port is not active - check if we should track it as down
                    let should_track = should_track_port_as_down(
                        guid,
                        &guid_to_index,
                        expected_inactive_devices.as_ref(),
                        &instance_guids,
                    );
                    if should_track {
                        result.down_port_guids.push(guid.clone());
                    }
                    (0xffff_u16, true)
                };

                if is_down {
                    tracing::debug!(
                        machine_id = %machine_id,
                        guid = %guid,
                        state = ?port_data.state,
                        "IB port is not active"
                    );
                }

                (fabric_id, lid, associated_pkeys, associated_partition_ids)
            }
            None => {
                // The port was not found on UFM. In this case we don't even try
                // to look up associated pkeys
                // Check if we should track it as down
                let should_track = should_track_port_as_down(
                    guid,
                    &guid_to_index,
                    expected_inactive_devices.as_ref(),
                    &instance_guids,
                );
                if should_track {
                    result.down_port_guids.push(guid.clone());
                }

                // TODO: We should differentiate between "Can not communicate with fabric"
                // and "UFM definitely did not know about this GUID".
                (&String::new(), 0xffff_u16, None, None)
            }
        };

        ib_interfaces_status.push(MachineIbInterfaceStatusObservation {
            guid: guid.clone(),
            lid,
            fabric_id: fabric_id.to_string(),
            associated_pkeys,
            associated_partition_ids,
        });
    }

    *metrics
        .num_machines_by_port_states
        .entry((guids.len(), active_ports))
        .or_default() += 1;
    *metrics
        .num_machines_by_ports_with_partitions
        .entry(ports_with_partitions)
        .or_default() += 1;

    if !result.missing_guid_pkeys.is_empty() {
        metrics.num_machines_with_missing_pkeys += 1;
        let mut msg = "Machine is missing pkeys on UFM: ".to_string();
        for (idx, (_fabric, guid, pkey)) in result.missing_guid_pkeys.iter().enumerate() {
            if idx != 0 {
                msg.push(',');
            }
            write!(&mut msg, "(guid: {guid}, pkey: {pkey})").unwrap();
        }
        tracing::warn!(machine_id = %machine_id, msg);
    }
    if !result.unexpected_guid_pkeys.is_empty() {
        metrics.num_machines_with_unexpected_pkeys += 1;
        let mut msg = "Machine has unexpected registered pkeys on UFM: ".to_string();
        for (idx, (_fabric, guid, pkey)) in result.unexpected_guid_pkeys.iter().enumerate() {
            if idx != 0 {
                msg.push(',');
            }
            write!(&mut msg, "(guid: {guid}, pkey: {pkey})").unwrap();
        }
        tracing::warn!(machine_id = %machine_id, msg);
    }
    if !result.unknown_guid_pkeys.is_empty() {
        metrics.num_machines_with_unknown_pkeys += 1;
        let mut msg =
            "Machine has registered pkeys on UFM that do not map to IB PartitionIDs: ".to_string();
        for (idx, (_fabric, guid, pkey)) in result.unknown_guid_pkeys.iter().enumerate() {
            if idx != 0 {
                msg.push(',');
            }
            write!(&mut msg, "(guid: {guid}, pkey: {pkey})").unwrap();
        }
        tracing::warn!(machine_id = %machine_id, msg);
    }

    let has_existing_ib_port_down_alert = mh_snapshot
        .aggregate_health
        .alerts
        .iter()
        .any(|alert| alert.id.as_str() == "IbPortDown");

    if !result.down_port_guids.is_empty() {
        tracing::warn!(
            machine_id = %machine_id,
            down_ports = ?result.down_port_guids,
            total_ports = guids.len(),
            "IB port(s) detected as down - setting PreventAllocations alert"
        );
        set_ib_port_down_alert(db_pool, machine_id, &result.down_port_guids, guids.len()).await?;
    } else if has_existing_ib_port_down_alert {
        tracing::info!(
            machine_id = %machine_id,
            "All IB ports are now active - clearing IbPortDown alert"
        );
        clear_ib_port_down_alert(db_pool, machine_id).await?;
    }

    let cur = MachineInfinibandStatusObservation {
        observed_at: Utc::now(),
        ib_interfaces: ib_interfaces_status,
    };

    // This allows to update a record ony in case of any changes.
    prev.observed_at = cur.observed_at;

    if let Some(alert) = mh_snapshot
        .aggregate_health
        .alerts
        .iter()
        .find(|alert| alert.id.as_str() == "IbCleanupPending")
    {
        let guids = parse_guids_from_alert(&alert.message);
        tracing::info!(
            machine_id = %machine_id,
            guids = ?guids,
            "Processing IbCleanupPending alert - checking if GUIDs are cleared from UFM"
        );
        let mut all_cleared = true;
        for guid in &guids {
            if result.missing_guid_pkeys.iter().any(|(_, g, _)| g == guid)
                || result
                    .unexpected_guid_pkeys
                    .iter()
                    .any(|(_, g, _)| g == guid)
                || result.unknown_guid_pkeys.iter().any(|(_, g, _)| g == guid)
            {
                all_cleared = false;
            }
        }
        if all_cleared {
            tracing::info!(
                machine_id = %machine_id,
                guids = ?guids,
                "All GUIDs cleared from UFM - clearing IbCleanupPending alert"
            );
            clear_ib_cleanup_alert(db_pool, machine_id).await?;
        } else {
            tracing::debug!(
                machine_id = %machine_id,
                "Not all GUIDs cleared yet - alert remains"
            );
        }
    }

    // Update Machine infiniband status in case any changes only
    // Vector of statuses is based on guids vector that is formed
    // from hardware_info.infiniband_interfaces[]
    // So it guarantees stable order between function calls
    if prev != cur {
        let mut conn = db_pool
            .acquire()
            .await
            .map_err(|e| DatabaseError::new("acquire connection", e))?;
        db::machine::update_infiniband_status_observation(&mut conn, machine_id, &cur).await?;
        metrics.num_machine_ib_status_updates += 1;
        mh_snapshot.host_snapshot.infiniband_status_observation = Some(cur);
    }

    Ok(result)
}

/// Clear the IbCleanupPending alert
async fn clear_ib_cleanup_alert(
    db_pool: &PgPool,
    machine_id: &MachineId,
) -> Result<(), CarbideError> {
    let mut conn = db_pool
        .acquire()
        .await
        .map_err(|e| DatabaseError::new("acquire connection", e))?;

    db::machine::remove_health_report_override(
        &mut conn,
        machine_id,
        OverrideMode::Merge,
        "ib-cleanup-validation",
    )
    .await
    .map_err(|e| CarbideError::internal(format!("Failed to clear IB cleanup alert: {e}")))?;

    Ok(())
}

const IB_PORT_DOWN_OVERRIDE_SOURCE: &str = "ib-port-down-monitor";

async fn set_ib_port_down_alert(
    db_pool: &PgPool,
    machine_id: &MachineId,
    down_port_guids: &[String],
    total_ports: usize,
) -> Result<(), CarbideError> {
    let mut conn = db_pool
        .acquire()
        .await
        .map_err(|e| DatabaseError::new("acquire connection", e))?;

    let alert =
        health_report::HealthProbeAlert::ib_port_down(down_port_guids.to_vec(), total_ports);
    let health_report = health_report::HealthReport {
        source: IB_PORT_DOWN_OVERRIDE_SOURCE.to_string(),
        triggered_by: None,
        observed_at: Some(Utc::now()),
        successes: vec![],
        alerts: vec![alert],
    };

    db::machine::insert_health_report_override(
        &mut conn,
        machine_id,
        OverrideMode::Merge,
        &health_report,
        false, // overwrite existing
    )
    .await
    .map_err(|e| CarbideError::internal(format!("Failed to set IB port down alert: {e}")))?;

    Ok(())
}

async fn clear_ib_port_down_alert(
    db_pool: &PgPool,
    machine_id: &MachineId,
) -> Result<(), CarbideError> {
    let mut conn = db_pool
        .acquire()
        .await
        .map_err(|e| DatabaseError::new("acquire connection", e))?;

    db::machine::remove_health_report_override(
        &mut conn,
        machine_id,
        OverrideMode::Merge,
        IB_PORT_DOWN_OVERRIDE_SOURCE,
    )
    .await
    .map_err(|e| CarbideError::internal(format!("Failed to clear IB port down alert: {e}")))?;

    Ok(())
}

/// Should down port be track alerting?
/// - If expected_inactive_devices is None: don't track (no SKU or SKU has no IB devices)
/// - For machines with an instance: only if the port is in the instance's IB config
/// - For machines without an instance: only if the port is not in the SKU's inactive_devices
fn should_track_port_as_down(
    guid: &str,
    guid_to_index: &HashMap<String, u32>,
    expected_inactive_devices: Option<&HashSet<u32>>,
    instance_guids: &Option<HashSet<String>>,
) -> bool {
    let Some(expected_inactive) = expected_inactive_devices else {
        return false;
    };

    match instance_guids {
        Some(guids) => guids.contains(&guid.to_lowercase()),
        None => {
            let port_index = guid_to_index.get(guid).copied().unwrap_or(u32::MAX);
            !expected_inactive.contains(&port_index)
        }
    }
}

/// Load expected inactive devices from the machine's SKU (hardware specification).
///
/// SKU defines the physical hardware configuration, including which IB ports
/// are intentionally disconnected or disabled by design (e.g., for specific
/// rack configurations or hardware variants).
///
/// Returns:
/// - `Ok(None)` if no SKU is assigned, SKU not found, or SKU has no infiniband_devices defined
///   (in these cases, IB port down monitoring should be skipped)
/// - `Ok(Some(set))` with the set of port indices expected to be inactive per SKU
async fn get_expected_inactive_devices(
    db_pool: &PgPool,
    hw_sku: Option<&str>,
) -> Result<Option<HashSet<u32>>, CarbideError> {
    let Some(sku_id) = hw_sku else {
        return Ok(None);
    };

    let mut conn = db_pool
        .acquire()
        .await
        .map_err(|e| DatabaseError::new("acquire connection", e))?;

    let skus = db::sku::find(&mut conn, &[sku_id])
        .await
        .map_err(|e| CarbideError::internal(format!("Failed to load SKU: {e}")))?;

    let Some(sku) = skus.into_iter().next() else {
        return Ok(None);
    };

    if sku.components.infiniband_devices.is_empty() {
        return Ok(None);
    }

    let inactive_devices: HashSet<u32> = sku
        .components
        .infiniband_devices
        .iter()
        .flat_map(|ib_dev| ib_dev.inactive_devices.iter().copied())
        .collect();

    Ok(Some(inactive_devices))
}

/// Parse GUIDs from IbCleanupPending alert message
/// Returns Vec<String> of GUIDs
/// Format: "IB port cleanup pending - IB Monitor will unbind. GUIDs: X; Y; Z"
fn parse_guids_from_alert(message: &str) -> Vec<String> {
    let Some(guids_str) =
        message.strip_prefix("IB port cleanup pending - IB Monitor will unbind. GUIDs: ")
    else {
        return Vec::new();
    };

    guids_str
        .split("; ")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Parses a u64 string in hexadecimal or decimal format
fn parse_num(input: &str) -> Option<u64> {
    match input.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => input.parse().ok(),
    }
}

/// Checks if a pkey is within the managed pkey ranges for a fabric.
/// Returns true if the pkey falls within any of the configured ranges.
fn is_pkey_in_managed_range(pkey: PartitionKey, fabric_definition: &IbFabricDefinition) -> bool {
    let pkey_value = u16::from(pkey) as u64;
    fabric_definition
        .pkeys
        .iter()
        .filter_map(|r| Some(parse_num(&r.start)?..parse_num(&r.end)?))
        .any(|range| range.contains(&pkey_value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_num() {
        assert_eq!(0, parse_num("0x0000000000000000").unwrap());
        assert_eq!(1, parse_num("0x0000000000000001").unwrap());
        assert_eq!(0, parse_num("0x00").unwrap());
        assert_eq!(1, parse_num("0x01").unwrap());
    }

    // ============================================================
    // Unit Tests for parse_guids_from_alert
    // ============================================================

    #[test]
    fn test_parse_guids_single() {
        let message = "IB port cleanup pending - IB Monitor will unbind. GUIDs: 946dae03006104f8";
        let result = parse_guids_from_alert(message);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], "946dae03006104f8");
    }

    #[test]
    fn test_parse_guids_multiple() {
        let message = "IB port cleanup pending - IB Monitor will unbind. GUIDs: 946dae03006104f8; abc123def4567890; fedcba9876543210";
        let result = parse_guids_from_alert(message);
        assert_eq!(result.len(), 3);
        assert_eq!(result[0], "946dae03006104f8");
        assert_eq!(result[1], "abc123def4567890");
        assert_eq!(result[2], "fedcba9876543210");
    }

    #[test]
    fn test_parse_guids_wrong_prefix() {
        let message = "Wrong prefix message";
        let result = parse_guids_from_alert(message);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_guids_empty() {
        let message = "IB port cleanup pending - IB Monitor will unbind. GUIDs: ";
        let result = parse_guids_from_alert(message);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn test_parse_guids_with_whitespace() {
        let message = "IB port cleanup pending - IB Monitor will unbind. GUIDs:  abc  ;  def  ";
        let result = parse_guids_from_alert(message);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], "abc");
        assert_eq!(result[1], "def");
    }

    // ============================================================
    // Unit Tests for HealthProbeAlert::ib_port_down
    // ============================================================

    #[test]
    fn test_ib_port_down_alert_single_port() {
        let alert =
            health_report::HealthProbeAlert::ib_port_down(vec!["946dae03006104f8".to_string()], 8);

        assert_eq!(alert.id.as_str(), "IbPortDown");
        assert!(alert.message.contains("1 of 8"));
        assert!(alert.message.contains("946dae03006104f8"));
        assert!(
            alert
                .classifications
                .contains(&health_report::HealthAlertClassification::prevent_allocations())
        );
    }

    #[test]
    fn test_ib_port_down_alert_multiple_ports() {
        let alert = health_report::HealthProbeAlert::ib_port_down(
            vec![
                "946dae03006104f8".to_string(),
                "abc123def4567890".to_string(),
            ],
            8,
        );

        assert_eq!(alert.id.as_str(), "IbPortDown");
        assert!(alert.message.contains("2 of 8"));
        assert!(alert.message.contains("946dae03006104f8"));
        assert!(alert.message.contains("abc123def4567890"));
        assert!(
            alert
                .classifications
                .contains(&health_report::HealthAlertClassification::prevent_allocations())
        );
    }

    #[test]
    fn test_ib_port_down_alert_has_tenant_message() {
        let alert =
            health_report::HealthProbeAlert::ib_port_down(vec!["946dae03006104f8".to_string()], 8);

        assert!(alert.tenant_message.is_some());
        assert!(alert.tenant_message.as_ref().unwrap().contains("1 port(s)"));
    }

    // ============================================================
    // Unit Tests for is_pkey_in_managed_range
    // ============================================================

    fn make_fabric_definition(ranges: Vec<(&str, &str)>) -> IbFabricDefinition {
        use model::resource_pool::define::Range;
        IbFabricDefinition {
            endpoints: vec![],
            pkeys: ranges
                .into_iter()
                .map(|(start, end)| Range {
                    start: start.to_string(),
                    end: end.to_string(),
                    auto_assign: true,
                })
                .collect(),
        }
    }

    #[test]
    fn test_pkey_in_range_decimal() {
        let fabric = make_fabric_definition(vec![("256", "2303")]);
        // 0x100 = 256, should be in range
        let pkey = PartitionKey::try_from(256u16).unwrap();
        assert!(is_pkey_in_managed_range(pkey, &fabric));

        // 0x8FE = 2302, should be in range (end is exclusive)
        let pkey = PartitionKey::try_from(2302u16).unwrap();
        assert!(is_pkey_in_managed_range(pkey, &fabric));

        // 0x500 = 1280, should be in range
        let pkey = PartitionKey::try_from(1280u16).unwrap();
        assert!(is_pkey_in_managed_range(pkey, &fabric));
    }

    #[test]
    fn test_pkey_outside_range() {
        let fabric = make_fabric_definition(vec![("256", "2303")]);

        // 0x5000 = 20480, should be OUTSIDE range
        let pkey = PartitionKey::try_from(0x5000u16).unwrap();
        assert!(!is_pkey_in_managed_range(pkey, &fabric));

        // 255 is just below range
        let pkey = PartitionKey::try_from(255u16).unwrap();
        assert!(!is_pkey_in_managed_range(pkey, &fabric));

        // 2303 is the exclusive end, should be OUTSIDE range
        let pkey = PartitionKey::try_from(2303u16).unwrap();
        assert!(!is_pkey_in_managed_range(pkey, &fabric));
    }

    #[test]
    fn test_pkey_in_range_hex() {
        let fabric = make_fabric_definition(vec![("0x100", "0x8FF")]);

        // 0x100 = 256, should be in range
        let pkey = PartitionKey::try_from(0x100u16).unwrap();
        assert!(is_pkey_in_managed_range(pkey, &fabric));

        // 0x8FE = 2302, should be in range (end is exclusive)
        let pkey = PartitionKey::try_from(0x8FEu16).unwrap();
        assert!(is_pkey_in_managed_range(pkey, &fabric));
    }

    #[test]
    fn test_pkey_multiple_ranges() {
        let fabric = make_fabric_definition(vec![("100", "200"), ("500", "600")]);

        // In first range
        let pkey = PartitionKey::try_from(150u16).unwrap();
        assert!(is_pkey_in_managed_range(pkey, &fabric));

        // In second range
        let pkey = PartitionKey::try_from(550u16).unwrap();
        assert!(is_pkey_in_managed_range(pkey, &fabric));

        // Between ranges (not managed)
        let pkey = PartitionKey::try_from(300u16).unwrap();
        assert!(!is_pkey_in_managed_range(pkey, &fabric));
    }

    #[test]
    fn test_pkey_empty_ranges() {
        let fabric = make_fabric_definition(vec![]);

        // No ranges configured, nothing is managed
        let pkey = PartitionKey::try_from(256u16).unwrap();
        assert!(!is_pkey_in_managed_range(pkey, &fabric));
    }

    // ============================================================
    // Unit Tests for should_track_port_as_down
    // ============================================================

    #[test]
    fn test_should_track_port_no_instance_with_sku_not_in_inactive() {
        // Machine has SKU but no instance, port is NOT in inactive_devices -> should track
        let guid_to_index: HashMap<String, u32> =
            [("guid1".to_string(), 0), ("guid2".to_string(), 1)]
                .into_iter()
                .collect();
        let expected_inactive: HashSet<u32> = [2, 3].into_iter().collect(); // indices 2,3 are inactive
        let instance_guids: Option<HashSet<String>> = None;

        // guid1 is at index 0, which is NOT in inactive_devices
        assert!(should_track_port_as_down(
            "guid1",
            &guid_to_index,
            Some(&expected_inactive),
            &instance_guids,
        ));
    }

    #[test]
    fn test_should_track_port_no_instance_with_sku_in_inactive() {
        // Machine has SKU but no instance, port IS in inactive_devices -> should NOT track
        let guid_to_index: HashMap<String, u32> = [
            ("guid1".to_string(), 0),
            ("guid2".to_string(), 1),
            ("guid3".to_string(), 2),
        ]
        .into_iter()
        .collect();
        let expected_inactive: HashSet<u32> = [2].into_iter().collect(); // index 2 is inactive
        let instance_guids: Option<HashSet<String>> = None;

        // guid3 is at index 2, which IS in inactive_devices
        assert!(!should_track_port_as_down(
            "guid3",
            &guid_to_index,
            Some(&expected_inactive),
            &instance_guids,
        ));
    }

    #[test]
    fn test_should_track_port_no_sku() {
        // Machine has no SKU -> should NOT track (lenient for initial setup)
        let guid_to_index: HashMap<String, u32> = [("guid1".to_string(), 0)].into_iter().collect();
        let instance_guids: Option<HashSet<String>> = None;

        // No SKU (None), so we don't track any ports as down
        assert!(!should_track_port_as_down(
            "guid1",
            &guid_to_index,
            None, // No SKU or SKU has no IB devices
            &instance_guids,
        ));
    }

    #[test]
    fn test_should_track_port_sku_no_ib_devices() {
        // Machine has SKU but SKU has no IB devices -> should NOT track
        // This is the same as None for expected_inactive_devices
        let guid_to_index: HashMap<String, u32> = [("guid1".to_string(), 0)].into_iter().collect();
        let instance_guids: Option<HashSet<String>> = None;

        // SKU exists but has no IB devices (represented as None)
        assert!(!should_track_port_as_down(
            "guid1",
            &guid_to_index,
            None, // SKU has no IB devices
            &instance_guids,
        ));
    }

    #[test]
    fn test_should_track_port_with_instance_port_in_config() {
        // Machine has instance, port IS in instance's IB config -> should track
        let guid_to_index: HashMap<String, u32> =
            [("guid1".to_string(), 0), ("guid2".to_string(), 1)]
                .into_iter()
                .collect();
        let expected_inactive: HashSet<u32> = HashSet::new();
        let instance_guids: Option<HashSet<String>> = Some(
            ["guid1".to_string(), "guid2".to_string()]
                .into_iter()
                .collect(),
        );

        assert!(should_track_port_as_down(
            "guid1",
            &guid_to_index,
            Some(&expected_inactive),
            &instance_guids,
        ));
    }

    #[test]
    fn test_should_track_port_with_instance_port_not_in_config() {
        // Machine has instance, port is NOT in instance's IB config -> should NOT track
        let guid_to_index: HashMap<String, u32> = [
            ("guid1".to_string(), 0),
            ("guid2".to_string(), 1),
            ("guid3".to_string(), 2),
        ]
        .into_iter()
        .collect();
        let expected_inactive: HashSet<u32> = HashSet::new();
        let instance_guids: Option<HashSet<String>> = Some(
            ["guid1".to_string(), "guid2".to_string()]
                .into_iter()
                .collect(),
        );

        // guid3 is NOT in instance's IB config
        assert!(!should_track_port_as_down(
            "guid3",
            &guid_to_index,
            Some(&expected_inactive),
            &instance_guids,
        ));
    }

    #[test]
    fn test_should_track_port_with_empty_instance_config() {
        // Machine has instance but empty IB config -> should NOT track any ports
        let guid_to_index: HashMap<String, u32> = [("guid1".to_string(), 0)].into_iter().collect();
        let expected_inactive: HashSet<u32> = HashSet::new();
        let instance_guids: Option<HashSet<String>> = Some(HashSet::new()); // Empty config

        // Even though port exists, empty instance config means no ports should be tracked
        assert!(!should_track_port_as_down(
            "guid1",
            &guid_to_index,
            Some(&expected_inactive),
            &instance_guids,
        ));
    }

    #[test]
    fn test_should_track_port_guid_case_insensitive() {
        // GUID comparison should be case-insensitive
        let guid_to_index: HashMap<String, u32> = [("GUID1".to_string(), 0)].into_iter().collect();
        let expected_inactive: HashSet<u32> = HashSet::new();
        let instance_guids: Option<HashSet<String>> =
            Some(["guid1".to_string()].into_iter().collect()); // lowercase

        // Should match even though casing differs
        assert!(should_track_port_as_down(
            "GUID1", // uppercase
            &guid_to_index,
            Some(&expected_inactive),
            &instance_guids,
        ));
    }

    #[test]
    fn test_should_track_port_unknown_guid_with_sku() {
        // Unknown GUID (not in guid_to_index) with SKU but no instance -> should track (fail-open)
        let guid_to_index: HashMap<String, u32> = HashMap::new();
        let expected_inactive: HashSet<u32> = [0, 1, 2].into_iter().collect();
        let instance_guids: Option<HashSet<String>> = None;

        // Unknown GUID gets u32::MAX which won't be in inactive_devices
        assert!(should_track_port_as_down(
            "unknown_guid",
            &guid_to_index,
            Some(&expected_inactive),
            &instance_guids,
        ));
    }

    // ============================================================
    // Integration Tests - TODO
    // ============================================================
    // Integration tests deferred until after code review.
    //
    // Planned test scenarios:
    // 1. Alert found + alert GUIDs NOT in result lists → Alert cleared
    // 2. Alert found + alert GUIDs present in unexpected_guid_pkeys → Alert NOT cleared (retry next iteration)
    // 3. Alert found + alert GUIDs present in missing_guid_pkeys → Alert NOT cleared
    // 4. Alert found + alert GUIDs present in unknown_guid_pkeys → Alert NOT cleared
    // 5. No alert present → No action taken
    // 6. Alert with malformed message → Gracefully ignored (no GUIDs extracted)
    // 7. Multiple GUIDs in single alert → All GUIDs checked for clearing condition
}
