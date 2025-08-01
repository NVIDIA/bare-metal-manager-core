/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use chrono::Utc;
use forge_uuid::machine::MachineId;
use sqlx::{PgConnection, PgPool};
use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};
use tokio::sync::oneshot;
use tracing::Instrument;

use crate::{
    CarbideError, CarbideResult,
    cfg::file::{CarbideConfig, HostHealthConfig, IbFabricDefinition},
    db::{self, DatabaseError, machine::MachineSearchConfig, managed_host::LoadSnapshotOptions},
    ib::{
        GetPartitionOptions, IBFabricManager, IBFabricManagerType,
        types::{IBNetwork, IBPort, IBPortState},
    },
    model::{
        ib_partition::PartitionKey,
        machine::{
            ManagedHostStateSnapshot,
            infiniband::{MachineIbInterfaceStatusObservation, MachineInfinibandStatusObservation},
        },
    },
};

mod metrics;
use metrics::IbFabricMonitorMetrics;

use self::metrics::FabricMetrics;

/// `IbFabricMonitor` monitors the health of all connected InfiniBand fabrics in periodic intervals
pub struct IbFabricMonitor {
    db_pool: PgPool,

    fabrics: HashMap<String, IbFabricDefinition>,
    metric_holder: Arc<metrics::MetricHolder>,
    /// API for interaction with Forge IBFabricManager
    fabric_manager: Arc<dyn IBFabricManager>,

    host_health: HostHealthConfig,
}

impl IbFabricMonitor {
    const DB_LOCK_NAME: &'static str = "ib_fabric_monitor_lock";
    const DB_LOCK_QUERY: &'static str = "SELECT pg_try_advisory_xact_lock((SELECT 'ib_fabric_monitor_lock'::regclass::oid)::integer)";

    /// Create a IbFabricMonitor
    pub fn new(
        db_pool: PgPool,
        fabrics: HashMap<String, IbFabricDefinition>,
        meter: opentelemetry::metrics::Meter,
        fabric_manager: Arc<dyn IBFabricManager>,
        config: Arc<CarbideConfig>,
    ) -> Self {
        // We want to hold metrics for longer than the iteration interval, so there is continuity
        // in emitting metrics. However we want to avoid reporting outdated metrics in case
        // reporting gets stuck. Therefore round up the iteration interval by 1min.
        let hold_period = fabric_manager
            .get_config()
            .fabric_manager_run_interval
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(meter, hold_period));

        IbFabricMonitor {
            db_pool,
            fabrics,
            metric_holder,
            fabric_manager,
            host_health: config.host_health,
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

        loop {
            if let Err(e) = self.run_single_iteration().await {
                tracing::warn!("IbFabricMonitor error: {}", e);
            }

            tokio::select! {
                _ = tokio::time::sleep(run_interval) => {},
                _ = &mut stop_receiver => {
                    tracing::info!("IbFabricMonitor stop was requested");
                    return;
                }
            }
        }
    }

    pub async fn run_single_iteration(&self) -> CarbideResult<()> {
        let mut metrics = IbFabricMonitorMetrics::new();

        let mut txn =
            self.db_pool.begin().await.map_err(|e| {
                CarbideError::internal(format!("Failed to create transaction: {e}"))
            })?;

        if sqlx::query_scalar(Self::DB_LOCK_QUERY)
            .fetch_one(&mut *txn)
            .await
            .unwrap_or(false)
        {
            tracing::trace!(
                lock = Self::DB_LOCK_NAME,
                "IbFabricMonitor acquired the lock",
            );

            let span_id: String = format!("{:#x}", u64::from_le_bytes(rand::random::<[u8; 8]>()));

            let check_ib_fabrics_span = tracing::span!(
                parent: None,
                tracing::Level::INFO,
                "check_ib_fabrics",
                span_id,
                otel.status_code = tracing::field::Empty,
                otel.status_message = tracing::field::Empty,
                num_fabrics = 0,
                fabric_metrics = tracing::field::Empty,
            );

            let res = self
                .check_ib_fabrics(&mut metrics)
                .instrument(check_ib_fabrics_span.clone())
                .await;
            check_ib_fabrics_span.record("num_fabrics", metrics.num_fabrics);
            check_ib_fabrics_span.record(
                "fabric_metrics",
                serde_json::to_string(&metrics.fabrics).unwrap_or_default(),
            );

            match &res {
                Ok(()) => {
                    check_ib_fabrics_span.record("otel.status_code", "ok");
                }
                Err(e) => {
                    tracing::error!("IbFabricMonitor run failed due to: {:?}", e);
                    check_ib_fabrics_span.record("otel.status_code", "error");
                    // Writing this field will set the span status to error
                    // Therefore we only write it on errors
                    check_ib_fabrics_span.record("otel.status_message", format!("{:?}", e));
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

    async fn check_ib_fabrics(&self, metrics: &mut IbFabricMonitorMetrics) -> CarbideResult<()> {
        if self.fabric_manager.get_config().manager_type == IBFabricManagerType::Disable {
            return Ok(());
        }

        let mut conn = self.db_pool.acquire().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "acquire connection",
                e,
            ))
        })?;
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

        for (machine, mut snapshot) in snapshots {
            match record_machine_infiniband_status_observation(
                &self.db_pool,
                &mut snapshot,
                &fabric_data,
                metrics,
            )
            .await
            {
                Ok(()) => {}
                Err(e) => {
                    tracing::error!(error = %e, machine_id = %machine, "Failed to update IB Status observation");
                }
            }
        }

        Ok(())
    }

    async fn get_all_snapshots(
        &self,
        txn: &mut PgConnection,
    ) -> CarbideResult<HashMap<MachineId, ManagedHostStateSnapshot>> {
        let machine_ids = crate::db::machine::find_machine_ids(
            txn,
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?;
        crate::db::managed_host::load_by_machine_ids(
            txn,
            &machine_ids,
            LoadSnapshotOptions {
                include_history: false,
                include_instance_data: true,
                host_health_config: self.host_health,
            },
        )
        .await
        .map_err(CarbideError::from)
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

    let conn = fabric_manager.connect(fabric).await?;
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
    let conn = fabric_manager.connect(fabric).await?;

    let ports = conn.find_ib_port(None).await?;
    let mut ports_by_state = HashMap::new();
    let mut ports_by_guid = HashMap::new();
    for port in ports.into_iter() {
        let state = match port.state.as_ref() {
            Some(state) => format!("{:?}", state),
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
    let conn = fabric_manager.connect(fabric).await?;

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

async fn record_machine_infiniband_status_observation(
    db_pool: &PgPool,
    mh_snapshot: &mut ManagedHostStateSnapshot,
    data_by_fabric: &HashMap<String, FabricData>,
    metrics: &mut IbFabricMonitorMetrics,
) -> Result<(), CarbideError> {
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
        return Ok(());
    }

    let machine_id = &mh_snapshot.host_snapshot.id;
    let ib_hw_info = &mh_snapshot
        .host_snapshot
        .hardware_info
        .as_ref()
        .unwrap()
        .infiniband_interfaces;

    // Form list of requested guids
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

        let (fabric_id, lid, associated_pkeys) = match found_port_data {
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

                if associated_pkeys
                    .as_ref()
                    .is_some_and(|pkeys| !pkeys.is_empty())
                {
                    ports_with_partitions += 1;
                }

                (
                    fabric_id,
                    if port_data.state == Some(IBPortState::Active) {
                        active_ports += 1;
                        port_data.lid as u16
                    } else {
                        0xffff_u16
                    },
                    associated_pkeys,
                )
            }
            None => {
                // The port was not found on UFM. In this case we don't even try
                // to look up associated pkeys

                // TODO: We should differentiate between "Can not communicate with fabric"
                // and "UFM definitely did not know about this GUID".
                (&String::new(), 0xffff_u16, None)
            }
        };

        ib_interfaces_status.push(MachineIbInterfaceStatusObservation {
            guid: guid.clone(),
            lid,
            fabric_id: fabric_id.to_string(),
            associated_pkeys,
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

    let cur = MachineInfinibandStatusObservation {
        observed_at: Utc::now(),
        ib_interfaces: ib_interfaces_status,
    };

    // This allows to update a record ony in case of any changes.
    prev.observed_at = cur.observed_at;

    // Update Machine infiniband status in case any changes only
    // Vector of statuses is based on guids vector that is formed
    // from hardware_info.infiniband_interfaces[]
    // So it guarantees stable order between function calls
    if prev != cur {
        let mut conn = db_pool.acquire().await.map_err(|e| {
            CarbideError::from(DatabaseError::new(
                file!(),
                line!(),
                "acquire connection",
                e,
            ))
        })?;
        db::machine::update_infiniband_status_observation(&mut conn, machine_id, &cur).await?;
        metrics.num_machine_ib_status_updates += 1;
        mh_snapshot.host_snapshot.infiniband_status_observation = Some(cur);
    }

    Ok(())
}

/// Parses a u64 string in hexadecimal or decimal format
fn parse_num(input: &str) -> Option<u64> {
    match input.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => input.parse().ok(),
    }
}

#[test]
fn test_parse_num() {
    assert_eq!(0, parse_num("0x0000000000000000").unwrap());
    assert_eq!(1, parse_num("0x0000000000000001").unwrap());
    assert_eq!(0, parse_num("0x00").unwrap());
    assert_eq!(1, parse_num("0x01").unwrap());
}
