use std::collections::HashMap;
use std::sync::Arc;

use carbide_uuid::machine::MachineId;
use carbide_uuid::nvlink::{NvLinkDomainId, NvLinkLogicalPartitionId, NvLinkPartitionId};
use chrono::Utc;
use db::machine::find_machine_ids;
use db::managed_host::load_by_machine_ids;
use db::nvl_logical_partition::{IdColumn as LpIdColumn, LogicalPartition};
use db::nvl_partition::{IdColumn, NvlPartition, NvlPartitionName};
use db::{self, ObjectColumnFilter, machine};
use model::hardware_info::{MachineNvLinkInfo, NvLinkGpu};
use model::instance::snapshot::InstanceSnapshot;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::nvlink::{MachineNvLinkGpuStatusObservation, MachineNvLinkStatusObservation};
use model::machine::{HostHealthConfig, LoadSnapshotOptions, ManagedHostStateSnapshot};
use sqlx::PgPool;
use tokio::sync::oneshot;

use crate::cfg::file::NvLinkConfig;
use crate::nvlink::NmxmClientPool;
use crate::{CarbideError, CarbideResult};

mod metrics;

#[derive(Debug, Clone)]
struct NmxmPartitionOperation {
    domain_uuid: NvLinkDomainId,
    operation_type: NmxmPartitionOperationType,
    original_operation_type: Option<NmxmPartitionOperationType>,
    gpu_ids: Vec<String>,
    name: String,
    db_partition_id: Option<NvLinkPartitionId>,
}

#[derive(Debug, Clone)]
enum NmxmPartitionOperationType {
    Create,
    Remove(String), // TODO: create an NmxMId type
    Update(String),
    Pending(String), // Operation ID
}

// Context for GPU helper functions in check_nv_link_partitions
struct GpuProcessingContext {
    gpu_nmx_m_id: String,
    domain_uuid: NvLinkDomainId,
    logical_partition_id: Option<NvLinkLogicalPartitionId>,
    partition_id: Option<NvLinkPartitionId>,
    partition_name: String,
    partition_nmx_m_id: String,
}

// Context for partition helper functions in check_nv_link_partitions.
struct PartitionProcessingContext {
    nmx_m_partitions: HashMap<String, libnmxm::nmxm_model::Partition>,
    db_nvl_logical_partitions: HashMap<NvLinkLogicalPartitionId, LogicalPartition>,
    db_nvl_partitions: HashMap<String, NvlPartition>, // NMX-M ID to NvlPartition
    machine_nvlink_info: HashMap<MachineId, Option<MachineNvLinkInfo>>,
    gpu_map: HashMap<String, String>, // NMX-M GPU ID to NMX-M partition ID
    nmx_m_operations: HashMap<NvLinkLogicalPartitionId, Vec<NmxmPartitionOperation>>,
}

impl PartitionProcessingContext {
    fn new(
        nmx_m_partitions: Vec<libnmxm::nmxm_model::Partition>,
        db_nvl_logical_partitions: Vec<LogicalPartition>,
        db_nvl_partitions: Vec<NvlPartition>,
        machine_nvlink_info: HashMap<MachineId, Option<MachineNvLinkInfo>>,
    ) -> Self {
        let gpu_map = Self::build_gpu_to_partition_map(&nmx_m_partitions);
        let nmx_m_partitions = nmx_m_partitions
            .into_iter()
            .map(|p| (p.id.clone(), p))
            .collect();
        let db_nvl_logical_partitions = db_nvl_logical_partitions
            .into_iter()
            .map(|p| (p.id, p))
            .collect();
        let db_nvl_partitions = db_nvl_partitions
            .into_iter()
            .map(|p| (p.nmx_m_id.clone(), p))
            .collect();
        Self {
            nmx_m_partitions,
            db_nvl_logical_partitions,
            db_nvl_partitions,
            machine_nvlink_info,
            gpu_map,
            nmx_m_operations: HashMap::new(),
        }
    }
    // Build a map from GPU IDs to their partition IDs from NMX-M partitions
    fn build_gpu_to_partition_map(
        nmx_m_partitions: &[libnmxm::nmxm_model::Partition],
    ) -> HashMap<String, String> {
        let mut gpu_map = HashMap::new();
        for partition in nmx_m_partitions {
            if let libnmxm::nmxm_model::PartitionMembers::Ids(ref ids) = *partition.members {
                for gpu_id in ids {
                    gpu_map.insert(gpu_id.clone(), partition.id.clone());
                }
            }
        }
        gpu_map
    }

    // Get the NMX-M GPU ID for a specific GPU index on a machine
    fn get_gpu_nvlink_info(
        &self,
        machine_id: &MachineId,
        device_instance: u32,
    ) -> Option<NvLinkGpu> {
        self.machine_nvlink_info.get(machine_id).and_then(|info| {
            info.as_ref().map(|info| {
                info.gpus
                    .iter()
                    .find(|g| g.device_id as u32 == device_instance + 1) // NMX-M GPU indices are 1-based
                    .cloned()
            })
        })?
    }

    // Validate that a logical partition exists and is not deleted
    fn validate_logical_partition(&self, logical_partition_id: &NvLinkLogicalPartitionId) -> bool {
        if let Some(matching_logical_partition) =
            self.db_nvl_logical_partitions.get(logical_partition_id)
        {
            if db::nvl_logical_partition::is_marked_as_deleted(matching_logical_partition) {
                tracing::error!(
                    "logical partition already marked as deleted, cannot modify physical partition"
                );
                return false;
            }
            true
        } else {
            tracing::error!("logical partition {} not found!!", logical_partition_id);
            false
        }
    }

    // Get partition information from the database for a given NMX-M partition ID
    fn get_db_partition_info(
        &self,
        nmxm_partition_id: &str,
    ) -> Option<(
        Option<NvLinkPartitionId>,
        Option<NvLinkLogicalPartitionId>,
        String,
        String,
    )> {
        self.db_nvl_partitions.get(nmxm_partition_id).map(|p| {
            (
                Some(p.id),
                p.logical_partition_id,
                p.name.clone().into(),
                p.nmx_m_id.clone(),
            )
        })
    }

    // Get the list of GPUs that should remain in a partition after removing a specific GPU from a logical partition.
    // To remove a GPU from a partition in NMX-M, we need to do an update op with every other GPU in the partition except the one
    // getting removed.
    fn get_gpus_to_keep_after_removal(
        &self,
        logical_partition_id: &NvLinkLogicalPartitionId,
        db_partition_nmx_m_id: &str,
        gpu_nmx_m_id: &str,
        machine_id: &MachineId,
        device_instance: u32,
    ) -> Option<Vec<String>> {
        let gpus_to_keep: Vec<String> = match self.nmx_m_operations.get(logical_partition_id) {
            Some(ops) => {
                if let Some(op) = ops
                    .iter()
                    .find(|op| op.gpu_ids.contains(&gpu_nmx_m_id.to_string()))
                {
                    op.gpu_ids
                        .iter()
                        .filter(|id| **id != gpu_nmx_m_id)
                        .cloned()
                        .collect()
                } else {
                    // No operation found for this physical partition, so get the partition members from NMX-M.
                    match self.nmx_m_partitions.get(db_partition_nmx_m_id) {
                        Some(p) => match p.members.as_ref() {
                            libnmxm::nmxm_model::PartitionMembers::Ids(ids) => ids
                                .iter()
                                .filter(|id| **id != gpu_nmx_m_id)
                                .cloned()
                                .collect(),
                            _ => {
                                tracing::error!(
                                    "NMX-M partition members not found for machine {}, GPU index {}",
                                    machine_id,
                                    device_instance
                                );
                                return None;
                            }
                        },
                        None => {
                            tracing::error!(
                                "NMX-M partition not found for machine {}, GPU index {}",
                                machine_id,
                                device_instance
                            );
                            return None;
                        }
                    }
                }
            }
            None => {
                // No pending operations found, so get the GPUs from NMX-M.
                match self.nmx_m_partitions.get(db_partition_nmx_m_id) {
                    Some(p) => match p.members.as_ref() {
                        libnmxm::nmxm_model::PartitionMembers::Ids(ids) => ids
                            .iter()
                            .filter(|id| **id != gpu_nmx_m_id)
                            .cloned()
                            .collect(),
                        _ => {
                            tracing::error!(
                                "NMX-M partition members not found for machine {}, GPU index {}",
                                machine_id,
                                device_instance
                            );
                            return None;
                        }
                    },
                    None => {
                        tracing::error!(
                            "NMX-M partition not found for machine {}, GPU index {}",
                            machine_id,
                            device_instance
                        );
                        return None;
                    }
                }
            }
        };
        Some(gpus_to_keep)
    }

    // Handle GPU removal from a logical partition
    fn handle_gpu_removal(
        &mut self,
        ctx: &GpuProcessingContext,
        gpus_to_keep: Vec<String>,
    ) -> CarbideResult<()> {
        let Some(logical_partition_id) = ctx.logical_partition_id else {
            return Err(CarbideError::internal(
                "Logical partition ID is required for GPU removal".to_string(),
            ));
        };
        if gpus_to_keep.is_empty() {
            // All members need to be removed, enqueue a Remove request
            let operation = NmxmPartitionOperation {
                domain_uuid: ctx.domain_uuid,
                operation_type: NmxmPartitionOperationType::Remove(ctx.partition_nmx_m_id.clone()),
                original_operation_type: None,
                gpu_ids: gpus_to_keep.clone(),
                name: ctx.partition_name.clone(),
                db_partition_id: ctx.partition_id,
            };

            self.nmx_m_operations
                .entry(logical_partition_id)
                .and_modify(|ops| {
                    if let Some(op) = ops
                        .iter_mut()
                        .find(|op| op.gpu_ids.contains(&ctx.gpu_nmx_m_id))
                    {
                        op.operation_type =
                            NmxmPartitionOperationType::Remove(ctx.partition_nmx_m_id.clone());
                        op.original_operation_type = None;
                        op.gpu_ids = gpus_to_keep.clone();
                        op.name = ctx.partition_name.clone();
                    } else {
                        ops.push(operation.clone());
                    }
                })
                .or_insert(vec![operation]);
        } else {
            // Some members remain, enqueue an Update request
            let operation = NmxmPartitionOperation {
                domain_uuid: ctx.domain_uuid,
                operation_type: NmxmPartitionOperationType::Update(ctx.partition_nmx_m_id.clone()),
                original_operation_type: None,
                gpu_ids: gpus_to_keep.clone(),
                name: ctx.partition_name.clone(),
                db_partition_id: ctx.partition_id,
            };

            self.nmx_m_operations
                .entry(logical_partition_id)
                .and_modify(|ops| {
                    if let Some(op) = ops
                        .iter_mut()
                        .find(|op| op.gpu_ids.contains(&ctx.gpu_nmx_m_id))
                    {
                        op.operation_type =
                            NmxmPartitionOperationType::Update(ctx.partition_nmx_m_id.clone());
                        op.original_operation_type = None;
                        op.gpu_ids = gpus_to_keep.clone();
                        op.name = ctx.partition_name.clone();
                    } else {
                        ops.push(operation.clone());
                    }
                })
                .or_insert(vec![operation]);
        }
        Ok(())
    }

    // Handle GPU addition to a logical partition when no other partitions exist in the logical partition.
    fn handle_gpu_addition_new_partition(
        &mut self,
        ctx: &GpuProcessingContext,
    ) -> CarbideResult<()> {
        let Some(logical_partition_id) = ctx.logical_partition_id else {
            return Err(CarbideError::internal(
                "Logical partition ID is required for GPU addition to new partition".to_string(),
            ));
        };
        let operation = NmxmPartitionOperation {
            domain_uuid: ctx.domain_uuid,
            operation_type: NmxmPartitionOperationType::Create,
            original_operation_type: None,
            gpu_ids: vec![ctx.gpu_nmx_m_id.clone()],
            name: format!("{}{}", logical_partition_id, ctx.gpu_nmx_m_id),
            db_partition_id: None,
        };

        self.nmx_m_operations
            .entry(logical_partition_id)
            .and_modify(|ops| {
                if let Some(op) = ops.iter_mut().find(|op| op.domain_uuid == ctx.domain_uuid) {
                    op.gpu_ids.push(ctx.gpu_nmx_m_id.clone());
                } else {
                    ops.push(operation.clone());
                }
            })
            .or_insert(vec![operation]);
        Ok(())
    }

    // Handle GPU addition to an existing partition in the same domain
    fn handle_gpu_addition_existing_partition(
        &mut self,
        ctx: &GpuProcessingContext,
        partition: &NvlPartition,
    ) -> CarbideResult<()> {
        let Some(logical_partition_id) = ctx.logical_partition_id else {
            return Err(CarbideError::internal(
                "Logical partition ID is required for GPU addition to existing partition"
                    .to_string(),
            ));
        };
        let operation = NmxmPartitionOperation {
            domain_uuid: ctx.domain_uuid,
            operation_type: NmxmPartitionOperationType::Update(partition.nmx_m_id.clone()),
            original_operation_type: None,
            gpu_ids: vec![ctx.gpu_nmx_m_id.clone()],
            name: partition.name.clone().into(),
            db_partition_id: ctx.partition_id, // TODO: should try to verify that these are not nil
        };

        self.nmx_m_operations
            .entry(logical_partition_id)
            .and_modify(|ops| {
                if let Some(op) = ops.iter_mut().find(|op| match &op.operation_type {
                    NmxmPartitionOperationType::Update(nmx_m_partition_id) => {
                        *nmx_m_partition_id == partition.nmx_m_id.clone()
                    }
                    _ => false,
                }) {
                    op.gpu_ids.push(ctx.gpu_nmx_m_id.clone());
                } else {
                    ops.push(operation.clone());
                }
            })
            .or_insert(vec![operation]);
        Ok(())
    }
}

pub struct NvlPartitionMonitor {
    db_pool: PgPool,
    nmxm_client_pool: Arc<dyn NmxmClientPool>,
    config: NvLinkConfig,
    host_health: HostHealthConfig,
}

impl NvlPartitionMonitor {
    const DB_LOCK_NAME: &'static str = "nvlink_partition_monitor_lock";
    const DB_LOCK_QUERY: &'static str = "SELECT pg_try_advisory_xact_lock((SELECT 'nvlink_partition_monitor_lock'::regclass::oid)::integer)";

    pub fn new(
        db_pool: PgPool,
        nmxm_client_pool: Arc<dyn NmxmClientPool>,
        //metric_holder: Arc<MetricHolder>,
        config: NvLinkConfig,
        host_health: HostHealthConfig,
    ) -> Self {
        Self {
            db_pool,
            nmxm_client_pool,
            //metric_holder,
            config,
            host_health,
        }
    }

    pub fn start(self) -> eyre::Result<oneshot::Sender<i32>> {
        let (stop_sender, stop_receiver) = oneshot::channel();

        if self.config.enabled {
            tokio::task::Builder::new()
                .name("nvl-partition-monitor")
                .spawn(async move { self.run(stop_receiver).await })?;
        }

        Ok(stop_sender)
    }

    pub async fn run(&self, mut stop_receiver: oneshot::Receiver<i32>) {
        let run_interval = self.config.monitor_run_interval;
        loop {
            let sleep_interval = match self.run_single_iteration().await {
                Ok(num_changes) => {
                    if num_changes > 0 {
                        // Decrease the interval if changes have been made.
                        tokio::time::Duration::from_millis(1000)
                    } else {
                        run_interval
                    }
                }
                Err(e) => {
                    tracing::warn!("NvlPartitionMonitor error: {}", e);
                    run_interval
                }
            };

            tokio::select! {
                _ = tokio::time::sleep(sleep_interval) => {},
                _ = &mut stop_receiver => {
                    tracing::info!("NvlPartitionMonitor stop was requested");
                    return;
                }
            }
        }
    }

    #[allow(txn_held_across_await)]
    pub async fn run_single_iteration(&self) -> CarbideResult<usize> {
        let mut txn =
            self.db_pool.begin().await.map_err(|e| {
                CarbideError::internal(format!("Failed to create transaction: {e}"))
            })?;

        let num_changes = if sqlx::query_scalar(Self::DB_LOCK_QUERY)
            .fetch_one(&mut *txn)
            .await
            .unwrap_or(false)
        {
            tracing::trace!(
                lock = Self::DB_LOCK_NAME,
                "NvlPartitionMonitor acquired the lock",
            );

            let nmxm_client = self
                .nmxm_client_pool
                .create_client(&self.config.nmx_m_endpoint, None)
                .await
                .map_err(|e| {
                    CarbideError::internal(format!("Failed to create NMXM client: {e}"))
                })?;

            // Gather instances and NMX-M GPU info from DB, and partitions list from NMX-M.
            let managed_host_snapshots = self.load_mnnvl_managed_host_snapshots(&mut txn).await?;
            let machine_nvlink_info = machine::find_nvlink_info_by_machine_ids(
                &mut txn,
                &managed_host_snapshots.keys().copied().collect::<Vec<_>>(),
            )
            .await?;
            let db_nvl_partitions =
                db::nvl_partition::find_by(&mut txn, ObjectColumnFilter::<IdColumn>::All).await?;

            let db_nvl_logical_partitions =
                db::nvl_logical_partition::find_by(&mut txn, ObjectColumnFilter::<LpIdColumn>::All)
                    .await?;

            let nmx_m_partitions = nmxm_client.get_partitions_list().await.map_err(|e| {
                CarbideError::internal(format!("Failed to get NMXM partitions list: {e}"))
            })?;

            let mut partition_processing_context = PartitionProcessingContext::new(
                nmx_m_partitions,
                db_nvl_logical_partitions.clone(),
                db_nvl_partitions,
                machine_nvlink_info,
            );

            // Check if any partitions need to be created, updated, or deleted.
            let observations = self
                .check_nv_link_partitions(
                    &mut partition_processing_context,
                    &managed_host_snapshots
                        .values()
                        .filter_map(|mh| mh.instance.clone())
                        .collect::<Vec<_>>(),
                )
                .await?;

            self.record_nvlink_status_observation(observations).await?;

            let nmx_m_operations = partition_processing_context.nmx_m_operations;

            // Execute any NMX-M operations.
            let pending_nmx_m_operations = self.execute_nmx_m_operations(nmx_m_operations).await?;

            // Poll NMX-M operation IDs with timeout
            let completed_nmx_m_operations = self
                .poll_nmx_m_operations_with_timeout(pending_nmx_m_operations)
                .await?;

            let num_completed_operations = completed_nmx_m_operations.len();

            // Get a fresh list of partitions from NMX-M.
            let nmx_m_partitions = nmxm_client.get_partitions_list().await.map_err(|e| {
                CarbideError::internal(format!("Failed to get NMXM partitions list: {e}"))
            })?;

            // Update db.
            self.update_db_with_nmx_m_operations(
                &mut txn,
                completed_nmx_m_operations.clone(),
                &db_nvl_logical_partitions,
                &nmx_m_partitions,
            )
            .await?;

            num_completed_operations
        } else {
            0
        };

        txn.commit()
            .await
            .map_err(|e| CarbideError::internal(format!("Failed to commit transaction: {e}")))?;
        Ok(num_changes)
    }

    // Check the passed NvLink partition "observations" (physical partition info from NMX-M supplemented by physical and logical partition info from DB)
    // against the instance config and generate NMX-M operations to bring the observations into alignment with the config.
    async fn check_nv_link_partitions(
        &self,
        partition_ctx: &mut PartitionProcessingContext,
        instances: &[InstanceSnapshot],
    ) -> CarbideResult<HashMap<MachineId, MachineNvLinkStatusObservation>> {
        let mut machine_gpu_statuses = HashMap::new();
        for instance in instances {
            let mut instance_gpu_statuses = Vec::new();
            for instance_gpu_config in &instance.config.nvlink.gpu_configs {
                // Start with an empty observation and build it, so that we still get a status observation when we have an error.
                let mut gpu_status_observation = MachineNvLinkGpuStatusObservation {
                    device_instance: instance_gpu_config.device_instance,
                    ..Default::default()
                };
                // Get domain UUID for this machine
                let domain_uuid = match partition_ctx
                    .machine_nvlink_info
                    .get(&instance.machine_id)
                    .and_then(|info| info.as_ref().map(|info| info.domain_uuid))
                {
                    Some(uuid) => uuid,
                    None => {
                        tracing::error!("NMX-M info not found for machine {}", instance.machine_id);
                        instance_gpu_statuses.push(gpu_status_observation);
                        continue;
                    }
                };
                gpu_status_observation.domain_id = domain_uuid;

                // Get the NMX-M GPU ID
                let gpu_nvlink_info = match partition_ctx
                    .get_gpu_nvlink_info(&instance.machine_id, instance_gpu_config.device_instance)
                {
                    Some(info) => info,
                    None => {
                        tracing::error!("NMX-M GPU not found for machine {}", instance.machine_id);
                        instance_gpu_statuses.push(gpu_status_observation);
                        continue;
                    }
                };
                gpu_status_observation.gpu_id = gpu_nvlink_info.nmx_m_id.clone();
                gpu_status_observation.guid = gpu_nvlink_info.guid;

                // Get partition information from database if it exists
                let nmxm_partition_id = partition_ctx.gpu_map.get(&gpu_nvlink_info.nmx_m_id);
                let (
                    db_partition_id,
                    db_logical_partition_id,
                    db_partition_name,
                    db_partition_nmx_m_id,
                ) = if let Some(id) = nmxm_partition_id {
                    match partition_ctx.get_db_partition_info(id) {
                        Some(info) => info,
                        None => {
                            // carbide does not know about this partition. We should enqueue a removal operation, since we can't
                            // make any assumptions about the partition. On the next monitor iteration, NMX-M and carbide will be
                            // back in sync.
                            // This will happen if a default partition is enabled for a rack - when the monitor runs, all the GPUs
                            // will be in a partition that carbide does not know about.
                            // For now, just log an error and continue.
                            tracing::error!("No partition found with nmx_m_id = {id}");
                            instance_gpu_statuses.push(gpu_status_observation);
                            continue;
                        }
                    }
                } else {
                    (None, None, String::new(), String::new())
                };

                // ADd the rest of the status obs from the db. The db gets populated after NMX-M gets updated, so technically we're
                // just "observing" the db, but indirectly we're observing the NMX-M as well.
                gpu_status_observation.partition_id = db_partition_id;
                gpu_status_observation.logical_partition_id = db_logical_partition_id;
                gpu_status_observation.guid = gpu_nvlink_info.guid;
                instance_gpu_statuses.push(gpu_status_observation.clone());

                // Validate logical partition exists and is not deleted
                if let Some(logical_partition_id) = db_logical_partition_id
                    && !partition_ctx.validate_logical_partition(&logical_partition_id)
                {
                    continue;
                }

                // Create context for processing this GPU. The logical partition ID comes from the config if it exists, otherwise it comes from the status.
                let gpu_ctx = GpuProcessingContext {
                    gpu_nmx_m_id: gpu_nvlink_info.nmx_m_id.clone(),
                    domain_uuid,
                    partition_id: db_partition_id,
                    partition_name: db_partition_name.clone(),
                    partition_nmx_m_id: db_partition_nmx_m_id.clone(),
                    logical_partition_id: if let Some(logical_partition_id) =
                        instance_gpu_config.logical_partition_id
                    {
                        // If the config logical partition is set use it
                        Some(logical_partition_id)
                    } else {
                        // ...or if the obs one is set use it, or None.
                        gpu_status_observation.logical_partition_id
                    },
                };

                match (
                    instance_gpu_config.logical_partition_id,
                    gpu_status_observation.logical_partition_id,
                ) {
                    (None, Some(_status_logical_partition_id)) => {
                        // The tenant has requested this GPU be removed from a logical partition
                        let gpus_to_keep = match partition_ctx.get_gpus_to_keep_after_removal(
                            &gpu_status_observation.logical_partition_id.unwrap(),
                            &db_partition_nmx_m_id,
                            &gpu_nvlink_info.nmx_m_id,
                            &instance.machine_id,
                            instance_gpu_config.device_instance,
                        ) {
                            Some(gpus) => gpus,
                            None => continue,
                        };

                        partition_ctx.handle_gpu_removal(&gpu_ctx, gpus_to_keep)?;
                    }
                    (Some(_config_logical_partition_id), None) => {
                        // Tenant has requested this GPU be part of a logical partition.
                        if let Some(partition_id) = gpu_status_observation.partition_id {
                            tracing::error!(
                                "Instance GPU {} is part of physical partition {}, but not in a logical partition",
                                instance_gpu_config.device_instance,
                                partition_id
                            );
                            continue;
                        }

                        // Check if there are other physical partitions in the logical partition
                        let matching_partitions: Vec<NvlPartition> = partition_ctx
                            .db_nvl_partitions
                            .values()
                            .filter(|p| {
                                p.logical_partition_id.unwrap_or_default()
                                    == instance_gpu_config.logical_partition_id.unwrap_or_default()
                            })
                            .cloned()
                            .collect();

                        let partition_with_same_domain = matching_partitions
                            .iter()
                            .find(|p| p.domain_uuid == domain_uuid);

                        if matching_partitions.is_empty() {
                            // No other physical partitions in the logical partition - create new
                            partition_ctx.handle_gpu_addition_new_partition(&gpu_ctx)?;
                        } else if let Some(partition) = partition_with_same_domain {
                            // Add to existing partition in the same domain
                            partition_ctx
                                .handle_gpu_addition_existing_partition(&gpu_ctx, partition)?;
                        } else {
                            // Create new partition in a different domain
                            partition_ctx.handle_gpu_addition_new_partition(&gpu_ctx)?;
                        }
                    }
                    (Some(config_logical_partition_id), Some(status_logical_partition_id)) => {
                        if config_logical_partition_id != status_logical_partition_id {
                            // TODO: move to new logical partition.
                            // Not sure how much this path will be exercised. Most use cases will involve an explicit delete of the logical
                            // partition before adding GPU to a new partition.
                        }
                    }
                    (None, None) => {
                        // No op
                    }
                }
            }
            // Now we've generated the operations, record an observation.
            let observation = MachineNvLinkStatusObservation {
                observed_at: Utc::now(),
                nvlink_gpus: instance_gpu_statuses,
            };
            machine_gpu_statuses.insert(instance.machine_id, observation);
        }
        Ok(machine_gpu_statuses)
    }

    // Use a separate transaction to record the observations to avoid blocking the main transaction when we poll NMX-M.
    async fn record_nvlink_status_observation(
        &self,
        observations: HashMap<MachineId, MachineNvLinkStatusObservation>,
    ) -> CarbideResult<()> {
        let mut obs_txn = self.db_pool.begin().await.map_err(|e| {
            CarbideError::internal(format!(
                "Failed to create transaction for nvlink status observation: {e}"
            ))
        })?;
        for (machine_id, observations) in observations {
            db::machine::update_nvlink_status_observation(&mut obs_txn, &machine_id, &observations)
                .await?;
        }
        obs_txn.commit().await.map_err(|e| {
            CarbideError::internal(format!(
                "Failed to commit transaction for nvlink status observation: {e}"
            ))
        })?;
        Ok(())
    }

    async fn execute_nmx_m_operations(
        &self,
        nmx_m_operations: HashMap<NvLinkLogicalPartitionId, Vec<NmxmPartitionOperation>>,
    ) -> CarbideResult<HashMap<NvLinkLogicalPartitionId, Vec<NmxmPartitionOperation>>> {
        let nmxm_client = self
            .nmxm_client_pool
            .create_client(&self.config.nmx_m_endpoint, None)
            .await
            .map_err(|e| CarbideError::internal(format!("Failed to create NMXM client: {e}")))?;

        let mut pending_operations: HashMap<NvLinkLogicalPartitionId, Vec<NmxmPartitionOperation>> =
            HashMap::new();
        for (logical_partition_id, operations) in nmx_m_operations {
            for operation in operations {
                match operation.operation_type {
                    NmxmPartitionOperationType::Create => {
                        // Create the nvl partition.
                        let request = libnmxm::nmxm_model::CreatePartitionRequest {
                            // For integration test to pass, till we can fix SimClient to cache partition info dynamically
                            name: format!(
                                "{}{}",
                                logical_partition_id,
                                operation.gpu_ids.join(",")
                            ),
                            members: Box::new(libnmxm::nmxm_model::PartitionMembers::Ids(
                                operation.gpu_ids.clone(),
                            )),
                        };
                        let result =
                            nmxm_client
                                .create_partition(Some(request))
                                .await
                                .map_err(|e| {
                                    CarbideError::internal(format!(
                                        "Failed to create partition: {e}"
                                    ))
                                })?;
                        pending_operations
                            .entry(logical_partition_id)
                            .and_modify(|ops| {
                                ops.push(NmxmPartitionOperation {
                                    domain_uuid: operation.domain_uuid,
                                    operation_type: NmxmPartitionOperationType::Pending(
                                        result.operation_id.clone(),
                                    ),
                                    original_operation_type: Some(
                                        NmxmPartitionOperationType::Create,
                                    ),
                                    gpu_ids: operation.gpu_ids.clone(),
                                    name: operation.name.clone(),
                                    db_partition_id: operation.db_partition_id,
                                });
                            })
                            .or_insert(vec![NmxmPartitionOperation {
                                domain_uuid: operation.domain_uuid,
                                operation_type: NmxmPartitionOperationType::Pending(
                                    result.operation_id.clone(),
                                ),
                                original_operation_type: Some(NmxmPartitionOperationType::Create),
                                gpu_ids: operation.gpu_ids.clone(),
                                name: operation.name.clone(),
                                db_partition_id: operation.db_partition_id,
                            }]);
                    }
                    NmxmPartitionOperationType::Remove(nmx_m_partition_id) => {
                        // Remove from the partition.

                        let result = nmxm_client
                            .delete_partition(nmx_m_partition_id.clone())
                            .await
                            .map_err(|e| {
                                CarbideError::internal(format!("Failed to create partition: {e}"))
                            })?;
                        pending_operations
                            .entry(logical_partition_id)
                            .and_modify(|ops| {
                                ops.push(NmxmPartitionOperation {
                                    domain_uuid: operation.domain_uuid,
                                    operation_type: NmxmPartitionOperationType::Pending(
                                        result.operation_id.clone(),
                                    ),
                                    original_operation_type: Some(
                                        NmxmPartitionOperationType::Remove(
                                            nmx_m_partition_id.clone(),
                                        ),
                                    ),
                                    gpu_ids: operation.gpu_ids.clone(),
                                    name: operation.name.clone(),
                                    db_partition_id: operation.db_partition_id,
                                });
                            })
                            .or_insert(vec![NmxmPartitionOperation {
                                domain_uuid: operation.domain_uuid,
                                operation_type: NmxmPartitionOperationType::Pending(
                                    result.operation_id.clone(),
                                ),
                                original_operation_type: Some(NmxmPartitionOperationType::Remove(
                                    nmx_m_partition_id.clone(),
                                )),
                                gpu_ids: operation.gpu_ids.clone(),
                                name: operation.name.clone(),
                                db_partition_id: operation.db_partition_id,
                            }]);
                    }
                    NmxmPartitionOperationType::Update(nmx_m_partition_id) => {
                        // Update the partition.
                        let request = libnmxm::nmxm_model::UpdatePartitionRequest {
                            members: Box::new(libnmxm::nmxm_model::PartitionMembers::Ids(
                                operation.gpu_ids.clone(),
                            )),
                        };
                        let result = nmxm_client
                            .update_partition(nmx_m_partition_id.clone(), request)
                            .await
                            .map_err(|e| {
                                CarbideError::internal(format!("Failed to update partition: {e}"))
                            })?;
                        pending_operations
                            .entry(logical_partition_id)
                            .and_modify(|ops| {
                                ops.push(NmxmPartitionOperation {
                                    domain_uuid: operation.domain_uuid,
                                    operation_type: NmxmPartitionOperationType::Pending(
                                        result.operation_id.clone(),
                                    ),
                                    original_operation_type: Some(
                                        NmxmPartitionOperationType::Update(
                                            nmx_m_partition_id.clone(),
                                        ),
                                    ),
                                    gpu_ids: operation.gpu_ids.clone(),
                                    name: operation.name.clone(),
                                    db_partition_id: operation.db_partition_id,
                                });
                            })
                            .or_insert(vec![NmxmPartitionOperation {
                                domain_uuid: operation.domain_uuid,
                                operation_type: NmxmPartitionOperationType::Pending(
                                    result.operation_id.clone(),
                                ),
                                original_operation_type: Some(NmxmPartitionOperationType::Update(
                                    nmx_m_partition_id.clone(),
                                )),
                                gpu_ids: operation.gpu_ids.clone(),
                                name: operation.name.clone(),
                                db_partition_id: operation.db_partition_id,
                            }]);
                    }
                    NmxmPartitionOperationType::Pending(_operation_id) => {
                        // This will be handled by the poll_nmx_m_operations_with_timeout function, there should not be any Pending operations in this step.
                    }
                }
            }
        }
        Ok(pending_operations)
    }

    async fn poll_nmx_m_operations_with_timeout(
        &self,
        pending_nmx_m_operations: HashMap<NvLinkLogicalPartitionId, Vec<NmxmPartitionOperation>>,
    ) -> CarbideResult<HashMap<NvLinkLogicalPartitionId, Vec<NmxmPartitionOperation>>> {
        let nmxm_client = self
            .nmxm_client_pool
            .create_client(&self.config.nmx_m_endpoint, None)
            .await
            .map_err(|e| CarbideError::internal(format!("Failed to create NMXM client: {e}")))?;

        let timeout_duration = self.config.nmx_m_operation_timeout;
        let poll_interval = std::time::Duration::from_millis(500);
        let start_time = std::time::Instant::now();

        let mut completed_operations: HashMap<
            NvLinkLogicalPartitionId,
            Vec<NmxmPartitionOperation>,
        > = HashMap::new();
        let mut pending_nmx_m_operations = pending_nmx_m_operations;
        while !pending_nmx_m_operations.is_empty() && start_time.elapsed() < timeout_duration {
            let mut operations_to_remove = Vec::new();

            for (logical_partition_id, operations) in &pending_nmx_m_operations {
                let mut completed_operations_for_this_logical_partition = Vec::new();
                for operation in operations {
                    let operation_id = match &operation.operation_type {
                        NmxmPartitionOperationType::Pending(operation_id) => operation_id,
                        _ => {
                            tracing::error!(
                                "Operation {operation:?} for logical partition {logical_partition_id} is not a pending operation"
                            );
                            continue;
                        }
                    };
                    let result = nmxm_client
                        .get_operation(operation_id.to_string())
                        .await
                        .map_err(|e| {
                            CarbideError::internal(format!("Failed to get operation: {e}"))
                        })?;

                    match result.status {
                        libnmxm::nmxm_model::OperationStatus::Completed => {
                            tracing::info!(
                                "Operation {operation:?} for logical partition {logical_partition_id} completed successfully"
                            );
                            completed_operations_for_this_logical_partition.push(operation.clone());
                            operations_to_remove.push(*logical_partition_id);
                        }
                        libnmxm::nmxm_model::OperationStatus::Failed => {
                            tracing::error!(
                                "Operation {operation:?} for logical partition {logical_partition_id} failed with error"
                            );
                            operations_to_remove.push(*logical_partition_id);
                        }
                        libnmxm::nmxm_model::OperationStatus::Pending
                        | libnmxm::nmxm_model::OperationStatus::InProgress => {
                            // Continue polling
                        }
                        libnmxm::nmxm_model::OperationStatus::Cancelled => {
                            tracing::error!(
                                "Operation {operation:?} for logical partition {logical_partition_id} cancelled"
                            );
                            operations_to_remove.push(*logical_partition_id);
                        }
                    }
                }
                completed_operations
                    .entry(*logical_partition_id)
                    .and_modify(|ops| {
                        ops.extend(completed_operations_for_this_logical_partition.clone());
                    })
                    .or_insert(completed_operations_for_this_logical_partition);
            }

            // Remove completed/failed operations
            for logical_partition_id in operations_to_remove {
                pending_nmx_m_operations.remove(&logical_partition_id);
            }

            if !pending_nmx_m_operations.is_empty() {
                tokio::time::sleep(poll_interval).await;
            }
        }
        // Log any remaining pending operations that timed out
        for (logical_partition_id, operation) in pending_nmx_m_operations {
            tracing::warn!(
                "Operation {operation:?} for logical partition {logical_partition_id} timed out after 10 seconds"
            );
        }
        Ok(completed_operations)
    }

    async fn update_db_with_nmx_m_operations(
        &self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        completed_nmx_m_operations: HashMap<NvLinkLogicalPartitionId, Vec<NmxmPartitionOperation>>,
        db_nvl_logical_partitions: &[LogicalPartition],
        nmx_m_partitions: &[libnmxm::nmxm_model::Partition],
    ) -> CarbideResult<()> {
        for (logical_partition_id, operations) in completed_nmx_m_operations {
            for mut operation in operations {
                // operation type will change to Pending after it has been enqueued. Restore the original operation type
                // after completion
                if let Some(original_type) = operation.original_operation_type.take() {
                    operation.operation_type = original_type;
                }
                match operation.operation_type {
                    NmxmPartitionOperationType::Create => {
                        // Create the nvl partition in the database
                        let new_partition = db::nvl_partition::NewNvlPartition {
                            id: NvLinkPartitionId::from(uuid::Uuid::new_v4()),
                            logical_partition_id,
                            name: NvlPartitionName::try_from(operation.name.clone())?,
                            domain_uuid: operation.domain_uuid,
                            nmx_m_id: match nmx_m_partitions.iter().find(|p| {
                                // Check if the GPUs match
                                let p_members = match p.members.as_ref() {
                                    libnmxm::nmxm_model::PartitionMembers::Ids(ids) => ids,
                                    _ => return false,
                                };
                                p_members.iter().all(|id| operation.gpu_ids.contains(id))
                                    && operation.gpu_ids.iter().all(|id| p_members.contains(id))
                            }) {
                                Some(p) => p.id.clone(),
                                None => {
                                    tracing::error!(
                                        "NMX-M partition not found for name {}",
                                        operation.name
                                    );
                                    continue;
                                }
                            },
                        };
                        let _partition = new_partition.create(txn).await?;
                    }
                    NmxmPartitionOperationType::Remove(_) => {
                        db::nvl_partition::final_delete(
                            operation.db_partition_id.unwrap_or_default(),
                            txn,
                        )
                        .await?;
                    }
                    NmxmPartitionOperationType::Update(_) => {
                        // No-op, since partition membership is not tracked in the partitions table. The status observation of the
                        // added/removed GPUs will be updated.
                    }
                    NmxmPartitionOperationType::Pending(_operation_id) => {
                        // Should be no pending operations in this step.
                    }
                }
            }
        }

        // walk the logical partition list and check if any logical partitions need to be cleaned up
        for lp in db_nvl_logical_partitions {
            if db::nvl_logical_partition::is_marked_as_deleted(lp) {
                println!("\n\nDeleteing parition with id {:?}", lp.id);
                db::nvl_logical_partition::final_delete(lp.id, txn).await?;
            }
        }

        Ok(())
    }

    async fn load_mnnvl_managed_host_snapshots(
        &self,
        txn: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> CarbideResult<HashMap<MachineId, ManagedHostStateSnapshot>> {
        let mnvvl_machine_ids = find_machine_ids(
            txn,
            MachineSearchConfig {
                mnnvl_only: true,
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?;
        load_by_machine_ids(
            txn,
            mnvvl_machine_ids.as_slice(),
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
