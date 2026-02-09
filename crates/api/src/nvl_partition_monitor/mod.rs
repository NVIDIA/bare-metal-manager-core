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
use std::collections::HashMap;
use std::sync::Arc;

use carbide_uuid::machine::MachineId;
use carbide_uuid::nvlink::{NvLinkDomainId, NvLinkLogicalPartitionId, NvLinkPartitionId};
use chrono::Utc;
use db::machine::find_machine_ids;
use db::managed_host::load_by_machine_ids;
use db::nvl_logical_partition::{IdColumn as LpIdColumn, LogicalPartition};
use db::nvl_partition::{IdColumn, NvlPartition, NvlPartitionName};
use db::work_lock_manager::WorkLockManagerHandle;
use db::{self, ObjectColumnFilter, machine};
use metrics::{AppliedChange, NmxmPartitionOperationStatus, NvlPartitionMonitorMetrics};
use model::hardware_info::{MachineNvLinkInfo, NvLinkGpu};
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::nvlink::{MachineNvLinkGpuStatusObservation, MachineNvLinkStatusObservation};
use model::machine::{HostHealthConfig, LoadSnapshotOptions, ManagedHostStateSnapshot};
use sqlx::PgPool;
use tokio::sync::oneshot;

use crate::api::TransactionVending;
use crate::cfg::file::NvLinkConfig;
use crate::nvlink::NmxmClientPool;
use crate::{CarbideError, CarbideResult};

mod metrics;

#[derive(Debug, Clone)]
struct NmxmPartitionOperation {
    domain_uuid: Option<NvLinkDomainId>,
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
    RemoveDefaultPartition(String),
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
pub struct PartitionProcessingContext {
    nmx_m_partitions: HashMap<String, libnmxm::nmxm_model::Partition>,
    db_nvl_logical_partitions: HashMap<NvLinkLogicalPartitionId, LogicalPartition>,
    db_nvl_partitions: HashMap<String, NvlPartition>, // NMX-M ID to NvlPartition
    machine_nvlink_info: HashMap<MachineId, Option<MachineNvLinkInfo>>,
    gpu_map: HashMap<String, libnmxm::nmxm_model::Partition>, // NMX-M GPU ID to NMX-M partition
    nmx_m_operations: HashMap<NvLinkLogicalPartitionId, Vec<NmxmPartitionOperation>>,
    default_partition_removal_operations: HashMap<String, Vec<NmxmPartitionOperation>>,
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
            default_partition_removal_operations: HashMap::new(),
        }
    }
    // Build a map from GPU IDs to their partition IDs from NMX-M partitions
    fn build_gpu_to_partition_map(
        nmx_m_partitions: &[libnmxm::nmxm_model::Partition],
    ) -> HashMap<String, libnmxm::nmxm_model::Partition> {
        let mut gpu_map = HashMap::new();
        for partition in nmx_m_partitions {
            if let libnmxm::nmxm_model::PartitionMembers::Ids(ref ids) = *partition.members {
                for gpu_id in ids {
                    gpu_map.insert(gpu_id.clone(), partition.clone());
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
        logical_partition_id: Option<NvLinkLogicalPartitionId>,
        partition_nmx_m_id: &str,
        gpu_nmx_m_id: &str,
        machine_id: &MachineId,
        device_instance: u32,
    ) -> Option<Vec<String>> {
        let Some(logical_partition_id) = logical_partition_id else {
            tracing::error!(
                "Logical partition ID is required for getting GPUs to keep after removal"
            );
            return None;
        };
        let gpus_to_keep = match self.nmx_m_operations.get(&logical_partition_id) {
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
                    match self.nmx_m_partitions.get(partition_nmx_m_id) {
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
                match self.nmx_m_partitions.get(partition_nmx_m_id) {
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

    fn get_gpus_to_keep_in_default_partition_after_removal(
        &self,
        partition_nmx_m_id: &str,
        gpu_nmx_m_id: &str,
        machine_id: &MachineId,
        device_instance: u32,
    ) -> Option<Vec<String>> {
        let gpus_to_keep = match self
            .default_partition_removal_operations
            .get(partition_nmx_m_id)
        {
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
                    // No operation found for this GPU, so get the GPUs from the default partition.
                    match self.nmx_m_partitions.get(partition_nmx_m_id) {
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
                // No removal operations found, so get the GPUs from the default partition.
                match self.nmx_m_partitions.get(partition_nmx_m_id) {
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
                domain_uuid: Some(ctx.domain_uuid),
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
                domain_uuid: Some(ctx.domain_uuid),
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

    // Handle GPU removal from the default partition
    fn handle_gpu_removal_from_default_partition(
        &mut self,
        partition_nmx_m_id: &str,
        gpu_nmx_m_id: &str,
        gpus_to_keep: Vec<String>,
    ) -> CarbideResult<()> {
        if gpus_to_keep.is_empty() {
            let operation = NmxmPartitionOperation {
                domain_uuid: None,
                operation_type: NmxmPartitionOperationType::RemoveDefaultPartition(
                    partition_nmx_m_id.to_string(),
                ),
                original_operation_type: None,
                gpu_ids: gpus_to_keep.clone(),
                name: "".to_string(),
                db_partition_id: None,
            };

            self.default_partition_removal_operations
                .entry(partition_nmx_m_id.to_string())
                .and_modify(|ops| {
                    if let Some(op) = ops
                        .iter_mut()
                        .find(|op| op.gpu_ids.contains(&gpu_nmx_m_id.to_string()))
                    {
                        op.operation_type = NmxmPartitionOperationType::RemoveDefaultPartition(
                            partition_nmx_m_id.to_string(),
                        );
                        op.original_operation_type = None;
                        op.gpu_ids = gpus_to_keep.clone();
                    } else {
                        ops.push(operation.clone());
                    }
                })
                .or_insert(vec![operation.clone()]);
        } else {
            let operation = NmxmPartitionOperation {
                domain_uuid: None,
                operation_type: NmxmPartitionOperationType::Update(partition_nmx_m_id.to_string()),
                original_operation_type: None,
                gpu_ids: gpus_to_keep.clone(),
                name: "".to_string(),
                db_partition_id: None,
            };
            self.default_partition_removal_operations
                .entry(partition_nmx_m_id.to_string())
                .and_modify(|ops| {
                    if let Some(op) = ops
                        .iter_mut()
                        .find(|op| op.gpu_ids.contains(&gpu_nmx_m_id.to_string()))
                    {
                        op.operation_type =
                            NmxmPartitionOperationType::Update(partition_nmx_m_id.to_string());
                        op.original_operation_type = None;
                        op.gpu_ids = gpus_to_keep.clone();
                    } else {
                        ops.push(operation.clone());
                    }
                })
                .or_insert(vec![operation.clone()]);
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
            domain_uuid: Some(ctx.domain_uuid),
            operation_type: NmxmPartitionOperationType::Create,
            original_operation_type: None,
            gpu_ids: vec![ctx.gpu_nmx_m_id.clone()],
            name: format!("{}{}", logical_partition_id, ctx.gpu_nmx_m_id),
            db_partition_id: None,
        };

        self.nmx_m_operations
            .entry(logical_partition_id)
            .and_modify(|ops| {
                if let Some(op) = ops
                    .iter_mut()
                    .find(|op| op.domain_uuid.unwrap_or_default() == ctx.domain_uuid)
                {
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
            domain_uuid: Some(ctx.domain_uuid),
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
    metric_holder: Arc<metrics::MetricHolder>,
    work_lock_manager_handle: WorkLockManagerHandle,
    last_nvlink_info_validation: std::sync::Mutex<Option<std::time::Instant>>,
}

impl NvlPartitionMonitor {
    const ITERATION_WORK_KEY: &'static str = "NvlPartitionMonitor::run_single_iteration";

    pub fn new(
        db_pool: PgPool,
        nmxm_client_pool: Arc<dyn NmxmClientPool>,
        meter: opentelemetry::metrics::Meter,
        config: NvLinkConfig,
        host_health: HostHealthConfig,
        work_lock_manager_handle: WorkLockManagerHandle,
    ) -> Self {
        let hold_period = config
            .monitor_run_interval
            .saturating_add(std::time::Duration::from_secs(60));

        let metric_holder = Arc::new(metrics::MetricHolder::new(meter, hold_period));

        Self {
            db_pool,
            nmxm_client_pool,
            config,
            host_health,
            metric_holder,
            work_lock_manager_handle,
            last_nvlink_info_validation: std::sync::Mutex::new(None),
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

    pub async fn run_single_iteration(&self) -> CarbideResult<usize> {
        let mut metrics = NvlPartitionMonitorMetrics::new();

        let _lock = match self
            .work_lock_manager_handle
            .try_acquire_lock(Self::ITERATION_WORK_KEY.into())
            .await
        {
            Ok(lock) => lock,
            Err(e) => {
                tracing::warn!(
                    "NvlPartitionMonitor failed to acquire work lock: Another instance of carbide running? {e}"
                );
                return Ok(0);
            }
        };
        tracing::trace!(
            lock = Self::ITERATION_WORK_KEY,
            "NvlPartitionMonitor acquired the lock",
        );

        let span_id: String = format!("{:#x}", u64::from_le_bytes(rand::random::<[u8; 8]>()));
        let check_nvl_partition_span = tracing::span!(
            parent: None,
            tracing::Level::INFO,
            "nvlink_partition_monitor",
            span_id,
            otel.status_code = tracing::field::Empty,
            otel.status_message = tracing::field::Empty,
            metrics = tracing::field::Empty,
        );

        let nmxm_client = self
            .nmxm_client_pool
            .create_client(&self.config.nmx_m_endpoint, None)
            .await
            .map_err(|e| {
                metrics.nmxm.connect_error = "Failed to create NMXM client".to_string();
                check_nvl_partition_span.record("otel.status_code", "error");
                check_nvl_partition_span.record(
                    "otel.status_message",
                    format!("Failed to create NMMX client {e:?}"),
                );

                CarbideError::internal(format!("Failed to create NMXM client: {e}"))
            })?;

        // Gather instances and NMX-M GPU info from DB, and partitions list from NMX-M.
        let mut txn = self.db_pool.txn_begin().await?;
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

        // Don't hold the transaction across unrelated awaits
        txn.commit().await?;

        let nmx_m_partitions = nmxm_client.get_partitions_list().await.map_err(|e| {
            metrics.nmxm.connect_error = "Failed to get NMXM partitions list".to_string();

            check_nvl_partition_span.record("otel.status_code", "error");
            check_nvl_partition_span.record(
                "otel.status_message",
                format!("Failed to get NMXM partitions list {e:?}"),
            );

            CarbideError::internal(format!("Failed to get NMXM partitions list: {e}"))
        })?;

        let nmx_m_gpus = nmxm_client.get_gpu(None).await.map_err(|e| {
            metrics.nmxm.connect_error = "Failed to get NMXM gpu list".to_string();
            check_nvl_partition_span.record("otel.status_code", "error");
            check_nvl_partition_span.record(
                "otel.status_message",
                format!("Failed to get NMXM gpu list {e:?}"),
            );

            CarbideError::internal(format!("Failed to get NMXM gpu list: {e}"))
        })?;

        // Validate machine_nvlink_info is consistent with nmx-m get_gpu information.
        // This runs at most once per hour to avoid unnecessary DB updates.
        let (machine_nvlink_info, db_nvl_partitions) = self
            .validate_and_sync_nmxm_info(
                machine_nvlink_info,
                &nmx_m_gpus,
                db_nvl_partitions,
                &nmx_m_partitions,
                &mut metrics,
            )
            .await?;

        metrics.num_logical_partitions = db_nvl_logical_partitions.len();
        metrics.num_physical_partitions = db_nvl_partitions.len();
        metrics.nmxm.num_partitions = nmx_m_partitions.len();

        let mut partition_processing_context = PartitionProcessingContext::new(
            nmx_m_partitions,
            db_nvl_logical_partitions.clone(),
            db_nvl_partitions,
            machine_nvlink_info,
        );

        // Check if any partitions need to be created, updated, or deleted.
        let observations = self.check_nv_link_partitions(
            &mut partition_processing_context,
            managed_host_snapshots,
            &mut metrics,
        );

        self.record_nvlink_status_observation(observations?).await?;

        let nmx_m_operations = partition_processing_context.nmx_m_operations;

        if !nmx_m_operations.is_empty() {
            tracing::debug!("NMX-M operations: {:?}", nmx_m_operations);
        }

        // Execute any NMX-M operations.
        let pending_nmx_m_operations = self.execute_nmx_m_operations(nmx_m_operations).await?;

        if !pending_nmx_m_operations.is_empty() {
            tracing::debug!("Pending NMX-M operations: {:?}", pending_nmx_m_operations);
        }

        // Poll NMX-M operation IDs with timeout
        let completed_nmx_m_operations = self
            .poll_nmx_m_operations_with_timeout(pending_nmx_m_operations, &mut metrics)
            .await?;

        if !completed_nmx_m_operations.is_empty() {
            tracing::debug!(
                "Completed NMX-M operations: {:?}",
                completed_nmx_m_operations
            );
        }

        let num_completed_operations = completed_nmx_m_operations.len();
        metrics.num_completed_operations = num_completed_operations;

        check_nvl_partition_span.record("metrics", metrics.to_string());

        // Get a fresh list of partitions from NMX-M.
        let nmx_m_partitions = nmxm_client.get_partitions_list().await.map_err(|e| {
            metrics.nmxm.connect_error =
                "Failed to get NMXM partitions list when updating db".to_string();
            check_nvl_partition_span.record("otel.status_code", "error");
            check_nvl_partition_span.record(
                "otel.status_message",
                format!("Failed to get NMXM partitions list when updating db {e:?}"),
            );
            CarbideError::internal(format!("Failed to get NMXM partitions list: {e}"))
        })?;

        check_nvl_partition_span.record("otel.status_code", "ok");

        self.metric_holder.update_metrics(metrics);

        // Update db.
        let mut txn = self.db_pool.txn_begin().await?;
        self.update_db_with_nmx_m_operations(
            &mut txn,
            completed_nmx_m_operations.clone(),
            &db_nvl_logical_partitions,
            &nmx_m_partitions,
        )
        .await?;
        txn.commit().await?;

        Ok(num_completed_operations)
    }

    /// Validate that machine_nvlink_info from the DB is consistent with NMX-M get_gpu information.
    /// Matches GPUs by domain_uuid, guid (device_uid), and device_id, then verifies nmx_m_id matches.
    /// If nmx_m_id doesn't match, updates the DB to match NMX-M and returns the corrected data.
    /// Also checks for stale partitions in DB that no longer exist in NMX-M and deletes them.
    /// This validation only runs once per hour to avoid unnecessary overhead.
    async fn validate_and_sync_nmxm_info(
        &self,
        machine_nvlink_info: HashMap<MachineId, Option<MachineNvLinkInfo>>,
        nmx_m_gpus: &[libnmxm::nmxm_model::Gpu],
        db_nvl_partitions: Vec<db::nvl_partition::NvlPartition>,
        nmx_m_partitions: &[libnmxm::nmxm_model::Partition],
        metrics: &mut NvlPartitionMonitorMetrics,
    ) -> CarbideResult<(
        HashMap<MachineId, Option<MachineNvLinkInfo>>,
        Vec<db::nvl_partition::NvlPartition>,
    )> {
        // Only run validation once per hour.
        {
            let last_validation = self.last_nvlink_info_validation.lock().unwrap();
            if let Some(last_time) = *last_validation
                && last_time.elapsed() < std::time::Duration::from_secs(3600)
            {
                return Ok((machine_nvlink_info, db_nvl_partitions));
            }
        }

        // Build a map of NMX-M GPUs by (domain_uuid, device_uid, device_id) for matching.
        // device_uid in NMX-M corresponds to guid in nvlink_info.
        let nmx_m_gpu_map: HashMap<(uuid::Uuid, u64, i32), &libnmxm::nmxm_model::Gpu> = nmx_m_gpus
            .iter()
            .filter_map(|gpu| {
                gpu.domain_uuid
                    .map(|domain| ((domain, gpu.device_uid, gpu.device_id), gpu))
            })
            .collect();

        // Track machines that need DB updates for nmx_m_id corrections.
        let mut machines_to_update: Vec<(MachineId, MachineNvLinkInfo)> = Vec::new();

        // Check each machine's nvlink info for consistency with NMX-M.
        for (machine_id, nvlink_info_opt) in &machine_nvlink_info {
            let Some(nvlink_info) = nvlink_info_opt else {
                continue;
            };

            let mut needs_update = false;
            let mut updated_gpus: Vec<NvLinkGpu> = Vec::new();

            for db_gpu in &nvlink_info.gpus {
                let mut updated_gpu = db_gpu.clone();

                // Match GPU by domain_uuid, guid (device_uid), and device_id
                let key = (
                    nvlink_info.domain_uuid.into(),
                    db_gpu.guid,
                    db_gpu.device_id,
                );
                match nmx_m_gpu_map.get(&key) {
                    Some(nmx_m_gpu) => {
                        let nmx_m_id = nmx_m_gpu.id.as_deref().unwrap_or_default();
                        // Verify nmx_m_id matches
                        if db_gpu.nmx_m_id != nmx_m_id {
                            tracing::warn!(
                                machine_id = %machine_id,
                                device_id = db_gpu.device_id,
                                guid = db_gpu.guid,
                                db_nmx_m_id = %db_gpu.nmx_m_id,
                                nmx_m_nmx_m_id = %nmx_m_id,
                                "NvLink GPU nmx_m_id mismatch between DB and NMX-M, updating DB"
                            );
                            updated_gpu.nmx_m_id = nmx_m_id.to_string();
                            needs_update = true;
                            metrics.num_nvlink_info_mismatches += 1;
                        }
                    }
                    None => {
                        tracing::warn!(
                            machine_id = %machine_id,
                            device_id = db_gpu.device_id,
                            guid = db_gpu.guid,
                            domain_uuid = %nvlink_info.domain_uuid,
                            "NvLink GPU from DB not found in NMX-M gpu list by domain_uuid, guid, and device_id"
                        );
                    }
                }
                updated_gpus.push(updated_gpu);
            }

            if needs_update {
                let updated_nvlink_info = MachineNvLinkInfo {
                    domain_uuid: nvlink_info.domain_uuid,
                    gpus: updated_gpus,
                };
                machines_to_update.push((*machine_id, updated_nvlink_info));
            }
        }

        // Build a set of nmx_m_ids from NMX-M partitions for stale partition detection.
        let nmx_m_partition_ids: std::collections::HashSet<&str> =
            nmx_m_partitions.iter().map(|p| p.id.as_str()).collect();

        // Find DB partitions that no longer exist in NMX-M (by nmx_m_id).
        let stale_partition_ids: std::collections::HashSet<_> = db_nvl_partitions
            .iter()
            .filter(|db_partition| !nmx_m_partition_ids.contains(db_partition.nmx_m_id.as_str()))
            .map(|p| p.id)
            .collect();

        // Update the DB: update machine nvlink_info and delete stale partitions.
        let needs_db_update = !machines_to_update.is_empty() || !stale_partition_ids.is_empty();

        if needs_db_update {
            let mut txn = self.db_pool.txn_begin().await?;

            // Update machine nvlink_info for nmx_m_id mismatches.
            for (machine_id, updated_nvlink_info) in &machines_to_update {
                tracing::info!(
                    machine_id = %machine_id,
                    "Updating machine nvlink_info in DB to match NMX-M nmx_m_id"
                );
                db::machine::update_nvlink_info(&mut txn, machine_id, updated_nvlink_info.clone())
                    .await?;
            }

            // Delete stale partitions that no longer exist in NMX-M.
            for stale_partition in db_nvl_partitions
                .iter()
                .filter(|p| stale_partition_ids.contains(&p.id))
            {
                tracing::info!(
                    partition_id = %stale_partition.id,
                    nmx_m_id = %stale_partition.nmx_m_id,
                    domain_uuid = %stale_partition.domain_uuid,
                    "Deleting stale nvlink partition from DB - not found in NMX-M"
                );
                db::nvl_partition::final_delete(stale_partition.id, &mut txn).await?;
                metrics.num_stale_partitions_deleted += 1;
            }

            txn.commit().await?;

            // Update the in-memory map with the corrected values.
            let mut updated_map = machine_nvlink_info;
            for (machine_id, updated_nvlink_info) in machines_to_update {
                updated_map.insert(machine_id, Some(updated_nvlink_info));
            }

            // Filter out stale partitions from the returned list.
            let good_partitions: Vec<_> = db_nvl_partitions
                .into_iter()
                .filter(|p| !stale_partition_ids.contains(&p.id))
                .collect();

            *self.last_nvlink_info_validation.lock().unwrap() = Some(std::time::Instant::now());
            Ok((updated_map, good_partitions))
        } else {
            *self.last_nvlink_info_validation.lock().unwrap() = Some(std::time::Instant::now());
            Ok((machine_nvlink_info, db_nvl_partitions))
        }
    }

    // Check the passed NvLink partition "observations" (physical partition info from NMX-M supplemented by physical and logical partition info from DB)
    // against the instance config and generate NMX-M operations to bring the observations into alignment with the config.
    fn check_nv_link_partitions(
        &self,
        partition_ctx: &mut PartitionProcessingContext,
        mh_snapshots: HashMap<MachineId, ManagedHostStateSnapshot>,
        metrics: &mut NvlPartitionMonitorMetrics,
    ) -> CarbideResult<HashMap<MachineId, MachineNvLinkStatusObservation>> {
        let mut machine_gpu_statuses = HashMap::new();

        for mh in mh_snapshots.values() {
            metrics.num_machines_scanned += 1;
            if let Some(instance) = &mh.instance {
                metrics.num_instances_scanned += 1;
                let mut instance_gpu_statuses = Vec::new();
                for instance_gpu_config in &instance.config.nvlink.gpu_configs {
                    metrics.num_gpus_scanned += 1;
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
                            tracing::error!(
                                "NMX-M info not found for machine {}",
                                instance.machine_id
                            );
                            instance_gpu_statuses.push(gpu_status_observation);
                            continue;
                        }
                    };
                    gpu_status_observation.domain_id = domain_uuid;

                    // Get the NMX-M GPU ID
                    let gpu_nvlink_info = match partition_ctx.get_gpu_nvlink_info(
                        &instance.machine_id,
                        instance_gpu_config.device_instance,
                    ) {
                        Some(info) => info,
                        None => {
                            tracing::error!(
                                machine_id = %instance.machine_id,
                                device_instance = instance_gpu_config.device_instance,
                                "NMX-M GPU not found for machine"
                            );
                            instance_gpu_statuses.push(gpu_status_observation);
                            continue;
                        }
                    };
                    gpu_status_observation.gpu_id = gpu_nvlink_info.nmx_m_id.clone();
                    gpu_status_observation.guid = gpu_nvlink_info.guid;

                    // Get partition information from database if it exists
                    let nmxm_partition = partition_ctx
                        .gpu_map
                        .get(&gpu_nvlink_info.nmx_m_id)
                        .cloned();
                    let (
                        db_partition_id,
                        db_logical_partition_id,
                        db_partition_name,
                        db_partition_nmx_m_id,
                    ) = if let Some(nmxm_partition) = nmxm_partition {
                        match partition_ctx.get_db_partition_info(&nmxm_partition.id) {
                            Some(info) => info,
                            None => {
                                // carbide does not know about this partition. If the tenant has requested this GPU be part of a logical partition,
                                // and the partition it's in is a default partition, remove it from the default partition.
                                if instance_gpu_config.logical_partition_id.is_some()
                                    && is_nmx_m_default_partition(&nmxm_partition)
                                {
                                    tracing::info!(
                                        "Removing GPU {} from default partition {}",
                                        gpu_nvlink_info.nmx_m_id,
                                        nmxm_partition.id
                                    );
                                    // Enqueue a removal operation for this GPU.
                                    if let Some(gpus_to_keep) = partition_ctx
                                        .get_gpus_to_keep_in_default_partition_after_removal(
                                            &nmxm_partition.id,
                                            &gpu_nvlink_info.nmx_m_id,
                                            &instance.machine_id,
                                            instance_gpu_config.device_instance,
                                        )
                                    {
                                        partition_ctx.handle_gpu_removal_from_default_partition(
                                            &nmxm_partition.id,
                                            &gpu_nvlink_info.nmx_m_id,
                                            gpus_to_keep,
                                        )?;
                                    } else {
                                        tracing::error!(
                                            "No default partition found with nmx_m_id = {}",
                                            nmxm_partition.id
                                        );
                                    }
                                } else {
                                    tracing::error!(
                                        "No partition found with nmx_m_id = {}",
                                        nmxm_partition.id
                                    );
                                }
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
                                gpu_status_observation.logical_partition_id,
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
                                        == instance_gpu_config
                                            .logical_partition_id
                                            .unwrap_or_default()
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
            } else {
                // For machines with no instance, check if machine is in admin network and any cleanup is required
                let _ = self.check_machine_and_handle_gpu_removals(mh, partition_ctx);
            }
        }

        metrics.num_machine_nvl_status_updates = machine_gpu_statuses.len();

        // Add all default partition removals to the normal list so they get executed.
        for (_partition_nmx_m_id, operations) in
            partition_ctx.default_partition_removal_operations.iter()
        {
            for operation in operations {
                partition_ctx
                    .nmx_m_operations
                    .entry(NvLinkLogicalPartitionId::default())
                    .and_modify(|ops| {
                        ops.push(operation.clone());
                    })
                    .or_insert(vec![operation.clone()]);
            }
        }
        Ok(machine_gpu_statuses)
    }

    pub fn check_machine_and_handle_gpu_removals(
        &self,
        mh: &ManagedHostStateSnapshot,
        partition_ctx: &mut PartitionProcessingContext,
    ) -> CarbideResult<()> {
        // Check if machine is in admin network
        let use_admin_network = mh
            .dpu_snapshots
            .iter()
            .any(|dpu| dpu.network_config.use_admin_network.unwrap_or(true));

        // If not on admin network, skip processing
        if !use_admin_network {
            return Ok(());
        }

        if let Some(nvlink_info) = &mh.host_snapshot.nvlink_info {
            for gpu in &nvlink_info.gpus {
                // Get partition information from database if it exists
                let Some(nmxm_partition) = partition_ctx.gpu_map.get(&gpu.nmx_m_id) else {
                    continue;
                };

                let Some((
                    db_partition_id,
                    db_logical_partition_id,
                    db_partition_name,
                    db_partition_nmx_m_id,
                )) = partition_ctx.get_db_partition_info(&nmxm_partition.id)
                else {
                    tracing::error!("No partition found with nmx_m_id = {}", nmxm_partition.id);
                    continue;
                };

                let gpu_ctx = GpuProcessingContext {
                    gpu_nmx_m_id: gpu.nmx_m_id.clone(),
                    domain_uuid: nvlink_info.domain_uuid,
                    partition_id: db_partition_id,
                    partition_name: db_partition_name.clone(),
                    partition_nmx_m_id: db_partition_nmx_m_id.clone(),
                    logical_partition_id: db_logical_partition_id,
                };

                let Some(gpus_to_keep) = partition_ctx.get_gpus_to_keep_after_removal(
                    db_logical_partition_id,
                    &db_partition_nmx_m_id,
                    &gpu.nmx_m_id,
                    &mh.host_snapshot.id,
                    gpu.device_id.try_into().unwrap(),
                ) else {
                    continue;
                };

                let logical_id = db_logical_partition_id.unwrap_or_default();
                tracing::info!(
                    machine_id = %mh.host_snapshot.id,
                    gpu_nmx_m_id = %gpu.nmx_m_id,
                    logical_partition_id = %logical_id,
                    gpus_to_keep = ?gpus_to_keep,
                    "Handling GPU removal for machine in admin network"
                );
                partition_ctx.handle_gpu_removal(&gpu_ctx, gpus_to_keep)?;
            }
        }
        Ok(())
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
                    NmxmPartitionOperationType::RemoveDefaultPartition(nmx_m_partition_id) => {
                        tracing::info!("NOT Removing default partition {nmx_m_partition_id}");
                        // Remove from the default partition.
                        let result = nmxm_client
                            .delete_partition(nmx_m_partition_id.clone())
                            .await
                            .map_err(|e| {
                                CarbideError::internal(format!(
                                    "Failed to delete default partition: {e}"
                                ))
                            })?;
                        pending_operations
                            .entry(NvLinkLogicalPartitionId::default()) // Default partition has no logical partition ID
                            .and_modify(|ops| {
                                ops.push(NmxmPartitionOperation {
                                    domain_uuid: operation.domain_uuid,
                                    operation_type: NmxmPartitionOperationType::Pending(
                                        result.operation_id.clone(),
                                    ),
                                    original_operation_type: Some(
                                        NmxmPartitionOperationType::RemoveDefaultPartition(
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
                                original_operation_type: Some(
                                    NmxmPartitionOperationType::RemoveDefaultPartition(
                                        nmx_m_partition_id.clone(),
                                    ),
                                ),
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
        metrics: &mut NvlPartitionMonitorMetrics,
    ) -> CarbideResult<HashMap<NvLinkLogicalPartitionId, Vec<NmxmPartitionOperation>>> {
        let nmxm_client = self
            .nmxm_client_pool
            .create_client(&self.config.nmx_m_endpoint, None)
            .await
            .map_err(|e| {
                metrics.nmxm.connect_error =
                    "Failed to create NMXM client while polling for completion".to_string();
                CarbideError::internal(format!("Failed to create NMXM client: {e}"))
            })?;

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
                            metrics.nmxm.connect_error =
                                "Failed to get operation from NMXM".to_string();
                            CarbideError::internal(format!(
                                "Failed to get operation from NMXM: {e}"
                            ))
                        })?;

                    match result.status {
                        libnmxm::nmxm_model::OperationStatus::Completed => {
                            tracing::info!(
                                "Operation {operation:?} for logical partition {logical_partition_id} completed successfully"
                            );
                            completed_operations_for_this_logical_partition.push(operation.clone());
                            operations_to_remove.push(*logical_partition_id);

                            let applied_change = AppliedChange {
                                operation: operation.operation_type.clone().into(),
                                status: NmxmPartitionOperationStatus::Completed,
                            };
                            *metrics
                                .applied_changes
                                .entry(applied_change.clone())
                                .or_default() += 1;
                            metrics
                                .operation_latencies
                                .entry(applied_change)
                                .or_default()
                                .push(start_time.elapsed());
                        }
                        libnmxm::nmxm_model::OperationStatus::Failed => {
                            tracing::error!(
                                "Operation {operation:?} for logical partition {logical_partition_id} failed with error"
                            );
                            operations_to_remove.push(*logical_partition_id);

                            let applied_change = AppliedChange {
                                operation: operation.operation_type.clone().into(),
                                status: NmxmPartitionOperationStatus::Failed,
                            };
                            *metrics
                                .applied_changes
                                .entry(applied_change.clone())
                                .or_default() += 1;
                            metrics
                                .operation_latencies
                                .entry(applied_change)
                                .or_default()
                                .push(start_time.elapsed());
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

                            let applied_change = AppliedChange {
                                operation: operation.operation_type.clone().into(),
                                status: NmxmPartitionOperationStatus::Cancelled,
                            };
                            *metrics
                                .applied_changes
                                .entry(applied_change.clone())
                                .or_default() += 1;
                            metrics
                                .operation_latencies
                                .entry(applied_change)
                                .or_default()
                                .push(start_time.elapsed());
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
            for op in &operation {
                let applied_change = AppliedChange {
                    operation: op.operation_type.clone().into(),
                    status: NmxmPartitionOperationStatus::Timedout,
                };
                *metrics
                    .applied_changes
                    .entry(applied_change.clone())
                    .or_default() += 1;
                metrics
                    .operation_latencies
                    .entry(applied_change)
                    .or_default()
                    .push(start_time.elapsed());
            }
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
                            id: NvLinkPartitionId::new(),
                            logical_partition_id,
                            name: NvlPartitionName::try_from(operation.name.clone())?,
                            domain_uuid: operation.domain_uuid.unwrap_or_default(),
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
                    NmxmPartitionOperationType::RemoveDefaultPartition(_) => {
                        // No-op, since default partition membership is not tracked in the partitions table. The status observation of the
                        // added/removed GPUs will be updated.
                    }
                }
            }
        }

        // walk the logical partition list and check if any logical partitions need to be cleaned up
        for lp in db_nvl_logical_partitions {
            if db::nvl_logical_partition::is_marked_as_deleted(lp) {
                tracing::info!(logical_partition_id = %lp.id, "Deleting logical partition");
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
            txn.as_mut(),
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

fn is_nmx_m_default_partition(partition: &libnmxm::nmxm_model::Partition) -> bool {
    partition.partition_id == 32766
}
