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
pub mod dpu_nic_firmware;
pub mod dpu_nic_firmware_metrics;
pub mod host_firmware;
pub mod machine_update_module;
pub mod metrics;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use carbide_uuid::machine::MachineId;
use db::work_lock_manager::WorkLockManagerHandle;
use db::{DatabaseError, ObjectFilter, Transaction};
use host_firmware::HostFirmwareUpdate;
use machine_update_module::MachineUpdateModule;
use model::dpu_machine_update::DpuMachineUpdate;
use model::machine::machine_search_config::MachineSearchConfig;
use model::machine::{HostHealthConfig, LoadSnapshotOptions, ManagedHostStateSnapshot};
use model::machine_update_module::HOST_UPDATE_HEALTH_REPORT_SOURCE;
use sqlx::{PgConnection, PgPool};
use tokio::sync::oneshot;

use self::dpu_nic_firmware::DpuNicFirmwareUpdate;
use self::metrics::MachineUpdateManagerMetrics;
use crate::CarbideResult;
use crate::cfg::file::{CarbideConfig, MaxConcurrentUpdates};

/// The MachineUpdateManager periodically runs [modules](machine_update_module::MachineUpdateModule) to initiate upgrades of machine components.
/// On each iteration the MachineUpdateManager will:
/// 1. collect the number of outstanding updates from all modules.
/// 2. if there are less than the max allowed updates each module will be told to start updates until
///    the number of updates reaches the maximum allowed.
///
/// Config from [CarbideConfig]:
/// * `max_concurrent_machine_updates` the maximum number of updates allowed across all modules
/// * `machine_update_run_interval` how often the manager calls the modules to start updates
pub struct MachineUpdateManager {
    database_connection: PgPool,
    max_concurrent_machine_updates: MaxConcurrentUpdates,
    run_interval: Duration,
    update_modules: Vec<Box<dyn MachineUpdateModule>>,
    metrics: Option<MachineUpdateManagerMetrics>,
    host_health: HostHealthConfig,
    work_lock_manager_handle: WorkLockManagerHandle,
}

impl MachineUpdateManager {
    const ITERATION_WORK_KEY: &'static str = "MachineUpdateManager::run_single_iteration";
    const DEFAULT_MAX_CONCURRENT_MACHINE_UPDATES: i32 = 0;

    /// create a MachineUpdateManager with provided modules, overriding the default.
    #[cfg(test)]
    pub fn new_with_modules(
        database_connection: sqlx::PgPool,
        config: Arc<CarbideConfig>,
        modules: Vec<Box<dyn MachineUpdateModule>>,
        work_lock_manager_handle: WorkLockManagerHandle,
    ) -> Self {
        MachineUpdateManager {
            database_connection,
            max_concurrent_machine_updates: config.max_concurrent_machine_updates(),
            run_interval: Duration::from_secs(config.machine_update_run_interval.unwrap_or(300)),
            update_modules: modules,
            metrics: None,
            host_health: config.host_health,
            work_lock_manager_handle,
        }
    }

    /// Create a MachineUpdateManager with the default modules.
    pub fn new(
        database_connection: sqlx::PgPool,
        config: Arc<CarbideConfig>,
        meter: opentelemetry::metrics::Meter,
        work_lock_manager_handle: WorkLockManagerHandle,
    ) -> Self {
        let mut update_modules = vec![];

        if let Some(dpu_nic_firmware) = DpuNicFirmwareUpdate::new(config.clone(), meter.clone()) {
            update_modules.push(Box::new(dpu_nic_firmware) as Box<dyn MachineUpdateModule>);
        }

        let mut machine_update_metrics = MachineUpdateManagerMetrics::new();
        machine_update_metrics.register_callbacks(&meter);

        if let Some(host_firmware) =
            HostFirmwareUpdate::new(config.clone(), meter.clone(), config.get_firmware_config())
        {
            update_modules.push(Box::new(host_firmware));
        }

        MachineUpdateManager {
            database_connection,
            max_concurrent_machine_updates: config.max_concurrent_machine_updates(),
            run_interval: Duration::from_secs(config.machine_update_run_interval.unwrap_or(300)),
            update_modules,
            metrics: Some(machine_update_metrics),
            host_health: config.host_health,
            work_lock_manager_handle,
        }
    }

    /// Start the MachineUpdateManager and return a [sending channel](tokio::sync::oneshot::Sender) that will stop the MachineUpdateManager when dropped.
    pub fn start(self) -> eyre::Result<oneshot::Sender<i32>> {
        let (stop_sender, stop_receiver) = oneshot::channel();

        if !self.update_modules.is_empty() {
            tokio::task::Builder::new()
                .name("machine_update_manager")
                .spawn(async move { self.run(stop_receiver).await })?;
        } else {
            tracing::info!("No modules configured.  Machine updates disabled");
        }
        Ok(stop_sender)
    }

    async fn run(&self, mut stop_receiver: oneshot::Receiver<i32>) {
        loop {
            if let Err(e) = self.run_single_iteration().await {
                tracing::warn!("MachineUpdateManager error: {}", e);
            }

            tokio::select! {
                _ = tokio::time::sleep(self.run_interval) => {},
                _ = &mut stop_receiver => {
                    tracing::info!("Machine update manager stop was requested");
                    return;
                }
            }
        }
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
                include_instance_data: false,
                host_health_config: self.host_health,
            },
        )
        .await
        .map_err(Into::into)
    }

    pub async fn run_single_iteration(&self) -> CarbideResult<()> {
        let mut updates_started_count = 0;

        let _lock = match self
            .work_lock_manager_handle
            .try_acquire_lock(Self::ITERATION_WORK_KEY.into())
            .await
        {
            Ok(lock) => lock,
            Err(e) => {
                tracing::warn!(
                    "MachineUpdateManager failed to acquire work lock: Another instance of carbide running? {e}"
                );
                return Ok(());
            }
        };

        tracing::trace!(
            lock = MachineUpdateManager::ITERATION_WORK_KEY,
            "Machine update manager acquired the lock",
        );

        let mut txn = Transaction::begin(&self.database_connection).await?;

        for update_module in self.update_modules.iter() {
            update_module.clear_completed_updates(&mut txn).await?;
        }

        // current host machines in maintenance
        let mut current_updating_machines: HashSet<MachineId> =
            MachineUpdateManager::get_updating_machines(&mut txn).await?;

        for update_module in self.update_modules.iter() {
            current_updating_machines = update_module
                .get_updates_in_progress(&mut txn)
                .await?
                .union(&current_updating_machines)
                .copied()
                .collect();
        }

        let snapshots = self.get_all_snapshots(&mut txn).await?;

        let (all_count, unhealthy_count) =
            db::machine::count_healthy_unhealthy_host_machines(&snapshots);
        let max_concurrent_updates = self
            .max_concurrent_machine_updates
            .max_concurrent_updates(all_count, unhealthy_count)
            .unwrap_or(MachineUpdateManager::DEFAULT_MAX_CONCURRENT_MACHINE_UPDATES); // XXX
        for update_module in self.update_modules.iter() {
            if (current_updating_machines.len() as i32) >= max_concurrent_updates {
                break;
            }
            tracing::debug!("in progress: {:?}", current_updating_machines);
            let available_updates = max_concurrent_updates - current_updating_machines.len() as i32;

            let updates_started = update_module
                .start_updates(
                    &mut txn,
                    available_updates,
                    &current_updating_machines,
                    &snapshots,
                )
                .await?;
            tracing::debug!("started: {:?}", updates_started);

            updates_started_count += updates_started.len();

            current_updating_machines = current_updating_machines
                .union(&updates_started)
                .copied()
                .collect();
        }
        let current_updating_count = current_updating_machines.len();

        //refresh snapshots for metrics
        let snapshots = self.get_all_snapshots(&mut txn).await?;

        for update_module in self.update_modules.iter() {
            update_module.update_metrics(&mut txn, &snapshots).await;
        }

        txn.commit().await?;

        if let Some(metrics) = self.metrics.as_ref() {
            metrics
                .machine_updates_started
                .store(updates_started_count as u64, Ordering::Relaxed);
            metrics
                .machines_in_maintenance
                .store(current_updating_count as u64, Ordering::Relaxed);
            metrics
                .concurrent_machine_updates_available
                .store(max_concurrent_updates as u64, Ordering::Relaxed);
        }

        Ok(())
    }

    /// Removes all markers from a Host that are used to indicate that updates are applied
    /// This includes
    /// - A Health Override
    pub async fn remove_machine_update_markers(
        txn: &mut PgConnection,
        machine_update: &DpuMachineUpdate,
    ) -> CarbideResult<()> {
        db::machine::remove_health_report_override(
            txn,
            &machine_update.host_machine_id,
            health_report::OverrideMode::Merge,
            HOST_UPDATE_HEALTH_REPORT_SOURCE,
        )
        .await?;

        Ok(())
    }

    /// get host machines that are applying updates
    pub async fn get_updating_machines(
        txn: &mut PgConnection,
    ) -> Result<HashSet<MachineId>, DatabaseError> {
        let machines = db::machine::find(
            txn,
            ObjectFilter::All,
            MachineSearchConfig {
                include_predicted_host: true,
                ..Default::default()
            },
        )
        .await?;

        Ok(machines
            .into_iter()
            .filter_map(|m| {
                if !m.is_dpu() && m.machine_updates_in_progress() {
                    Some(m.id)
                } else {
                    None
                }
            })
            .collect())
    }
}
