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
pub mod dpu_nic_firmware;
mod dpu_nic_firmware_metrics;
pub mod machine_update_module;
mod metrics;

use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    time::Duration,
};

use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::oneshot;

use crate::{
    cfg::CarbideConfig,
    db::{
        dpu_machine_update::DpuMachineUpdate,
        machine::{Machine, MachineSearchConfig, MaintenanceMode},
        DatabaseError, ObjectFilter,
    },
    model::machine::machine_id::MachineId,
    CarbideError, CarbideResult,
};

use self::{
    dpu_nic_firmware::DpuNicFirmwareUpdate,
    machine_update_module::{DpuReprovisionInitiator, MachineUpdateModule},
    metrics::MachineUpdateManagerMetrics,
};

/// The MachineUpdateManager periodically runs [modules](machine_update_module::MachineUpdateModule) to initiate upgrades of machine components.
/// On each iteration the MachineUpdateManager will:
/// 1. collect the number of outstanding updates from all modules.
/// 2. if there are less than the max allowed updates each module will be told to start updates until
/// the number of updates reaches the maximum allowed.
///
/// Config from [CarbideConfig]:
/// * `max_concurrent_machine_updates` the maximum number of updates allowed across all modules
/// * `machine_update_run_interval` how often the manager calls the modules to start updates
pub struct MachineUpdateManager {
    database_connection: PgPool,
    max_concurrent_machine_updates: i32,
    run_interval: Duration,
    update_modules: Vec<Box<dyn MachineUpdateModule>>,
    metrics: Option<Arc<Mutex<MachineUpdateManagerMetrics>>>,
}

impl MachineUpdateManager {
    const DB_LOCK_NAME: &'static str = "machine_update_lock";
    const DB_LOCK_QUERY: &'static str =
        "SELECT pg_try_advisory_xact_lock((SELECT 'machine_update_lock'::regclass::oid)::integer);";
    const DEFAULT_MAX_CONCURRENT_MACHINE_UPDATES: i32 = 0;

    /// create a MachineUpdateManager with provided modules, overridding the default.
    pub fn new_with_modules(
        database_connection: sqlx::PgPool,
        config: Arc<CarbideConfig>,
        modules: Vec<Box<dyn MachineUpdateModule>>,
    ) -> Self {
        MachineUpdateManager {
            database_connection,
            max_concurrent_machine_updates: config
                .max_concurrent_machine_updates
                .unwrap_or(MachineUpdateManager::DEFAULT_MAX_CONCURRENT_MACHINE_UPDATES),
            run_interval: Duration::from_secs(config.machine_update_run_interval.unwrap_or(300)),
            update_modules: modules,
            metrics: None,
        }
    }

    /// Create a MachineUpdateManager with the default modules.
    pub fn new(
        database_connection: sqlx::PgPool,
        config: Arc<CarbideConfig>,
        meter: opentelemetry::metrics::Meter,
    ) -> Self {
        let mut update_modules = vec![];

        if let Some(dpu_nic_firmware) = DpuNicFirmwareUpdate::new(config.clone(), meter.clone()) {
            update_modules.push(Box::new(dpu_nic_firmware) as Box<dyn MachineUpdateModule>);
        }

        let machine_update_metrics = Arc::new(Mutex::new(MachineUpdateManagerMetrics::new(&meter)));

        let instruments = if let Ok(machine_update_metrics) = machine_update_metrics.lock() {
            machine_update_metrics.instruments()
        } else {
            vec![]
        };

        let machine_update_metrics_clone = machine_update_metrics.clone();

        if let Err(e) = meter.register_callback(&instruments, move |observer| {
            if let Ok(mut machine_update_metrics) = machine_update_metrics_clone.lock() {
                machine_update_metrics.observe(observer);
            }
        }) {
            tracing::warn!(
                "Failed to register callback for machine update manager metrics: {}",
                e
            );
        }

        MachineUpdateManager {
            database_connection,
            max_concurrent_machine_updates: config
                .max_concurrent_machine_updates
                .unwrap_or(MachineUpdateManager::DEFAULT_MAX_CONCURRENT_MACHINE_UPDATES),
            run_interval: Duration::from_secs(config.machine_update_run_interval.unwrap_or(300)),
            update_modules,
            metrics: Some(machine_update_metrics),
        }
    }

    pub fn get_modules(&self) -> &Vec<Box<dyn MachineUpdateModule>> {
        &self.update_modules
    }

    /// Start the MachineUpdateManager and return a [sending channel](tokio::sync::oneshot::Sender) that will stop the MachineUpdateManager when dropped.
    pub fn start(self) -> oneshot::Sender<i32> {
        let (stop_sender, stop_receiver) = oneshot::channel();

        if !self.update_modules.is_empty() {
            tokio::spawn(async move { self.run(stop_receiver).await });
        } else {
            tracing::info!("No modules configured.  Machine updates disabled");
        }
        stop_sender
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

    pub async fn run_single_iteration(&self) -> CarbideResult<()> {
        let mut updates_started_count = 0;
        let mut current_updating_count = 0;

        let mut txn = self.database_connection.begin().await.map_err(|e| {
            CarbideError::GenericError(format!("Failed to create transaction: {e}"))
        })?;

        if sqlx::query_scalar(MachineUpdateManager::DB_LOCK_QUERY)
            .fetch_one(&mut *txn)
            .await
            .unwrap_or(false)
        {
            tracing::trace!(
                lock = MachineUpdateManager::DB_LOCK_NAME,
                "Machine update manager acquired the lock",
            );

            for update_module in self.update_modules.iter() {
                update_module.clear_completed_updates(&mut txn).await?;
            }

            // current host machines in maintenance
            let mut current_updating_machines =
                MachineUpdateManager::get_machines_in_maintenance(&mut txn).await?;

            for update_module in self.update_modules.iter() {
                current_updating_machines = update_module
                    .get_updates_in_progress(&mut txn)
                    .await?
                    .union(&current_updating_machines)
                    .cloned()
                    .collect();
            }

            for update_module in self.update_modules.iter() {
                if (current_updating_machines.len() as i32) >= self.max_concurrent_machine_updates {
                    break;
                }
                tracing::info!("in progress: {:?}", current_updating_machines);
                let available_updates =
                    self.max_concurrent_machine_updates - current_updating_machines.len() as i32;

                let updates_started = update_module
                    .start_updates(&mut txn, available_updates, &current_updating_machines)
                    .await?;

                tracing::info!("started: {:?}", updates_started);

                updates_started_count += updates_started.len();

                current_updating_machines = current_updating_machines
                    .union(&updates_started)
                    .cloned()
                    .collect();
            }
            current_updating_count = current_updating_machines.len();
            txn.commit().await.map_err(|e| {
                CarbideError::GenericError(format!("Failed to create transaction: {e}"))
            })?;
        }
        if let Some(metrics) = self.metrics.as_ref() {
            if let Ok(mut metrics) = metrics.lock() {
                metrics.machine_updates_started = updates_started_count;
                metrics.machines_in_maintenance = current_updating_count;
            }
        }

        Ok(())
    }

    pub async fn put_machine_in_maintenance(
        txn: &mut Transaction<'_, Postgres>,
        machine_update: &DpuMachineUpdate,
        reference: &DpuReprovisionInitiator,
    ) -> CarbideResult<()> {
        Machine::set_maintenance_mode(
            txn,
            &machine_update.host_machine_id,
            MaintenanceMode::On {
                reference: reference.to_string(),
            },
        )
        .await
        .map_err(CarbideError::from)?;

        Machine::set_maintenance_mode(
            txn,
            &machine_update.dpu_machine_id,
            MaintenanceMode::On {
                reference: reference.to_string(),
            },
        )
        .await
        .map_err(CarbideError::from)?;
        Ok(())
    }

    pub async fn remove_machine_from_maintenance(
        txn: &mut Transaction<'_, Postgres>,
        machine_update: &DpuMachineUpdate,
    ) -> CarbideResult<()> {
        Machine::set_maintenance_mode(txn, &machine_update.host_machine_id, MaintenanceMode::Off)
            .await
            .map_err(CarbideError::from)?;

        Machine::set_maintenance_mode(txn, &machine_update.dpu_machine_id, MaintenanceMode::Off)
            .await
            .map_err(CarbideError::from)?;
        Ok(())
    }

    /// get host machines in maintenance
    pub async fn get_machines_in_maintenance(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<HashSet<MachineId>, DatabaseError> {
        let machines = Machine::find(
            txn,
            ObjectFilter::All,
            MachineSearchConfig {
                include_history: false,
                only_maintenance: true,
            },
        )
        .await?;

        Ok(machines
            .into_iter()
            .filter(|m| !m.is_dpu())
            .map(|m| m.id().clone())
            .collect())
    }
}
