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
pub mod machine_update_module;

use std::{sync::Arc, time::Duration};

use sqlx::{PgPool, Postgres, Transaction};
use tokio::sync::oneshot;

use crate::{
    cfg::CarbideConfig,
    db::{
        dpu_machine_update::DpuMachineUpdate,
        machine::{Machine, MaintenanceMode},
    },
    CarbideError, CarbideResult,
};

use self::{
    dpu_nic_firmware::DpuNicFirmwareUpdate,
    machine_update_module::{MachineUpdateModule, MaintenanceReference},
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
        }
    }

    /// Create a MachineUpdateManager with the default modules.
    pub fn new(database_connection: sqlx::PgPool, config: Arc<CarbideConfig>) -> Self {
        let mut update_modules = vec![];

        if let Some(dpu_nic_firmware_update_version) =
            config.dpu_nic_firmware_update_version.as_ref()
        {
            update_modules.push(Box::new(DpuNicFirmwareUpdate {
                expected_dpu_firmware_version: dpu_nic_firmware_update_version.clone(),
            }) as Box<dyn MachineUpdateModule>);
        }

        MachineUpdateManager {
            database_connection,
            max_concurrent_machine_updates: config
                .max_concurrent_machine_updates
                .unwrap_or(MachineUpdateManager::DEFAULT_MAX_CONCURRENT_MACHINE_UPDATES),
            run_interval: Duration::from_secs(config.machine_update_run_interval.unwrap_or(300)),
            update_modules,
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
            self.run_single_iteration().await;

            tokio::select! {
                _ = tokio::time::sleep(self.run_interval) => {},
                _ = &mut stop_receiver => {
                    tracing::info!("Machine update manager stop was requested");
                    return;
                }
            }
        }
    }

    pub async fn run_single_iteration(&self) {
        match self.database_connection.begin().await {
            Ok(mut txn) => {
                if sqlx::query_scalar(MachineUpdateManager::DB_LOCK_QUERY)
                    .fetch_one(&mut *txn)
                    .await
                    .unwrap_or(false)
                {
                    tracing::trace!(
                        lock = MachineUpdateManager::DB_LOCK_NAME,
                        "Machine update manager acquired the lock",
                    );

                    let mut current_updating_count = 0;
                    for update_module in self.update_modules.iter() {
                        match update_module.get_updates_in_progress_count(&mut txn).await {
                            Ok(module_update_count) => {
                                current_updating_count += module_update_count
                            }
                            Err(e) => {
                                tracing::warn!(
                                    "module {} failed checking for updates: {}",
                                    update_module,
                                    e
                                );
                                return;
                            }
                        }
                    }
                    let mut available_updates =
                        self.max_concurrent_machine_updates - current_updating_count;

                    if available_updates > 0 {
                        for update_module in self.update_modules.iter() {
                            let updates_started = update_module
                                .start_updates(&mut txn, available_updates)
                                .await;

                            available_updates -= updates_started;
                            if available_updates <= 0 {
                                break;
                            }
                        }
                    }
                }
                if let Err(e) = txn.commit().await {
                    tracing::warn!("Failed to commit database transaction: {}", e);
                }
            }
            Err(e) => {
                tracing::warn!("Failed to create database transaction: {}", e);
            }
        }
    }

    pub async fn put_machine_in_maintenance(
        txn: &mut Transaction<'_, Postgres>,
        machine_update: &DpuMachineUpdate,
        reference: &MaintenanceReference,
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
}
