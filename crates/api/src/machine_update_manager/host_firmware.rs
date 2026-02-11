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

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use async_trait::async_trait;
use carbide_uuid::machine::MachineId;
use db::{self, desired_firmware};
use model::machine::ManagedHostStateSnapshot;
use model::machine_update_module::HOST_FW_UPDATE_HEALTH_REPORT_SOURCE;
use opentelemetry::metrics::Meter;
use sqlx::PgConnection;
use tokio::sync::Mutex;

use super::machine_update_module::MachineUpdateModule;
use crate::CarbideResult;
use crate::cfg::file::{CarbideConfig, FirmwareConfig};

pub struct HostFirmwareUpdate {
    pub metrics: HostFirmwareUpdateMetrics,
    config: Arc<CarbideConfig>,
    firmware_config: FirmwareConfig,
    firmware_dir_last_read: Arc<Mutex<Option<std::time::SystemTime>>>,
}

#[async_trait]
impl MachineUpdateModule for HostFirmwareUpdate {
    async fn get_updates_in_progress(
        &self,
        txn: &mut PgConnection,
    ) -> CarbideResult<HashSet<MachineId>> {
        let current_updating_machines = db::machine::get_host_reprovisioning_machines(txn).await?;

        Ok(current_updating_machines.iter().map(|m| m.id).collect())
    }

    async fn start_updates(
        &self,
        txn: &mut PgConnection,
        available_updates: i32,
        updating_host_machines: &HashSet<MachineId>,
        _snapshots: &HashMap<MachineId, ManagedHostStateSnapshot>,
    ) -> CarbideResult<HashSet<MachineId>> {
        if let Ok(mut firmware_dir_last_read) = self.firmware_dir_last_read.try_lock() {
            let firmware_dir_mod_time = self.firmware_config.config_update_time();
            if (firmware_dir_mod_time.is_none() && firmware_dir_last_read.is_none()) // Not using an auto firmware directory, one and done
                || (firmware_dir_mod_time.is_some_and(|firmware_dir_mod_time| {
                firmware_dir_last_read.unwrap_or(std::time::SystemTime::UNIX_EPOCH)
                    < firmware_dir_mod_time // Using an auto firmware directory, and a new file has been created or this is the first run
            })) {
                // Save the firmware config in an SQL table so that we can filter for hosts with non-matching firmware there.
                tracing::info!("Firmware config now: {:?}", self.firmware_config.map());
                let models = self.firmware_config.map().into_values().collect::<Vec<_>>();
                desired_firmware::snapshot_desired_firmware(txn, &models).await?;
                *firmware_dir_last_read =
                    Some(firmware_dir_mod_time.unwrap_or(std::time::SystemTime::now()));
            }
        }

        let machine_updates = self.check_for_updates(txn, available_updates).await?;
        let mut updates_started = HashSet::default();
        self.metrics
            .pending_firmware_updates
            .store(machine_updates.len() as u64, Ordering::Relaxed);

        for machine_update in machine_updates.iter() {
            if updating_host_machines.contains(machine_update) {
                continue;
            }

            tracing::info!("Moving {} to host reprovision", machine_update);

            db::host_machine_update::trigger_host_reprovisioning_request(
                txn,
                "Automated",
                machine_update,
            )
            .await?;

            updates_started.insert(*machine_update);
        }

        Ok(updates_started)
    }

    async fn clear_completed_updates(&self, txn: &mut PgConnection) -> CarbideResult<()> {
        let completed = db::host_machine_update::find_completed_updates(txn).await?;

        if !completed.is_empty() {
            tracing::info!("Completed host firmware updates: {completed:?}");
            for machine in completed {
                db::machine::remove_health_report_override(
                    txn,
                    &machine,
                    health_report::OverrideMode::Merge,
                    HOST_FW_UPDATE_HEALTH_REPORT_SOURCE,
                )
                .await?;
                db::machine::update_update_complete(&machine, true, txn).await?;
            }
        }
        Ok(())
    }

    async fn update_metrics(
        &self,
        txn: &mut PgConnection,
        _snapshots: &HashMap<MachineId, ManagedHostStateSnapshot>,
    ) {
        match db::host_machine_update::find_upgrade_needed(
            txn,
            self.config.firmware_global.autoupdate,
            self.config.firmware_global.instance_updates_manual_tagging,
        )
        .await
        {
            Ok(upgrade_needed) => {
                self.metrics
                    .pending_firmware_updates
                    .store(upgrade_needed.len() as u64, Ordering::Relaxed);
            }
            Err(e) => tracing::warn!(error=%e, "Error geting host upgrade needed for metrics"),
        };
        match db::host_machine_update::find_upgrade_in_progress(txn).await {
            Ok(upgrade_in_progress) => {
                self.metrics
                    .active_firmware_updates
                    .store(upgrade_in_progress.len() as u64, Ordering::Relaxed);
            }
            Err(e) => tracing::warn!(error=%e, "Error geting host upgrade in progress for metrics"),
        };
    }
}

impl HostFirmwareUpdate {
    pub fn new(
        config: Arc<CarbideConfig>,
        meter: opentelemetry::metrics::Meter,
        firmware_config: FirmwareConfig,
    ) -> Option<Self> {
        tracing::info!("Using firmware configuration: {firmware_config:?}");

        let metrics = HostFirmwareUpdateMetrics::new();
        metrics.register_callbacks(&meter);

        Some(Self {
            firmware_config,
            config,
            metrics,
            firmware_dir_last_read: Arc::new(Mutex::new(None)),
        })
    }

    pub async fn check_for_updates(
        &self,
        txn: &mut PgConnection,
        mut available_updates: i32,
    ) -> CarbideResult<Vec<MachineId>> {
        let mut machines = vec![];
        if available_updates == 0 {
            return Ok(machines);
        };
        // find_upgrade_needed filters for just things that need upgrades
        for update_needed in db::host_machine_update::find_upgrade_needed(
            txn,
            self.config.firmware_global.autoupdate,
            self.config.firmware_global.instance_updates_manual_tagging,
        )
        .await?
        {
            if available_updates == 0 {
                return Ok(machines);
            };
            if self
                .config
                .firmware_global
                .host_disable_autoupdate
                .iter()
                .any(|x| **x == update_needed.id.to_string())
            {
                // This machine is specifically disabled
                break;
            }
            available_updates -= 1;
            machines.push(update_needed.id);
        }
        Ok(machines)
    }
}

impl fmt::Display for HostFirmwareUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HostFirmwareUpdate")
    }
}

pub struct HostFirmwareUpdateMetrics {
    pub pending_firmware_updates: Arc<AtomicU64>,
    pub active_firmware_updates: Arc<AtomicU64>,
}

impl HostFirmwareUpdateMetrics {
    pub fn new() -> Self {
        HostFirmwareUpdateMetrics {
            pending_firmware_updates: Arc::new(AtomicU64::new(0)),
            active_firmware_updates: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn register_callbacks(&self, meter: &Meter) {
        let pending_firmware_updates = self.pending_firmware_updates.clone();
        let active_firmware_updates = self.active_firmware_updates.clone();
        meter
            .u64_observable_gauge("carbide_pending_host_firmware_update_count")
            .with_description(
                "The number of host machines in the system that need a firmware update.",
            )
            .with_callback(move |observer| {
                observer.observe(pending_firmware_updates.load(Ordering::Relaxed), &[])
            })
            .build();
        meter
            .u64_observable_gauge("carbide_active_host_firmware_update_count")
            .with_description(
                "The number of host machines in the system currently working on updating their firmware.",
            )
            .with_callback(move |observer|
                observer.observe(active_firmware_updates.load(Ordering::Relaxed), &[]))
            .build();
    }
}
