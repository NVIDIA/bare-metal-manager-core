/*
 * SPDX-FileCopyrightText: Copyright (c) 2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use super::machine_update_module::MachineUpdateModule;
use crate::{
    cfg::{CarbideConfig, FirmwareConfig},
    db::{desired_firmware, host_machine_update::HostMachineUpdate, machine::Machine},
    model::machine::machine_id::MachineId,
    CarbideResult,
};
use async_trait::async_trait;
use opentelemetry::metrics::{ObservableGauge, Observer};
use sqlx::{Postgres, Transaction};
use std::{any::Any, collections::HashSet, fmt, sync::Arc};
use tokio::sync::Mutex;

pub struct HostFirmwareUpdate {
    pub metrics: Option<Arc<std::sync::Mutex<HostFirmwareUpdateMetrics>>>,
    config: Arc<CarbideConfig>,
    firmware_config: FirmwareConfig,
    desired_firmware_set: Arc<Mutex<bool>>,
}

#[async_trait]
impl MachineUpdateModule for HostFirmwareUpdate {
    async fn get_updates_in_progress(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<HashSet<MachineId>> {
        let current_updating_machines = Machine::get_host_reprovisioning_machines(txn).await?;

        Ok(current_updating_machines
            .iter()
            .map(|m| m.id().clone())
            .collect())
    }

    async fn start_updates(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        available_updates: i32,
        updating_host_machines: &HashSet<MachineId>,
    ) -> CarbideResult<HashSet<MachineId>> {
        let mut desired_firmware_set = self.desired_firmware_set.lock().await;
        if !*desired_firmware_set {
            // Save the firmware config in an SQL table so that we can filter for hosts with non-matching firmware there.
            desired_firmware::snapshot_desired_firmware(txn, &self.firmware_config).await?;
            *desired_firmware_set = true;
        }
        drop(desired_firmware_set);

        let machine_updates = self.check_for_updates(txn, available_updates).await?;
        let mut updates_started = HashSet::default();
        if let Some(metrics) = &self.metrics {
            if let Ok(mut metrics) = metrics.lock() {
                metrics.pending_firmware_updates = machine_updates.len();
            }
        }

        for machine_update in machine_updates.iter() {
            if updating_host_machines.contains(machine_update) {
                continue;
            }

            tracing::debug!("Moving {} to host reprovision", machine_update);

            Machine::trigger_host_reprovisioning_request(txn, machine_update).await?;

            updates_started.insert(machine_update.clone());
        }

        self.update_metrics(txn).await;
        Ok(updates_started)
    }

    async fn clear_completed_updates(
        &self,
        _txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<()> {
        // This functionality doesn't match what we do with hosts and is unused for host_firmware.
        Ok(())
    }

    async fn update_metrics(&self, txn: &mut Transaction<'_, Postgres>) {
        match HostMachineUpdate::find_upgrade_needed(txn, self.config.firmware_global.autoupdate)
            .await
        {
            Ok(upgrade_needed) => {
                if let Some(metrics) = &self.metrics {
                    if let Ok(mut metrics) = metrics.lock() {
                        metrics.pending_firmware_updates = upgrade_needed.len();
                    }
                }
            }
            Err(e) => tracing::warn!(error=%e, "Error geting host upgrade needed for metrics"),
        };
        match HostMachineUpdate::find_upgrade_in_progress(txn).await {
            Ok(upgrade_in_progress) => {
                if let Some(metrics) = &self.metrics {
                    if let Ok(mut metrics) = metrics.lock() {
                        metrics.active_firmware_updates = upgrade_in_progress.len();
                    }
                }
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
        let config = config.clone();

        let metrics = Arc::new(std::sync::Mutex::new(HostFirmwareUpdateMetrics::new(
            meter.clone(),
        )));
        let metrics_clone = metrics.clone();
        if let Ok(locked_metrics) = metrics.lock() {
            if let Err(e) =
                meter.register_callback(&locked_metrics.instruments(), move |observer| {
                    if let Ok(mut locked_metrics_clone) = metrics_clone.lock() {
                        locked_metrics_clone.observe(observer);
                    }
                })
            {
                tracing::warn!(
                    "Failed to register metrics callback for DpuNicFirmwareUpdate: {}",
                    e
                );
            }
        }

        Some(Self {
            firmware_config,
            config,
            metrics: Some(metrics),
            desired_firmware_set: Arc::new(Mutex::new(false)),
        })
    }

    pub async fn check_for_updates(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        mut available_updates: i32,
    ) -> CarbideResult<Vec<MachineId>> {
        let mut machines = vec![];
        if available_updates == 0 {
            return Ok(machines);
        };
        // find_upgrade_needed filters for just things that need upgrades
        for update_needed in
            HostMachineUpdate::find_upgrade_needed(txn, self.config.firmware_global.autoupdate)
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
    pub pending_firmware_updates: usize,
    pub active_firmware_updates: usize,

    pub pending_firmware_updates_gauge: ObservableGauge<u64>,
    pub active_firmware_updates_gauge: ObservableGauge<u64>,
}

impl HostFirmwareUpdateMetrics {
    pub fn new(meter: opentelemetry::metrics::Meter) -> Self {
        HostFirmwareUpdateMetrics {
            pending_firmware_updates: 0,
            pending_firmware_updates_gauge: meter
                .u64_observable_gauge("forge_pending_host_firmware_update_count")
                .with_description(
                    "The number of host machines in the system that need a firmware update.",
                )
                .init(),
                active_firmware_updates: 0,
                active_firmware_updates_gauge: meter
                .u64_observable_gauge("forge_active_host_firmware_update_count")
                .with_description(
                    "The number of host machines in the system currently working on updating their firmware.",
                )
                .init(),
        }
    }

    pub fn instruments(&self) -> Vec<Arc<dyn Any>> {
        vec![
            self.pending_firmware_updates_gauge.as_any(),
            self.active_firmware_updates_gauge.as_any(),
        ]
    }

    pub fn observe(&mut self, observer: &dyn Observer) {
        observer.observe_u64(
            &self.pending_firmware_updates_gauge,
            self.pending_firmware_updates as u64,
            &[],
        );
        observer.observe_u64(
            &self.active_firmware_updates_gauge,
            self.active_firmware_updates as u64,
            &[],
        );
    }
}
