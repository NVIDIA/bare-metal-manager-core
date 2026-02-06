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
use std::sync::atomic::Ordering;

use async_trait::async_trait;
use carbide_uuid::machine::MachineId;
use db::dpu_machine_update;
use model::dpu_machine_update::DpuMachineUpdate;
use model::machine::ManagedHostStateSnapshot;
use sqlx::PgConnection;

use super::dpu_nic_firmware_metrics::DpuNicFirmwareUpdateMetrics;
use super::machine_update_module::MachineUpdateModule;
use crate::cfg::file::CarbideConfig;
use crate::machine_update_manager::MachineUpdateManager;
use crate::{CarbideResult, DatabaseError};

/// DpuNicFirmwareUpdate is a module used [MachineUpdateManager](crate::machine_update_manager::MachineUpdateManager)
/// to ensure that DPU NIC firmware matches the expected version of the carbide release.
///
/// Config used from [CarbideConfig](crate::cfg::CarbideConfig)
/// * `dpu_nic_firmware_update_version` the version of the DPU NIC firmware that is expected to be running on the DPU.
///
/// Note that if the version does not match in either direction, the DPU will be updated.
pub struct DpuNicFirmwareUpdate {
    pub metrics: Option<DpuNicFirmwareUpdateMetrics>,
    pub config: Arc<CarbideConfig>,
}

#[async_trait]
impl MachineUpdateModule for DpuNicFirmwareUpdate {
    async fn get_updates_in_progress(
        &self,
        txn: &mut PgConnection,
    ) -> CarbideResult<HashSet<MachineId>> {
        let current_updating_machines =
            match dpu_machine_update::get_reprovisioning_machines(txn).await {
                Ok(current_updating_machines) => current_updating_machines,
                Err(e) => {
                    tracing::warn!("Error getting outstanding reprovisioning count: {}", e);
                    vec![]
                }
            };

        Ok(current_updating_machines
            .iter()
            .map(|mu| mu.host_machine_id)
            .collect())
    }

    async fn start_updates(
        &self,
        txn: &mut PgConnection,
        available_updates: i32,
        updating_host_machines: &HashSet<MachineId>,
        snapshots: &HashMap<MachineId, ManagedHostStateSnapshot>,
    ) -> CarbideResult<HashSet<MachineId>> {
        let machine_updates: Vec<DpuMachineUpdate> = self
            .check_for_updates(snapshots, available_updates)
            .into_iter()
            .filter(|u| updating_host_machines.get(&u.host_machine_id).is_none())
            .collect();

        // The outcome is vec<DpuMachineUpdate>, let's convert it to HashMap<host_machine_id, vec<DpuMachineUpdate>>
        // This way we can run our loop based on host_machine id.
        let mut host_machine_updates: HashMap<MachineId, Vec<DpuMachineUpdate>> = HashMap::new();

        for machine_update in machine_updates {
            host_machine_updates
                .entry(machine_update.host_machine_id)
                .or_default()
                .push(machine_update);
        }

        let mut updates_started = HashSet::default();

        for (host_machine_id, machine_updates) in host_machine_updates {
            if updating_host_machines.contains(&host_machine_id) {
                continue;
            }

            let dpu_update_string = machine_updates.iter().fold("".to_string(), |output, dpu| {
                output + format!("{} ({}) ", dpu.dpu_machine_id, dpu.firmware_version).as_str()
            });

            tracing::info!(
                "Starting DPU updates for host {}: {}",
                host_machine_id,
                dpu_update_string
            );
            // If the reprovisioning failed to update the database for a
            // given {dpu,host}_machine_id, log it as a warning and don't
            // add it to updates_started.
            if let Err(reprovisioning_err) =
                dpu_machine_update::trigger_reprovisioning_for_managed_host(txn, &machine_updates)
                    .await
            {
                match reprovisioning_err {
                    DatabaseError::NotFoundError { id, .. } => {
                        tracing::warn!(
                            "failed to trigger reprovisioning for managed host : {} - no update match for id: {}",
                            host_machine_id,
                            id
                        );
                        continue;
                    }
                    _ => {
                        return Err(reprovisioning_err.into());
                    }
                }
            }

            updates_started.insert(host_machine_id);
        }

        Ok(updates_started)
    }

    async fn clear_completed_updates(&self, txn: &mut PgConnection) -> CarbideResult<()> {
        let updated_machines =
            dpu_machine_update::get_updated_machines(txn, self.config.host_health).await?;
        tracing::debug!("found {} updated machines", updated_machines.len());
        for updated_machine in updated_machines {
            if self
                .config
                .dpu_config
                .dpu_nic_firmware_update_versions
                .contains(&updated_machine.firmware_version)
            {
                if let Err(e) =
                    MachineUpdateManager::remove_machine_update_markers(txn, &updated_machine).await
                {
                    tracing::warn!(
                        machine_id = %updated_machine.dpu_machine_id,
                        "Failed to remove machine update markers: {}", e
                    );
                }
            } else {
                tracing::warn!(
                    machine_id = %updated_machine.dpu_machine_id,
                    firmware_version = %updated_machine.firmware_version,
                    "Incorrect firmware version after attempted update"
                );
            }
        }
        Ok(())
    }

    async fn update_metrics(
        &self,
        txn: &mut PgConnection,
        snapshots: &HashMap<MachineId, ManagedHostStateSnapshot>,
    ) {
        match DpuMachineUpdate::find_available_outdated_dpus(
            None,
            &self.config.dpu_config.dpu_nic_firmware_update_versions,
            snapshots,
        ) {
            Ok(outdated_dpus) => {
                if let Some(metrics) = &self.metrics {
                    metrics
                        .pending_firmware_updates
                        .store(outdated_dpus.len() as u64, Ordering::Relaxed);
                }
            }
            Err(e) => tracing::warn!(error=%e, "Error geting outdated dpus for metrics"),
        }

        let outdated_dpus = DpuMachineUpdate::find_unavailable_outdated_dpus(
            &self.config.dpu_config.dpu_nic_firmware_update_versions,
            snapshots,
        );
        if let Some(metrics) = &self.metrics {
            metrics
                .unavailable_dpu_updates
                .store(outdated_dpus.len() as u64, Ordering::Relaxed);
        }

        match dpu_machine_update::get_fw_updates_running_count(txn).await {
            Ok(count) => {
                if let Some(metrics) = &self.metrics {
                    metrics
                        .running_dpu_updates
                        .store(count as u64, Ordering::Relaxed);
                }
            }
            Err(e) => tracing::warn!(
                error = %e,
                "Error getting running upgrade count for metrics",
            ),
        }
    }
}

impl DpuNicFirmwareUpdate {
    pub fn new(config: Arc<CarbideConfig>, meter: opentelemetry::metrics::Meter) -> Option<Self> {
        if !config
            .dpu_config
            .dpu_nic_firmware_reprovision_update_enabled
        {
            return None;
        }

        let mut metrics = DpuNicFirmwareUpdateMetrics::new();
        metrics.register_callbacks(&meter);
        Some(DpuNicFirmwareUpdate {
            metrics: Some(metrics),
            config,
        })
    }

    pub fn check_for_updates(
        &self,
        snapshots: &HashMap<MachineId, ManagedHostStateSnapshot>,
        available_updates: i32,
    ) -> Vec<DpuMachineUpdate> {
        match DpuMachineUpdate::find_available_outdated_dpus(
            Some(available_updates),
            &self.config.dpu_config.dpu_nic_firmware_update_versions,
            snapshots,
        ) {
            Ok(machine_updates) => machine_updates,
            Err(e) => {
                tracing::warn!("Failed to find machines needing updates: {}", e);
                vec![]
            }
        }
    }
}

impl fmt::Display for DpuNicFirmwareUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DpuNicFirmwareUpdate")
    }
}
