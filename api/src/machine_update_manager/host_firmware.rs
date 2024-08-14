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
    db::{
        explored_endpoints::DbExploredEndpoint,
        host_machine_update::HostMachineUpdate,
        machine::{Machine, MachineSearchConfig},
        machine_topology::MachineTopology,
    },
    model::machine::machine_id::MachineId,
    CarbideResult,
};
use async_trait::async_trait;
use opentelemetry::metrics::{ObservableGauge, Observer};
use sqlx::{Postgres, Transaction};
use std::{
    any::Any,
    collections::HashSet,
    fmt,
    sync::{Arc, Mutex},
};

pub struct HostFirmwareUpdate {
    pub metrics: Option<Arc<Mutex<HostFirmwareUpdateMetrics>>>,
    config: Arc<CarbideConfig>,
    firmware_config: FirmwareConfig,
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
        match HostMachineUpdate::find_upgrade_needed(txn).await {
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

        let metrics = Arc::new(Mutex::new(HostFirmwareUpdateMetrics::new(meter.clone())));
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
        // TODO: We would like this to pare down the results in the query itself, FORGE-3870
        for endpoint in DbExploredEndpoint::find_all(txn).await? {
            // Async functions in a closure is messy, so no iter().filter_map() here.
            if available_updates == 0 {
                return Ok(machines);
            };
            let Some(vendor) = endpoint.report.vendor else {
                continue;
            };
            let Some(model) = endpoint.report.model() else {
                continue;
            };
            let Some(host_info) = self.firmware_config.find(vendor, model) else {
                continue;
            };

            for (component, current_version) in endpoint.report.versions {
                if let Some(desired) = host_info.components.get(&component) {
                    if let Some(desired) = desired.known_firmware.iter().find(|x| x.default) {
                        if desired.version != current_version {
                            tracing::debug!(
                                "machine_update_manager: Host {:?} has {:?} version {} desired {}",
                                endpoint.address,
                                component,
                                current_version,
                                desired.version,
                            );
                            // Machines do not have their BMC IPs directly listed, we need machine topology
                            let Some(machine_id) = MachineTopology::find_machine_id_by_bmc_ip(
                                txn,
                                endpoint.address.to_string().as_str(),
                            )
                            .await?
                            else {
                                // Should generally not happen, but if we somehow lost info about the host we shouldn't be messing with it.
                                break;
                            };
                            if !firmware_updates_enabled(txn, &self.config, &machine_id).await? {
                                break;
                            }
                            available_updates -= 1;
                            machines.push(machine_id);
                            break;
                        }
                    }
                }
            }
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

/// firmware_update_enabled detrmines if firmware updates are enabled for this specific machine.  Database setting has top priority, then configuration file setting, then global.
async fn firmware_updates_enabled(
    txn: &mut Transaction<'_, Postgres>,
    config: &CarbideConfig,
    machine_id: &MachineId,
) -> CarbideResult<bool> {
    let Some(machine) = Machine::find_one(txn, machine_id, MachineSearchConfig::default()).await?
    else {
        // Machine is missing?  Best do nothing.
        return Ok(false);
    };

    if let Some(setting) = machine.firmware_autoupdate() {
        // Specified in DB
        return Ok(setting);
    }

    let machine_id_string = machine_id.to_string();

    if config
        .firmware_global
        .host_disable_autoupdate
        .iter()
        .any(|x| **x == machine_id_string)
    {
        // Explicitly disabled in config file
        return Ok(false);
    }
    if config
        .firmware_global
        .host_enable_autoupdate
        .iter()
        .any(|x| **x == machine_id_string)
    {
        // Explicitly enabled in config file
        return Ok(true);
    }

    // Use the global
    Ok(config.firmware_global.autoupdate)
}
