use crate::{
    cfg::CarbideConfig, db::dpu_machine_update::DpuMachineUpdate,
    machine_update_manager::MachineUpdateManager, CarbideError, CarbideResult,
};
use async_trait::async_trait;
use sqlx::{Postgres, Transaction};
use std::sync::atomic::Ordering;
use std::{
    collections::{HashMap, HashSet},
    fmt,
    sync::Arc,
};

use super::dpu_nic_firmware_metrics::DpuNicFirmwareUpdateMetrics;
use super::machine_update_module::MachineUpdateModule;
use forge_uuid::machine::MachineId;

/// DpuNicFirmwareUpdate is a module used [MachineUpdateManager](crate::machine_update_manager::MachineUpdateManager)
/// to ensure that DPU NIC firmware matches the expected version of the carbide release.
///
/// Config used from [CarbideConfig](crate::cfg::CarbideConfig)
/// * `dpu_nic_firmware_update_version` the version of the DPU NIC firmware that is expected to be running on the DPU.
///
/// Note that if the version does not match in either direction, the DPU will be updated.

pub struct DpuNicFirmwareUpdate {
    pub expected_dpu_firmware_versions: HashMap<String, String>,
    pub metrics: Option<DpuNicFirmwareUpdateMetrics>,
}

#[async_trait]
impl MachineUpdateModule for DpuNicFirmwareUpdate {
    async fn get_updates_in_progress(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<HashSet<MachineId>> {
        let current_updating_machines =
            match DpuMachineUpdate::get_reprovisioning_machines(txn).await {
                Ok(current_updating_machines) => current_updating_machines,
                Err(e) => {
                    tracing::warn!("Error getting outstanding reprovisioning count: {}", e);
                    vec![]
                }
            };

        Ok(current_updating_machines
            .iter()
            .map(|mu| mu.host_machine_id.clone())
            .collect())
    }

    async fn start_updates(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        available_updates: i32,
        updating_host_machines: &HashSet<MachineId>,
    ) -> CarbideResult<HashSet<MachineId>> {
        let machine_updates: Vec<DpuMachineUpdate> = self
            .check_for_updates(txn, available_updates)
            .await
            .into_iter()
            .filter(|u| updating_host_machines.get(&u.host_machine_id).is_none())
            .collect();

        // The outcome is vec<DpuMachineUpdate>, let's convert it to HashMap<host_machine_id, vec<DpuMachineUpdate>>
        // This way we can run our loop based on host_machine id.
        let mut host_machine_updates: HashMap<MachineId, Vec<DpuMachineUpdate>> = HashMap::new();

        for machine_update in machine_updates {
            host_machine_updates
                .entry(machine_update.host_machine_id.clone())
                .or_default()
                .push(machine_update);
        }

        let mut updates_started = HashSet::default();

        for (host_machine_id, machine_updates) in host_machine_updates {
            if updating_host_machines.contains(&host_machine_id) {
                continue;
            }

            // If the reprovisioning failed to update the database for a
            // given {dpu,host}_machine_id, log it as a warning and don't
            // add it to updates_started.
            if let Err(reprovisioning_err) =
                DpuMachineUpdate::trigger_reprovisioning_for_managed_host(
                    txn,
                    &host_machine_id,
                    &machine_updates,
                    self.expected_dpu_firmware_versions.clone(),
                )
                .await
            {
                match reprovisioning_err {
                    CarbideError::NotFoundError { id, .. } => {
                        tracing::warn!("failed to trigger reprovisioning for managed host : {} - no update match for id: {}",
                        host_machine_id,
                        id);
                        continue;
                    }
                    _ => {
                        return Err(reprovisioning_err);
                    }
                }
            }

            updates_started.insert(host_machine_id);
        }

        self.update_metrics(txn).await;

        Ok(updates_started)
    }

    async fn clear_completed_updates(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<()> {
        let updated_machines = DpuMachineUpdate::get_updated_machines(txn).await?;
        tracing::debug!("found {} updated machines", updated_machines.len());
        for updated_machine in updated_machines {
            if let Some(expected_dpu_firmware_version) = self
                .expected_dpu_firmware_versions
                .get(&updated_machine.product_name)
            {
                if &updated_machine.firmware_version == expected_dpu_firmware_version {
                    if let Err(e) =
                        MachineUpdateManager::remove_machine_from_maintenance(txn, &updated_machine)
                            .await
                    {
                        tracing::warn!(
                            machine_id = %updated_machine.dpu_machine_id,
                            "Failed to remove machine from maintenance: {}", e
                        );
                    }
                } else {
                    tracing::warn!(
                        machine_id = %updated_machine.dpu_machine_id,
                        firmware_version = %updated_machine.firmware_version,
                        "Incorrect firmware version after attempted update"
                    );
                }
            } else {
                tracing::warn!(
                    "Missing expected firmware version for product {}",
                    updated_machine.product_name,
                );
            }
        }
        Ok(())
    }

    async fn update_metrics(&self, txn: &mut Transaction<'_, Postgres>) {
        match DpuMachineUpdate::find_available_outdated_dpus(
            txn,
            &self.expected_dpu_firmware_versions,
            None,
        )
        .await
        {
            Ok(outdated_dpus) => {
                if let Some(metrics) = &self.metrics {
                    metrics
                        .pending_firmware_updates
                        .store(outdated_dpus.len() as u64, Ordering::Relaxed);
                }
            }
            Err(e) => tracing::warn!(error=%e, "Error geting outdated dpus for metrics"),
        }

        match DpuMachineUpdate::find_unavailable_outdated_dpus(
            txn,
            &self.expected_dpu_firmware_versions,
        )
        .await
        {
            Ok(outdated_dpus) => {
                if let Some(metrics) = &self.metrics {
                    metrics
                        .unavailable_dpu_updates
                        .store(outdated_dpus.len() as u64, Ordering::Relaxed);
                }
            }
            Err(e) => tracing::warn!(
                error=%e,
                "Error geting outdated and unavailable dpus for metrics",
            ),
        }

        match DpuMachineUpdate::get_fw_updates_running_count(txn).await {
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
        if !config.dpu_nic_firmware_reprovision_update_enabled {
            return None;
        }

        if let Some(expected_dpu_firmware_version) = config.dpu_nic_firmware_update_version.as_ref()
        {
            let mut metrics = DpuNicFirmwareUpdateMetrics::new();
            metrics.register_callbacks(&meter);
            Some(DpuNicFirmwareUpdate {
                expected_dpu_firmware_versions: expected_dpu_firmware_version.clone(),
                metrics: Some(metrics),
            })
        } else {
            None
        }
    }

    pub async fn check_for_updates(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        available_updates: i32,
    ) -> Vec<DpuMachineUpdate> {
        match DpuMachineUpdate::find_available_outdated_dpus(
            txn,
            &self.expected_dpu_firmware_versions,
            Some(available_updates),
        )
        .await
        {
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
