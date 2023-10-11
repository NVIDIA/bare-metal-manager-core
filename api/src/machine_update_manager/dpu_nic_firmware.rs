use std::{
    collections::HashSet,
    fmt,
    sync::{Arc, Mutex},
};

use crate::{
    cfg::CarbideConfig, db::dpu_machine_update::DpuMachineUpdate,
    machine_update_manager::MachineUpdateManager, model::machine::machine_id::MachineId,
    CarbideError, CarbideResult,
};
use async_trait::async_trait;
use sqlx::{Postgres, Transaction};

use super::dpu_nic_firmware_metrics::DpuNicFirmwareUpdateMetrics;
use super::machine_update_module::MachineUpdateModule;

/// DpuNicFirmwareUpdate is a module used [MachineUpdateManager](crate::machine_update_manager::MachineUpdateManager)
/// to ensure that DPU NIC firmware matches the expected version of the carbide release.
///
/// Config used from [CarbideConfig](crate::cfg::CarbideConfig)
/// * `dpu_nic_firmware_update_version` the version of the DPU NIC firmware that is expected to be running on the DPU.
///
/// Note that if the version does not match in either direction, the DPU will be updated.

pub struct DpuNicFirmwareUpdate {
    pub expected_dpu_firmware_version: String,
    pub metrics: Option<Arc<Mutex<DpuNicFirmwareUpdateMetrics>>>,
}

#[async_trait]
impl MachineUpdateModule for DpuNicFirmwareUpdate {
    fn new(config: Arc<CarbideConfig>, meter: opentelemetry::metrics::Meter) -> Option<Self>
    where
        Self: Sized,
    {
        if let Some(expected_dpu_firmware_version) = config.dpu_nic_firmware_update_version.as_ref()
        {
            let metrics = Arc::new(Mutex::new(DpuNicFirmwareUpdateMetrics::new(meter.clone())));
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

            Some(DpuNicFirmwareUpdate {
                expected_dpu_firmware_version: expected_dpu_firmware_version.clone(),
                metrics: Some(metrics),
            })
        } else {
            None
        }
    }

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
        let mut updates_started = HashSet::default();

        for machine_update in machine_updates.iter() {
            tracing::trace!(
                "dpu_machine_id: {} current_firmware_version: {}",
                machine_update.dpu_machine_id,
                machine_update.firmware_version
            );

            if updating_host_machines.contains(&machine_update.host_machine_id) {
                continue;
            }

            let updated_machines = DpuMachineUpdate::trigger_reprovisioning_for_managed_host(
                txn,
                machine_update,
                self.expected_dpu_firmware_version.clone(),
            )
            .await?;

            if updated_machines.len() != 2 {
                return Err(CarbideError::GenericError(format!("Unexpected update result from trigger_reprovisioning_for_managed_host: updated_machines={:?}", updated_machines)));
            }

            updates_started.insert(machine_update.host_machine_id.clone());
        }

        self.update_metrics(txn).await;

        Ok(updates_started)
    }

    async fn clear_completed_updates(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<()> {
        let updated_machines = DpuMachineUpdate::get_updated_machines(txn).await?;
        tracing::info!("found {} update machines", updated_machines.len());
        for updated_machine in updated_machines {
            if updated_machine.firmware_version == self.expected_dpu_firmware_version {
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
        }
        Ok(())
    }
}

impl DpuNicFirmwareUpdate {
    pub async fn check_for_updates(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        available_updates: i32,
    ) -> Vec<DpuMachineUpdate> {
        match DpuMachineUpdate::find_outdated_dpus(
            txn,
            &self.expected_dpu_firmware_version,
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

    pub async fn update_metrics(&self, txn: &mut Transaction<'_, Postgres>) {
        match DpuMachineUpdate::find_outdated_dpus(txn, &self.expected_dpu_firmware_version, None)
            .await
        {
            Ok(outdated_dpus) => {
                if let Some(metrics) = &self.metrics {
                    if let Ok(mut metrics) = metrics.lock() {
                        metrics.pending_firmware_updates = outdated_dpus.len();
                    }
                }
            }
            Err(e) => tracing::warn!("Error geting outdated dpus for metrics: {}", e),
        }
    }
}

impl fmt::Display for DpuNicFirmwareUpdate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DpuNicFirmwareUpdate")
    }
}
