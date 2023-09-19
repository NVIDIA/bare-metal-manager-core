use std::fmt;

use async_trait::async_trait;
use sqlx::{Postgres, Transaction};

use crate::{
    db::{
        dpu_machine_update::DpuMachineUpdate,
        machine::{Machine, MachineSearchConfig},
    },
    machine_update_manager::MachineUpdateManager,
    CarbideResult,
};

use super::machine_update_module::MachineUpdateModule;

pub struct DpuNicFirmwareUpdate {
    pub expected_dpu_firmware_version: String,
}

#[async_trait]
impl MachineUpdateModule for DpuNicFirmwareUpdate {
    async fn get_updates_in_progress_count(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<i32> {
        // Note: this includes any machines that are reprovisioning, even if they
        // are user triggered.
        let current_updating_count = match DpuMachineUpdate::get_reprovisioning_count(txn).await {
            Ok(current_updating_count) => current_updating_count,
            Err(e) => {
                tracing::warn!("Error getting outstanding reprovisioning count: {}", e);
                0
            }
        };

        Ok(current_updating_count)
    }

    async fn start_updates(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        available_updates: i32,
    ) -> i32 {
        let machine_updates = self.check_for_updates(txn, available_updates).await;
        let mut updates_started = 0;
        for machine_update in machine_updates {
            tracing::trace!(
                "dpu_machine_id: {} current_firmware_version: {}",
                machine_update.dpu_machine_id,
                machine_update.firmware_version
            );

            let reference: String = format!(
                "Automatic dpu firmware update from '{}' to '{}'",
                machine_update.firmware_version, self.expected_dpu_firmware_version
            );

            if let Err(e) =
                MachineUpdateManager::put_machine_in_maintenance(txn, &machine_update, &reference)
                    .await
            {
                tracing::warn!(
                machine_id=%machine_update.dpu_machine_id,
                "Failed to put machine into maintenance: {}", e);
                continue;
            }

            match Machine::find_one(
                txn,
                &machine_update.dpu_machine_id,
                MachineSearchConfig::default(),
            )
            .await
            {
                Ok(machine) => match machine {
                    Some(machine) => {
                        if let Err(e) = machine
                            .trigger_reprovisioning_request(
                                txn,
                                "Automatic dpu firmware update",
                                true,
                            )
                            .await
                        {
                            tracing::warn!(
                        machine_id=%machine_update.dpu_machine_id,
                        "Failed to trigger reprovisioning: {}", e);
                            continue;
                        }
                        updates_started += 1;
                    }
                    None => {
                        tracing::warn!(
                        machine_id=%machine_update.dpu_machine_id,
                        "Failed to trigger reprovisioning.  No machine found");
                        continue;
                    }
                },
                Err(e) => {
                    tracing::warn!(
                    machine_id=%machine_update.dpu_machine_id,
                    "Failed to put machine into maintenance: {}", e);
                    continue;
                }
            }
        }
        updates_started
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
            available_updates,
        )
        .await
        {
            // TODO! stash the machine updates somewhere
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
