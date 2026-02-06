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
use std::collections::HashMap;

use carbide_uuid::machine::MachineId;
use casbin::error::ModelError;
use sqlx::FromRow;

use crate::machine::{ManagedHostState, ManagedHostStateSnapshot};

#[derive(Debug, FromRow)]
pub struct DpuMachineUpdate {
    pub host_machine_id: MachineId,
    pub dpu_machine_id: MachineId,
    pub firmware_version: String,
}

impl DpuMachineUpdate {
    /// Find DPUs and the corresponding host that needs to have its firmware updated.
    /// DPUs can be updated when:
    /// 1. the installed firmware does not match the expected firmware
    /// 2. the DPU is not marked for reprovisioning
    /// 3. the DPU is not marked for maintenance.
    /// 4. the Host is healthy (no pending health alert)
    /// 5. If all DPUs need upgrade, put all in queue. State machine supports upgrading multiple
    ///    DPUs of a managedhost.
    /// 6. If some of the DPUs for a managed host need upgrade, put them in queue.
    ///    6.1. Make sure none of the DPU is under reprovisioning while queuing a new DPU for a
    ///    managedhost. This is done by confirming that Host is not marked for updates
    ///
    pub fn find_available_outdated_dpus(
        limit: Option<i32>,
        dpu_nic_firmware_update_versions: &[String],
        snapshots: &HashMap<MachineId, ManagedHostStateSnapshot>,
    ) -> Result<Vec<DpuMachineUpdate>, ModelError> {
        if limit.is_some_and(|l| l <= 0) {
            return Ok(vec![]);
        }

        let outdated_dpus = Self::find_outdated_dpus(dpu_nic_firmware_update_versions, snapshots);

        let mut scheduled_host_updates = 0;
        let available_outdated_dpus: Vec<DpuMachineUpdate> = outdated_dpus
            .into_iter()
            .filter_map(|outdated_host| {
                // If the limit on scheduled host updates is reached, skip creating more
                if let Some(limit) = limit
                    && scheduled_host_updates >= limit
                {
                    return None;
                }
                if !outdated_host.is_available_for_updates() {
                    return None;
                }
                scheduled_host_updates += 1;
                Some(outdated_host.outdated_dpus)
            })
            .flatten()
            .collect();

        Ok(available_outdated_dpus)
    }

    pub fn find_unavailable_outdated_dpus(
        dpu_nic_firmware_update_versions: &[String],
        snapshots: &HashMap<MachineId, ManagedHostStateSnapshot>,
    ) -> Vec<DpuMachineUpdate> {
        let outdated_dpus = Self::find_outdated_dpus(dpu_nic_firmware_update_versions, snapshots);

        let unavailable_outdated_dpus: Vec<DpuMachineUpdate> = outdated_dpus
            .into_iter()
            .filter_map(|outdated_host| {
                if outdated_host.is_available_for_updates() {
                    return None;
                }
                Some(outdated_host.outdated_dpus)
            })
            .flatten()
            .collect();

        unavailable_outdated_dpus
    }

    pub fn find_outdated_dpus(
        dpu_nic_firmware_update_versions: &[String],
        snapshots: &HashMap<MachineId, ManagedHostStateSnapshot>,
    ) -> Vec<OutdatedHost> {
        snapshots
            .iter()
            .filter_map(|(machine_id, managed_host)| {
                let outdated_dpus: Vec<DpuMachineUpdate> = managed_host
                    .dpu_snapshots
                    .iter()
                    .filter_map(|dpu| {
                        let firmware_version = dpu
                            .hardware_info
                            .as_ref()
                            .and_then(|info| info.dpu_info.as_ref())
                            .map(|dpu_info| dpu_info.firmware_version.trim().to_owned())?;

                        if dpu_nic_firmware_update_versions.contains(&firmware_version) {
                            return None;
                        }

                        Some(DpuMachineUpdate {
                            host_machine_id: *machine_id,
                            dpu_machine_id: dpu.id,
                            firmware_version,
                        })
                    })
                    .collect();

                if outdated_dpus.is_empty() {
                    return None;
                }

                Some(OutdatedHost {
                    managed_host: managed_host.clone(),
                    outdated_dpus,
                })
            })
            .collect()
    }
}

pub struct OutdatedHost {
    pub managed_host: ManagedHostStateSnapshot,
    pub outdated_dpus: Vec<DpuMachineUpdate>,
}

impl OutdatedHost {
    pub fn is_available_for_updates(&self) -> bool {
        // Skip any machines that have pending health alerts
        if !self.managed_host.aggregate_health.alerts.is_empty() {
            return false;
        }
        // Skip looking at any machines that are marked for updates
        if self
            .managed_host
            .host_snapshot
            .machine_updates_in_progress()
        {
            return false;
        }
        // Skip any machines that are not Ready
        if !matches!(self.managed_host.managed_state, ManagedHostState::Ready) {
            return false;
        }

        // Check if all DPUs have the `reprovisioning_requested` flag cleared
        if self
            .managed_host
            .dpu_snapshots
            .iter()
            .any(|dpu| dpu.reprovision_requested.is_some())
        {
            return false;
        }

        true
    }
}
