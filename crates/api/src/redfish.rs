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

use std::sync::Arc;

use carbide_redfish::libredfish::RedfishClientPool;
use chrono::Utc;
use libredfish::model::BootProgress;
use libredfish::{PowerState, Redfish, RedfishError, SystemPowerControl};
use model::machine::Machine;

use crate::state_controller::machine::context::MachineStateHandlerContextObjects;
use crate::state_controller::machine::write_ops::MachineWriteOp;
use crate::state_controller::state_handler::StateHandlerContext;
use crate::{CarbideError, CarbideResult};

#[track_caller]
pub fn host_power_control(
    redfish_client: &dyn Redfish,
    machine: &Machine,
    action: SystemPowerControl,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
) -> impl Future<Output = CarbideResult<()>> {
    let trigger_location = std::panic::Location::caller();
    host_power_control_with_location(redfish_client, machine, action, ctx, trigger_location)
}

/// redfish utility functions
///
/// host_power_control allows control over the power of the host
pub async fn host_power_control_with_location(
    redfish_client: &dyn Redfish,
    machine: &Machine,
    action: SystemPowerControl,
    ctx: &mut StateHandlerContext<'_, MachineStateHandlerContextObjects>,
    trigger_location: &std::panic::Location<'_>,
) -> CarbideResult<()> {
    let action = if action == SystemPowerControl::ACPowercycle
        && !redfish_client.ac_powercycle_supported_by_power()
    {
        // Not supported here, so just turn off
        SystemPowerControl::ForceOff
    } else {
        action
    };
    // Always log to ensure we can see that carbide is doing the power controlling
    tracing::info!(
        machine_id = machine.id.to_string(),
        action = action.to_string(),
        trigger_location = %trigger_location,
        "Host Power Control"
    );
    ctx.pending_db_writes
        .push(MachineWriteOp::UpdateRebootRequestedTime {
            machine_id: machine.id,
            mode: action.into(),
            time: Utc::now(),
        });

    if (action == SystemPowerControl::GracefulRestart)
        || (action == SystemPowerControl::ForceRestart)
    {
        let power_result: Result<PowerState, RedfishError> = redfish_client.get_power_state().await;
        if let Ok(power_state) = power_result {
            tracing::info!(
                machine_id = machine.id.to_string(),
                action = power_state.to_string(),
                "Host Power State"
            );
            if power_state == PowerState::Off {
                tracing::info!(
                    machine_id = machine.id.to_string(),
                    action = "Manual intervention required to initiate power-on".to_string(),
                    "Host Power Action"
                );
                /* // reserve for future proactive power on action
                redfish_client
                .power(SystemPowerControl::On)
                .await
                .map_err(CarbideError::RedfishError)?
                */
            } else {
                redfish_client
                    .power(action)
                    .await
                    .map_err(CarbideError::RedfishError)?
            }
        }
    } else if action == SystemPowerControl::ACPowercycle {
        let power_state = redfish_client
            .get_power_state()
            .await
            .map_err(CarbideError::RedfishError)?;
        if power_state != PowerState::Off {
            tracing::warn!(
                machine_id = machine.id.to_string(),
                %power_state,
                "ACPowercycle requires chassis to be Off, forcing off first"
            );
            redfish_client
                .power(SystemPowerControl::ForceOff)
                .await
                .map_err(CarbideError::RedfishError)?;
        }
        redfish_client
            .power(action)
            .await
            .map_err(CarbideError::RedfishError)?
    } else {
        redfish_client
            .power(action)
            .await
            .map_err(CarbideError::RedfishError)?
    }

    Ok(())
}

/// set_host_uefi_password sets the UEFI password on the host and then power-cycles it.
/// It returns the job ID for the UEFI password change for vendors that require
/// generating a job to set the UEFI password.
pub async fn set_host_uefi_password(
    redfish_client: &dyn Redfish,
    redfish_client_pool: Arc<dyn RedfishClientPool>,
) -> CarbideResult<Option<String>> {
    redfish_client_pool
        .uefi_setup(redfish_client, false)
        .await
        .map_err(|e| {
            tracing::error!(%e, "Failed to run uefi_setup call");
            CarbideError::internal(format!("Failed redfish uefi_setup subtask: {e}"))
        })
}

pub async fn clear_host_uefi_password(
    redfish_client: &dyn Redfish,
    redfish_client_pool: Arc<dyn RedfishClientPool>,
) -> CarbideResult<Option<String>> {
    redfish_client_pool
        .clear_host_uefi_password(redfish_client)
        .await
        .map_err(|e| {
            tracing::error!(%e, "Failed to run clear_host_uefi_password call");
            CarbideError::internal(format!(
                "Failed redfish clear_host_uefi_password subtask: {e}"
            ))
        })
}

const LAST_OEM_STATE_OS_IS_RUNNING: &str = "OsIsRunning";

// did_dpu_finish_booting returns true if the DPU has come up from the last reboot and the OS is running. It will return false if the DPU has not come up from the last reboot or is stuck booting.
// the function will return the BootProgress structure to the caller if it returns true.
pub async fn did_dpu_finish_booting(
    dpu_redfish_client: &dyn Redfish,
) -> Result<(bool, Option<BootProgress>), RedfishError> {
    let system = dpu_redfish_client.get_system().await?;
    match system.boot_progress.clone() {
        Some(boot_progress) => {
            let is_dpu_up = match boot_progress
                .last_state
                .unwrap_or(libredfish::model::BootProgressTypes::None)
            {
                libredfish::model::BootProgressTypes::OSRunning => true,
                _ => {
                    boot_progress.oem_last_state.unwrap_or_default() == LAST_OEM_STATE_OS_IS_RUNNING
                }
            };

            Ok((is_dpu_up, system.boot_progress))
        }
        None => Ok((false, None)),
    }
}
