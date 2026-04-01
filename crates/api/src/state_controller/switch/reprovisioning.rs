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

//! Handler for SwitchControllerState::ReProvisioning.

use carbide_uuid::switch::SwitchId;
use model::switch::{FirmwareUpgradeStatus, ReProvisioningState, Switch, SwitchControllerState};

use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};
use crate::state_controller::switch::context::SwitchStateHandlerContextObjects;

/// Handles the ReProvisioning state for a switch.
pub async fn handle_reprovisioning(
    _switch_id: &SwitchId,
    state: &mut Switch,
    _ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let reprovisioning_state = match &state.controller_state.value {
        SwitchControllerState::ReProvisioning {
            reprovisioning_state,
        } => reprovisioning_state,
        _ => unreachable!("handle_reprovisioning called with non-ReProvisioning state"),
    };

    match reprovisioning_state {
        ReProvisioningState::Start => {
            tracing::info!("ReProvisioning Switch: Start");
            // TODO: Trigger reprovisioning (e.g. call switch API). Then transition to waiting.
            Ok(StateHandlerOutcome::transition(
                SwitchControllerState::ReProvisioning {
                    reprovisioning_state: ReProvisioningState::WaitFirmwareUpdateCompletion,
                },
            ))
        }
        ReProvisioningState::WaitFirmwareUpdateCompletion => {
            match state.firmware_upgrade_status.as_ref() {
                Some(FirmwareUpgradeStatus::Completed) => {
                    tracing::info!(
                        "ReProvisioning Switch: firmware upgrade completed, moving to Ready"
                    );
                    Ok(StateHandlerOutcome::transition(
                        SwitchControllerState::Ready,
                    ))
                }
                Some(FirmwareUpgradeStatus::Failed { cause }) => {
                    tracing::warn!("ReProvisioning Switch: firmware upgrade failed: {}", cause);
                    Ok(StateHandlerOutcome::transition(
                        SwitchControllerState::Error {
                            cause: cause.clone(),
                        },
                    ))
                }
                Some(FirmwareUpgradeStatus::Started)
                | Some(FirmwareUpgradeStatus::InProgress)
                | None => {
                    tracing::info!(
                        "ReProvisioning Switch: WaitFirmwareUpdateCompletion, status {:?} — keep waiting",
                        state.firmware_upgrade_status
                    );
                    Ok(StateHandlerOutcome::do_nothing())
                }
            }
        }
    }
}
