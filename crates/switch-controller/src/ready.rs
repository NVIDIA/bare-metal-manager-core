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

//! Handler for SwitchControllerState::Ready.

use carbide_uuid::switch::SwitchId;
use model::switch::{ReProvisioningState, Switch, SwitchControllerState};
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::SwitchStateHandlerContextObjects;

/// Handles the Ready state for a switch.
///
/// If the switch is marked for deletion, transitions to `Deleting`.
/// If a maintenance request has been posted via `switch_maintenance_requested`,
/// transitions to `Maintenance` with the requested operation. If rack-level
/// reprovisioning has been requested, transitions to `ReProvisioning`.
/// Otherwise idles.
pub async fn handle_ready(
    _switch_id: &SwitchId,
    state: &mut Switch,
    _ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    if state.is_marked_as_deleted() {
        return Ok(StateHandlerOutcome::transition(
            SwitchControllerState::Deleting,
        ));
    }

    if let Some(req) = state.switch_maintenance_requested.as_ref() {
        tracing::info!(
            operation = ?req.operation,
            initiator = %req.initiator,
            "Switch maintenance requested; transitioning to Maintenance"
        );
        return Ok(StateHandlerOutcome::transition(
            SwitchControllerState::maintenance_for_operation(req.operation),
        ));
    }

    if let Some(req) = &state.switch_reprovisioning_requested {
        if req.initiator.starts_with("rack-") {
            tracing::info!(
                "Rack-level firmware upgrade requested — transitioning to WaitingForRackFirmwareUpgrade"
            );
            return Ok(StateHandlerOutcome::transition(
                SwitchControllerState::ReProvisioning {
                    reprovisioning_state: ReProvisioningState::WaitingForRackFirmwareUpgrade,
                },
            ));
        }

        tracing::warn!(
            initiator = %req.initiator,
            "Unknown initiator for switch reprovisioning request",
        );
        return Ok(StateHandlerOutcome::transition(
            SwitchControllerState::Error {
                cause: format!(
                    "unknown initiator for switch reprovisioning request: {}",
                    req.initiator
                ),
            },
        ));
    }

    Ok(StateHandlerOutcome::do_nothing())
}
