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

use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};
use crate::state_controller::switch::context::SwitchStateHandlerContextObjects;

/// Handles the Ready state for a switch.
/// TODO: Implement Switch monitoring (health checks, status updates, etc.).
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

    if is_switch_reprovisioning_requested(state) {
        tracing::info!("Switch reprovisioning requested, transitioning to ReProvisioning::Start");
        return Ok(StateHandlerOutcome::transition(
            SwitchControllerState::ReProvisioning {
                reprovisioning_state: ReProvisioningState::Start,
            },
        ));
    }

    tracing::info!("Switch is ready");
    Ok(StateHandlerOutcome::do_nothing())
}

fn is_switch_reprovisioning_requested(switch: &Switch) -> bool {
    switch.switch_reprovisioning_requested.is_some()
}
