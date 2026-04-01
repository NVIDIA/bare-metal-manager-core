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

//! State Handler implementation for Switches (mirrors Machine state handler structure).

use carbide_uuid::switch::SwitchId;
use model::switch::{Switch, SwitchControllerState};
use tracing::instrument;

use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};
use crate::state_controller::switch::bom_validating::handle_bom_validating;
use crate::state_controller::switch::configuring::handle_configuring;
use crate::state_controller::switch::context::SwitchStateHandlerContextObjects;
use crate::state_controller::switch::created::handle_created;
use crate::state_controller::switch::deleting::handle_deleting;
use crate::state_controller::switch::error_state::handle_error;
use crate::state_controller::switch::initializing::handle_initializing;
use crate::state_controller::switch::ready::handle_ready;
use crate::state_controller::switch::reprovisioning::handle_reprovisioning;
use crate::state_controller::switch::validating::handle_validating;

/// The actual Switch State handler (structure mirrors MachineStateHandler).
#[derive(Debug, Default, Clone)]
pub struct SwitchStateHandler {}

impl SwitchStateHandler {
    /// Records metrics for the switch. Stub for now; extend when switch metrics are defined.
    fn record_metrics(
        &self,
        _state: &Switch,
        _ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
    ) {
        // TODO: Populate when SwitchMetrics has fields (e.g. health, version, etc.)
    }

    /// Attempts a state transition by delegating to the appropriate state handler.
    async fn attempt_state_transition(
        &self,
        switch_id: &SwitchId,
        state: &mut Switch,
        ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
    ) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
        let controller_state = &state.controller_state.value;

        match controller_state {
            SwitchControllerState::Created => handle_created(switch_id, state, ctx).await,
            SwitchControllerState::Initializing { .. } => {
                handle_initializing(switch_id, state, ctx).await
            }
            SwitchControllerState::Configuring { .. } => {
                handle_configuring(switch_id, state, ctx).await
            }
            SwitchControllerState::Validating { .. } => {
                handle_validating(switch_id, state, ctx).await
            }
            SwitchControllerState::BomValidating { .. } => {
                handle_bom_validating(switch_id, state, ctx).await
            }
            SwitchControllerState::ReProvisioning { .. } => {
                handle_reprovisioning(switch_id, state, ctx).await
            }
            SwitchControllerState::Ready => handle_ready(switch_id, state, ctx).await,
            SwitchControllerState::Deleting => handle_deleting(switch_id, state, ctx).await,
            SwitchControllerState::Error { .. } => handle_error(switch_id, state, ctx).await,
        }
    }
}

#[async_trait::async_trait]
impl StateHandler for SwitchStateHandler {
    type ObjectId = SwitchId;
    type State = Switch;
    type ControllerState = SwitchControllerState;
    type ContextObjects = SwitchStateHandlerContextObjects;

    #[instrument(skip_all, fields(object_id=%switch_id))]
    async fn handle_object_state(
        &self,
        switch_id: &SwitchId,
        state: &mut Switch,
        _controller_state: &SwitchControllerState,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
        self.record_metrics(state, ctx);
        self.attempt_state_transition(switch_id, state, ctx).await
    }
}
