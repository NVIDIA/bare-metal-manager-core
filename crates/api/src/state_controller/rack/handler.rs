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

//! State Handler implementation for Racks.

use carbide_uuid::rack::RackId;
use model::rack::{Rack, RackState};

use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::rack::created::handle_created;
use crate::state_controller::rack::deleting::handle_deleting;
use crate::state_controller::rack::discovering::handle_discovering;
use crate::state_controller::rack::error_state::handle_error;
use crate::state_controller::rack::maintenance::handle_maintenance;
use crate::state_controller::rack::ready::handle_ready;
use crate::state_controller::rack::validating::handle_validating;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

//------------------------------------------------------------------------------

// STATE HANDLER IMPLEMENTATION

#[derive(Debug, Default, Clone)]
pub struct RackStateHandler {}

impl RackStateHandler {
    async fn attempt_state_transition(
        &self,
        id: &RackId,
        state: &mut Rack,
        controller_state: &RackState,
        ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
    ) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
        let rack_profile_id = state.rack_profile_id.clone();
        let config = state.config.clone();

        match controller_state {
            RackState::Created => handle_created(id, rack_profile_id.as_ref(), ctx).await,
            RackState::Discovering => handle_discovering(id, rack_profile_id.as_ref(), ctx).await,
            RackState::Maintenance { maintenance_state } => {
                handle_maintenance(id, state, rack_profile_id.as_ref(), maintenance_state, ctx)
                    .await
            }
            RackState::Validating { validating_state } => {
                handle_validating(id, state, validating_state, ctx).await
            }
            RackState::Ready => handle_ready(id, state, &config, ctx).await,
            RackState::Error { cause } => handle_error(id, state, &config, cause, ctx).await,
            RackState::Deleting => handle_deleting().await,
        }
    }
}

#[async_trait::async_trait]
impl StateHandler for RackStateHandler {
    type ObjectId = RackId;
    type State = Rack;
    type ControllerState = RackState;
    type ContextObjects = RackStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        id: &Self::ObjectId,
        state: &mut Rack,
        controller_state: &Self::ControllerState,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
        tracing::info!("Rack {} is in state {}", id, controller_state.to_string());

        if state.deleted.is_some() && !matches!(controller_state, RackState::Deleting) {
            tracing::info!(
                "Rack {} is marked as deleted, transitioning from {} to Deleting",
                id,
                controller_state
            );
            return Ok(StateHandlerOutcome::transition(RackState::Deleting));
        }

        self.attempt_state_transition(id, state, controller_state, ctx)
            .await
    }
}
