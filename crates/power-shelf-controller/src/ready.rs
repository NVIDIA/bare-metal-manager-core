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

//! Handler for PowerShelfControllerState::Ready.

use carbide_uuid::power_shelf::PowerShelfId;
use model::power_shelf::{PowerShelf, PowerShelfControllerState};
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::PowerShelfStateHandlerContextObjects;

/// Handles the Ready state for a power shelf.
///
/// If the power shelf is marked for deletion, transitions to `Deleting`.
/// If a maintenance request has been posted via
/// `power_shelf_maintenance_requested`, transitions to `Maintenance` with the
/// requested operation (PowerOn / PowerOff). Otherwise idles.
///
/// TODO: Implement PowerShelf monitoring (health checks, status updates,
/// power consumption / efficiency tracking).
pub async fn handle_ready(
    power_shelf_id: &PowerShelfId,
    state: &mut PowerShelf,
    _ctx: &mut StateHandlerContext<'_, PowerShelfStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<PowerShelfControllerState>, StateHandlerError> {
    if state.is_marked_as_deleted() {
        return Ok(StateHandlerOutcome::transition(
            PowerShelfControllerState::Deleting,
        ));
    }

    if let Some(req) = state.power_shelf_maintenance_requested.as_ref() {
        tracing::info!(
            operation = ?req.operation,
            initiator = %req.initiator,
            "PowerShelf maintenance requested; transitioning to Maintenance"
        );
        return Ok(StateHandlerOutcome::transition(
            PowerShelfControllerState::Maintenance {
                operation: req.operation,
            },
        ));
    }

    tracing::info!("PowerShelf {} is ready", power_shelf_id,);
    Ok(StateHandlerOutcome::wait(format!(
        "PowerShelf {} is ready",
        power_shelf_id
    )))
}
