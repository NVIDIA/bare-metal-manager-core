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

//! Handler for RackState::Ready.

use carbide_uuid::rack::RackId;
use db::rack as db_rack;
use model::rack::{FirmwareUpgradeState, Rack, RackConfig, RackMaintenanceState, RackState};

use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

pub async fn handle_ready(
    id: &RackId,
    state: &mut Rack,
    config: &RackConfig,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
    if config.topology_changed {
        tracing::info!(
            "Rack {} topology changed, transitioning from Ready to Discovering",
            id
        );
        state.config.topology_changed = false;
        let mut txn = ctx.services.db_pool.begin().await?;
        db_rack::update(txn.as_mut(), id, &state.config).await?;
        return Ok(StateHandlerOutcome::transition(RackState::Discovering).with_txn(txn));
    }

    if config.reprovision_requested {
        tracing::info!(
            "Rack {} reprovision requested, transitioning from Ready to Maintenance",
            id
        );
        state.config.reprovision_requested = false;
        let mut txn = ctx.services.db_pool.begin().await?;
        db_rack::update(txn.as_mut(), id, &state.config).await?;
        return Ok(StateHandlerOutcome::transition(RackState::Maintenance {
            maintenance_state: RackMaintenanceState::FirmwareUpgrade {
                rack_firmware_upgrade: FirmwareUpgradeState::Start,
            },
        })
        .with_txn(txn));
    }

    Ok(StateHandlerOutcome::do_nothing())
}
