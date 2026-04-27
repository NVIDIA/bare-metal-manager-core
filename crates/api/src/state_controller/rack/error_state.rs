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

//! Handler for RackState::Error.

use carbide_uuid::rack::RackId;
use model::rack::{Rack, RackConfig, RackState};

use crate::state_controller::rack::context::RackStateHandlerContextObjects;
use crate::state_controller::rack::maintenance::first_maintenance_state;
use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

pub async fn handle_error(
    id: &RackId,
    _state: &mut Rack,
    config: &RackConfig,
    cause: &str,
    ctx: &mut StateHandlerContext<'_, RackStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<RackState>, StateHandlerError> {
    if let Some(scope) = &config.maintenance_requested {
        let activities_desc = if scope.activities.is_empty() {
            "all".to_string()
        } else {
            scope
                .activities
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        };
        if scope.is_full_rack() {
            tracing::info!(
                "Rack {} on-demand maintenance requested from Error state (full rack, activities: [{}]), transitioning to Maintenance",
                id,
                activities_desc,
            );
        } else {
            tracing::info!(
                "Rack {} on-demand maintenance requested from Error state (partial: {} machines, {} switches, {} power shelves, activities: [{}]), transitioning to Maintenance",
                id,
                scope.machine_ids.len(),
                scope.switch_ids.len(),
                scope.power_shelf_ids.len(),
                activities_desc,
            );
        }
        let txn = ctx.services.db_pool.begin().await?;
        return Ok(StateHandlerOutcome::transition(RackState::Maintenance {
            maintenance_state: first_maintenance_state(scope),
        })
        .with_txn(txn));
    }

    tracing::error!("Rack {} is in error state: {}", id, cause);
    Ok(StateHandlerOutcome::wait(format!(
        "rack in error state: {}",
        cause
    )))
}
