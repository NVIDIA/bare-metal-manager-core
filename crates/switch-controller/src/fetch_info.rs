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

//! Handler for SwitchControllerState::FetchInfo.

use carbide_uuid::switch::SwitchId;
use model::switch::{Switch, SwitchControllerState, ValidatingState};
use state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

use crate::context::SwitchStateHandlerContextObjects;
use crate::endpoint;

/// Handles the FetchInfo state for a switch.
pub async fn handle_fetch_info(
    switch_id: &SwitchId,
    state: &Switch,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    if let (Some(_rack_id), Some(component_manager)) =
        (&state.rack_id, &ctx.services.component_manager)
    {
        match endpoint::resolve_switch_endpoint(
            switch_id,
            &ctx.services.db_pool,
            &ctx.services.credential_manager,
        )
        .await
        {
            Ok(endpoint) => match component_manager
                .nv_switch
                .get_slot_and_tray(std::slice::from_ref(&endpoint))
                .await
            {
                Ok(results) => {
                    if let Some(result) = results.into_iter().next() {
                        if let Some(error) = result.error.as_ref() {
                            tracing::warn!(
                                %error,
                                %switch_id,
                                backend = component_manager.nv_switch.name(),
                                "Failed to get slot and tray from component manager backend"
                            );
                        }
                        let mut update_txn = ctx.services.db_pool.begin().await?;
                        if let Err(e) = db::switch::update_slot_and_tray(
                            &mut update_txn,
                            switch_id,
                            result.slot_number,
                            result.tray_index,
                        )
                        .await
                        {
                            tracing::warn!(
                                error = %e,
                                %switch_id,
                                "Failed to update slot_number and tray_index for switch"
                            );
                        }
                        update_txn.commit().await?;
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        %error,
                        %switch_id,
                        backend = component_manager.nv_switch.name(),
                        "Failed to get slot and tray from component manager backend"
                    );
                }
            },
            Err(error) => {
                tracing::warn!(
                    %error,
                    %switch_id,
                    "Failed to resolve switch endpoint for slot and tray lookup"
                );
            }
        }
    }

    tracing::info!(
        %switch_id,
        "Switch slot and tray fetch complete, transitioning to Validating"
    );
    Ok(StateHandlerOutcome::transition(
        SwitchControllerState::Validating {
            validating_state: ValidatingState::ValidationComplete,
        },
    ))
}
