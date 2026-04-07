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
use db::switch as db_switch;
use model::rack::{RackFirmwareUpgradeState, RackFirmwareUpgradeStatus};
use model::switch::{ReProvisioningState, Switch, SwitchControllerState};

use crate::state_controller::state_handler::{
    StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};
use crate::state_controller::switch::context::SwitchStateHandlerContextObjects;

/// Handles the ReProvisioning state for a switch.
pub async fn handle_reprovisioning(
    switch_id: &SwitchId,
    state: &mut Switch,
    ctx: &mut StateHandlerContext<'_, SwitchStateHandlerContextObjects>,
) -> Result<StateHandlerOutcome<SwitchControllerState>, StateHandlerError> {
    let reprovisioning_state = match &state.controller_state.value {
        SwitchControllerState::ReProvisioning {
            reprovisioning_state,
        } => reprovisioning_state,
        _ => unreachable!("handle_reprovisioning called with non-ReProvisioning state"),
    };

    match reprovisioning_state {
        ReProvisioningState::WaitingForRackFirmwareUpgrade => {
            let is_current_cycle = |status: &RackFirmwareUpgradeStatus| -> bool {
                match (&status.ended_at, &state.switch_reprovisioning_requested) {
                    (Some(ended), Some(req)) => ended >= &req.requested_at,
                    _ => true,
                }
            };

            if let Some(status) = state.firmware_upgrade_status.as_ref()
                && !status.is_in_progress()
                && is_current_cycle(status)
            {
                match &status.status {
                    RackFirmwareUpgradeState::Completed => {
                        tracing::info!(
                            "Switch {}: rack firmware upgrade completed — returning to Ready",
                            switch_id
                        );
                        let mut txn = ctx.services.db_pool.begin().await?;
                        db_switch::clear_switch_reprovisioning_requested(txn.as_mut(), *switch_id)
                            .await?;
                        return Ok(
                            StateHandlerOutcome::transition(SwitchControllerState::Ready)
                                .with_txn(txn),
                        );
                    }
                    RackFirmwareUpgradeState::Failed { cause } => {
                        tracing::warn!(
                            "Switch {}: rack firmware upgrade failed: {}",
                            switch_id,
                            cause
                        );
                        let mut txn = ctx.services.db_pool.begin().await?;
                        db_switch::clear_switch_reprovisioning_requested(txn.as_mut(), *switch_id)
                            .await?;
                        return Ok(
                            StateHandlerOutcome::transition(SwitchControllerState::Error {
                                cause: cause.clone(),
                            })
                            .with_txn(txn),
                        );
                    }
                    _ => {}
                }
            }

            Ok(StateHandlerOutcome::wait(format!(
                "Waiting for rack firmware upgrade to be completed (firmware_upgrade_status: {:?}) switch_id: {}",
                state.firmware_upgrade_status, switch_id
            )))
        }
    }
}
