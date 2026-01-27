/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use carbide_uuid::switch::SwitchId;
use db::switch as db_switch;
use model::switch::{Switch, SwitchControllerState};

use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
    StateHandlerOutcomeWithTransaction,
};
use crate::state_controller::switch::context::SwitchStateHandlerContextObjects;

/// The actual Switch State handler
#[derive(Debug, Default, Clone)]
pub struct SwitchStateHandler {}

#[async_trait::async_trait]
impl StateHandler for SwitchStateHandler {
    type ObjectId = SwitchId;
    type State = Switch;
    type ControllerState = SwitchControllerState;
    type ContextObjects = SwitchStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        switch_id: &SwitchId,
        state: &mut Switch,
        controller_state: &Self::ControllerState,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<SwitchControllerState>, StateHandlerError> {
        match controller_state {
            SwitchControllerState::Initializing => {
                // TODO: Implement Switch initialization logic
                // This would typically involve:
                // 1. Validating the Switch configuration
                // 2. Allocating resources
                tracing::info!("Initializing Switch");
                let new_state = SwitchControllerState::FetchingData;
                Ok(StateHandlerOutcome::transition(new_state).with_txn(None))
            }

            SwitchControllerState::FetchingData => {
                tracing::info!("Fetching Switch data");
                // TODO: Implement Switch fetching data logic
                // This would typically involve:
                // 1. Fetching data from the Switch
                // 2. Updating the Switch status
                let new_state = SwitchControllerState::Configuring;
                Ok(StateHandlerOutcome::transition(new_state).with_txn(None))
            }

            SwitchControllerState::Configuring => {
                tracing::info!("Configuring Switch");
                // TODO: Implement Switch configuring logic
                // This would typically involve:
                // 1. Configuring the Switch
                // 2. Updating the Switch status
                let new_state = SwitchControllerState::Ready;
                Ok(StateHandlerOutcome::transition(new_state).with_txn(None))
            }

            SwitchControllerState::Deleting => {
                tracing::info!("Deleting Switch");
                // TODO: Implement Switch deletion logic
                // This would typically involve:
                // 1. Checking if the Switch is in use
                // 2. Safely shutting down the Switch
                // 3. Releasing allocated resources

                // For now, just delete the Switch from the database
                let mut txn = ctx.services.db_pool.begin().await?;
                db_switch::final_delete(*switch_id, &mut txn).await?;
                Ok(StateHandlerOutcome::deleted().with_txn(Some(txn)))
            }

            SwitchControllerState::Ready => {
                tracing::info!("Switch is ready");
                if state.is_marked_as_deleted() {
                    Ok(
                        StateHandlerOutcome::transition(SwitchControllerState::Deleting)
                            .with_txn(None),
                    )
                } else {
                    // TODO: Implement Switch monitoring logic
                    // This would typically involve:
                    // 1. Checking Switch health status
                    // 2. Updating Switch status

                    // For now, just do nothing
                    Ok(StateHandlerOutcome::do_nothing().with_txn(None))
                }
            }

            SwitchControllerState::Error { .. } => {
                tracing::info!("Switch is in error state");
                if state.is_marked_as_deleted() {
                    Ok(
                        StateHandlerOutcome::transition(SwitchControllerState::Deleting)
                            .with_txn(None),
                    )
                } else {
                    // If Switch is in error state, keep it there for manual intervention
                    Ok(StateHandlerOutcome::do_nothing().with_txn(None))
                }
            }
        }
    }
}
