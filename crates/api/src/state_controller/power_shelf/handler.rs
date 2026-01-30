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
use carbide_uuid::power_shelf::PowerShelfId;
use db::power_shelf as db_power_shelf;
use model::power_shelf::{PowerShelf, PowerShelfControllerState};

use crate::state_controller::power_shelf::context::PowerShelfStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
    StateHandlerOutcomeWithTransaction,
};

/// The actual PowerShelf State handler
#[derive(Debug, Default, Clone)]
pub struct PowerShelfStateHandler {}

#[async_trait::async_trait]
impl StateHandler for PowerShelfStateHandler {
    type ObjectId = PowerShelfId;
    type State = PowerShelf;
    type ControllerState = PowerShelfControllerState;
    type ContextObjects = PowerShelfStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        power_shelf_id: &PowerShelfId,
        state: &mut PowerShelf,
        controller_state: &Self::ControllerState,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<PowerShelfControllerState>, StateHandlerError>
    {
        match controller_state {
            PowerShelfControllerState::Initializing => {
                // TODO: Implement PowerShelf initialization logic
                // This would typically involve:
                // 1. Validating the PowerShelf configuration
                // 2. Allocating resources
                // 3. Setting up the PowerShelf in the power management system
                tracing::info!("Initializing PowerShelf");
                let new_state = PowerShelfControllerState::FetchingData;
                Ok(StateHandlerOutcome::transition(new_state).with_txn(None))
            }

            PowerShelfControllerState::FetchingData => {
                tracing::info!("Fetching PowerShelf data");
                // TODO: Implement PowerShelf fetching data logic
                // This would typically involve:
                // 1. Fetching data from the PowerShelf
                // 2. Updating the PowerShelf status
                let new_state = PowerShelfControllerState::Configuring;
                Ok(StateHandlerOutcome::transition(new_state).with_txn(None))
            }

            PowerShelfControllerState::Configuring => {
                tracing::info!("Configuring PowerShelf");
                // TODO: Implement PowerShelf configuring logic
                // This would typically involve:
                // 1. Configuring the PowerShelf
                // 2. Updating the PowerShelf status
                let new_state = PowerShelfControllerState::Ready;
                Ok(StateHandlerOutcome::transition(new_state).with_txn(None))
            }

            PowerShelfControllerState::Deleting => {
                tracing::info!("Deleting PowerShelf");
                // TODO: Implement PowerShelf deletion logic
                // This would typically involve:
                // 1. Checking if the PowerShelf is in use
                // 2. Safely shutting down the PowerShelf
                // 3. Releasing allocated resources

                // For now, just delete the PowerShelf from the database
                let mut txn = ctx.services.db_pool.begin().await?;
                db_power_shelf::final_delete(*power_shelf_id, &mut txn).await?;
                Ok(StateHandlerOutcome::deleted().with_txn(Some(txn)))
            }

            PowerShelfControllerState::Ready => {
                tracing::info!("PowerShelf is ready");
                if state.is_marked_as_deleted() {
                    Ok(
                        StateHandlerOutcome::transition(PowerShelfControllerState::Deleting)
                            .with_txn(None),
                    )
                } else {
                    // TODO: Implement PowerShelf monitoring logic
                    // This would typically involve:
                    // 1. Checking PowerShelf health status
                    // 2. Updating PowerShelf status
                    // 3. Monitoring power consumption and efficiency

                    // For now, just do nothing
                    Ok(StateHandlerOutcome::do_nothing().with_txn(None))
                }
            }

            PowerShelfControllerState::Error { .. } => {
                tracing::info!("PowerShelf is in error state");
                if state.is_marked_as_deleted() {
                    Ok(
                        StateHandlerOutcome::transition(PowerShelfControllerState::Deleting)
                            .with_txn(None),
                    )
                } else {
                    // If PowerShelf is in error state, keep it there for manual intervention
                    Ok(StateHandlerOutcome::do_nothing().with_txn(None))
                }
            }
        }
    }
}
