/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use crate::{
    db::ib_partition::{IBPartition, IBPartitionStatus},
    ib::{types::IBNetwork, IBFabricManagerConfig, DEFAULT_IB_FABRIC_NAME},
    model::ib_partition::IBPartitionControllerState,
    state_controller::{
        ib_partition::context::IBPartitionStateHandlerContextObjects,
        state_handler::{
            StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
        },
    },
    CarbideError,
};
use forge_uuid::infiniband::IBPartitionId;

/// The actual IBPartition State handler
#[derive(Debug, Default, Clone)]
pub struct IBPartitionStateHandler {}

#[async_trait::async_trait]
impl StateHandler for IBPartitionStateHandler {
    type ObjectId = IBPartitionId;
    type State = IBPartition;
    type ControllerState = IBPartitionControllerState;
    type ContextObjects = IBPartitionStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        partition_id: &IBPartitionId,
        state: &mut IBPartition,
        controller_state: &Self::ControllerState,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<IBPartitionControllerState>, StateHandlerError> {
        let ib_fabric = ctx
            .services
            .ib_fabric_manager
            .connect(DEFAULT_IB_FABRIC_NAME)
            .await
            .map_err(|e| StateHandlerError::IBFabricError {
                operation: "connect".to_string(),
                error: e.into(),
            })?;

        let ib_config = ctx.services.ib_fabric_manager.get_config();

        match controller_state {
            IBPartitionControllerState::Provisioning => {
                // TODO(k82cn): get IB network from IB Fabric Manager to avoid duplication.
                let new_state = IBPartitionControllerState::Ready;
                Ok(StateHandlerOutcome::Transition(new_state))
            }

            IBPartitionControllerState::Deleting => {
                match state.config.pkey {
                    None => {
                        let cause = "The pkey is None when deleting an IBPartition.";
                        tracing::error!(cause);
                        let new_state = IBPartitionControllerState::Error {
                            cause: cause.to_string(),
                        };
                        Ok(StateHandlerOutcome::Transition(new_state))
                    }
                    Some(pkey) => {
                        // When ib_partition is deleting, it should wait until all instances are
                        // released. As releasing instance will also remove ib_port from ib_network,
                        // and the ib_network will be removed when no ports are in it.
                        let res = ib_fabric.get_ib_network(pkey.to_string().as_ref()).await;
                        if let Err(e) = res {
                            match e {
                                // The IBPartition maybe deleted during controller cycle.
                                CarbideError::NotFoundError { .. } => {
                                    IBPartition::final_delete(*partition_id, txn).await?;
                                    // Release pkey after ib_partition deleted.
                                    let pkey_pool = ctx
                                        .services
                                        .ib_pools
                                        .pkey_pools
                                        .get(DEFAULT_IB_FABRIC_NAME)
                                        .ok_or_else(|| StateHandlerError::IBFabricError {
                                            operation: "release_pkey".to_string(),
                                            error: eyre::eyre!(
                                            "pkey pool for fabric \"{DEFAULT_IB_FABRIC_NAME}\" was not found"
                                        )})?;

                                    pkey_pool.release(txn, pkey).await?;
                                    Ok(StateHandlerOutcome::Deleted)
                                }
                                _ => Err(StateHandlerError::IBFabricError {
                                    operation: "get_ib_network".to_string(),
                                    error: e.into(),
                                }),
                            }
                        } else {
                            Ok(StateHandlerOutcome::Wait(
                                "Waiting for all IB instances are released".to_string(),
                            ))
                        }
                    }
                }
            }

            IBPartitionControllerState::Ready => match state.config.pkey {
                None => {
                    let cause = "The pkey is None when IBPartition is ready";
                    tracing::error!(cause);

                    Ok(StateHandlerOutcome::Transition(
                        IBPartitionControllerState::Error {
                            cause: cause.to_string(),
                        },
                    ))
                }
                Some(pkey) => {
                    if state.is_marked_as_deleted() {
                        Ok(StateHandlerOutcome::Transition(
                            IBPartitionControllerState::Deleting,
                        ))
                    } else {
                        let pkey = pkey.to_string();
                        let res = ib_fabric.get_ib_network(&pkey).await;

                        match res {
                            Ok(ibnetwork) => {
                                // If found the IBNetwork, update the status accordingly. And check
                                // it whether align with the config; if mismatched, return error.
                                // The mismatched status is still there in DB for debug.
                                state.status = Some(IBPartitionStatus::from(&ibnetwork));
                                state.update(txn).await?;

                                if !is_valid_status(&ib_config, &ibnetwork) {
                                    // Update the QoS of IBNetwork in UFM.
                                    //
                                    // TODO(k82cn): Currently, the IBNeetwork is created only after
                                    // at least one port was bound to the partition.
                                    // In latest version, the UFM will support create partition without
                                    // port.
                                    let mut ibnetwork = ibnetwork;
                                    ibnetwork.mtu = ib_config.mtu.clone();
                                    ibnetwork.rate_limit = ib_config.rate_limit.clone();
                                    ibnetwork.service_level = ib_config.service_level.clone();

                                    if let Err(e) = ib_fabric.update_ib_network(&ibnetwork).await {
                                        return Ok(StateHandlerOutcome::Transition(
                                            IBPartitionControllerState::Error {
                                                cause: format!("Failed to update IB partition {e}"),
                                            },
                                        ));
                                    }
                                }

                                Ok(StateHandlerOutcome::DoNothing)
                            }

                            Err(e) => {
                                match e {
                                    // The Partition maybe still empty as it will be only created
                                    // when at least one port associated with the Partition.
                                    CarbideError::NotFoundError { .. } => {
                                        Ok(StateHandlerOutcome::DoNothing)
                                    }
                                    _ => Err(StateHandlerError::IBFabricError {
                                        operation: "get_ib_network".to_string(),
                                        error: e.into(),
                                    }),
                                }
                            }
                        }
                    }
                }
            },

            IBPartitionControllerState::Error { .. } => {
                if state.config.pkey.is_some() && state.is_marked_as_deleted() {
                    Ok(StateHandlerOutcome::Transition(
                        IBPartitionControllerState::Deleting,
                    ))
                } else {
                    // If pkey is none, keep it in error state.
                    Ok(StateHandlerOutcome::DoNothing)
                }
            }
        }
    }
}

fn is_valid_status(c: &IBFabricManagerConfig, r: &IBNetwork) -> bool {
    c.mtu == r.mtu
        // NOTE: The rate_limit is defined as 'f64' for lagency device, e.g. 2.5G; so it's ok to
        // convert to i32 for new devices.
        && c.rate_limit == r.rate_limit
        && c.service_level == r.service_level
}

impl From<&IBNetwork> for IBPartitionStatus {
    fn from(ib: &IBNetwork) -> IBPartitionStatus {
        Self {
            partition: ib.name.clone(),
            mtu: ib.mtu.clone(),
            rate_limit: ib.rate_limit.clone(),
            service_level: ib.service_level.clone(),
        }
    }
}
