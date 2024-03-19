/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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
    db::ib_partition::{IBPartition, IBPartitionConfig, IBPartitionStatus},
    ib::{types::IBNetwork, DEFAULT_IB_FABRIC_NAME},
    model::ib_partition::IBPartitionControllerState,
    state_controller::{
        ib_partition::context::IBPartitionStateHandlerContextObjects,
        state_handler::{
            ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
        },
    },
    CarbideError,
};

/// The actual IBPartition State handler
#[derive(Debug, Default)]
pub struct IBPartitionStateHandler {}

#[async_trait::async_trait]
impl StateHandler for IBPartitionStateHandler {
    type ObjectId = uuid::Uuid;
    type State = IBPartition;
    type ControllerState = IBPartitionControllerState;
    type ContextObjects = IBPartitionStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        partition_id: &uuid::Uuid,
        state: &mut IBPartition,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<(), StateHandlerError> {
        let read_state: &IBPartitionControllerState = &*controller_state;

        let ib_fabric = ctx
            .services
            .ib_fabric_manager
            .connect(DEFAULT_IB_FABRIC_NAME)
            .await
            .map_err(|_| StateHandlerError::IBFabricError("can not get IB fabric".to_string()))?;

        match read_state {
            IBPartitionControllerState::Provisioning => {
                // TODO(k82cn): get IB network from IB Fabric Manager to avoid duplication.
                *controller_state.modify() = IBPartitionControllerState::Ready;
            }

            IBPartitionControllerState::Deleting => {
                match state.config.pkey {
                    None => {
                        tracing::error!("The pkey is None when deleting an IBPartition.");
                        *controller_state.modify() = IBPartitionControllerState::Error;
                    }
                    Some(pkey) => {
                        // When ib_partition is deleting, it should waiting for all instances are
                        // released. As releasing instance will also remove ib_port from ib_network,
                        // and the ib_network will be removed when no ports in it.
                        let res = ib_fabric.get_ib_network(pkey.to_string().as_ref()).await;
                        if let Err(e) = res {
                            match e {
                                // The IBPartition maybe deleted during controller cycle.
                                CarbideError::NotFoundError { .. } => {
                                    IBPartition::final_delete(*partition_id, txn).await?;
                                    // Release pkey after ib_partition deleted.
                                    if let Some(pool_pkey) = ctx.services.pool_pkey.as_ref() {
                                        pool_pkey.release(txn, pkey).await?;
                                    }
                                }
                                _ => {
                                    return Err(StateHandlerError::IBFabricError(
                                        "get_ib_network".to_string(),
                                    ))
                                }
                            }
                        }
                    }
                }
            }

            IBPartitionControllerState::Ready => match state.config.pkey {
                None => {
                    tracing::error!("The pkey is None when IBPartition is ready.");
                    *controller_state.modify() = IBPartitionControllerState::Error;
                }
                Some(pkey) => {
                    if state.is_marked_as_deleted() {
                        *controller_state.modify() = IBPartitionControllerState::Deleting;
                    } else {
                        let pkey = pkey.to_string();
                        let ibnetwork = ib_fabric.get_ib_network(&pkey).await.map_err(|_| {
                            StateHandlerError::IBFabricError("get_ib_network".to_string())
                        })?;

                        // If found the IBNetwork, update the status accordingly. And check
                        // it whether align with the config; if mismatched, return error.
                        // The mismatched status is still there in DB for debug.
                        state.status = Some(IBPartitionStatus::from(&ibnetwork));
                        state.update(txn).await?;

                        if !is_valid_status(&state.config, &ibnetwork) {
                            *controller_state.modify() = IBPartitionControllerState::Error;
                            return Err(StateHandlerError::IBFabricError(
                                "invalid status".to_string(),
                            ));
                        }
                    }
                }
            },

            IBPartitionControllerState::Error => {
                // If pkey is none, keep it in error state.
                if state.config.pkey.is_some() && state.is_marked_as_deleted() {
                    *controller_state.modify() = IBPartitionControllerState::Deleting;
                }
            }
        }

        Ok(())
    }
}

fn is_valid_status(c: &IBPartitionConfig, r: &IBNetwork) -> bool {
    c.mtu == r.mtu as i32
        // NOTE: The rate_limit is defined as 'f64' for lagency device, e.g. 2.5G; so it's ok to
        // convert to i32 for new devices.
        && c.rate_limit == r.rate_limit as i32
        && c.service_level == r.service_level as i32
}

impl From<&IBNetwork> for IBPartitionStatus {
    fn from(ib: &IBNetwork) -> IBPartitionStatus {
        Self {
            partition: ib.name.clone(),
            mtu: ib.mtu as i32,
            rate_limit: ib.rate_limit as i32,
            service_level: ib.service_level as i32,
        }
    }
}
