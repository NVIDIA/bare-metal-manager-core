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
    db::ib_subnet::{IBSubnet, IBSubnetConfig, IBSubnetStatus},
    ib::types::IBNetwork,
    model::ib_subnet::IBSubnetControllerState,
    state_controller::state_handler::{
        ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
    },
    CarbideError,
};

/// The actual IBSubnet State handler
#[derive(Debug)]
pub struct IBSubnetStateHandler {}

impl IBSubnetStateHandler {
    pub fn new(_drain_period: chrono::Duration) -> Self {
        Self {}
    }
}

#[async_trait::async_trait]
impl StateHandler for IBSubnetStateHandler {
    type ObjectId = uuid::Uuid;
    type State = IBSubnet;
    type ControllerState = IBSubnetControllerState;

    async fn handle_object_state(
        &self,
        subnet_id: &uuid::Uuid,
        state: &mut IBSubnet,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        let read_state: &IBSubnetControllerState = &*controller_state;
        match read_state {
            IBSubnetControllerState::Provisioning => {
                // TODO(k82cn): get IB network from IB Fabric Manager to avoid duplication.
                *controller_state.modify() = IBSubnetControllerState::Ready;
            }

            IBSubnetControllerState::Deleting => {
                match state.config.pkey {
                    None => {
                        tracing::error!("The pkey is None when deleting an IBSubnet.");
                        *controller_state.modify() = IBSubnetControllerState::Error;
                    }
                    Some(pkey) => {
                        // When ib_subnet is deleteing, it should waiting for all instances are
                        // released. As releasing instance will also remove ib_port from ib_network,
                        // and the ib_network will be removed when no ports in it.
                        let res = ctx
                            .services
                            .ib_fabric_manager
                            .get_ib_network(pkey.to_string().as_ref())
                            .await;
                        if let Err(e) = res {
                            match e {
                                // The IBSubnet maybe deleted during controller cycle.
                                CarbideError::NotFoundError { .. } => {
                                    IBSubnet::final_delete(*subnet_id, txn).await?;
                                    // Release pkey after ib_subnet deleted.
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

            IBSubnetControllerState::Ready => match state.config.pkey {
                None => {
                    tracing::error!("The pkey is None when IBSubnet is ready.");
                    *controller_state.modify() = IBSubnetControllerState::Error;
                }
                Some(pkey) => {
                    if state.is_marked_as_deleted() {
                        *controller_state.modify() = IBSubnetControllerState::Deleting;
                    } else {
                        let pkey = pkey.to_string();
                        let ibnetwork = ctx
                            .services
                            .ib_fabric_manager
                            .get_ib_network(&pkey)
                            .await
                            .map_err(|_| {
                                StateHandlerError::IBFabricError("get_ib_network".to_string())
                            })?;

                        // If found the IBNetwork, update the status accordingly. And check
                        // it whether align with the config; if mismatched, return error.
                        // The mismatched status is still there in DB for debug.
                        state.status = Some(IBSubnetStatus::from(&ibnetwork));
                        state.update(txn).await?;

                        if !is_valid_status(&state.config, &ibnetwork) {
                            *controller_state.modify() = IBSubnetControllerState::Error;
                            return Err(StateHandlerError::IBFabricError(
                                "invalid status".to_string(),
                            ));
                        }
                    }
                }
            },

            IBSubnetControllerState::Error => {
                // If pkey is none, keep it in error state.
                if state.config.pkey.is_some() && state.is_marked_as_deleted() {
                    *controller_state.modify() = IBSubnetControllerState::Deleting;
                }
            }
        }

        Ok(())
    }
}

fn is_valid_status(c: &IBSubnetConfig, r: &IBNetwork) -> bool {
    c.mtu == r.mtu as i32
        // NOTE: The rate_limit is defined as 'f64' for lagency device, e.g. 2.5G; so it's ok to
        // convert to i32 for new devices.
        && c.rate_limit == r.rate_limit as i32
        && c.service_level == r.service_level as i32
}

impl From<&IBNetwork> for IBSubnetStatus {
    fn from(ib: &IBNetwork) -> IBSubnetStatus {
        Self {
            partition: ib.name.clone(),
            mtu: ib.mtu as i32,
            rate_limit: ib.rate_limit as i32,
            service_level: ib.service_level as i32,
        }
    }
}
