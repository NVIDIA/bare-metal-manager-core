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

use sqlx::{Postgres, Transaction};

use crate::{
    db::ib_subnet::IBSubnet,
    model::ib_subnet::IBSubnetControllerState,
    resource_pool::OwnerType,
    state_controller::state_handler::{
        ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
    },
    CarbideError,
};

use crate::ib;

/// The actual IBSubnet State handler
#[derive(Debug)]
pub struct IBSubnetStateHandler {}

impl IBSubnetStateHandler {
    pub fn new(_drain_period: chrono::Duration) -> Self {
        Self {}
    }
}

impl IBSubnetStateHandler {
    /// Allocate a value from the pkey resource pool.
    ///
    /// If the pool doesn't exist return error.
    /// If the pool exists but is empty or has en error, return that.
    async fn allocate_pkey(
        txn: &mut Transaction<'_, Postgres>,
        ctx: &mut StateHandlerContext<'_>,
        owner_id: &str,
    ) -> Result<i16, StateHandlerError> {
        if ctx.services.pool_pkey.is_none() {
            return Err(StateHandlerError::MissingData {
                object_id: owner_id.to_string(),
                missing: "pool pkey",
            });
        }

        match ctx
            .services
            .pool_pkey
            .as_ref()
            .unwrap()
            .allocate(txn, OwnerType::IBSubnet, owner_id)
            .await
        {
            Ok(val) => Ok(val),
            Err(_) => Err(StateHandlerError::PoolAllocateError {
                owner_id: owner_id.to_string(),
            }),
        }
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
            IBSubnetControllerState::Initializing => {
                let (mtu, rate_limit, service_level) = match &state.status {
                    None => (2048, 100.0, 0),
                    Some(status) => (status.mtu, status.rate_limit as f64, status.service_level),
                };

                let pkey =
                    IBSubnetStateHandler::allocate_pkey(txn, ctx, &state.config.name).await?;

                let ib = ib::types::IBNetwork {
                    name: state.config.name.clone(),
                    pkey: Some(pkey as i32),
                    mtu,
                    enable_sharp: false,
                    ipoib: false,
                    rate_limit,
                    service_level,
                    state: None,
                };
                let _res = ctx
                    .services
                    .ib_fabric_manager
                    .create_ib_network(ib)
                    .await
                    .map_err(|_| {
                        StateHandlerError::IBFabricError("create_ib_network".to_string())
                    })?;

                *controller_state.modify() = IBSubnetControllerState::Initialized;
            }

            IBSubnetControllerState::Deleting => {
                let res = ctx
                    .services
                    .ib_fabric_manager
                    .delete_ib_network(&state.config.name)
                    .await;
                if let Err(e) = res {
                    match e {
                        // The IBSubnet maybe deleted during controller cycle.
                        CarbideError::NotFoundError { .. } => {
                            IBSubnet::force_delete(*subnet_id, txn).await?;
                        }
                        _ => {
                            return Err(StateHandlerError::IBFabricError(
                                "delete_ib_network".to_string(),
                            ))
                        }
                    }
                }
            }
            _ => {
                let res = ctx
                    .services
                    .ib_fabric_manager
                    .get_ib_network(&state.config.name)
                    .await
                    .map_err(|e| {
                        StateHandlerError::IBFabricError(format!(
                            "get_ib_network by name {}: {}",
                            &state.config.name, e
                        ))
                    })?;

                match res.state {
                    Some(s) => *controller_state.modify() = s,
                    None => *controller_state.modify() = IBSubnetControllerState::Error,
                }

                if state.is_marked_as_deleted() {
                    *controller_state.modify() = IBSubnetControllerState::Deleting;
                }
            }
        }

        Ok(())
    }
}
