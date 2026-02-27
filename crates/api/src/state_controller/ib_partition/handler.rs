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
use carbide_uuid::infiniband::IBPartitionId;
use db::ib_partition::{IBPartition, IBPartitionStatus};
use model::ib::{DEFAULT_IB_FABRIC_NAME, IBQosConf};
use model::ib_partition::IBPartitionControllerState;

use crate::CarbideError;
use crate::ib::{GetPartitionOptions, IBFabricManagerConfig};
use crate::state_controller::ib_partition::context::IBPartitionStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
};

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
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<IBPartitionControllerState>, StateHandlerError> {
        let ib_fabric = ctx
            .services
            .ib_fabric_manager
            .new_client(DEFAULT_IB_FABRIC_NAME)
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
                Ok(StateHandlerOutcome::transition(new_state))
            }

            IBPartitionControllerState::Deleting => {
                match state.status.as_ref().and_then(|s| s.pkey) {
                    None => {
                        let cause = "The pkey is None when deleting an IBPartition.";
                        tracing::error!(cause);
                        let new_state = IBPartitionControllerState::Error {
                            cause: cause.to_string(),
                        };
                        Ok(StateHandlerOutcome::transition(new_state))
                    }
                    Some(pkey) => {
                        // When ib_partition is deleting, it should wait until all instances are
                        // released. As releasing instance will also remove ib_port from ib_network,
                        // and the ib_network will be removed when no ports are in it.
                        let res = ib_fabric
                            .get_ib_network(
                                pkey.into(),
                                GetPartitionOptions {
                                    include_guids_data: false,
                                    include_qos_conf: true,
                                },
                            )
                            .await;
                        if let Err(e) = res {
                            match e {
                                // The IBPartition maybe deleted during controller cycle.
                                CarbideError::NotFoundError { .. } => {
                                    // Before deleting, check if any instances still reference
                                    // this partition. This prevents deleting a partition that
                                    // instances still depend on, which would cause errors when
                                    // the instance state handler tries to unbind ports.
                                    let mut txn = ctx.services.db_pool.begin().await?;
                                    let instance_count =
                                        db::ib_partition::count_instances_referencing_partition(
                                            txn.as_mut(),
                                            *partition_id,
                                        )
                                        .await?;

                                    if instance_count > 0 {
                                        tracing::info!(
                                            %partition_id,
                                            instance_count,
                                            "Postponing IB partition deletion: \
                                             {instance_count} instance(s) still reference this partition",
                                        );
                                        return Ok(StateHandlerOutcome::wait(format!(
                                            "Waiting for {instance_count} instance(s) to release IB partition"
                                        ))
                                        .with_txn(txn));
                                    }

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

                                    db::ib_partition::final_delete(*partition_id, &mut txn).await?;

                                    db::resource_pool::release(pkey_pool, &mut txn, pkey.into())
                                        .await?;
                                    Ok(StateHandlerOutcome::deleted().with_txn(txn))
                                }
                                _ => Err(StateHandlerError::IBFabricError {
                                    operation: "get_ib_network".to_string(),
                                    error: e.into(),
                                }),
                            }
                        } else {
                            Ok(StateHandlerOutcome::wait(
                                "Waiting for all IB instances are released".to_string(),
                            ))
                        }
                    }
                }
            }

            IBPartitionControllerState::Ready => match state.status.as_ref().and_then(|s| s.pkey) {
                None => {
                    let cause = "The pkey is None when IBPartition is ready";
                    tracing::error!(cause);

                    Ok(StateHandlerOutcome::transition(
                        IBPartitionControllerState::Error {
                            cause: cause.to_string(),
                        },
                    ))
                }
                Some(pkey) => {
                    if state.is_marked_as_deleted() {
                        Ok(StateHandlerOutcome::transition(
                            IBPartitionControllerState::Deleting,
                        ))
                    } else {
                        let res = ib_fabric
                            .get_ib_network(
                                pkey.into(),
                                GetPartitionOptions {
                                    include_guids_data: false,
                                    include_qos_conf: true,
                                },
                            )
                            .await;

                        match res {
                            Ok(ibnetwork) => {
                                // If found the IBNetwork, update the status accordingly. And check
                                // it whether align with the config; if mismatched, return error.
                                // The mismatched status is still there in DB for debug.
                                // QoS data can be exected here, since the API call above queries for it
                                let qos = ibnetwork.qos_conf.as_ref().ok_or_else(|| {
                                    StateHandlerError::MissingData {
                                        object_id: partition_id.to_string(),
                                        missing: "qos_conf",
                                    }
                                })?;

                                state.status = Some(IBPartitionStatus {
                                    partition: Some(ibnetwork.name.clone()),
                                    pkey: Some(pkey), // We need the pkey to persist.
                                    mtu: Some(qos.mtu.clone()),
                                    rate_limit: Some(qos.rate_limit.clone()),
                                    service_level: Some(qos.service_level.clone()),
                                });

                                let ib_result = if !is_qos_conf_applied(&ib_config, qos) {
                                    // Update the QoS of IBNetwork in UFM.
                                    //
                                    // TODO(k82cn): Currently, the IBNetwork is created only after
                                    // at least one port was bound to the partition.
                                    // In latest version, the UFM will support create partition without
                                    // port.
                                    let desired_qos_conf = IBQosConf {
                                        mtu: ib_config.mtu.clone(),
                                        rate_limit: ib_config.rate_limit.clone(),
                                        service_level: ib_config.service_level.clone(),
                                    };

                                    ib_fabric
                                        .update_partition_qos_conf(
                                            ibnetwork.pkey,
                                            &desired_qos_conf,
                                        )
                                        .await
                                } else {
                                    Ok(())
                                };

                                let mut txn = ctx.services.db_pool.begin().await?;
                                db::ib_partition::update(state, &mut txn).await?;

                                if let Err(e) = ib_result {
                                    return Ok(StateHandlerOutcome::transition(
                                        IBPartitionControllerState::Error {
                                            cause: format!("Failed to update IB partition {e}"),
                                        },
                                    )
                                    .with_txn(txn));
                                } else {
                                    Ok(StateHandlerOutcome::do_nothing().with_txn(txn))
                                }
                            }

                            Err(e) => {
                                match e {
                                    // The Partition maybe still empty as it will be only created
                                    // when at least one port associated with the Partition.
                                    CarbideError::NotFoundError { .. } => {
                                        Ok(StateHandlerOutcome::do_nothing())
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
                if state.status.as_ref().and_then(|s| s.pkey).is_some()
                    && state.is_marked_as_deleted()
                {
                    Ok(StateHandlerOutcome::transition(
                        IBPartitionControllerState::Deleting,
                    ))
                } else {
                    // If pkey is none, keep it in error state.
                    Ok(StateHandlerOutcome::do_nothing())
                }
            }
        }
    }
}

fn is_qos_conf_applied(c: &IBFabricManagerConfig, actual_qos: &IBQosConf) -> bool {
    c.mtu == actual_qos.mtu
        // NOTE: The rate_limit is defined as 'f64' for lagency device, e.g. 2.5G; so it's ok to
        // convert to i32 for new devices.
        && c.rate_limit == actual_qos.rate_limit
        && c.service_level == actual_qos.service_level
}
