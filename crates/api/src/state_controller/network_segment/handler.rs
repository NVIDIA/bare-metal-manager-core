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

//! State Handler implementation for Network Segments

use std::sync::Arc;

use carbide_uuid::network::NetworkSegmentId;
use db::{self};
use model::network_segment::{
    NetworkSegment, NetworkSegmentControllerState, NetworkSegmentDeletionState, NetworkSegmentType,
};
use model::resource_pool::ResourcePool;

use crate::state_controller::network_segment::context::NetworkSegmentStateHandlerContextObjects;
use crate::state_controller::state_handler::{
    StateHandler, StateHandlerContext, StateHandlerError, StateHandlerOutcome,
    StateHandlerOutcomeWithTransaction,
};

/// The actual Network Segment State handler
#[derive(Debug, Clone)]
pub struct NetworkSegmentStateHandler {
    /// Specifies for how long the number of allocated IPs on network prefixes
    /// need to be zero until the segment is deleted
    drain_period: chrono::Duration,

    pool_vlan_id: Arc<ResourcePool<i16>>,
    pool_vni: Arc<ResourcePool<i32>>,
}

impl NetworkSegmentStateHandler {
    pub fn new(
        drain_period: chrono::Duration,
        pool_vlan_id: Arc<ResourcePool<i16>>,
        pool_vni: Arc<ResourcePool<i32>>,
    ) -> Self {
        Self {
            drain_period,
            pool_vlan_id,
            pool_vni,
        }
    }

    fn record_metrics(
        &self,
        state: &mut NetworkSegment,
        ctx: &mut StateHandlerContext<NetworkSegmentStateHandlerContextObjects>,
    ) {
        // If there are no prefixes return.
        // Also, we don't want to put out stats for Tenant segments, as they are not under our control.
        if state.prefixes.is_empty() || state.segment_type == NetworkSegmentType::Tenant {
            return;
        }

        // The code below assumes that we have only one prefix of type IPV4
        ctx.metrics.available_ips = state.prefixes[0].num_free_ips as usize;
        ctx.metrics.reserved_ips = state.prefixes[0].num_reserved as usize;
        ctx.metrics.seg_name = state.name.clone();

        ctx.metrics.seg_type = state.segment_type.to_string();
        ctx.metrics.seg_id = state.id.to_string();
        ctx.metrics.prefix = state.prefixes[0].prefix.to_string();

        let total = state.prefixes[0].prefix.size();

        let total_cnt: u32 = match total {
            ipnetwork::NetworkSize::V4(nf) => nf,
            ipnetwork::NetworkSize::V6(_n128) => 0,
        };
        ctx.metrics.total_ips = total_cnt as usize;
    }
}

#[async_trait::async_trait]
impl StateHandler for NetworkSegmentStateHandler {
    type ObjectId = NetworkSegmentId;
    type State = NetworkSegment;
    type ControllerState = NetworkSegmentControllerState;
    type ContextObjects = NetworkSegmentStateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        segment_id: &NetworkSegmentId,
        state: &mut NetworkSegment,
        controller_state: &Self::ControllerState,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<NetworkSegmentControllerState>, StateHandlerError>
    {
        // record metrics irrespective of the state of the network segment
        self.record_metrics(state, ctx);
        match controller_state {
            NetworkSegmentControllerState::Provisioning => {
                let new_state = NetworkSegmentControllerState::Ready;
                tracing::info!(%segment_id, state = ?new_state, "Network Segment state transition");
                Ok(StateHandlerOutcome::transition(new_state).with_txn(None))
            }
            NetworkSegmentControllerState::Ready => {
                if state.is_marked_as_deleted() {
                    let delete_at = chrono::Utc::now()
                        .checked_add_signed(self.drain_period)
                        .unwrap_or_else(chrono::Utc::now);
                    let new_state = NetworkSegmentControllerState::Deleting {
                        deletion_state: NetworkSegmentDeletionState::DrainAllocatedIps {
                            delete_at,
                        },
                    };
                    tracing::info!(%segment_id, state = ?new_state, "Network Segment state transition");
                    Ok(StateHandlerOutcome::transition(new_state).with_txn(None))
                } else {
                    Ok(StateHandlerOutcome::do_nothing().with_txn(None))
                }
            }
            NetworkSegmentControllerState::Deleting { deletion_state } => {
                match deletion_state {
                    NetworkSegmentDeletionState::DrainAllocatedIps { delete_at } => {
                        // Check here whether the IPs are actually freed.
                        // If ones are still allocated, we can not delete and have to
                        // update the `delete_at` timestamp.
                        let mut txn = ctx.services.db_pool.begin().await?;
                        let num_machine_interfaces =
                            db::machine_interface::count_by_segment_id(&mut txn, &state.id).await?;
                        let num_instance_addresses =
                            db::instance_address::count_by_segment_id(&mut txn, &state.id).await?;
                        if num_machine_interfaces + num_instance_addresses > 0 {
                            let delete_at = chrono::Utc::now()
                                .checked_add_signed(self.drain_period)
                                .unwrap_or_else(chrono::Utc::now);
                            let total_allocated_ips =
                                num_machine_interfaces + num_instance_addresses;
                            tracing::info!(
                                ?delete_at,
                                total_allocated_ips,
                                segment = %state.id,
                                "{total_allocated_ips} allocated IPs for segment. Waiting for deletion until {delete_at:?}",
                            );
                            let new_state = NetworkSegmentControllerState::Deleting {
                                deletion_state: NetworkSegmentDeletionState::DrainAllocatedIps {
                                    delete_at,
                                },
                            };
                            tracing::info!(%segment_id, state = ?new_state, "Network Segment state transition");
                            Ok(StateHandlerOutcome::transition(new_state).with_txn(Some(txn)))
                        } else if chrono::Utc::now() >= *delete_at {
                            let new_state = NetworkSegmentControllerState::Deleting {
                                deletion_state: NetworkSegmentDeletionState::DBDelete,
                            };
                            tracing::info!(%segment_id, state = ?new_state, "Network Segment state transition");
                            Ok(StateHandlerOutcome::transition(new_state).with_txn(Some(txn)))
                        } else {
                            Ok(StateHandlerOutcome::wait(format!(
                                "Cannot delete from database until draining completes at {}",
                                delete_at.to_rfc3339()
                            ))
                            .with_txn(Some(txn)))
                        }
                    }
                    NetworkSegmentDeletionState::DBDelete => {
                        let mut txn = ctx.services.db_pool.begin().await?;
                        if let Some(vni) = state.vni.take() {
                            db::resource_pool::release(&self.pool_vni, &mut txn, vni).await?;
                        }
                        if let Some(vlan_id) = state.vlan_id.take() {
                            db::resource_pool::release(&self.pool_vlan_id, &mut txn, vlan_id)
                                .await?;
                        }
                        tracing::info!(
                            %segment_id,
                            "Network Segment getting removed from the database",
                        );
                        db::network_segment::final_delete(*segment_id, &mut txn).await?;
                        Ok(StateHandlerOutcome::deleted().with_txn(Some(txn)))
                    }
                }
            }
        }
    }
}
