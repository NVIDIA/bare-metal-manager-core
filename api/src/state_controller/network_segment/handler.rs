/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! State Handler implementation for Network Segments

use std::sync::Arc;

use crate::{
    db::{
        instance_address::InstanceAddress, machine_interface::MachineInterface,
        network_segment::NetworkSegment,
    },
    model::network_segment::{NetworkSegmentControllerState, NetworkSegmentDeletionState},
    resource_pool::DbResourcePool,
    state_controller::state_handler::{
        ControllerStateReader, StateHandler, StateHandlerContext, StateHandlerError,
    },
};

/// The actual Network Segment State handler
#[derive(Debug)]
pub struct NetworkSegmentStateHandler {
    /// Specifies for how long the number of allocated IPs on network prefixes
    /// need to be zero until the segment is deleted
    drain_period: chrono::Duration,

    pool_vlan_id: Arc<DbResourcePool<i16>>,
    pool_vni: Arc<DbResourcePool<i32>>,
}

impl NetworkSegmentStateHandler {
    pub fn new(
        drain_period: chrono::Duration,
        pool_vlan_id: Arc<DbResourcePool<i16>>,
        pool_vni: Arc<DbResourcePool<i32>>,
    ) -> Self {
        Self {
            drain_period,
            pool_vlan_id,
            pool_vni,
        }
    }
}

#[async_trait::async_trait]
impl StateHandler for NetworkSegmentStateHandler {
    type ObjectId = uuid::Uuid;
    type State = NetworkSegment;
    type ControllerState = NetworkSegmentControllerState;
    type ObjectMetrics = ();

    async fn handle_object_state(
        &self,
        segment_id: &uuid::Uuid,
        state: &mut NetworkSegment,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _metrics: &mut Self::ObjectMetrics,
        _ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        let read_state: &NetworkSegmentControllerState = &*controller_state;
        match read_state {
            NetworkSegmentControllerState::Provisioning => {
                tracing::info!(
                    "Network Segment {} is transitioning into state \"Ready\"",
                    segment_id
                );
                *controller_state.modify() = NetworkSegmentControllerState::Ready;
                return Ok(());
            }
            NetworkSegmentControllerState::Ready => {
                if state.is_marked_as_deleted() {
                    tracing::info!("Network Segment {} is transitioning into state \"Deleting::DrainAllocatedIps\"", segment_id);
                    let delete_at = chrono::Utc::now()
                        .checked_add_signed(self.drain_period)
                        .unwrap_or_else(chrono::Utc::now);
                    *controller_state.modify() = NetworkSegmentControllerState::Deleting {
                        deletion_state: NetworkSegmentDeletionState::DrainAllocatedIps {
                            delete_at,
                        },
                    };
                    return Ok(());
                }
            }
            NetworkSegmentControllerState::Deleting { deletion_state } => {
                match deletion_state {
                    NetworkSegmentDeletionState::DrainAllocatedIps { delete_at } => {
                        // Check here whether the IPs are actually freed.
                        // If ones are still allocated, we can not delete and have to
                        // update the `delete_at` timestamp.
                        let num_machine_interfaces =
                            MachineInterface::count_by_segment_id(txn, &state.id).await?;
                        let num_instance_addresses =
                            InstanceAddress::count_by_segment_id(txn, state.id).await?;
                        if num_machine_interfaces + num_instance_addresses > 0 {
                            let delete_at = chrono::Utc::now()
                                .checked_add_signed(self.drain_period)
                                .unwrap_or_else(chrono::Utc::now);
                            tracing::info!(
                                "{} Allocated IPs on Segment {} detected. Waiting for deletion until {:?}",
                                num_machine_interfaces + num_instance_addresses,
                                state.id, delete_at
                            );
                            *controller_state.modify() = NetworkSegmentControllerState::Deleting {
                                deletion_state: NetworkSegmentDeletionState::DrainAllocatedIps {
                                    delete_at,
                                },
                            };
                            return Ok(());
                        }

                        if chrono::Utc::now() >= *delete_at {
                            tracing::info!("Network Segment {} is transitioning into state \"Deleting::DBDelete\"", segment_id);
                            *controller_state.modify() = NetworkSegmentControllerState::Deleting {
                                deletion_state: NetworkSegmentDeletionState::DBDelete,
                            };
                            return Ok(());
                        }
                    }
                    NetworkSegmentDeletionState::DBDelete => {
                        if let Some(vni) = state.vni.take() {
                            self.pool_vni.release(txn, vni).await?;
                        }
                        if let Some(vlan_id) = state.vlan_id.take() {
                            self.pool_vlan_id.release(txn, vlan_id).await?;
                        }
                        tracing::info!(
                            "Network Segment {} getting removed from the database",
                            segment_id
                        );
                        NetworkSegment::final_delete(*segment_id, txn).await?;
                    }
                }
            }
        }

        Ok(())
    }
}
