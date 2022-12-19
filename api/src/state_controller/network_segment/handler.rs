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

//! State Handler implementation for Network Segments

use std::task::Poll;

use crate::{
    db::{network_prefix::NetworkPrefix, network_segment::NetworkSegment},
    model::network_segment::{NetworkSegmentControllerState, NetworkSegmentDeletionState},
    state_controller::state_handler::{StateHandler, StateHandlerContext, StateHandlerError},
};

/// The actual Network Segment State handler
#[derive(Debug)]
pub struct NetworkSegmentStateHandler {
    /// Specifies for how long the number of allocated IPs on network prefixes
    /// need to be zero until the segment is deleted
    drain_period: chrono::Duration,
}

impl NetworkSegmentStateHandler {
    pub fn new(drain_period: chrono::Duration) -> Self {
        Self { drain_period }
    }
}

#[async_trait::async_trait]
impl StateHandler for NetworkSegmentStateHandler {
    type ObjectId = uuid::Uuid;
    type State = NetworkSegment;

    async fn handle_object_state(
        &self,
        segment_id: &uuid::Uuid,
        state: &mut NetworkSegment,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        match &state.controller_state.value {
            NetworkSegmentControllerState::Provisioning => {
                let mut created_all_resource_groups = true;
                for prefix in state.prefixes.iter() {
                    match ctx
                        .services
                        .vpc_api
                        .try_create_resource_group(prefix.id, prefix.prefix, prefix.gateway)
                        .await?
                    {
                        Poll::Ready(result) => {
                            NetworkPrefix::update_circuit_id(txn, prefix.id, result.circuit_id)
                                .await?;
                        }
                        Poll::Pending => {
                            // We have to retry this. But we let the loop
                            // continue, so that resource groups for
                            // other prefixes are provisioned at the same time
                            created_all_resource_groups = false;
                        }
                    }
                }

                if !created_all_resource_groups {
                    // We need another iteration to get confirmation that
                    // all CRDs have actually been created
                    return Ok(());
                }

                // Once we discover that VPC is configured, we moved into the Ready state
                // While we could also immediately handle deletions here, we
                // opt to wait for being in the ready state - so that there's just a single
                // place covering them.
                tracing::info!(
                    "Network Segment {} is transitioning into state \"Ready\"",
                    segment_id
                );
                let new_state = NetworkSegmentControllerState::Ready;
                NetworkSegment::try_update_controller_state(
                    txn,
                    *segment_id,
                    state.controller_state.version,
                    &new_state,
                )
                .await?;
                return Ok(());
            }
            NetworkSegmentControllerState::Ready => {
                if state.is_marked_as_deleted() {
                    tracing::info!("Network Segment {} is transitioning into state \"Deleting::DrainAllocatedIps\"", segment_id);
                    let delete_at = chrono::Utc::now()
                        .checked_add_signed(self.drain_period)
                        .unwrap_or_else(chrono::Utc::now);
                    let new_state = NetworkSegmentControllerState::Deleting {
                        deletion_state: NetworkSegmentDeletionState::DrainAllocatedIps {
                            delete_at,
                        },
                    };
                    NetworkSegment::try_update_controller_state(
                        txn,
                        *segment_id,
                        state.controller_state.version,
                        &new_state,
                    )
                    .await?;
                    return Ok(());
                }
            }
            NetworkSegmentControllerState::Deleting { deletion_state } => {
                match deletion_state {
                    NetworkSegmentDeletionState::DrainAllocatedIps { delete_at } => {
                        // TODO: Check here whether the IPs are actually freed.
                        // If ones are still allocated, we can not delete and have to
                        // update the `delete_at` timestamp.

                        if chrono::Utc::now() >= *delete_at {
                            tracing::info!("Network Segment {} is transitioning into state \"Deleting::DeleteVPCResourceGroups\"", segment_id);
                            let new_state = NetworkSegmentControllerState::Deleting {
                                deletion_state:
                                    NetworkSegmentDeletionState::DeleteVPCResourceGroups,
                            };
                            NetworkSegment::try_update_controller_state(
                                txn,
                                *segment_id,
                                state.controller_state.version,
                                &new_state,
                            )
                            .await?;
                            return Ok(());
                        }
                    }
                    NetworkSegmentDeletionState::DeleteVPCResourceGroups => {
                        let mut deleted_all_crds = true;
                        for prefix in state.prefixes.iter() {
                            match ctx
                                .services
                                .vpc_api
                                .try_delete_resource_group(prefix.id)
                                .await?
                            {
                                Poll::Pending => {
                                    deleted_all_crds = false;
                                }
                                Poll::Ready(()) => {
                                    tracing::info!(
                                        "ResourceGroup for Prefix {} was deleted",
                                        prefix.id
                                    );
                                }
                            }
                        }

                        if !deleted_all_crds {
                            // We need another iteration to get confirmation that
                            // all CRDs have actually been deleted
                            return Ok(());
                        }

                        tracing::info!(
                            "Network Segment {} getting removed from the database",
                            segment_id
                        );
                        NetworkSegment::force_delete(*segment_id, txn).await?;
                    }
                }
            }
        }

        Ok(())
    }
}
