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

//! State Controller IO implementation for network segments

use crate::{
    db::{network_segment::NetworkSegment, UuidKeyedObjectFilter},
    model::{
        config_version::{ConfigVersion, Versioned},
        network_segment::NetworkSegmentControllerState,
    },
    state_controller::{controller::StateControllerIO, snapshot_loader::SnapshotLoaderError},
};

/// State Controller IO implementation for network segments
#[derive(Default, Debug)]
pub struct NetworkSegmentStateControllerIO {}

#[async_trait::async_trait]
impl StateControllerIO for NetworkSegmentStateControllerIO {
    type ObjectId = uuid::Uuid;
    type State = NetworkSegment;
    type ControllerState = NetworkSegmentControllerState;

    fn db_lock_name() -> &'static str {
        "network_segments_controller_lock"
    }

    async fn list_objects(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
    ) -> Result<Vec<Self::ObjectId>, SnapshotLoaderError> {
        NetworkSegment::list_segment_ids(txn)
            .await
            .map_err(SnapshotLoaderError::from)
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        segment_id: &Self::ObjectId,
    ) -> Result<Self::State, SnapshotLoaderError> {
        let mut segments = NetworkSegment::find(
            txn,
            UuidKeyedObjectFilter::One(*segment_id),
            crate::db::network_segment::NetworkSegmentSearchConfig::default(),
        )
        .await?;
        if segments.len() != 1 {
            return Err(SnapshotLoaderError::InvalidResult(format!(
                "Searching for NetworkSegment {} returned zero or multiple results",
                segment_id
            )));
        }
        let segment = segments.swap_remove(0);
        Ok(segment)
    }

    async fn load_controller_state(
        &self,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _object_id: &Self::ObjectId,
        state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, SnapshotLoaderError> {
        Ok(state.controller_state.clone())
    }

    async fn persist_controller_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
        old_version: ConfigVersion,
        new_state: Self::ControllerState,
    ) -> Result<(), SnapshotLoaderError> {
        let _updated =
            NetworkSegment::try_update_controller_state(txn, *object_id, old_version, &new_state)
                .await?;
        Ok(())
    }

    fn metric_state_names(state: &NetworkSegmentControllerState) -> (&'static str, &'static str) {
        use crate::model::network_segment::NetworkSegmentDeletionState;

        fn deletion_state_name(deletion_state: &NetworkSegmentDeletionState) -> &'static str {
            match deletion_state {
                NetworkSegmentDeletionState::DrainAllocatedIps { .. } => "drainallocatedips",
                NetworkSegmentDeletionState::DeleteVPCResourceGroups => "deletevpcresourcegroups",
            }
        }

        match state {
            NetworkSegmentControllerState::Provisioning => ("provisioning", ""),
            NetworkSegmentControllerState::Ready => ("ready", ""),
            NetworkSegmentControllerState::Deleting { deletion_state } => {
                ("deleting", deletion_state_name(deletion_state))
            }
        }
    }
}
