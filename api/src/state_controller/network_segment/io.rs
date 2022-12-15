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

//! State Controller IO implementation for network segments

use crate::{
    db::{network_segment::NetworkSegment, UuidKeyedObjectFilter},
    state_controller::{controller::StateControllerIO, snapshot_loader::SnapshotLoaderError},
};

/// State Controller IO implementation for network segments
#[derive(Default, Debug)]
pub struct NetworkSegmentStateControllerIO {}

#[async_trait::async_trait]
impl StateControllerIO for NetworkSegmentStateControllerIO {
    type ObjectId = uuid::Uuid;
    type State = NetworkSegment;

    fn db_lock_name() -> &'static str {
        "network_segments_controller_lock"
    }

    async fn list_objects(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
    ) -> Result<Vec<Self::ObjectId>, SnapshotLoaderError> {
        Ok(crate::db::network_segment::NetworkSegment::list_segment_ids(txn).await?)
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        segment_id: &Self::ObjectId,
    ) -> Result<Self::State, SnapshotLoaderError> {
        let mut segments = crate::db::network_segment::NetworkSegment::find(
            txn,
            UuidKeyedObjectFilter::One(*segment_id),
        )
        .await
        .map_err(|e| {
            SnapshotLoaderError::GenericError(anyhow::anyhow!(
                "Unable to load network segment state: {:?}",
                e
            ))
        })?;
        if segments.len() != 1 {
            return Err(SnapshotLoaderError::GenericError(anyhow::anyhow!(
                "Searching for NetworkSegment {} returned zero or multiple results",
                segment_id
            )));
        }
        let segment = segments.swap_remove(0);
        Ok(segment)
    }
}
