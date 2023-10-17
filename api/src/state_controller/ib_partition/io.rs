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

//! State Controller IO implementation for Infiniband Partitions

use crate::{
    db::{
        ib_partition::{IBPartition, IBPartitionSearchConfig},
        UuidKeyedObjectFilter,
    },
    model::config_version::{ConfigVersion, Versioned},
    model::ib_partition::IBPartitionControllerState,
    state_controller::{
        io::StateControllerIO, metrics::NoopMetricsEmitter, snapshot_loader::SnapshotLoaderError,
    },
};

/// State Controller IO implementation for Infiniband Partitions
#[derive(Default, Debug)]
pub struct IBPartitionStateControllerIO {}

#[async_trait::async_trait]
impl StateControllerIO for IBPartitionStateControllerIO {
    type ObjectId = uuid::Uuid;
    type State = IBPartition;
    type ControllerState = IBPartitionControllerState;
    type MetricsEmitter = NoopMetricsEmitter;

    const DB_LOCK_NAME: &'static str = "ib_partition_controller_lock";

    const LOG_SPAN_CONTROLLER_NAME: &'static str = "ib_partition_controller";

    async fn list_objects(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
    ) -> Result<Vec<Self::ObjectId>, SnapshotLoaderError> {
        IBPartition::list_segment_ids(txn)
            .await
            .map_err(SnapshotLoaderError::from)
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        segment_id: &Self::ObjectId,
    ) -> Result<Self::State, SnapshotLoaderError> {
        let mut segments = IBPartition::find(
            txn,
            UuidKeyedObjectFilter::One(*segment_id),
            IBPartitionSearchConfig::default(),
        )
        .await?;
        if segments.len() != 1 {
            return Err(SnapshotLoaderError::InvalidResult(format!(
                "Searching for IBPartition {} returned zero or multiple results",
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
            IBPartition::try_update_controller_state(txn, *object_id, old_version, &new_state)
                .await?;
        Ok(())
    }

    fn metric_state_names(state: &IBPartitionControllerState) -> (&'static str, &'static str) {
        match state {
            IBPartitionControllerState::Provisioning => ("provisioning", ""),
            IBPartitionControllerState::Ready => ("ready", ""),
            IBPartitionControllerState::Error => ("error", ""),
            IBPartitionControllerState::Deleting => ("deleting", ""),
        }
    }
}
