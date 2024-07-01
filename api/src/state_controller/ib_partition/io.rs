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

use config_version::{ConfigVersion, Versioned};

use crate::{
    db::{
        ib_partition::{
            IBPartition, IBPartitionId, IBPartitionIdKeyedObjectFilter, IBPartitionSearchConfig,
        },
        DatabaseError,
    },
    model::controller_outcome::PersistentStateHandlerOutcome,
    model::ib_partition::IBPartitionControllerState,
    state_controller::{
        ib_partition::context::IBPartitionStateHandlerContextObjects, io::StateControllerIO,
        metrics::NoopMetricsEmitter, snapshot_loader::SnapshotLoaderError,
    },
};

/// State Controller IO implementation for Infiniband Partitions
#[derive(Default, Debug)]
pub struct IBPartitionStateControllerIO {}

#[async_trait::async_trait]
impl StateControllerIO for IBPartitionStateControllerIO {
    type ObjectId = IBPartitionId;
    type State = IBPartition;
    type ControllerState = IBPartitionControllerState;
    type MetricsEmitter = NoopMetricsEmitter;
    type ContextObjects = IBPartitionStateHandlerContextObjects;

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
        partition_id: &Self::ObjectId,
    ) -> Result<Self::State, SnapshotLoaderError> {
        let mut partitions = IBPartition::find(
            txn,
            IBPartitionIdKeyedObjectFilter::One(*partition_id),
            IBPartitionSearchConfig::default(),
        )
        .await?;
        if partitions.len() != 1 {
            return Err(SnapshotLoaderError::InvalidResult(format!(
                "Searching for IBPartition {} returned zero or multiple results",
                partition_id
            )));
        }
        let partition = partitions.swap_remove(0);
        Ok(partition)
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

    async fn persist_outcome(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError> {
        IBPartition::update_controller_state_outcome(txn, *object_id, outcome).await
    }

    fn metric_state_names(state: &IBPartitionControllerState) -> (&'static str, &'static str) {
        match state {
            IBPartitionControllerState::Provisioning => ("provisioning", ""),
            IBPartitionControllerState::Ready => ("ready", ""),
            IBPartitionControllerState::Error { .. } => ("error", ""),
            IBPartitionControllerState::Deleting => ("deleting", ""),
        }
    }

    fn time_in_state_above_sla(state: &Versioned<Self::ControllerState>) -> bool {
        let time_in_state = chrono::Utc::now()
            .signed_duration_since(state.version.timestamp())
            .to_std()
            .unwrap_or(std::time::Duration::from_secs(60 * 60 * 24));

        match &state.value {
            IBPartitionControllerState::Provisioning => {
                time_in_state > std::time::Duration::from_secs(15 * 60)
            }
            IBPartitionControllerState::Ready => false,
            IBPartitionControllerState::Error { .. } => false,
            IBPartitionControllerState::Deleting => {
                time_in_state > std::time::Duration::from_secs(15 * 60)
            }
        }
    }
}
