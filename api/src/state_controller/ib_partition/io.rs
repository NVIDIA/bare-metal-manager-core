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
use sqlx::PgConnection;

use crate::db::ObjectColumnFilter;
use crate::{
    db::{
        self, DatabaseError,
        ib_partition::{IBPartition, IBPartitionSearchConfig},
    },
    model::{
        StateSla,
        controller_outcome::PersistentStateHandlerOutcome,
        ib_partition::{self, IBPartitionControllerState},
    },
    state_controller::{
        ib_partition::context::IBPartitionStateHandlerContextObjects, io::StateControllerIO,
        metrics::NoopMetricsEmitter,
    },
};
use forge_uuid::infiniband::IBPartitionId;

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
        txn: &mut PgConnection,
    ) -> Result<Vec<Self::ObjectId>, DatabaseError> {
        IBPartition::list_segment_ids(txn).await
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut PgConnection,
        partition_id: &Self::ObjectId,
    ) -> Result<Option<Self::State>, DatabaseError> {
        let mut partitions = IBPartition::find_by(
            txn,
            ObjectColumnFilter::One(db::ib_partition::IdColumn, partition_id),
            IBPartitionSearchConfig::default(),
        )
        .await?;
        if partitions.is_empty() {
            return Ok(None);
        } else if partitions.len() != 1 {
            return Err(DatabaseError::new(
                "IBPartition::find()",
                sqlx::Error::Decode(
                    eyre::eyre!(
                        "Searching for IBPartition {} returned multiple results",
                        partition_id
                    )
                    .into(),
                ),
            ));
        }
        let partition = partitions.swap_remove(0);
        Ok(Some(partition))
    }

    async fn load_controller_state(
        &self,
        _txn: &mut PgConnection,
        _object_id: &Self::ObjectId,
        state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, DatabaseError> {
        Ok(state.controller_state.clone())
    }

    async fn persist_controller_state(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
        old_version: ConfigVersion,
        new_state: &Self::ControllerState,
    ) -> Result<(), DatabaseError> {
        let _updated =
            IBPartition::try_update_controller_state(txn, *object_id, old_version, new_state)
                .await?;
        Ok(())
    }

    async fn persist_outcome(
        &self,
        txn: &mut PgConnection,
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

    fn state_sla(state: &Versioned<Self::ControllerState>) -> StateSla {
        ib_partition::state_sla(&state.value, &state.version)
    }
}
