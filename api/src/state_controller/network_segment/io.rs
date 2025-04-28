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

use config_version::{ConfigVersion, Versioned};
use sqlx::PgConnection;

use crate::db::ObjectColumnFilter;
use crate::{
    db::{self, DatabaseError, network_segment::NetworkSegment},
    model::{
        StateSla,
        controller_outcome::PersistentStateHandlerOutcome,
        network_segment::{self, NetworkSegmentControllerState},
    },
    state_controller::{
        io::StateControllerIO,
        network_segment::{
            context::NetworkSegmentStateHandlerContextObjects,
            metrics::NetworkSegmentMetricsEmitter,
        },
    },
};
use forge_uuid::network::NetworkSegmentId;

/// State Controller IO implementation for network segments
#[derive(Default, Debug)]
pub struct NetworkSegmentStateControllerIO {}

#[async_trait::async_trait]
impl StateControllerIO for NetworkSegmentStateControllerIO {
    type ObjectId = NetworkSegmentId;
    type State = NetworkSegment;
    type ControllerState = NetworkSegmentControllerState;
    type MetricsEmitter = NetworkSegmentMetricsEmitter;
    type ContextObjects = NetworkSegmentStateHandlerContextObjects;

    const DB_LOCK_NAME: &'static str = "network_segments_controller_lock";

    const LOG_SPAN_CONTROLLER_NAME: &'static str = "network_segments_controller";

    async fn list_objects(
        &self,
        txn: &mut PgConnection,
    ) -> Result<Vec<Self::ObjectId>, DatabaseError> {
        NetworkSegment::list_segment_ids(txn, None).await
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut PgConnection,
        segment_id: &Self::ObjectId,
    ) -> Result<Option<Self::State>, DatabaseError> {
        let mut segments = NetworkSegment::find_by(
            txn,
            ObjectColumnFilter::One(db::network_segment::IdColumn, segment_id),
            db::network_segment::NetworkSegmentSearchConfig {
                include_num_free_ips: true,
                include_history: false,
            },
        )
        .await?;
        if segments.is_empty() {
            return Ok(None);
        }
        if segments.len() > 1 {
            return Err(DatabaseError::new(
                file!(),
                line!(),
                "NetworkSegment::find()",
                sqlx::Error::Decode(
                    eyre::eyre!(
                        "Searching for NetworkSegment {} returned multiple results",
                        segment_id
                    )
                    .into(),
                ),
            ));
        }
        let segment = segments.swap_remove(0);
        Ok(Some(segment))
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
        new_state: Self::ControllerState,
    ) -> Result<(), DatabaseError> {
        let _updated =
            NetworkSegment::try_update_controller_state(txn, *object_id, old_version, &new_state)
                .await?;
        Ok(())
    }

    async fn persist_outcome(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError> {
        NetworkSegment::update_controller_state_outcome(txn, *object_id, outcome).await
    }

    fn metric_state_names(state: &NetworkSegmentControllerState) -> (&'static str, &'static str) {
        use crate::model::network_segment::NetworkSegmentDeletionState;

        fn deletion_state_name(deletion_state: &NetworkSegmentDeletionState) -> &'static str {
            match deletion_state {
                NetworkSegmentDeletionState::DrainAllocatedIps { .. } => "drainallocatedips",
                NetworkSegmentDeletionState::DBDelete => "dbdelete",
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

    fn state_sla(state: &Versioned<Self::ControllerState>) -> StateSla {
        network_segment::state_sla(&state.value, &state.version)
    }
}
