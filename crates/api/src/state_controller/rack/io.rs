/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! State Controller IO implementation for Racks

use carbide_uuid::rack::RackId;
use config_version::{ConfigVersion, Versioned};
use db::rack::IdColumn;
use db::{DatabaseError, ObjectColumnFilter, rack as db_rack};
use model::StateSla;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::rack::{Rack, RackState, state_sla};
use sqlx::PgConnection;

use crate::state_controller::io::StateControllerIO;
use crate::state_controller::metrics::NoopMetricsEmitter;
use crate::state_controller::rack::context::RackStateHandlerContextObjects;

/// State Controller IO implementation for Racks
#[derive(Default, Debug)]
pub struct RackStateControllerIO {}

#[async_trait::async_trait]
impl StateControllerIO for RackStateControllerIO {
    type ObjectId = RackId;
    type State = Rack;
    type ControllerState = RackState;
    type MetricsEmitter = NoopMetricsEmitter;
    type ContextObjects = RackStateHandlerContextObjects;

    const DB_ITERATION_ID_TABLE_NAME: &'static str = "rack_controller_iteration_ids";
    const DB_QUEUED_OBJECTS_TABLE_NAME: &'static str = "rack_controller_queued_objects";

    const LOG_SPAN_CONTROLLER_NAME: &'static str = "rack_controller";

    async fn list_objects(
        &self,
        txn: &mut PgConnection,
    ) -> Result<Vec<Self::ObjectId>, DatabaseError> {
        db_rack::list(txn)
            .await
            .map(|racks| racks.into_iter().map(|r| r.id).collect())
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut PgConnection,
        rack_id: &Self::ObjectId,
    ) -> Result<Option<Self::State>, DatabaseError> {
        let mut racks = db_rack::find_by(txn, ObjectColumnFilter::One(IdColumn, rack_id)).await?;
        if racks.is_empty() {
            return Ok(None);
        } else if racks.len() != 1 {
            return Err(DatabaseError::new(
                "Rack::find()",
                sqlx::Error::Decode(
                    eyre::eyre!("Searching for Rack {} returned multiple results", rack_id).into(),
                ),
            ));
        }
        let rack = racks.swap_remove(0);
        Ok(Some(rack))
    }

    async fn load_controller_state(
        &self,
        _txn: &mut PgConnection,
        _rack_id: &Self::ObjectId,
        state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, DatabaseError> {
        Ok(state.controller_state.clone())
    }

    async fn persist_controller_state(
        &self,
        txn: &mut PgConnection,
        rack_id: &Self::ObjectId,
        old_version: ConfigVersion,
        new_state: &Self::ControllerState,
    ) -> Result<(), DatabaseError> {
        let _updated =
            db_rack::try_update_controller_state(txn, *rack_id, old_version, new_state).await?;

        // Persist state history for debugging purposes
        let _history =
            db::rack_state_history::persist(txn, *rack_id, new_state, old_version).await?;

        Ok(())
    }

    async fn persist_outcome(
        &self,
        txn: &mut PgConnection,
        rack_id: &Self::ObjectId,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError> {
        db_rack::update_controller_state_outcome(txn, *rack_id, outcome).await
    }

    fn metric_state_names(state: &RackState) -> (&'static str, &'static str) {
        match state {
            RackState::Expected => ("expected", ""),
            RackState::Discovering => ("discovering", ""),
            RackState::Maintenance { .. } => ("maintenance", ""),
            RackState::Ready { .. } => ("ready", ""),
            RackState::Error { .. } => ("error", ""),
            RackState::Deleting => ("deleting", ""),
            RackState::Unknown => ("unknown", ""),
        }
    }

    fn state_sla(state: &Versioned<Self::ControllerState>) -> StateSla {
        state_sla(&state.value, &state.version)
    }
}
