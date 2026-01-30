/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

//! State Controller IO implementation for Switches

use carbide_uuid::switch::SwitchId;
use config_version::{ConfigVersion, Versioned};
use db::switch::SwitchSearchConfig;
use db::{DatabaseError, ObjectColumnFilter, switch as db_switch};
use model::StateSla;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::switch::{Switch, SwitchControllerState, state_sla};
use sqlx::PgConnection;

use crate::state_controller::io::StateControllerIO;
use crate::state_controller::metrics::NoopMetricsEmitter;
use crate::state_controller::switch::context::SwitchStateHandlerContextObjects;

/// State Controller IO implementation for Switches
#[derive(Default, Debug)]
pub struct SwitchStateControllerIO {}

#[async_trait::async_trait]
impl StateControllerIO for SwitchStateControllerIO {
    type ObjectId = SwitchId;
    type State = Switch;
    type ControllerState = SwitchControllerState;
    type MetricsEmitter = NoopMetricsEmitter;
    type ContextObjects = SwitchStateHandlerContextObjects;

    const DB_ITERATION_ID_TABLE_NAME: &'static str = "switch_controller_iteration_ids";
    const DB_QUEUED_OBJECTS_TABLE_NAME: &'static str = "switch_controller_queued_objects";

    const LOG_SPAN_CONTROLLER_NAME: &'static str = "switch_controller";

    async fn list_objects(
        &self,
        txn: &mut PgConnection,
    ) -> Result<Vec<Self::ObjectId>, DatabaseError> {
        db_switch::find_all(txn).await
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut PgConnection,
        switch_id: &Self::ObjectId,
    ) -> Result<Option<Self::State>, DatabaseError> {
        let mut switches = db_switch::find_by(
            txn,
            ObjectColumnFilter::One(db::switch::IdColumn, switch_id),
            SwitchSearchConfig::default(),
        )
        .await?;
        if switches.is_empty() {
            return Ok(None);
        } else if switches.len() != 1 {
            return Err(DatabaseError::new(
                "Switch::find()",
                sqlx::Error::Decode(
                    eyre::eyre!(
                        "Searching for Switch {} returned multiple results",
                        switch_id
                    )
                    .into(),
                ),
            ));
        }
        let switch = switches.swap_remove(0);
        Ok(Some(switch))
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
            db_switch::try_update_controller_state(txn, *object_id, old_version, new_state).await?;

        // Persist state history for debugging purposes
        let _history =
            db::switch_state_history::persist(txn, object_id, new_state, old_version).await?;

        Ok(())
    }

    async fn persist_outcome(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError> {
        db_switch::update_controller_state_outcome(txn, *object_id, outcome).await
    }

    fn metric_state_names(state: &SwitchControllerState) -> (&'static str, &'static str) {
        match state {
            SwitchControllerState::Initializing => ("initializing", ""),
            SwitchControllerState::FetchingData => ("fetching_data", ""),
            SwitchControllerState::Configuring => ("configuring", ""),
            SwitchControllerState::Ready => ("ready", ""),
            SwitchControllerState::Error { .. } => ("error", ""),
            SwitchControllerState::Deleting => ("deleting", ""),
        }
    }

    fn state_sla(state: &Versioned<Self::ControllerState>) -> StateSla {
        state_sla(&state.value, &state.version)
    }
}
