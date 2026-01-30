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

//! State Controller IO implementation for PowerShelves

use carbide_uuid::power_shelf::PowerShelfId;
use config_version::{ConfigVersion, Versioned};
use db::power_shelf::PowerShelfSearchConfig;
use db::{DatabaseError, ObjectColumnFilter, power_shelf as db_power_shelf};
use model::StateSla;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::power_shelf::{PowerShelf, PowerShelfControllerState, state_sla};
use sqlx::PgConnection;

use crate::state_controller::io::StateControllerIO;
use crate::state_controller::metrics::NoopMetricsEmitter;
use crate::state_controller::power_shelf::context::PowerShelfStateHandlerContextObjects;

/// State Controller IO implementation for PowerShelves
#[derive(Default, Debug)]
pub struct PowerShelfStateControllerIO {}

#[async_trait::async_trait]
impl StateControllerIO for PowerShelfStateControllerIO {
    type ObjectId = PowerShelfId;
    type State = PowerShelf;
    type ControllerState = PowerShelfControllerState;
    type MetricsEmitter = NoopMetricsEmitter;
    type ContextObjects = PowerShelfStateHandlerContextObjects;

    const DB_ITERATION_ID_TABLE_NAME: &'static str = "power_shelf_controller_iteration_ids";
    const DB_QUEUED_OBJECTS_TABLE_NAME: &'static str = "power_shelf_controller_queued_objects";

    const LOG_SPAN_CONTROLLER_NAME: &'static str = "power_shelf_controller";

    async fn list_objects(
        &self,
        txn: &mut PgConnection,
    ) -> Result<Vec<Self::ObjectId>, DatabaseError> {
        db_power_shelf::list_segment_ids(txn).await
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut PgConnection,
        power_shelf_id: &Self::ObjectId,
    ) -> Result<Option<Self::State>, DatabaseError> {
        let mut power_shelves = db_power_shelf::find_by(
            txn,
            ObjectColumnFilter::One(db::power_shelf::IdColumn, power_shelf_id),
            PowerShelfSearchConfig::default(),
        )
        .await?;
        if power_shelves.is_empty() {
            return Ok(None);
        } else if power_shelves.len() != 1 {
            return Err(DatabaseError::new(
                "PowerShelf::find()",
                sqlx::Error::Decode(
                    eyre::eyre!(
                        "Searching for PowerShelf {} returned multiple results",
                        power_shelf_id
                    )
                    .into(),
                ),
            ));
        }
        let power_shelf = power_shelves.swap_remove(0);
        Ok(Some(power_shelf))
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
            db_power_shelf::try_update_controller_state(txn, *object_id, old_version, new_state)
                .await?;

        // Persist state history for debugging purposes
        let _history =
            db::power_shelf_state_history::persist(txn, object_id, new_state, old_version).await?;

        Ok(())
    }

    async fn persist_outcome(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError> {
        db_power_shelf::update_controller_state_outcome(txn, *object_id, outcome).await
    }

    fn metric_state_names(state: &PowerShelfControllerState) -> (&'static str, &'static str) {
        match state {
            PowerShelfControllerState::Initializing => ("initializing", ""),
            PowerShelfControllerState::FetchingData => ("fetching_data", ""),
            PowerShelfControllerState::Configuring => ("configuring", ""),
            PowerShelfControllerState::Ready => ("ready", ""),
            PowerShelfControllerState::Error { .. } => ("error", ""),
            PowerShelfControllerState::Deleting => ("deleting", ""),
        }
    }

    fn state_sla(state: &Versioned<Self::ControllerState>) -> StateSla {
        state_sla(&state.value, &state.version)
    }
}
