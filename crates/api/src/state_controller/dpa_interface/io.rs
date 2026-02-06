/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

//! State Controller IO implementation for dpa interfaces

use carbide_uuid::dpa_interface::DpaInterfaceId;
use config_version::{ConfigVersion, Versioned};
use db::DatabaseError;
use model::StateSla;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::dpa_interface::{self, DpaInterface, DpaInterfaceControllerState};
use sqlx::PgConnection;

use crate::state_controller::dpa_interface::context::DpaInterfaceStateHandlerContextObjects;
use crate::state_controller::dpa_interface::metrics::DpaInterfaceMetricsEmitter;
use crate::state_controller::io::StateControllerIO;

/// State Controller IO implementation for dpa interfaces
#[derive(Default, Debug)]
pub struct DpaInterfaceStateControllerIO {}

#[async_trait::async_trait]
impl StateControllerIO for DpaInterfaceStateControllerIO {
    type ObjectId = DpaInterfaceId;
    type State = DpaInterface;
    type ControllerState = DpaInterfaceControllerState;
    type MetricsEmitter = DpaInterfaceMetricsEmitter;
    type ContextObjects = DpaInterfaceStateHandlerContextObjects;

    const DB_ITERATION_ID_TABLE_NAME: &'static str = "dpa_interfaces_controller_iteration_ids";
    const DB_QUEUED_OBJECTS_TABLE_NAME: &'static str = "dpa_interfaces_controller_queued_objects";

    const LOG_SPAN_CONTROLLER_NAME: &'static str = "dpa_interfaces_controller";

    async fn list_objects(
        &self,
        txn: &mut PgConnection,
    ) -> Result<Vec<Self::ObjectId>, DatabaseError> {
        db::dpa_interface::find_ids(txn).await
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut PgConnection,
        interface_id: &Self::ObjectId,
    ) -> Result<Option<Self::State>, DatabaseError> {
        let mut interfaces = db::dpa_interface::find_by_ids(txn, &[*interface_id], false).await?;
        if interfaces.is_empty() {
            tracing::debug!("DPA load_object_state empty ifid: {:#?}", interface_id);
            return Ok(None);
        }
        if interfaces.len() > 1 {
            tracing::debug!(
                "DPA load_object_state len ifid: {:#?} len: {}",
                interface_id,
                interfaces.len()
            );
            return Err(DatabaseError::new(
                "DpaInterface::find_by_ids()",
                sqlx::Error::Decode(
                    eyre::eyre!(
                        "Searching for DpaInterface {} returned multiple results",
                        interface_id
                    )
                    .into(),
                ),
            ));
        }
        let intf = interfaces.swap_remove(0);

        Ok(Some(intf))
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
            db::dpa_interface::try_update_controller_state(txn, *object_id, old_version, new_state)
                .await?;
        Ok(())
    }

    async fn persist_outcome(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError> {
        db::dpa_interface::update_controller_state_outcome(txn, *object_id, outcome).await
    }

    fn metric_state_names(state: &DpaInterfaceControllerState) -> (&'static str, &'static str) {
        match state {
            DpaInterfaceControllerState::Provisioning => ("provisioning", ""),
            DpaInterfaceControllerState::Unlocking => ("unlocking", ""),
            DpaInterfaceControllerState::ApplyProfile => ("locking", ""),
            DpaInterfaceControllerState::Locking => ("locking", ""),
            DpaInterfaceControllerState::Ready => ("ready", ""),
            DpaInterfaceControllerState::WaitingForSetVNI => ("waitingforsetvni", ""),
            DpaInterfaceControllerState::WaitingForResetVNI => ("waitingforresetvni", ""),
            DpaInterfaceControllerState::Assigned => ("assigned", ""),
        }
    }

    fn state_sla(state: &Versioned<Self::ControllerState>) -> StateSla {
        dpa_interface::state_sla(&state.value, &state.version)
    }
}
