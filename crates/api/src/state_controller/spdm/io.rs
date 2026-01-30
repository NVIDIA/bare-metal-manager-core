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

//! State Controller IO implementation for dpa interfaces

use config_version::{ConfigVersion, Versioned};
use db::DatabaseError;
use db::attestation::spdm::{
    load_snapshot_for_machine_and_device_id, load_snapshot_for_machine_with_no_device,
};
use model::StateSla;
use model::attestation::spdm::{
    AttestationState, SpdmMachineSnapshot, SpdmMachineStateSnapshot, SpdmObjectId,
};
use model::controller_outcome::PersistentStateHandlerOutcome;
use sqlx::PgConnection;

use crate::state_controller::io::StateControllerIO;
use crate::state_controller::spdm::context::SpdmStateHandlerContextObjects;
use crate::state_controller::spdm::metrics::SpdmMetricsEmitter;

/// State Controller IO implementation for dpa interfaces
#[derive(Default, Debug)]
pub struct SpdmStateControllerIO {}

#[async_trait::async_trait]
impl StateControllerIO for SpdmStateControllerIO {
    type ObjectId = SpdmObjectId; // tuple of machine id and device id
    type State = SpdmMachineSnapshot;
    type ControllerState = SpdmMachineStateSnapshot;
    type MetricsEmitter = SpdmMetricsEmitter;
    type ContextObjects = SpdmStateHandlerContextObjects;

    const DB_ITERATION_ID_TABLE_NAME: &'static str = "attestation_controller_iteration_ids";
    const DB_QUEUED_OBJECTS_TABLE_NAME: &'static str = "attestation_controller_queued_objects";

    const LOG_SPAN_CONTROLLER_NAME: &'static str = "attestation_controller";

    async fn list_objects(
        &self,
        txn: &mut PgConnection,
    ) -> Result<Vec<Self::ObjectId>, DatabaseError> {
        db::attestation::spdm::find_machine_ids_for_attestation(txn).await
    }

    /// Loads a state snapshot from the database
    async fn load_object_state(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
    ) -> Result<Option<Self::State>, DatabaseError> {
        Ok(Some(match (object_id.0, object_id.1.clone()) {
            (machine_id, Some(device_id)) => {
                load_snapshot_for_machine_and_device_id(txn, &machine_id, &device_id).await?
            }
            (machine_id, None) => {
                load_snapshot_for_machine_with_no_device(txn, &machine_id).await?
            }
        }))
    }

    async fn load_controller_state(
        &self,
        _txn: &mut PgConnection,
        _object_id: &Self::ObjectId,
        state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, DatabaseError> {
        let version = state.machine.state_version;
        Ok(Versioned::new(state.clone().into(), version))
    }

    async fn persist_controller_state(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
        _old_version: ConfigVersion,
        new_state: &Self::ControllerState,
    ) -> Result<(), DatabaseError> {
        db::attestation::spdm::persist_controller_state(txn, object_id, new_state).await
    }

    async fn persist_outcome(
        &self,
        txn: &mut PgConnection,
        object_id: &Self::ObjectId,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError> {
        db::attestation::spdm::persist_outcome(txn, object_id, outcome).await
    }

    fn metric_state_names(
        state: &model::attestation::spdm::SpdmMachineStateSnapshot,
    ) -> (&'static str, &'static str) {
        match state.machine_state {
            AttestationState::CheckIfAttestationSupported => ("checkifattestationsupported", ""),
            AttestationState::FetchAttestationTargetsAndUpdateDb => {
                ("fetchattestationtargetsandupdatedb", "")
            }
            AttestationState::FetchData => ("fetchdata", ""),
            AttestationState::Verification => ("verification", ""),
            AttestationState::ApplyEvidenceResultAppraisalPolicy => {
                ("applyevidenceresultappraisalpolicy", "")
            }
            AttestationState::Completed => ("completed", ""),
        }
    }

    fn state_sla(_state: &Versioned<Self::ControllerState>) -> StateSla {
        StateSla::no_sla()
    }
}
