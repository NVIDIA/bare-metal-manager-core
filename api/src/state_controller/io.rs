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

use config_version::{ConfigVersion, Versioned};
use serde::{Deserialize, Serialize};

use super::state_handler::{StateHandlerError, StateHandlerOutcome};
use crate::{
    db::DatabaseError,
    state_controller::{
        metrics::MetricsEmitter, snapshot_loader::SnapshotLoaderError,
        state_handler::StateHandlerContextObjects,
    },
};

/// This trait defines on what objects a state controller instance will act,
/// and how it loads the objects state.
#[async_trait::async_trait]
pub trait StateControllerIO: Send + Sync + std::fmt::Debug + 'static + Default {
    /// Uniquely identifies the object that is controlled
    type ObjectId: std::fmt::Display + std::fmt::Debug + Send + Sync + 'static + Clone;
    /// The full state of the object.
    /// This might contain all kinds of information, which different pieces of the full
    /// state being updated by various components.
    type State: Send + Sync + 'static;
    /// This defines the state that the state machine implemented in the state handler
    /// actively acts upon. It is passed via the `controller_state` parameter to
    /// each state handler, and can be modified via this parameter.
    /// This state may not be updated by any other component.
    type ControllerState: std::fmt::Debug + Send + Sync + 'static + Clone;
    /// Defines how metrics that are specific to this kind of object are handled
    type MetricsEmitter: MetricsEmitter;
    /// The collection of generic objects which are referenced in StateHandlerContext
    type ContextObjects: StateHandlerContextObjects<
        ObjectMetrics = <Self::MetricsEmitter as MetricsEmitter>::ObjectMetrics,
    >;

    /// The name of the table in the database that will be used for advisory locking
    ///
    /// This lock will prevent multiple instances of controller running on multiple nodes
    /// from making changes to objects at the same time
    const DB_LOCK_NAME: &'static str;

    /// The name that will be used for the logging span created by the State Controller
    const LOG_SPAN_CONTROLLER_NAME: &'static str;

    /// Resolves the list of objects that the state controller should act upon
    async fn list_objects(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
    ) -> Result<Vec<Self::ObjectId>, SnapshotLoaderError>;

    /// Loads a state of an object
    async fn load_object_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
    ) -> Result<Self::State, SnapshotLoaderError>;

    /// Loads the object state that is owned by the state controller
    async fn load_controller_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
        state: &Self::State,
    ) -> Result<Versioned<Self::ControllerState>, SnapshotLoaderError>;

    /// Persists the object state that is owned by the state controller
    async fn persist_controller_state(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
        old_version: ConfigVersion,
        new_state: Self::ControllerState,
    ) -> Result<(), SnapshotLoaderError>;

    /// Save the result of the most recent controller iteration
    async fn persist_outcome(
        &self,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        object_id: &Self::ObjectId,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError>;

    /// Returns the names that should be used in metrics for a given object state
    /// The first returned value is the value that will be used for the main `state`
    /// attribute on each metric. The 2nd value - if not empty - will be used for
    /// an optional substate attribute.
    fn metric_state_names(state: &Self::ControllerState) -> (&'static str, &'static str);

    /// Defines whether an object is in a certain state for longer than allowed
    /// by the SLA.
    ///
    /// If an object stays in a state for longer than expected, a metric will
    /// be emitted.
    ///
    /// `false` can be used to indicate that an object can stay in any state
    /// for an indefinite time in a state.
    fn time_in_state_above_sla(state: &Versioned<Self::ControllerState>) -> bool;
}

/// DB storage of the result of a state handler iteration
/// It is different from a StateHandlerOutcome in that it also stores the error message,
/// and does not store the state, which is already stored elsewhere.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum PersistentStateHandlerOutcome {
    Wait { reason: String },
    Error { err: String },
    Transition,
    DoNothing,
    Todo,
}

impl<S> From<Result<&StateHandlerOutcome<S>, &StateHandlerError>>
    for PersistentStateHandlerOutcome
{
    fn from(
        r: Result<&StateHandlerOutcome<S>, &StateHandlerError>,
    ) -> PersistentStateHandlerOutcome {
        match r {
            Ok(StateHandlerOutcome::Wait(reason)) => PersistentStateHandlerOutcome::Wait {
                reason: reason.clone(),
            },
            Ok(StateHandlerOutcome::Transition(_)) => PersistentStateHandlerOutcome::Transition,
            Ok(StateHandlerOutcome::DoNothing) => PersistentStateHandlerOutcome::DoNothing,
            Ok(StateHandlerOutcome::Todo) => PersistentStateHandlerOutcome::Todo,
            Err(err) => PersistentStateHandlerOutcome::Error {
                err: err.to_string(),
            },
        }
    }
}

impl From<PersistentStateHandlerOutcome> for rpc::forge::ControllerStateReason {
    fn from(p: PersistentStateHandlerOutcome) -> rpc::forge::ControllerStateReason {
        use rpc::forge::ControllerStateOutcome::*;
        let (outcome, outcome_msg) = match p {
            PersistentStateHandlerOutcome::Wait { reason } => (Wait, Some(reason)),
            PersistentStateHandlerOutcome::Error { err } => (Error, Some(err)),
            PersistentStateHandlerOutcome::Transition => (Transition, None),
            PersistentStateHandlerOutcome::DoNothing => (DoNothing, None),
            PersistentStateHandlerOutcome::Todo => (Todo, None),
        };
        rpc::forge::ControllerStateReason {
            outcome: outcome.into(), // into converts it to i32
            outcome_msg,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_outcome_serialize() {
        let wait_state = PersistentStateHandlerOutcome::Wait {
            reason: "Reason goes here".to_string(),
        };
        let serialized = serde_json::to_string(&wait_state).unwrap();
        assert_eq!(
            serialized,
            r#"{"outcome":"wait","reason":"Reason goes here"}"#
        );
    }

    #[test]
    fn test_state_outcome_deserialize() {
        let serialized = r#"{"outcome":"error","err":"Error message here"}"#;
        let expected_error_state = PersistentStateHandlerOutcome::Error {
            err: "Error message here".to_string(),
        };
        let deserialized: PersistentStateHandlerOutcome = serde_json::from_str(serialized).unwrap();
        assert_eq!(deserialized, expected_error_state);
    }

    #[test]
    fn test_state_outcome_serialize_deserialize_basic() {
        let transition_state = PersistentStateHandlerOutcome::Transition;
        let serialized = serde_json::to_string(&transition_state).unwrap();
        assert_eq!(serialized, r#"{"outcome":"transition"}"#);

        let deserialized: PersistentStateHandlerOutcome =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(deserialized, transition_state);
    }
}
