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
use std::panic::Location;

use carbide_uuid::machine::MachineId;
use db::DatabaseError;
use libredfish::RedfishError;
use librms::RackManagerError;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::machine::ManagedHostState;
use model::resource_pool::ResourcePoolError;
use sqlx::PgTransaction;

use crate::redfish::RedfishClientCreationError;

/// The collection of generic objects which are referenced in StateHandlerContext
pub trait StateHandlerContextObjects: Send + Sync + 'static {
    /// The type of services accessible on the state handler context object
    /// via [`StateHandlerContext::services`]
    type Services: Clone + Send + Sync + 'static;

    /// The type that can hold metrics specific to a single object.
    ///
    /// These metrics can be produced by code inside the state handler by writing
    /// them to `ObjectMetrics`.
    /// After state has been processed for all all objects, the various metrics
    /// are merged into an `IterationMetrics` object.
    type ObjectMetrics: std::fmt::Debug + Default + Send + Sync + 'static;
}

/// Context parameter passed to `StateHandler`
pub struct StateHandlerContext<'a, T: StateHandlerContextObjects> {
    /// Services that are available to the `StateHandler`
    pub services: &'a mut T::Services,
    /// Metrics that are produced as a result of acting on an object
    pub metrics: &'a mut T::ObjectMetrics,
}

/// Defines a function that will be called to determine the next step in
/// an objects lifecycle.
///
/// The function retrieves the full Object state as loaded from the database
/// as input, and can take any decisions to advance the Object state.
#[async_trait::async_trait]
pub trait StateHandler: std::fmt::Debug + Send + Sync + 'static {
    type ObjectId: Clone + std::fmt::Display + std::fmt::Debug;
    type State;
    type ControllerState;
    type ContextObjects: StateHandlerContextObjects;

    async fn handle_object_state(
        &self,
        object_id: &Self::ObjectId,
        state: &mut Self::State,
        controller_state: &Self::ControllerState,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<Self::ControllerState>, StateHandlerError>;
}

/// [`StateHandlerOutcomeWithTransaction`] includes a transaction with the StateHandlerOutcome, so
/// that the state controller can re-use this transaction for any further writes it does (for
/// instance when calling [`StateControllerIO::persist_controller_state`] and
/// [`StateControllerIO::persist_outcome`]). The reason we don't just store the transaction in an
/// instance variable in ControllerState, is so that we can catch (and avoid) cases where the
/// transaction is held open across an await point (see `lints/carbide-lints/README.md` in the
/// carbide repo for explanation.)
pub struct StateHandlerOutcomeWithTransaction<S> {
    pub outcome: StateHandlerOutcome<S>,
    pub transaction: Option<PgTransaction<'static>>,
}

pub enum StateHandlerOutcome<S> {
    Wait {
        /// The reason we're waiting
        reason: String,
        source_ref: &'static Location<'static>,
    },
    Transition {
        /// The state we are transitioning to
        next_state: S,
        source_ref: &'static Location<'static>,
    },
    DoNothing {
        source_ref: &'static Location<'static>,
    }, // Nothing to do. Typically in Ready or Assigned/Ready
    Deleted {
        _source_ref: &'static Location<'static>,
    }, // The object was removed from the database
}

impl<S> StateHandlerOutcome<S> {
    pub fn with_txn(
        self,
        transaction: Option<PgTransaction<'static>>,
    ) -> StateHandlerOutcomeWithTransaction<S> {
        StateHandlerOutcomeWithTransaction {
            outcome: self,
            transaction,
        }
    }

    #[track_caller]
    pub fn do_nothing() -> Self {
        StateHandlerOutcome::DoNothing {
            source_ref: Location::caller(),
        }
    }

    #[track_caller]
    pub fn transition(next_state: S) -> Self {
        StateHandlerOutcome::Transition {
            next_state,
            source_ref: Location::caller(),
        }
    }

    #[track_caller]
    pub fn wait(reason: String) -> Self {
        StateHandlerOutcome::Wait {
            reason,
            source_ref: Location::caller(),
        }
    }

    #[track_caller]
    pub fn deleted() -> Self {
        StateHandlerOutcome::Deleted {
            _source_ref: Location::caller(),
        }
    }
}

impl<S> std::fmt::Display for StateHandlerOutcome<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        use StateHandlerOutcome::*;
        let msg = match self {
            Wait { reason, .. } => reason.as_str(),
            Transition { .. } => "Transition to next state",
            DoNothing { .. } => "Do nothing",
            Deleted { .. } => "Deleted",
        };
        write!(f, "{msg}")
    }
}

/// Error type for handling a Machine State
#[derive(Debug, thiserror::Error)]
pub enum StateHandlerError {
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] sqlx::Error),
    #[error("Failed to advance state: {0}")]
    GenericError(eyre::Report),
    #[error("State for object {object_id} can not be advanced. Missing data: {missing}")]
    MissingData {
        object_id: String,
        missing: &'static str,
    },
    #[error("{0}")]
    DBError(#[from] DatabaseError),

    #[error("Error releasing from resource pool: {0}")]
    PoolReleaseError(#[from] ResourcePoolError),

    #[error("Invalid host state {1} for DPU {0}.")]
    InvalidHostState(MachineId, Box<ManagedHostState>),

    #[error("Failed to execute \"{operation}\" on IB fabric manager: {error}")]
    IBFabricError {
        operation: String,
        error: eyre::Report,
    },

    #[error("Failed to create redfish client: {0}")]
    RedfishClientCreationError(#[from] RedfishClientCreationError),

    #[error("The state handler for object {object_id} in state \"{state}\" timed out")]
    Timeout { object_id: String, state: String },

    #[error("Failed redfish operation: {operation}. Details: {error}")]
    RedfishError {
        operation: &'static str,
        error: RedfishError,
    },

    #[error("Failed to update firmware: {0}")]
    FirmwareUpdateError(eyre::Report),

    #[error("Manual intervention required. Cannot make progress. {0}")]
    ManualInterventionRequired(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),

    #[error("State will not be advanced due to health probe alert")]
    HealthProbeAlert,

    #[error(
        "The object is in the state for longer than defined by the SLA. Handler outcome: {handler_outcome}"
    )]
    TimeInStateAboveSla { handler_outcome: String },

    #[error("Resource {resource} cleanup error: {error}")]
    ResourceCleanupError {
        resource: &'static str,
        error: String,
    },

    #[error("Spdm error: {0}")]
    SpdmError(#[from] model::attestation::spdm::SpdmHandlerError),

    #[error("Rack Manager error: {0}")]
    RackManagerError(#[from] RackManagerError),

    #[error("DPF error: {0}")]
    DpfError(#[from] carbide_dpf::DpfError),
}

impl StateHandlerError {
    /// Returns the label that will be used to identify the error in metrics
    ///
    /// This will be a simplified description of the error, to avoid having too
    /// many metric dimensions.
    pub fn metric_label(&self) -> &'static str {
        match self {
            StateHandlerError::TransactionError(_) => "transaction_error",
            StateHandlerError::GenericError(_) => "generic_error",
            StateHandlerError::FirmwareUpdateError(_) => "firware_update_error",
            StateHandlerError::MissingData { .. } => "missing_data",
            StateHandlerError::DBError(_) => "db_error",
            StateHandlerError::Timeout { .. } => "timeout",
            StateHandlerError::PoolReleaseError(_) => "pool_release_error",
            StateHandlerError::InvalidHostState(_, _) => "invalid_host_state",
            StateHandlerError::IBFabricError { .. } => "ib_fabric_error",
            StateHandlerError::InvalidState(_) => "invalid_state",
            StateHandlerError::RedfishClientCreationError(_) => "redfish_client_creation_error",
            StateHandlerError::RedfishError { operation, .. } => match *operation {
                "restart" => "redfish_restart_error",
                "lockdown" => "redfish_lockdown_error",
                _ => "redfish_other_error",
            },
            StateHandlerError::ManualInterventionRequired(_) => "manual_intervention_required",
            StateHandlerError::HealthProbeAlert => "health_probe_alert",
            StateHandlerError::TimeInStateAboveSla { .. } => "time_in_state_above_sla",
            StateHandlerError::ResourceCleanupError { resource, .. } => match *resource {
                "VpcLoopbackIp" => "vpcloopback_release_failed",
                "network_segment" => "network_segment_cleanup_failed",
                _ => "resource_cleanup_failed",
            },
            StateHandlerError::SpdmError(_) => "spdm_attestation_error",
            StateHandlerError::RackManagerError(_) => "rack_manager_error",
            StateHandlerError::DpfError(_) => "dpf_error",
        }
    }
}

/// A `StateHandler` implementation which does nothing
pub struct NoopStateHandler<I, S, CS, CO> {
    _phantom_data: std::marker::PhantomData<Option<(I, S, CS, CO)>>,
}

impl<I, S, CS, CO> std::fmt::Debug for NoopStateHandler<I, S, CS, CO> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoopStateHandler").finish()
    }
}

impl<I, S, CS, CO> Default for NoopStateHandler<I, S, CS, CO> {
    fn default() -> Self {
        Self {
            _phantom_data: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl<
    I: Clone + std::fmt::Display + std::fmt::Debug + Send + Sync + 'static,
    S: Send + Sync + 'static,
    CS: Send + Sync + 'static,
    CO: StateHandlerContextObjects,
> StateHandler for NoopStateHandler<I, S, CS, CO>
{
    type State = S;
    type ControllerState = CS;
    type ObjectId = I;
    type ContextObjects = CO;

    async fn handle_object_state(
        &self,
        _object_id: &Self::ObjectId,
        _state: &mut Self::State,
        _controller_state: &Self::ControllerState,
        _ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcomeWithTransaction<Self::ControllerState>, StateHandlerError> {
        Ok(StateHandlerOutcome::do_nothing().with_txn(None))
    }
}

pub trait FromStateHandlerResult<S> {
    fn from_result(r: Result<&StateHandlerOutcome<S>, &StateHandlerError>) -> Self;
}

impl<S> FromStateHandlerResult<S> for PersistentStateHandlerOutcome {
    fn from_result(
        r: Result<&StateHandlerOutcome<S>, &StateHandlerError>,
    ) -> PersistentStateHandlerOutcome {
        match r {
            Ok(StateHandlerOutcome::Wait { reason, source_ref }) => {
                PersistentStateHandlerOutcome::Wait {
                    reason: reason.clone(),
                    source_ref: Some(source_ref.into()),
                }
            }
            Ok(StateHandlerOutcome::Transition { source_ref, .. }) => {
                PersistentStateHandlerOutcome::Transition {
                    source_ref: Some(source_ref.into()),
                }
            }
            Ok(StateHandlerOutcome::DoNothing { source_ref }) => {
                PersistentStateHandlerOutcome::DoNothing {
                    source_ref: Some(source_ref.into()),
                }
            }
            Ok(StateHandlerOutcome::Deleted { .. }) => unreachable!(),
            Err(err) => PersistentStateHandlerOutcome::Error {
                err: err.to_string(),
                // TODO: Make it possible to determine where errors are generated
                source_ref: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_transition_source_location() {
        let StateHandlerOutcome::<String>::DoNothing { source_ref } =
            StateHandlerOutcome::do_nothing()
        else {
            unreachable!()
        };
        assert_eq!(source_ref.line(), line!() - 4);
        assert_eq!(source_ref.file(), file!());

        let StateHandlerOutcome::<String>::Wait { source_ref, .. } =
            StateHandlerOutcome::wait("reason".into())
        else {
            unreachable!()
        };
        assert_eq!(source_ref.line(), line!() - 4);
        assert_eq!(source_ref.file(), file!());

        let StateHandlerOutcome::<String>::Transition { source_ref, .. } =
            StateHandlerOutcome::transition("next".into())
        else {
            unreachable!()
        };
        assert_eq!(source_ref.line(), line!() - 4);
        assert_eq!(source_ref.file(), file!());

        let StateHandlerOutcome::<String>::Deleted { _source_ref } = StateHandlerOutcome::deleted()
        else {
            unreachable!()
        };
        assert_eq!(_source_ref.line(), line!() - 4);
        assert_eq!(_source_ref.file(), file!());
    }
}
