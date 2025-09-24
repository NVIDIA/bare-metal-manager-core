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

use std::sync::Arc;

use crate::cfg::file::CarbideConfig;
use crate::model::power_manager::PowerOptions;
use crate::resource_pool::common::IbPools;
use crate::storage::StorageError;
use crate::{
    db::DatabaseError,
    ib::IBFabricManager,
    ipmitool::IPMITool,
    model::machine::ManagedHostState,
    redfish::{RedfishClientCreationError, RedfishClientPool},
    resource_pool::ResourcePoolError,
    storage::NvmeshClientPool,
};
use forge_uuid::machine::MachineId;
use libredfish::RedfishError;
use mqttea::MqtteaClient;
use sqlx::PgConnection;

/// Services that are accessible to the `StateHandler`
pub struct StateHandlerServices {
    /// A database connection pool that can be used for additional queries
    pub pool: sqlx::PgPool,

    /// API for interaction with Libredfish
    pub redfish_client_pool: Arc<dyn RedfishClientPool>,

    /// API for interaction with Forge IBFabricManager
    pub ib_fabric_manager: Arc<dyn IBFabricManager>,

    /// API for interaction with NVMesh storage cluster
    pub nvmesh_client_pool: Arc<dyn NvmeshClientPool>,

    /// Resource pools for ib pkey allocation/release.
    pub ib_pools: IbPools,

    /// An implementation of the IPMITool that understands how to reboot a machine
    pub ipmi_tool: Arc<dyn IPMITool>,

    /// Access to the site config
    pub site_config: Arc<CarbideConfig>,

    pub mqtt_client: Option<Arc<MqtteaClient>>,
}

/// The collection of generic objects which are referenced in StateHandlerContext
pub trait StateHandlerContextObjects: Send + Sync + 'static {
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
    pub services: &'a Arc<StateHandlerServices>,
    /// Metrics that are produced as a result of acting on an object
    pub metrics: &'a mut T::ObjectMetrics,
    /// Power Options.
    pub power_options: Option<PowerOptions>,
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
        txn: &mut PgConnection,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<Self::ControllerState>, StateHandlerError>;
}

/// References the source code that lead to the result
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct SourceReference {
    pub file: &'static str,
    pub line: u32,
}

pub enum StateHandlerOutcome<S> {
    Wait {
        /// The reason we're waiting
        reason: String,
        source_ref: SourceReference,
    },
    Transition {
        /// The state we are transitioning to
        next_state: S,
        source_ref: SourceReference,
    },
    DoNothing {
        source_ref: SourceReference,
    }, // Nothing to do. Typically in Ready or Assigned/Ready
    Deleted {
        source_ref: SourceReference,
    }, // The object was removed from the database
}

macro_rules! source_ref {
    () => {
        crate::state_controller::state_handler::SourceReference {
            file: file!(),
            line: line!(),
        }
    };
}
pub(crate) use source_ref;

macro_rules! do_nothing {
    () => {
        StateHandlerOutcome::DoNothing {
            source_ref: crate::state_controller::state_handler::source_ref!(),
        }
    };
}

macro_rules! transition {
    ($next_state:expr) => {
        StateHandlerOutcome::Transition {
            next_state: $next_state,
            source_ref: crate::state_controller::state_handler::source_ref!(),
        }
    };
}

macro_rules! wait {
    ($reason:expr) => {
        StateHandlerOutcome::Wait {
            reason: $reason,
            source_ref: crate::state_controller::state_handler::source_ref!(),
        }
    };
}

macro_rules! deleted {
    () => {
        StateHandlerOutcome::Deleted {
            source_ref: crate::state_controller::state_handler::source_ref!(),
        }
    };
}

pub(crate) use deleted;
pub(crate) use do_nothing;
pub(crate) use transition;
pub(crate) use wait;

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

#[derive(Debug)]
pub enum MeasuringProblem {
    NoEkCertVerificationStatusFound(String),
}

impl std::fmt::Display for MeasuringProblem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            MeasuringProblem::NoEkCertVerificationStatusFound(info) => {
                write!(f, "NoEkCertVerificationStatusFound - {info}")
            }
        }
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

    #[error("Storage error {0}")]
    StorageError(#[from] StorageError),

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

    #[error("Dpu: {0} is missing from states.")]
    MissingDpuFromState(MachineId),

    #[error("State will not be advanced due to health probe alert")]
    HealthProbeAlert,

    #[error(
        "The object is in the state for longer than defined by the SLA. Handler outcome: {handler_outcome}"
    )]
    TimeInStateAboveSla { handler_outcome: String },

    #[error("Problem with measured boot: {0}")]
    MeasuringError(MeasuringProblem),

    #[error("Resource {resource} cleanup error: {error}")]
    ResourceCleanupError {
        resource: &'static str,
        error: String,
    },
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
            StateHandlerError::StorageError(_) => "storage_error",
            StateHandlerError::InvalidState(_) => "invalid_state",
            StateHandlerError::RedfishClientCreationError(_) => "redfish_client_creation_error",
            StateHandlerError::RedfishError { operation, .. } => match *operation {
                "restart" => "redfish_restart_error",
                "lockdown" => "redfish_lockdown_error",
                _ => "redfish_other_error",
            },
            StateHandlerError::ManualInterventionRequired(_) => "manual_intervention_required",
            StateHandlerError::MissingDpuFromState(_) => "missing_dpu_from_managedhost_state",
            StateHandlerError::HealthProbeAlert => "health_probe_alert",
            StateHandlerError::TimeInStateAboveSla { .. } => "time_in_state_above_sla",
            StateHandlerError::MeasuringError(problem) => match problem {
                MeasuringProblem::NoEkCertVerificationStatusFound(_) => {
                    "no_ek_cert_verification_status_found"
                }
            },
            StateHandlerError::ResourceCleanupError { resource, .. } => match *resource {
                "VpcLoopbackIp" => "vpcloopback_release_failed",
                "network_segment" => "network_segment_cleanup_failed",
                _ => "resource_cleanup_failed",
            },
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
        _txn: &mut PgConnection,
        _ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<StateHandlerOutcome<Self::ControllerState>, StateHandlerError> {
        Ok(do_nothing!())
    }
}
