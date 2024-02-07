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

use libredfish::RedfishError;
use opentelemetry::metrics::Meter;

use crate::{
    db::DatabaseError,
    ib::IBFabricManager,
    ipmitool::IPMITool,
    model::machine::{machine_id::MachineId, ManagedHostState},
    redfish::{RedfishClientCreationError, RedfishClientPool},
    resource_pool::{DbResourcePool, ResourcePoolError},
    state_controller::{controller::ReachabilityParams, snapshot_loader::SnapshotLoaderError},
};

/// Services that are accessible to the `StateHandler`
pub struct StateHandlerServices {
    /// A database connection pool that can be used for additional queries
    pub pool: sqlx::PgPool,

    /// API for interaction with Forge
    pub forge_api: Arc<dyn rpc::forge::forge_server::Forge>,

    /// API for interaction with Libredfish
    pub redfish_client_pool: Arc<dyn RedfishClientPool>,

    // Reachability params to check if DPU is up or not.
    pub reachability_params: ReachabilityParams,

    /// Meter for emitting metrics
    pub meter: Option<Meter>,

    /// API for interaction with Forge IBFabricManager
    pub ib_fabric_manager: Arc<dyn IBFabricManager>,

    /// Resource pool for ib pkey allocate/release.
    pub pool_pkey: Option<Arc<DbResourcePool<i16>>>,

    /// An implementation of the IPMITool that understands how to reboot a machine
    pub ipmi_tool: Arc<dyn IPMITool>,
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
}

/// An object which makes the current controller state available to a state handler
///
/// The state can be read accessed by default via dereferencing the holder to the
/// state type.
///
/// For write access, the `.as_mut()` method can be used.
/// If the state is write accessed, the new state will be automatically be persisted.
pub struct ControllerStateReader<'a, S> {
    state: &'a mut S,
    /// Whether the state might possibly have been mutated
    is_modified: bool,
}

impl<'a, S> std::ops::Deref for ControllerStateReader<'a, S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        self.state
    }
}

impl<'a, S> ControllerStateReader<'a, S> {
    pub fn new(state: &'a mut S) -> Self {
        Self {
            state,
            is_modified: false,
        }
    }

    /// Whether the state might have been modified
    ///
    /// If this flag is true, the new state will be persisted
    pub fn is_modified(&self) -> bool {
        self.is_modified
    }

    /// Provides write access to the controller state
    ///
    /// One this function is called, the state will be automatically persisted
    pub fn modify(&mut self) -> ControllerStateModifier<'_, S> {
        self.is_modified = true;
        ControllerStateModifier { state: self.state }
    }
}

/// A guard object that allows to mutate the actual ControllerState
///
/// If the state was modified, the new state will automatically be persisted
pub struct ControllerStateModifier<'a, S> {
    state: &'a mut S,
}

impl<'a, S> std::ops::Deref for ControllerStateModifier<'a, S> {
    type Target = S;

    fn deref(&self) -> &Self::Target {
        self.state
    }
}

impl<'a, S> std::ops::DerefMut for ControllerStateModifier<'a, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.state
    }
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
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<(), StateHandlerError>;
}

/// Error type for handling a Machine State
#[derive(Debug, thiserror::Error)]
pub enum StateHandlerError {
    #[error("Unable to load state snapshot: {0}")]
    LoadSnapshotError(#[from] SnapshotLoaderError),
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] sqlx::Error),
    #[error("Machine not found: {0}")]
    MachineNotFoundError(MachineId),
    // TODO: This should be replaced - but requires downstream errors to migrate
    // off from CarbideError
    #[error("Unable to load snapshot: {0}")]
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
    #[error("Can not allocate resource. Pool for {owner_id} is exhausted.")]
    PoolAllocateError { owner_id: String },

    #[error("Invalid host state {1} for DPU {0}.")]
    InvalidHostState(MachineId, ManagedHostState),

    #[error("Failed to call IBFabricManager: {0}")]
    IBFabricError(String),

    #[error("Failed to create redfish client: {0}")]
    RedfishClientCreationError(#[from] RedfishClientCreationError),

    #[error("The state handler for object {object_id} in state \"{state}\" timed out")]
    Timeout { object_id: String, state: String },

    #[error("Failed redfish operation: {operation}. Details: {error}")]
    RedfishError {
        operation: &'static str,
        error: RedfishError,
    },
}

impl StateHandlerError {
    /// Returns the label that will be used to identify the error in metrics
    ///
    /// This will be a simplified description of the error, to avoid having too
    /// many metric dimensions.
    pub fn metric_label(&self) -> &'static str {
        match self {
            StateHandlerError::LoadSnapshotError(_) => "load_snapshot_error",
            StateHandlerError::TransactionError(_) => "transaction_error",
            StateHandlerError::MachineNotFoundError(_) => "machine_not_found_error",
            StateHandlerError::GenericError(_) => "generic_error",
            StateHandlerError::MissingData { .. } => "missing_data",
            StateHandlerError::DBError(_) => "db_error",
            StateHandlerError::Timeout { .. } => "timeout",
            StateHandlerError::PoolReleaseError(_) => "pool_release_error",
            StateHandlerError::PoolAllocateError { .. } => "pool_allocate_error",
            StateHandlerError::InvalidHostState(_, _) => "invalid_host_state",
            StateHandlerError::IBFabricError(_) => "ib_fabric_error",
            StateHandlerError::RedfishClientCreationError(_) => "redfish_client_creation_error",
            StateHandlerError::RedfishError { operation, .. } => match *operation {
                "restart" => "redfish_restart_error",
                "lockdown" => "redfish_lockdown_error",
                _ => "redfish_other_error",
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
        _controller_state: &mut ControllerStateReader<Self::ControllerState>,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut StateHandlerContext<Self::ContextObjects>,
    ) -> Result<(), StateHandlerError> {
        Ok(())
    }
}
