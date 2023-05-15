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

use opentelemetry::metrics::Meter;

use crate::{
    db::DatabaseError,
    kubernetes::{VpcApi, VpcApiError},
    model::machine::{machine_id::MachineId, ManagedHostState},
    redfish::RedfishClientPool,
    resource_pool::{DbResourcePool, ResourcePoolError},
    state_controller::{controller::ReachabilityParams, snapshot_loader::SnapshotLoaderError},
};

/// Services that are accessible to the `StateHandler`
pub struct StateHandlerServices {
    /// A database connection pool that can be used for additional queries
    pub pool: sqlx::PgPool,

    /// API for interaction with Forge VPC
    pub vpc_api: Arc<dyn VpcApi>,

    /// API for interaction with Forge VPC
    pub forge_api: Arc<dyn rpc::forge::forge_server::Forge>,

    /// API for interaction with Libredfish
    pub redfish_client_pool: Arc<dyn RedfishClientPool>,

    // Reachability params to check if DPU is up or not.
    pub reachability_params: ReachabilityParams,

    /// Resource pool for VNI (VXLAN ID) allocate/release
    /// None if VPC is managing this data
    pub pool_vlan_id: Option<Arc<DbResourcePool<i16>>>,

    /// Resource pool for VLAN ID alllocate/release
    /// None if VPC is managing this data
    pub pool_vni: Option<Arc<DbResourcePool<i32>>>,

    /// Meter for emitting metrics
    pub meter: Option<Meter>,
}

/// Context parameter passed to `StateHandler`
pub struct StateHandlerContext<'a> {
    /// Services that are available to the `StateHandler`
    pub services: &'a Arc<StateHandlerServices>,
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

    async fn handle_object_state(
        &self,
        object_id: &Self::ObjectId,
        state: &mut Self::State,
        controller_state: &mut ControllerStateReader<Self::ControllerState>,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError>;
}

/// Error type for handling a Machine State
#[derive(Debug, thiserror::Error)]
pub enum StateHandlerError {
    #[error("Unable to load state snapshot: {0}")]
    LoadSnapshotError(#[from] SnapshotLoaderError),
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] sqlx::Error),
    #[error("Failed interaction with VPC: {0}")]
    VpcApiError(#[from] VpcApiError),
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
    #[error("Invalid host state {1} for DPU {0}.")]
    InvalidHostState(MachineId, ManagedHostState),
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
            StateHandlerError::VpcApiError(_) => "vpc_api_error",
            StateHandlerError::MachineNotFoundError(_) => "machine_not_found_error",
            StateHandlerError::HostSnapshotMissing(_, _) => "host_snapshot_missing",
            StateHandlerError::GenericError(_) => "generic_error",
            StateHandlerError::MissingData { .. } => "missing_data",
            StateHandlerError::DBError(_) => "db_error",
            StateHandlerError::PoolReleaseError(_) => "pool_release_error",
        }
    }
}

/// A `StateHandler` implementation which does nothing
pub struct NoopStateHandler<I, S, CS> {
    _phantom_data: std::marker::PhantomData<Option<(I, S, CS)>>,
}

impl<I, S, CS> std::fmt::Debug for NoopStateHandler<I, S, CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoopStateHandler").finish()
    }
}

impl<I, S, CS> Default for NoopStateHandler<I, S, CS> {
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
    > StateHandler for NoopStateHandler<I, S, CS>
{
    type State = S;
    type ControllerState = CS;
    type ObjectId = I;

    async fn handle_object_state(
        &self,
        _object_id: &Self::ObjectId,
        _state: &mut Self::State,
        _controller_state: &mut ControllerStateReader<Self::ControllerState>,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        Ok(())
    }
}
