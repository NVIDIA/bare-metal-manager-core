/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
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

use crate::{
    kubernetes::{VpcApi, VpcApiError},
    state_controller::snapshot_loader::SnapshotLoaderError,
};

/// Services that are accessible to the `StateHandler`
#[derive(Debug)]
pub struct StateHandlerServices {
    /// A database connection pool that can be used for additional queries
    pub pool: sqlx::PgPool,
    /// API for interaction with Forge VPC
    pub vpc_api: Arc<dyn VpcApi>,
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
    type ObjectId;
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
impl<I: Send + Sync + 'static, S: Send + Sync + 'static, CS: Send + Sync + 'static> StateHandler
    for NoopStateHandler<I, S, CS>
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
