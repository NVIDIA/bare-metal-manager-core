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

use crate::state_controller::snapshot_loader::SnapshotLoaderError;

/// Services that are accessible to the `StateHandler`
#[derive(Debug)]
pub struct StateHandlerServices {
    /// A database connection pool that can be used for additional queries
    pub pool: sqlx::PgPool,
}

/// Context parameter passed to `StateHandler`
pub struct StateHandlerContext<'a> {
    /// Services that are available to the `StateHandler`
    pub services: &'a Arc<StateHandlerServices>,
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

    async fn handle_object_state(
        &self,
        object_id: &Self::ObjectId,
        state: &mut Self::State,
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
}

/// A `StateHandler` implementation which does nothing
pub struct NoopStateHandler<I, S> {
    _phantom_data: std::marker::PhantomData<Option<(I, S)>>,
}

impl<I, S> std::fmt::Debug for NoopStateHandler<I, S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoopStateHandler").finish()
    }
}

impl<I, S> Default for NoopStateHandler<I, S> {
    fn default() -> Self {
        Self {
            _phantom_data: Default::default(),
        }
    }
}

#[async_trait::async_trait]
impl<I: Send + Sync + 'static, S: Send + Sync + 'static> StateHandler for NoopStateHandler<I, S> {
    type State = S;
    type ObjectId = I;

    async fn handle_object_state(
        &self,
        _object_id: &Self::ObjectId,
        _state: &mut Self::State,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut StateHandlerContext,
    ) -> Result<(), StateHandlerError> {
        Ok(())
    }
}
