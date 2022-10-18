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
    machine_state_controller::snapshot_loader::{
        MachineStateSnapshotLoader, MachineStateSnapshotLoaderError,
    },
    model::machine::MachineStateSnapshot,
};

/// Services that are accessible to the `MachineStateHandler`
#[derive(Debug)]
pub struct MachineStateHandlerServices {
    /// A database connection pool that can be used for additional queries
    pub pool: sqlx::PgPool,
    /// Allows to load the latest `MachineStateSnapshot` for a `Machine`
    pub snapshot_loader: Box<dyn MachineStateSnapshotLoader>,
}

/// Context parameter passed to `MachineStateHandler`
pub struct MachineStateHandlerContext<'a> {
    /// Services that are available to the `MachineStateHandler`
    pub services: &'a Arc<MachineStateHandlerServices>,
}

/// Defines a function that will be called to determine the next step in
/// a `Machine`s lifecycle.
///
/// The function retrieves the full `Machine` state as loaded from the database
/// as input, and can take any decisions to advance the `Machine` state.
#[async_trait::async_trait]
pub trait MachineStateHandler: std::fmt::Debug + Send + Sync + 'static {
    async fn handle_machine_state(
        &self,
        state: &mut MachineStateSnapshot,
        txn: &mut sqlx::Transaction<sqlx::Postgres>,
        ctx: &mut MachineStateHandlerContext,
    ) -> Result<(), MachineStateHandlerError>;
}

/// Error type for handling a Machine State
#[derive(Debug, thiserror::Error)]
pub enum MachineStateHandlerError {
    #[error("Unable to load machine state snapshot: {0}")]
    LoadSnapshotError(#[from] MachineStateSnapshotLoaderError),
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] sqlx::Error),
}

/// A `MachineStateHandler` implementation which does nothing
#[derive(Debug, Default)]
pub struct NoopMachineStateHandler {}

#[async_trait::async_trait]
impl MachineStateHandler for NoopMachineStateHandler {
    async fn handle_machine_state(
        &self,
        _state: &mut MachineStateSnapshot,
        _txn: &mut sqlx::Transaction<sqlx::Postgres>,
        _ctx: &mut MachineStateHandlerContext,
    ) -> Result<(), MachineStateHandlerError> {
        Ok(())
    }
}
