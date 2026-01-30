/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::db::DatabaseError;
use ::db::work_lock_manager::WorkLock;
use chrono::{DateTime, Utc};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Row};
use tokio_util::sync::CancellationToken;

use crate::state_controller::controller::periodic_enqueuer::PeriodicEnqueuer;
use crate::state_controller::io::StateControllerIO;
use crate::state_controller::state_handler::StateHandlerError;

mod builder;
pub mod db;
mod enqueuer;
pub use enqueuer::Enqueuer;
pub mod periodic_enqueuer;
pub mod processor;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ControllerIterationId(pub i64);

/// Metadata for a single state controller iteration
#[derive(Debug, Clone)]
pub struct ControllerIteration {
    /// The ID of the iteration
    pub id: ControllerIterationId,
    /// When the iteration started
    #[allow(dead_code)]
    pub started_at: DateTime<Utc>,
}

pub struct LockedControllerIteration {
    pub iteration_data: ControllerIteration,
    /// The lock for the work done in this iteration.
    pub _work_lock: WorkLock,
}

impl<'r> FromRow<'r, PgRow> for ControllerIteration {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let id: i64 = row.try_get("id")?;
        let started_at = row.try_get("started_at")?;
        Ok(ControllerIteration {
            id: ControllerIterationId(id),
            started_at,
        })
    }
}

/// Metadata for a single state controller iteration
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueuedObject {
    /// The ID of the object which should get scheduled
    pub object_id: String,
    /// Identifies the processor which is executing the state handler
    /// The value of this field will be NULL in case the object is not yet processed
    pub processed_by: Option<String>,
}

impl<'r> FromRow<'r, PgRow> for QueuedObject {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let object_id = row.try_get("object_id")?;
        let processed_by: Option<String> = row.try_get("processed_by")?;
        Ok(QueuedObject {
            object_id,
            processed_by,
        })
    }
}

/// The object static controller evaluates the current state of all objects of a
/// certain type in a Forge site, and decides which actions the system should
/// undertake to bring the state inline with the state users requested.
///
/// Each Forge API server is running a StateController instance for each object type.
/// While all instances run in parallel, the StateController uses internal
/// synchronization to make sure that inside a single site - only a single controller
/// will decide the next step for a single object.
pub struct StateController<IO: StateControllerIO> {
    enqueuer: PeriodicEnqueuer<IO>,
    processor: processor::StateProcessor<IO>,
}

impl<IO: StateControllerIO> StateController<IO> {
    /// Returns a [`Builder`] for configuring `StateController`
    pub fn builder() -> builder::Builder<IO> {
        builder::Builder::default()
    }

    /// Enqueues state handling tasks for all objects and processes them
    #[cfg(test)]
    pub async fn run_single_iteration(&mut self) {
        self.run_single_iteration_ext(true).await
    }

    /// Enqueues state handling tasks for all objects and processes them
    #[cfg(test)]
    pub async fn run_single_iteration_ext(&mut self, allow_requeue: bool) {
        let enqueuer_result = self.enqueuer.run_single_iteration().await;
        loop {
            if let Err(err) = self
                .processor
                .run_single_iteration(std::time::Duration::MAX, allow_requeue)
                .await
            {
                tracing::error!(%err, "State processor iteration error");
            }
            if self.processor.in_flight.is_empty() {
                break;
            }
        }
        // Immediately emit the latest set of metrics
        self.processor
            .emit_metrics_for_iteration(enqueuer_result.iteration.map(|iteration| iteration.id));
    }
}

#[derive(Debug, thiserror::Error)]
enum IterationError {
    #[error("Unable to perform database transaction: {0}")]
    TransactionError(#[from] sqlx::Error),
    #[error("Unable to perform database transaction: {0}")]
    DatabaseError(#[from] DatabaseError),
    #[error("Unable to acquire lock and start iteration")]
    LockError,
    #[error("A task panicked: {0}")]
    Panic(#[from] tokio::task::JoinError),
    #[error("State handler error: {0}")]
    StateHandlerError(#[from] StateHandlerError),
}

/// A remote handle for the state controller
pub struct StateControllerHandle {
    /// Instructs the state conroller to stop.
    stop_token: CancellationToken,
}

impl Drop for StateControllerHandle {
    fn drop(&mut self) {
        self.stop_token.cancel();
    }
}
