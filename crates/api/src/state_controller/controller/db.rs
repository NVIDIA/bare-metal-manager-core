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

//! Database access methods used in the StateController framework

use db::work_lock_manager::{AcquireLockError, WorkLockManagerHandle};
use db::{BIND_LIMIT, DatabaseError};
use sqlx::{PgConnection, PgPool};

use crate::api::TransactionVending;
use crate::state_controller::controller::{
    ControllerIteration, ControllerIterationId, LockedControllerIteration, QueuedObject,
};

/// Inserts a new entry into the iteration table
async fn create_iteration(
    txn: &mut PgConnection,
    table_id: &str,
) -> Result<ControllerIteration, DatabaseError> {
    let query = format!("INSERT INTO {table_id} DEFAULT VALUES RETURNING *");
    sqlx::query_as::<_, ControllerIteration>(&query)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new("ControllerIteration::insert", e))
}

/// Loads all iterations, with the latest iteration being the last entry in the results
#[cfg(test)]
pub async fn fetch_iterations(
    txn: &mut PgConnection,
    table_id: &str,
) -> Result<Vec<ControllerIteration>, DatabaseError> {
    let query = format!("SELECT * FROM {table_id} ORDER BY id ASC");
    sqlx::query_as::<_, ControllerIteration>(&query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("ControllerIteration::fetch_iterations", e))
}

/// Deletes entries from the iteration table that are no longer required in order
/// to cap the maximum length of the table. By default 10 entries are retained.
/// The minimum amount required is 2 (current iteration and last iteration that is
/// still in progress).
pub async fn delete_old_iterations(
    txn: &mut PgConnection,
    table_id: &str,
    current_iteration_id: ControllerIterationId,
) -> Result<(), DatabaseError> {
    /// Iterations to retain
    const NUM_RETAINED: u64 = 10;

    let last_retained = (current_iteration_id.0 as u64).saturating_sub(NUM_RETAINED) + 1;

    let query = format!("DELETE FROM {table_id} WHERE id < $1");
    sqlx::query(&query)
        .bind(last_retained as i64)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::new("ControllerIteration::delete_old_iterations", e))?;

    Ok(())
}

/// Acquires a work lock for iteration_table and creates a new entry in it, returning the ControllerIteration
/// along with the WorkLock.
pub async fn lock_and_start_iteration(
    pool: &PgPool,
    work_lock_manager_handle: &WorkLockManagerHandle,
    table_id: &str,
) -> Result<LockedControllerIteration, LockIterationTableError> {
    let work_lock = work_lock_manager_handle
        .try_acquire_lock(format!("lock_iteration::{table_id}"))
        .await?;
    let mut txn = pool.txn_begin().await?;
    let iteration_data = create_iteration(&mut txn, table_id).await?;
    delete_old_iterations(&mut txn, table_id, iteration_data.id).await?;
    txn.commit().await?;
    Ok(LockedControllerIteration {
        iteration_data,
        _work_lock: work_lock,
    })
}

#[derive(thiserror::Error, Debug)]
pub enum LockIterationTableError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    #[error(transparent)]
    AcquireLock(#[from] AcquireLockError),
}

/// Enqueues object IDs for processing into the queued objects table with name `table_id`
pub async fn queue_objects(
    txn: &mut PgConnection,
    table_id: &str,
    queued_objects: &[(String, ControllerIterationId)],
) -> Result<(), DatabaseError> {
    // Make sure we are not running into the BIND_LIMIT
    // The theoretical limit would be BIND_LIMIT/2 (for 2 parameters)
    // However shorter transactions are ok here - we still queue 1k objects
    // per chunk
    const OBJECTS_PER_QUERY: usize = BIND_LIMIT / 32;

    for queued_objects in queued_objects.chunks(OBJECTS_PER_QUERY) {
        let mut builder = sqlx::QueryBuilder::new("INSERT INTO ");
        builder.push(table_id);
        builder.push("(object_id, iteration_id)");

        builder.push_values(queued_objects, |mut b, (object_id, iteration_id)| {
            b.push_bind(object_id).push_bind(iteration_id.0);
        });

        builder.push("ON CONFLICT (object_id) DO UPDATE SET iteration_id=EXCLUDED.iteration_id");
        let query = builder.build();

        let _result = query
            .execute(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new("StateController::queue_object", e))?;
    }

    Ok(())
}

/// Fetches all objects which have been queued for execution
#[cfg(test)]
pub async fn fetch_queued_objects(
    txn: &mut PgConnection,
    table_id: &str,
) -> Result<Vec<QueuedObject>, DatabaseError> {
    let query = format!("SELECT * from {table_id} ORDER BY iteration_id ASC");

    let result = sqlx::query_as(&query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("StateController::fetch_queued_objects", e))?;

    Ok(result)
}

/// Dequeues all objects which have been scheduled for execution
pub async fn dequeue_queued_objects(
    txn: &mut PgConnection,
    table_id: &str,
) -> Result<Vec<QueuedObject>, DatabaseError> {
    // This query is more complicated that it needs to be:
    // DELETE FROM {table_id} RETURNING *
    // would achieve the same. however this meant to be forward compatible with adding a limit
    // of dequeued objects. If we dequeue with a limit, we want to make sure we dequeue old
    // objects first
    let query = format!(
        "WITH dequeued_ids AS (
            SELECT object_id FROM {table_id} ORDER BY iteration_id ASC FOR UPDATE SKIP LOCKED
        )
        DELETE FROM {table_id} WHERE object_id in (SELECT object_id FROM dequeued_ids) RETURNING *"
    );

    let result = sqlx::query_as(&query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("StateController::dequeue_queued_objects", e))?;

    Ok(result)
}
