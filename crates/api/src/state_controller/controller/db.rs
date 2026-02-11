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

//! Database access methods used in the StateController framework

use std::fmt::Write;

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

/// Loads the given amount iterations, starting by the newest iteration
pub async fn fetch_iterations(
    txn: &mut PgConnection,
    table_id: &str,
    limit: Option<usize>,
) -> Result<Vec<ControllerIteration>, DatabaseError> {
    let mut query = format!("SELECT * FROM {table_id} ORDER BY id DESC");
    if let Some(limit) = limit {
        write!(&mut query, " LIMIT {limit}").unwrap();
    }
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
/// If the object is enqueued, then keep the current entry. That guarantees that the object will be processed
/// with the oldest possible run id and that the processed_by field won't get lost.
pub async fn queue_objects(
    txn: &mut PgConnection,
    table_id: &str,
    queued_objects: &[String],
) -> Result<usize, DatabaseError> {
    // Object IDs need to be sorted in order to avoid a deadlock on concurrent calls to this
    // method.
    // If the object IDs would not be sorted and e.g.
    // - client 1 inserts "A", "B", "C"
    // - client 2 inserts "C", "B", "A"
    // then it is possible that
    // - the first DB transaction acquires a lock on row "A", and "B"
    // - the second DB transaction acquires a lock on row "B" and "C"
    // - the first DB transcation would wait forever to acquire the lock on "C"
    // - the second DB transaction would wait forever to acquire the lock on "B"
    //
    // An alternative to this would be to require the caller to present the
    // objects in stable order - however this would require a common understanding
    // of sort order across all callers.
    let mut sorted = queued_objects.to_vec();
    sorted.sort();
    // Make sure we are not running into the BIND_LIMIT
    // The theoretical limit would be BIND_LIMIT
    // However shorter transactions are ok here - we still queue 1k objects
    // per chunk
    const OBJECTS_PER_QUERY: usize = BIND_LIMIT / 32;

    let mut num_enqueued = 0;

    for queued_objects in sorted.chunks(OBJECTS_PER_QUERY) {
        let mut builder = sqlx::QueryBuilder::new("INSERT INTO ");
        builder.push(table_id);
        builder.push("(object_id)");

        builder.push_values(queued_objects, |mut b, object_id| {
            b.push_bind(object_id);
        });

        builder.push("ON CONFLICT (object_id) DO NOTHING");
        let query = builder.build();

        let result = query
            .execute(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new("StateController::queue_object", e))?;
        num_enqueued += result.rows_affected() as usize;
    }

    Ok(num_enqueued)
}

/// Fetches all objects which have been queued for execution
#[cfg(test)]
pub async fn fetch_queued_objects(
    txn: &mut PgConnection,
    table_id: &str,
) -> Result<Vec<QueuedObject>, DatabaseError> {
    let query = format!("SELECT * from {table_id}");

    let result = sqlx::query_as(&query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("StateController::fetch_queued_objects", e))?;

    Ok(result)
}

/// Fetches a certain amount of queued objects from the database which will be processed by the
/// current processor.
/// The objects will be marked as `processed_by` with the given ID - which will avoid
/// other processors to pick up the objects.
pub async fn acquire_queued_objects(
    txn: &mut PgConnection,
    table_id: &str,
    count: u32, // u32 to avoid u64 numbers getting passed that are not valid in postgres
    processor_id: &str,
    max_outdated: std::time::Duration,
) -> Result<Vec<QueuedObject>, DatabaseError> {
    let query = format!(
        "WITH dequeued_ids AS (
            SELECT object_id FROM {table_id} WHERE (processed_by IS NULL OR processing_started_at + $1::interval < now()) FOR UPDATE SKIP LOCKED LIMIT {count}
        )
        UPDATE {table_id} SET processed_by=$2, processing_started_at=now() WHERE object_id in (SELECT object_id FROM dequeued_ids) RETURNING *"
    );

    let result = sqlx::query_as(&query)
        .bind(max_outdated)
        .bind(processor_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("StateController::acquire_queued_objects", e))?;

    Ok(result)
}

pub async fn delete_queued_objects(
    txn: &mut PgConnection,
    table_id: &str,
    object_ids: &[String],
    processor_id: &str,
) -> Result<usize, DatabaseError> {
    // Make sure we are not running into the BIND_LIMIT
    // The theoretical limit would be BIND_LIMIT/2 (for 2 parameters)
    // However shorter transactions are ok here - we still queue 1k objects
    // per chunk
    const OBJECTS_PER_QUERY: usize = BIND_LIMIT / 32;

    let mut num_deleted = 0;
    for queued_objects in object_ids.chunks(OBJECTS_PER_QUERY) {
        let mut builder = sqlx::QueryBuilder::new("DELETE FROM ");
        builder.push(table_id);
        builder.push(" WHERE object_id IN(");
        let mut separated = builder.separated(", ");
        for object_id in queued_objects.iter() {
            separated.push_bind(object_id);
        }
        builder.push(") AND processed_by = ");
        builder.push_bind(processor_id);

        let query = builder.build();
        let result = query
            .execute(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new("StateController::delete_queued_objects", e))?;

        num_deleted += result.rows_affected();
    }

    Ok(num_deleted as usize)
}
