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
use std::time::Duration;

use carbide_instrument::{Event, LabelValue, emit};
use sqlx::pool::PoolConnection;
use sqlx::{PgConnection, PgPool, Postgres};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;
use tracing::Instrument;

use crate::{DatabaseError, DatabaseResult};

pub type WorkKey = String;
pub type WorkerId = uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
enum WorkLockOperation {
    Release,
    KeepAlive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, LabelValue)]
enum WorkLockFailure {
    Database,
    CommandDispatch,
    CommandReply,
    LockLost,
}

// These Events share one counter. Keep its kind, description, and label keys
// identical while each boundary retains its existing diagnostic message and
// context.
#[derive(Event)]
#[event(
    event_name = "work_lock_release_failed",
    metric_name = "carbide_work_lock_failures_total",
    component = "nico-api",
    log = error,
    metric = counter,
    message = "Could not release work lock",
    describe = "Number of work-lock lifecycle failures, by operation and failure kind."
)]
struct WorkLockReleaseFailed {
    #[label]
    operation: WorkLockOperation,
    #[label]
    failure: WorkLockFailure,
    #[context]
    work_key: WorkKey,
    #[context]
    error: String,
}

impl WorkLockReleaseFailed {
    fn new(work_key: WorkKey, error: &DatabaseError) -> Self {
        Self {
            operation: WorkLockOperation::Release,
            failure: match error {
                DatabaseError::FailedPrecondition(_) => WorkLockFailure::LockLost,
                _ => WorkLockFailure::Database,
            },
            work_key,
            error: error.to_string(),
        }
    }
}

#[derive(Event)]
#[event(
    event_name = "work_lock_release_dispatch_failed",
    metric_name = "carbide_work_lock_failures_total",
    component = "nico-api",
    log = error,
    metric = counter,
    message = "Could not release work lock: WorkLockManager queue is full; database is likely overloaded",
    describe = "Number of work-lock lifecycle failures, by operation and failure kind."
)]
struct WorkLockReleaseDispatchFailed {
    #[label]
    operation: WorkLockOperation,
    #[label]
    failure: WorkLockFailure,
    #[context]
    work_key: WorkKey,
    #[context]
    worker_id: WorkerId,
    #[context]
    error: String,
}

impl WorkLockReleaseDispatchFailed {
    fn new(work_key: WorkKey, worker_id: WorkerId, error: String) -> Self {
        Self {
            operation: WorkLockOperation::Release,
            failure: WorkLockFailure::CommandDispatch,
            work_key,
            worker_id,
            error,
        }
    }
}

#[derive(Event)]
#[event(
    event_name = "work_lock_lost",
    metric_name = "carbide_work_lock_failures_total",
    component = "nico-api",
    log = error,
    metric = counter,
    message = "worker lost lock",
    describe = "Number of work-lock lifecycle failures, by operation and failure kind."
)]
struct WorkLockLost {
    #[label]
    operation: WorkLockOperation,
    #[label]
    failure: WorkLockFailure,
    #[context]
    work_key: WorkKey,
    #[context]
    worker_id: WorkerId,
    #[context]
    error: String,
}

impl WorkLockLost {
    fn new(work_key: WorkKey, worker_id: WorkerId, error: String) -> Self {
        Self {
            operation: WorkLockOperation::KeepAlive,
            failure: WorkLockFailure::LockLost,
            work_key,
            worker_id,
            error,
        }
    }
}

#[derive(Event)]
#[event(
    event_name = "work_lock_keepalive_failed",
    metric_name = "carbide_work_lock_failures_total",
    component = "nico-api",
    log = error,
    metric = counter,
    message = "Failed to send work-lock keepalive; retrying",
    describe = "Number of work-lock lifecycle failures, by operation and failure kind."
)]
struct WorkLockKeepaliveFailed {
    #[label]
    operation: WorkLockOperation,
    #[label]
    failure: WorkLockFailure,
    #[context]
    work_key: WorkKey,
    #[context]
    worker_id: WorkerId,
    #[context]
    error: String,
}

impl WorkLockKeepaliveFailed {
    fn new(
        failure: WorkLockFailure,
        work_key: WorkKey,
        worker_id: WorkerId,
        error: String,
    ) -> Self {
        Self {
            operation: WorkLockOperation::KeepAlive,
            failure,
            work_key,
            worker_id,
            error,
        }
    }
}

/// A WorkLockManager buffers this many messages sent to it: This would only be exceeded if something
/// goes very wrong with the database.
static COMMAND_BUFFER_SIZE: usize = 100;

/// A clone-able handle to a (singleton, global) [`crate::work_lock_manager`] work loop.
///
/// This is used to logically "lock" units of work so that they are only done once at a time,
/// without the overhead of using a postgres advisory lock for every unit of work. Advisory locks
/// require holding a long-running connection to postgres, and are released when the connection is
/// released, which leads to long-lived connections occupying slots in the sqlx pool. Since logical
/// "work" can take a long time, especially when we have to make calls to (unreliable) external
/// services while holding the lock, a WorkLockManager instead does an atomic write to a
/// `work_locks` table, vending [`WorkLock`] objects back, which release the lock on Drop. In case
/// of a crash where drop is not called, each work lock expires after a time interval.
///
/// This is returned by [`start`], and can be used to communicate to acquire [`WorkLock`] items for doing
#[derive(Clone)]
pub struct WorkLockManagerHandle {
    keepalive_interval: Duration,
    cmd_tx: mpsc::Sender<WorkLockManagerCommand>,
}

#[derive(Clone, Copy)]
pub struct KeepaliveConfig {
    /// For any WorkLocks held, they send a keep-alive for their lock at this interval until they're dropped.
    pub interval: Duration,
    /// For any WorkLocks held, if they haven't sent a keep-alive in this long, they've expired.
    pub timeout: Duration,
}

impl Default for KeepaliveConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(10),
            timeout: Duration::from_secs(60),
        }
    }
}

/// Start a work manager in the background. This should only be done once per carbide instance.
///
/// To actually interact with the global work manager, use [`WorkLockManagerHandle`] (returned by this
/// function.)
///
/// This exists as a singleton message loop (instead of just a collection of database methods) for
/// two reasons:
///
/// 1) So that we can eagerly acquire a database connection at process startup, and not contend with
///    the connection pool being exhausted and being unable to keep locks up to date
/// 2) To avoid race conditions, so that locks can be released effecvely "immediately" in
///    [`WorkLock`]'s Drop impl (by placing the release command on the queue), such that the next
///    call to [`WorkLockManagerHandle::try_acquire_lock`] is guaranteed to be processed after the lock is
///    released.
pub async fn start(
    join_set: &mut JoinSet<()>,
    pool: PgPool,
    keepalive_config: KeepaliveConfig,
) -> DatabaseResult<WorkLockManagerHandle> {
    // Use a single long-running postgres connection for the duration of the process, so that we can
    // always do our work, even if the connection pool fills up. But keep the `pool` so that we can
    // grab a new connection if this one ever dies.
    let db: PoolConnection<Postgres> = pool.acquire().await.map_err(DatabaseError::acquire)?;

    let KeepaliveConfig {
        interval: keepalive_interval,
        timeout: keepalive_timeout,
    } = keepalive_config;

    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_BUFFER_SIZE);
    join_set
        .build_task()
        .name("WorkLockManager")
        // Note: don't inherit the callers span, since child spans can't outlive their parent.
        // This prevents a crash in tracing-subscriber.
        .spawn(
            run_loop(pool, db, cmd_rx, keepalive_timeout)
                .instrument(tracing::debug_span!(parent: None, "WorklockManager::run_loop")),
        )
        .expect("failed to start work manager");

    Ok(WorkLockManagerHandle {
        cmd_tx,
        keepalive_interval,
    })
}

// Note: This #[allow(txn_held_across_await)] is intentional, and not temporary. This is debatably
// the one place in the codebase where we actually want to hold open a connection for the whole
// process, because we don't want lock acquisition to be held up if the pool becomes full.
#[allow(txn_held_across_await)]
async fn run_loop(
    pool: PgPool,
    db: PoolConnection<Postgres>,
    mut cmd_rx: mpsc::Receiver<WorkLockManagerCommand>,
    keepalive_timeout: Duration,
) {
    let mut reserved_connection = ReservedConnection(Some(db));

    while let Some(command) = cmd_rx.recv().await {
        let db = match reserved_connection.get_if_healthy().await {
            Some(db) => db,
            None => {
                tracing::info!("WorkLockManager reacquiring database connection");
                let Some(db) = reserved_connection.reacquire(&pool).await else {
                    // Any reply channel for this command will now drop, and readers will get an
                    // error. Calls to ReleaseLock will fail as well, but we can rely on the timeout
                    // behavior with the last_keepalive column to consider the lock released once
                    // we do have a healthy connection.
                    continue;
                };
                db
            }
        };

        match command {
            WorkLockManagerCommand::AcquireLock { work_key, reply_tx } => {
                if reply_tx.is_closed() {
                    tracing::info!("Skipping AcquireLock command: caller already timed out");
                    continue;
                }
                match try_acquire_lock(db, &work_key, keepalive_timeout).await {
                    Ok(Some(worker_id)) => {
                        reply_tx.send(Ok(worker_id)).ok();
                        tracing::debug!(
                            work_key = %work_key,
                            "Acquired work lock",
                        );
                    }
                    Ok(None) => {
                        reply_tx
                            .send(Err(AcquireLockError::WorkAlreadyLocked(work_key)))
                            .ok();
                    }
                    Err(e) => {
                        reply_tx.send(Err(e.into())).ok();
                    }
                }
            }

            WorkLockManagerCommand::ReleaseLock {
                work_key,
                worker_id,
            } => {
                release_lock(db, &work_key, worker_id)
                    .await
                    .inspect_err(|e| {
                        emit(WorkLockReleaseFailed::new(work_key.clone(), e));
                    })
                    .ok();
                tracing::debug!(%work_key, "Released work lock");
            }

            WorkLockManagerCommand::KeepLockAlive {
                work_key,
                worker_id,
                reply_tx,
            } => match keep_lock_alive(db, &work_key, worker_id).await {
                Ok(()) => {
                    reply_tx.send(Ok(())).ok();
                }
                Err(DatabaseError::FailedPrecondition(msg)) => {
                    reply_tx.send(Err(KeepAliveError::LockLost(msg))).ok();
                }
                Err(e) => {
                    reply_tx.send(Err(e.into())).ok();
                }
            },
        }
    }
    tracing::info!("WorkLockManager: all handles dropped, shutting down");
}

/// A long-running connection WorkLockManager uses to manage locks, held open as long as
/// WorkLockManager is running so that we don't hit connection limit issues.
struct ReservedConnection(Option<PoolConnection<Postgres>>);

impl ReservedConnection {
    /// Use the current connection if it exists and is healthy for use by WorkLockManager, else
    /// close it.
    async fn get_if_healthy(&mut self) -> Option<&mut PgConnection> {
        let mut db = self.0.take()?;
        if !Self::connection_is_healthy(&mut db).await {
            // Do not return a live, read-only connection to the pool: it may be handed straight
            // back to us on the next acquire. Closing it also releases its pool slot before the
            // replacement is acquired, which is necessary when the pool is at its limit.
            db.close().await.ok();
            return None;
        }
        Some(self.0.insert(db))
    }

    /// Acquires a connection from the pool, checking if it's healthy and writable.
    async fn reacquire(&mut self, pool: &PgPool) -> Option<&mut PgConnection> {
        let mut db = match pool.acquire().await {
            Ok(db) => db,
            Err(e) => {
                tracing::error!(error = %e, "WorkLockManager could not reacquire database connection");
                return None;
            }
        };

        if !Self::connection_is_healthy(&mut db).await {
            tracing::warn!(
                "WorkLockManager database connection still unhealthy after reconnecting"
            );
            db.close().await.ok();
            return None;
        }

        Some(self.0.insert(db))
    }

    /// Check if the connection is healthy for use by WorkLockManager.
    ///
    /// Healthiness is determined by the connection being available and not inside a read-only
    /// transaction. This is in case the connection becomes a read-only standby, in which case we have
    /// to reconnect.
    async fn connection_is_healthy(db: &mut PgConnection) -> bool {
        match sqlx::query_scalar("SELECT current_setting('transaction_read_only')::bool")
            .fetch_one(db.as_mut())
            .await
        {
            Ok(false) => true,
            Ok(true) => {
                tracing::warn!("WorkLockManager database connection is read-only");
                false
            }
            Err(error) => {
                tracing::warn!(%error, "WorkLockManager database connection closed");
                false
            }
        }
    }
}

/// A lock representing exclusive ownership of a logical, named unit of work. Upon drop, the lock
/// will be released (assuming the global [`crate::work_lock_manager`] is healthy.) If the work manager's
/// buffer is full, the lock will fail to release, and work cannot be locked again until the lock
/// duration has expired.
pub struct WorkLock {
    // When this is dropped, the keepalive loop will exit.
    keepalive_stop_tx: Option<oneshot::Sender<()>>,
    #[cfg(test)]
    join_handle: tokio::task::JoinHandle<()>,
    manager: WorkLockManagerHandle,
    work_key: WorkKey,
    worker_id: WorkerId,
}

impl Drop for WorkLock {
    fn drop(&mut self) {
        tracing::debug!(
            work_key = %self.work_key,
            worker_id = %self.worker_id,
            "Releasing work lock",
        );

        // Let the keepalive loop stop
        self.keepalive_stop_tx.take();

        // Release the lock now
        self.manager
            .cmd_tx
            .try_send(WorkLockManagerCommand::ReleaseLock {
                work_key: self.work_key.clone(),
                worker_id: self.worker_id,
            })
            .inspect_err(|e| {
                emit(WorkLockReleaseDispatchFailed::new(
                    self.work_key.clone(),
                    self.worker_id,
                    e.to_string(),
                ));
            })
            .ok();
    }
}

impl WorkLock {
    fn new(
        manager: WorkLockManagerHandle,
        work_key: WorkKey,
        worker_id: WorkerId,
        keepalive_interval: Duration,
    ) -> Self {
        let (keepalive_stop_tx, mut keepalive_stop_rx) = oneshot::channel();
        let join_handle = tokio::task::Builder::new()
            .name(&format!("keepalive loop for {work_key} worker {worker_id}"))
            .spawn({
                let manager = manager.clone();
                let work_key = work_key.clone();
                let mut keepalive_timer = tokio::time::interval(keepalive_interval);
                keepalive_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
                let fut = async move {
                    loop {
                        tokio::select! {
                            _ = keepalive_timer.tick() => {
                                match manager.keep_lock_alive(work_key.clone(), worker_id).await {
                                    Ok(_) => {}
                                    Err(KeepAliveError::LockLost(msg)) => {
                                        emit(WorkLockLost::new(
                                            work_key,
                                            worker_id,
                                            msg,
                                        ));
                                        return;
                                    }
                                    Err(e) => {
                                        emit(WorkLockKeepaliveFailed::new(
                                            e.failure(),
                                            work_key.clone(),
                                            worker_id,
                                            e.to_string(),
                                        ));
                                    }
                                }
                            }
                            _ = &mut keepalive_stop_rx => {
                                break;
                            }
                        }
                    }
                };
                // Note: don't inherit the callers span, since child spans can't outlive their parent.
                // This prevents a crash in tracing-subscriber.
                fut.instrument(tracing::debug_span!(parent: None, "WorkLock keepalive loop"))
            })
            .expect("could not spawn tokio task");

        if !cfg!(test) {
            _ = join_handle;
        }

        WorkLock {
            keepalive_stop_tx: Some(keepalive_stop_tx),
            manager,
            work_key,
            worker_id,
            #[cfg(test)]
            join_handle,
        }
    }

    #[cfg(test)]
    pub fn is_alive(&self) -> bool {
        !self.join_handle.is_finished()
    }
}

/// Try to acquire a lock for `work_key`o
///
/// Returns `Some(WorkerId)` if the lock was acquired, or `None` if the lock is already being held.
async fn try_acquire_lock(
    pool: &mut PgConnection,
    work_key: &WorkKey,
    keepalive_timeout: Duration,
) -> DatabaseResult<Option<WorkerId>> {
    // Try to acquire the lock if it either doesn't exist, or exists but is expired.
    let query = r#"
WITH upsert AS (
    INSERT INTO work_locks (work_key)
    VALUES ($1)
    ON CONFLICT (work_key)
    DO UPDATE
        SET worker_id          = EXCLUDED.worker_id,
            started            = now(),
            last_keepalive     = now()
        WHERE work_locks.last_keepalive + $2::interval < now()
    RETURNING work_locks.worker_id AS worker_id
)
SELECT worker_id FROM upsert;
    "#;

    sqlx::query_scalar(query)
        .bind(work_key)
        .bind(keepalive_timeout)
        .fetch_optional(pool)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

async fn release_lock(
    pool: &mut PgConnection,
    work_key: &WorkKey,
    worker_id: WorkerId,
) -> DatabaseResult<()> {
    let query = r#"
DELETE FROM work_locks WHERE work_key = $1 AND worker_id = $2 RETURNING work_key
    "#;

    let deleted = sqlx::query_scalar::<_, WorkKey>(query)
        .bind(work_key)
        .bind(worker_id)
        .fetch_all(pool)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    if deleted.is_empty() {
        return Err(DatabaseError::FailedPrecondition(format!(
            "Tried to release nonexistent lock for work_key={}, worker_id={}",
            work_key, worker_id,
        )));
    }

    Ok(())
}

async fn keep_lock_alive(
    pool: &mut PgConnection,
    work_key: &WorkKey,
    worker_id: WorkerId,
) -> DatabaseResult<()> {
    let query = r#"
UPDATE work_locks SET last_keepalive = now() WHERE work_key = $1 AND worker_id = $2 RETURNING work_key
    "#;

    let updated = sqlx::query_scalar::<_, WorkKey>(query)
        .bind(work_key)
        .bind(worker_id)
        .fetch_all(pool)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    if updated.is_empty() {
        return Err(DatabaseError::FailedPrecondition(format!(
            // If this happens, the worker must have been alive (since the WorkLock was still in
            // scope), but didn't send keep-alives within the healthy ping interval. This is a bug,
            // becauase the ping interval should be tuned to account for the maximum amount of time
            // work should take (taking timeouts into account, etc.)
            "BUG: Tried to keep alive nonexistent lock for work_key={}, worker_id={} worker likely was not sending keep-alives frequently enough.",
            work_key, worker_id,
        )));
    }

    Ok(())
}

impl WorkLockManagerHandle {
    pub async fn try_acquire_lock(&self, work_key: WorkKey) -> Result<WorkLock, AcquireLockError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .try_send(WorkLockManagerCommand::AcquireLock {
                work_key: work_key.clone(),
                reply_tx,
            })
            .map_err(|e| AcquireLockError::WorkLockManagerSend(e.to_string()))?;

        let worker_id = reply_rx.await??;

        Ok(WorkLock::new(
            self.clone(),
            work_key,
            worker_id,
            self.keepalive_interval,
        ))
    }

    async fn keep_lock_alive(
        &self,
        work_key: WorkKey,
        worker_id: WorkerId,
    ) -> Result<(), KeepAliveError> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.cmd_tx
            .try_send(WorkLockManagerCommand::KeepLockAlive {
                work_key,
                worker_id,
                reply_tx,
            })
            .map_err(|e| KeepAliveError::WorkLockManagerSend(e.to_string()))?;

        reply_rx.await??;

        Ok(())
    }
}

enum WorkLockManagerCommand {
    AcquireLock {
        work_key: WorkKey,
        reply_tx: oneshot::Sender<Result<WorkerId, AcquireLockError>>,
    },
    KeepLockAlive {
        work_key: WorkKey,
        worker_id: WorkerId,
        reply_tx: oneshot::Sender<Result<(), KeepAliveError>>,
    },
    ReleaseLock {
        work_key: WorkKey,
        worker_id: WorkerId,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum AcquireLockError {
    #[error("work is already locked for {0}")]
    WorkAlreadyLocked(WorkKey),
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// This happens when the channel buffer is full, meaning more than COMMAND_BUFFER_SIZE commands
    /// are queued up waiting for the WorkLockManager to process them. Since a WorkLockManager owns
    /// a long-running connection to the database (and doesn't have to contend with the pool having
    /// no connections available), this should only  happen if the database is completely down, or
    /// is going so slow that simple updates to the table are blocked.
    #[error(
        "error sending AcquireLock command to WorkLockManager, database is likely overloaded: {0}"
    )]
    WorkLockManagerSend(String),
    #[error(
        "BUG: error receiving AcquireLock reply from WorkLockManager, database connections are likely failing: {0}"
    )]
    WorkLockManagerReply(#[from] tokio::sync::oneshot::error::RecvError),
    #[error(transparent)]
    Timeout(#[from] tokio::time::error::Elapsed),
}

#[derive(Debug, thiserror::Error)]
pub enum KeepAliveError {
    #[error("{0}")]
    LockLost(String),
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// See notes in AcquireLockError::WorkLockManagerSend
    #[error(
        "error sending KeepAlive command to WorkLockManager, database is likely overloaded: {0}"
    )]
    WorkLockManagerSend(String),
    #[error(
        "BUG: error receiving KeepAlive reply from WorkLockManager, database connections are likely failing: {0}"
    )]
    WorkLockManagerReply(#[from] tokio::sync::oneshot::error::RecvError),
}

impl KeepAliveError {
    fn failure(&self) -> WorkLockFailure {
        match self {
            Self::LockLost(_) => WorkLockFailure::LockLost,
            Self::Database(_) => WorkLockFailure::Database,
            Self::WorkLockManagerSend(_) => WorkLockFailure::CommandDispatch,
            Self::WorkLockManagerReply(_) => WorkLockFailure::CommandReply,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use carbide_instrument::testing::{MetricsCapture, capture_logs};
    use carbide_test_support::{Check, check_values};
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    const WORK_LOCK_FAILURES_METRIC: &str = "carbide_work_lock_failures_total";

    #[derive(Clone, Copy)]
    enum FailureEvent {
        ReleaseDatabase,
        ReleaseLockLost,
        ReleaseDispatch,
        KeepaliveLockLost,
        KeepaliveDatabase,
        KeepaliveDispatch,
        KeepaliveReply,
    }

    #[derive(Debug, PartialEq)]
    struct FailureRecord {
        metadata_name: String,
        level: tracing::Level,
        message: String,
        event_name: Option<String>,
        metric_name: Option<String>,
        operation: Option<String>,
        failure: Option<String>,
        work_key: Option<String>,
        worker_id: Option<String>,
        error: Option<String>,
        counter_delta: f64,
    }

    #[test]
    fn work_lock_failures_log_and_count_by_boundary() {
        let worker_id = WorkerId::nil();

        check_values(
            [
                Check {
                    scenario: "release database failure",
                    input: FailureEvent::ReleaseDatabase,
                    expect: FailureRecord {
                        metadata_name: "work_lock_release_failed".to_string(),
                        level: tracing::Level::ERROR,
                        message: "Could not release work lock".to_string(),
                        event_name: Some("work_lock_release_failed".to_string()),
                        metric_name: Some(WORK_LOCK_FAILURES_METRIC.to_string()),
                        operation: Some("release".to_string()),
                        failure: Some("database".to_string()),
                        work_key: Some("work-key".to_string()),
                        worker_id: None,
                        error: Some("internal error: database unavailable".to_string()),
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "release after lock loss",
                    input: FailureEvent::ReleaseLockLost,
                    expect: FailureRecord {
                        metadata_name: "work_lock_release_failed".to_string(),
                        level: tracing::Level::ERROR,
                        message: "Could not release work lock".to_string(),
                        event_name: Some("work_lock_release_failed".to_string()),
                        metric_name: Some(WORK_LOCK_FAILURES_METRIC.to_string()),
                        operation: Some("release".to_string()),
                        failure: Some("lock_lost".to_string()),
                        work_key: Some("work-key".to_string()),
                        worker_id: None,
                        error: Some("lock expired".to_string()),
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "release command dispatch failure",
                    input: FailureEvent::ReleaseDispatch,
                    expect: FailureRecord {
                        metadata_name: "work_lock_release_dispatch_failed".to_string(),
                        level: tracing::Level::ERROR,
                        message: "Could not release work lock: WorkLockManager queue is full; database is likely overloaded".to_string(),
                        event_name: Some("work_lock_release_dispatch_failed".to_string()),
                        metric_name: Some(WORK_LOCK_FAILURES_METRIC.to_string()),
                        operation: Some("release".to_string()),
                        failure: Some("command_dispatch".to_string()),
                        work_key: Some("work-key".to_string()),
                        worker_id: Some(worker_id.to_string()),
                        error: Some("no available capacity".to_string()),
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "keepalive lock lost",
                    input: FailureEvent::KeepaliveLockLost,
                    expect: FailureRecord {
                        metadata_name: "work_lock_lost".to_string(),
                        level: tracing::Level::ERROR,
                        message: "worker lost lock".to_string(),
                        event_name: Some("work_lock_lost".to_string()),
                        metric_name: Some(WORK_LOCK_FAILURES_METRIC.to_string()),
                        operation: Some("keep_alive".to_string()),
                        failure: Some("lock_lost".to_string()),
                        work_key: Some("work-key".to_string()),
                        worker_id: Some(worker_id.to_string()),
                        error: Some("lock expired".to_string()),
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "keepalive database failure",
                    input: FailureEvent::KeepaliveDatabase,
                    expect: FailureRecord {
                        metadata_name: "work_lock_keepalive_failed".to_string(),
                        level: tracing::Level::ERROR,
                        message: "Failed to send work-lock keepalive; retrying".to_string(),
                        event_name: Some("work_lock_keepalive_failed".to_string()),
                        metric_name: Some(WORK_LOCK_FAILURES_METRIC.to_string()),
                        operation: Some("keep_alive".to_string()),
                        failure: Some("database".to_string()),
                        work_key: Some("work-key".to_string()),
                        worker_id: Some(worker_id.to_string()),
                        error: Some("database unavailable".to_string()),
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "keepalive command dispatch failure",
                    input: FailureEvent::KeepaliveDispatch,
                    expect: FailureRecord {
                        metadata_name: "work_lock_keepalive_failed".to_string(),
                        level: tracing::Level::ERROR,
                        message: "Failed to send work-lock keepalive; retrying".to_string(),
                        event_name: Some("work_lock_keepalive_failed".to_string()),
                        metric_name: Some(WORK_LOCK_FAILURES_METRIC.to_string()),
                        operation: Some("keep_alive".to_string()),
                        failure: Some("command_dispatch".to_string()),
                        work_key: Some("work-key".to_string()),
                        worker_id: Some(worker_id.to_string()),
                        error: Some("no available capacity".to_string()),
                        counter_delta: 1.0,
                    },
                },
                Check {
                    scenario: "keepalive command reply failure",
                    input: FailureEvent::KeepaliveReply,
                    expect: FailureRecord {
                        metadata_name: "work_lock_keepalive_failed".to_string(),
                        level: tracing::Level::ERROR,
                        message: "Failed to send work-lock keepalive; retrying".to_string(),
                        event_name: Some("work_lock_keepalive_failed".to_string()),
                        metric_name: Some(WORK_LOCK_FAILURES_METRIC.to_string()),
                        operation: Some("keep_alive".to_string()),
                        failure: Some("command_reply".to_string()),
                        work_key: Some("work-key".to_string()),
                        worker_id: Some(worker_id.to_string()),
                        error: Some("reply channel closed".to_string()),
                        counter_delta: 1.0,
                    },
                },
            ],
            |event| {
                let metrics = MetricsCapture::start();
                let (operation, failure, logs) = match event {
                    FailureEvent::ReleaseDatabase => {
                        let operation = WorkLockOperation::Release;
                        let failure = WorkLockFailure::Database;
                        let error = DatabaseError::Internal {
                            message: "database unavailable".to_string(),
                        };
                        let logs = capture_logs(|| {
                            emit(WorkLockReleaseFailed::new(
                                "work-key".to_string(),
                                &error,
                            ));
                        });
                        (operation, failure, logs)
                    }
                    FailureEvent::ReleaseLockLost => {
                        let operation = WorkLockOperation::Release;
                        let failure = WorkLockFailure::LockLost;
                        let error = DatabaseError::FailedPrecondition("lock expired".to_string());
                        let logs = capture_logs(|| {
                            emit(WorkLockReleaseFailed::new("work-key".to_string(), &error));
                        });
                        (operation, failure, logs)
                    }
                    FailureEvent::ReleaseDispatch => {
                        let operation = WorkLockOperation::Release;
                        let failure = WorkLockFailure::CommandDispatch;
                        let logs = capture_logs(|| {
                            emit(WorkLockReleaseDispatchFailed::new(
                                "work-key".to_string(),
                                worker_id,
                                "no available capacity".to_string(),
                            ));
                        });
                        (operation, failure, logs)
                    }
                    FailureEvent::KeepaliveLockLost => {
                        let operation = WorkLockOperation::KeepAlive;
                        let failure = WorkLockFailure::LockLost;
                        let logs = capture_logs(|| {
                            emit(WorkLockLost::new(
                                "work-key".to_string(),
                                worker_id,
                                "lock expired".to_string(),
                            ));
                        });
                        (operation, failure, logs)
                    }
                    FailureEvent::KeepaliveDatabase => {
                        let operation = WorkLockOperation::KeepAlive;
                        let failure = WorkLockFailure::Database;
                        let logs = capture_logs(|| {
                            emit(WorkLockKeepaliveFailed::new(
                                failure,
                                "work-key".to_string(),
                                worker_id,
                                "database unavailable".to_string(),
                            ));
                        });
                        (operation, failure, logs)
                    }
                    FailureEvent::KeepaliveDispatch => {
                        let operation = WorkLockOperation::KeepAlive;
                        let failure = WorkLockFailure::CommandDispatch;
                        let logs = capture_logs(|| {
                            emit(WorkLockKeepaliveFailed::new(
                                failure,
                                "work-key".to_string(),
                                worker_id,
                                "no available capacity".to_string(),
                            ));
                        });
                        (operation, failure, logs)
                    }
                    FailureEvent::KeepaliveReply => {
                        let operation = WorkLockOperation::KeepAlive;
                        let failure = WorkLockFailure::CommandReply;
                        let logs = capture_logs(|| {
                            emit(WorkLockKeepaliveFailed::new(
                                failure,
                                "work-key".to_string(),
                                worker_id,
                                "reply channel closed".to_string(),
                            ));
                        });
                        (operation, failure, logs)
                    }
                };

                assert_eq!(logs.len(), 1, "one emit must produce one log record");
                let log = &logs[0];
                let operation = operation.label_value();
                let failure = failure.label_value();

                FailureRecord {
                    metadata_name: log.metadata_name.clone(),
                    level: log.level,
                    message: log.message.clone(),
                    event_name: log.field("event_name").map(str::to_string),
                    metric_name: log.field("metric_name").map(str::to_string),
                    operation: log.field("operation").map(str::to_string),
                    failure: log.field("failure").map(str::to_string),
                    work_key: log.field("work_key").map(str::to_string),
                    worker_id: log.field("worker_id").map(str::to_string),
                    error: log.field("error").map(str::to_string),
                    counter_delta: metrics.counter_delta(
                        WORK_LOCK_FAILURES_METRIC,
                        &[
                            ("operation", operation.as_str()),
                            ("failure", failure.as_str()),
                        ],
                    ),
                }
            },
        );
    }

    #[tokio::test]
    async fn keepalive_errors_map_to_bounded_failures() {
        let (reply_tx, reply_rx) = oneshot::channel::<()>();
        drop(reply_tx);
        let reply_error = reply_rx
            .await
            .expect_err("closed reply channel should fail");

        check_values(
            [
                Check {
                    scenario: "database failure",
                    input: KeepAliveError::Database(DatabaseError::Internal {
                        message: "database unavailable".to_string(),
                    }),
                    expect: WorkLockFailure::Database,
                },
                Check {
                    scenario: "command dispatch failure",
                    input: KeepAliveError::WorkLockManagerSend("no available capacity".to_string()),
                    expect: WorkLockFailure::CommandDispatch,
                },
                Check {
                    scenario: "command reply failure",
                    input: KeepAliveError::WorkLockManagerReply(reply_error),
                    expect: WorkLockFailure::CommandReply,
                },
                Check {
                    scenario: "lock lost",
                    input: KeepAliveError::LockLost("lock expired".to_string()),
                    expect: WorkLockFailure::LockLost,
                },
            ],
            |error| error.failure(),
        );
    }

    #[crate::sqlx_test]
    async fn test_exclusivity(pool: PgPool) {
        let mut join_set = JoinSet::new();
        {
            let manager = start(&mut join_set, pool, Default::default())
                .await
                .unwrap();

            let lock_1 = manager.try_acquire_lock("work_key_1".into()).await.unwrap();
            assert!(
                manager.try_acquire_lock("work_key_1".into()).await.is_err(),
                "Should not be able to acquire another lock while one is active"
            );
            std::mem::drop(lock_1);

            let _lock_1 = manager.try_acquire_lock("work_key_1".into()).await.expect(
                "Should be able to acquire a lock again if the other has gone out of scope",
            );
            let _lock_2 = manager.try_acquire_lock("work_key_2".into()).await.expect(
                "Should be able to acquire a lock with a different key while another is active",
            );

            // Make sure drops release locks in-order, before acquires are seen, and that the command
            // buffer doesn't become full over the course (we should be awaiting the replies, which
            // should not cause it to grow.)
            for i in 0..(COMMAND_BUFFER_SIZE * 2) {
                if manager.try_acquire_lock("work_key_3".into()).await.is_err() {
                    panic!(
                        "Lock failed to be acquired after the previous was dropped, after {i} iterations"
                    )
                }
                // lock is already dropped
            }
        }

        // Test cooperative cancellation
        tokio::select! {
            _ = join_set.join_all() => {}
            _ = tokio::time::sleep(Duration::from_secs(3)) => {
                panic!("WorkLockManager did not shut down in a timely manner")
            }
        }
    }

    #[crate::sqlx_test]
    async fn test_db_failure(pool: PgPool) {
        // Tests that can emit WorkLock failures hold this guard through teardown
        // so process-global counter deltas stay isolated.
        let _metrics_guard = MetricsCapture::start();
        let mut join_set = JoinSet::new();
        let manager = start(
            &mut join_set,
            pool.clone(),
            KeepaliveConfig {
                // Make the interval fast, to make sure reconnection works
                interval: Duration::from_millis(100),
                timeout: Duration::from_millis(500),
            },
        )
        .await
        .unwrap();

        let lock = manager.try_acquire_lock("work_key_1".into()).await.unwrap();

        let db_name = pool
            .connect_options()
            .get_database()
            .expect("Unknown database name")
            .to_string();

        // Kill all open db connections
        sqlx::query(
            r#"
SELECT pg_terminate_backend(pid)
FROM pg_stat_activity
WHERE datname = $1 AND pid <> pg_backend_pid()"#,
        )
        .bind(db_name)
        .execute(&pool)
        .await
        .expect("could not kill active database connections");

        tokio::time::sleep(Duration::from_millis(1000)).await;

        assert!(
            lock.is_alive(),
            "Lock should still be acquired even if the database connection died (it should have reconnected)"
        );

        assert!(
            manager.try_acquire_lock("work_key_1".into()).await.is_err(),
            "New locks should not be acquired even if the database connection died (it should have reconnected)"
        );
    }

    #[crate::sqlx_test]
    async fn test_read_only_connection_is_replaced(pool: PgPool) {
        // Use a one-connection pool so start() is guaranteed to reserve the session configured
        // below. Reconnection must close that session before another can be opened.
        let work_lock_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(pool.connect_options().as_ref().clone())
            .await
            .unwrap();
        let mut db = work_lock_pool.acquire().await.unwrap();
        sqlx::query("SET default_transaction_read_only = on")
            .execute(&mut *db)
            .await
            .unwrap();
        drop(db);

        let mut join_set = JoinSet::new();
        let manager = start(&mut join_set, work_lock_pool, Default::default())
            .await
            .unwrap();

        manager
            .try_acquire_lock("work_key_1".into())
            .await
            .expect("Lock should be acquired after replacing the read-only connection");
    }

    #[crate::sqlx_test]
    async fn test_expiry(pool: PgPool) {
        let metrics = MetricsCapture::start();
        let mut join_set = JoinSet::new();
        let manager = start(
            &mut join_set,
            pool.clone(),
            KeepaliveConfig {
                // Make timeout lower than interval, to test keepalive timeouts
                interval: Duration::from_millis(500),
                timeout: Duration::from_millis(100),
            },
        )
        .await
        .unwrap();

        let old_lock = manager.try_acquire_lock("work_key_1".into()).await.unwrap();

        let start = Instant::now();
        let new_lock = loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if start.elapsed() > Duration::from_secs(2) {
                panic!("Lock should have expired by now");
            }
            match manager.try_acquire_lock("work_key_1".into()).await {
                Ok(lock) => break lock,
                Err(_) => continue,
            }
        };

        // Give the keep-alive time to fire again
        tokio::time::sleep(Duration::from_millis(1000)).await;

        assert!(
            !old_lock.is_alive(),
            "Old lock should be dead, since the new lock has taken its place."
        );
        assert!(new_lock.is_alive(), "New lock should be alive still");
        assert_eq!(
            metrics.counter_delta(
                WORK_LOCK_FAILURES_METRIC,
                &[("operation", "keep_alive"), ("failure", "lock_lost")],
            ),
            1.0,
            "the expired worker should report one keepalive lock loss",
        );
    }
}
