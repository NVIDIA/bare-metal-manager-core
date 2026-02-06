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

use sqlx::pool::PoolConnection;
use sqlx::{Connection, PgConnection, PgPool, Postgres};
use tokio::sync::{mpsc, oneshot};
use tokio::time::MissedTickBehavior;

use crate::{DatabaseError, DatabaseResult};

pub type WorkKey = String;
pub type WorkerId = uuid::Uuid;

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
    tokio::task::Builder::new()
        .name("WorkLockManager")
        .spawn(run_loop(pool, db, cmd_rx, keepalive_timeout))
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
    mut db: PoolConnection<Postgres>,
    mut cmd_rx: mpsc::Receiver<WorkLockManagerCommand>,
    keepalive_timeout: Duration,
) {
    while let Some(command) = cmd_rx.recv().await {
        if let Err(e) = db.ping().await {
            tracing::warn!("WorkLockManager database connection closed, trying to re-acquire: {e}");
            db = match pool.acquire().await {
                Ok(db) => db,
                Err(e) => {
                    tracing::error!("WorkLockManager could not reacquire database connection: {e}");
                    // Any reply channel for this command will now drop, and readers will get an error
                    continue;
                }
            }
        };
        match command {
            WorkLockManagerCommand::AcquireLock { work_key, reply_tx } => {
                if reply_tx.is_closed() {
                    tracing::info!("Skipping AcquireLock command: caller already timed out");
                    continue;
                }
                match try_acquire_lock(&mut db, &work_key, keepalive_timeout).await {
                    Ok(Some(worker_id)) => {
                        reply_tx.send(Ok(worker_id)).ok();
                        tracing::debug!("Acquired work lock {work_key}");
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
                release_lock(&mut db, &work_key, worker_id)
                    .await
                    .inspect_err(|e| {
                        tracing::error!(%work_key, "Could not release work lock: {e}");
                    })
                    .ok();
                tracing::debug!(%work_key, "Released work lock");
            }

            WorkLockManagerCommand::KeepLockAlive {
                work_key,
                worker_id,
                reply_tx,
            } => match keep_lock_alive(&mut db, &work_key, worker_id).await {
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
            "Releasing lock for {} worker {}",
            self.work_key,
            self.worker_id
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
                tracing::error!("ERROR! Could not release lock for {} worker {}: WorkLockManager queue is full! Database is likely overloaded: {}", self.work_key, self.worker_id, e);
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
        let join_handle = tokio::task::Builder::new().name(&format!("keepalive loop for {work_key} worker {worker_id}")).spawn({
            let manager = manager.clone();
            let work_key = work_key.clone();
            let mut keepalive_timer = tokio::time::interval(keepalive_interval);
            keepalive_timer.set_missed_tick_behavior(MissedTickBehavior::Skip);
            async move {
                loop {
                    tokio::select! {
                        _ = keepalive_timer.tick() => {
                            match manager.keep_lock_alive(work_key.clone(), worker_id).await {
                                Ok(_) => {}
                                Err(KeepAliveError::LockLost(msg)) => {
                                    tracing::error!("{work_key} worker {worker_id} lost lock: {msg}");
                                    return;
                                }
                                Err(e) => {
                                    tracing::error!("Error sending keepalive for {work_key} worker {worker_id} (will retry): {e}");
                                }
                            }
                        }
                        _ = &mut keepalive_stop_rx => {
                            break;
                        }
                    }
                }
            }
        }).expect("could not spawn tokio task");

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
    #[error("Work is already locked for {0}")]
    WorkAlreadyLocked(WorkKey),
    #[error(transparent)]
    Database(#[from] DatabaseError),
    /// This happens when the channel buffer is full, meaning more than COMMAND_BUFFER_SIZE commands
    /// are queued up waiting for the WorkLockManager to process them. Since a WorkLockManager owns
    /// a long-running connection to the database (and doesn't have to contend with the pool having
    /// no connections available), this should only  happen if the database is completely down, or
    /// is going so slow that simple updates to the table are blocked.
    #[error(
        "Error sending AcquireLock command to WorkLockManager, database is likely overloaded: {0}"
    )]
    WorkLockManagerSend(String),
    #[error(
        "BUG: Error receiving AcquireLock reply from WorkLockManager, database connections are likely failing: {0}"
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
        "Error sending KeepAlive command to WorkLockManager, database is likely overloaded: {0}"
    )]
    WorkLockManagerSend(String),
    #[error(
        "BUG: Error receiving KeepAlive reply from WorkLockManager, database connections are likely failing: {0}"
    )]
    WorkLockManagerReply(#[from] tokio::sync::oneshot::error::RecvError),
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;

    #[crate::sqlx_test]
    async fn test_exclusivity(pool: PgPool) {
        let manager = start(pool, Default::default()).await.unwrap();

        let lock_1 = manager.try_acquire_lock("work_key_1".into()).await.unwrap();
        assert!(
            manager.try_acquire_lock("work_key_1".into()).await.is_err(),
            "Should not be able to acquire another lock while one is active"
        );
        std::mem::drop(lock_1);

        let _lock_1 = manager
            .try_acquire_lock("work_key_1".into())
            .await
            .expect("Should be able to acquire a lock again if the other has gone out of scope");
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

    #[crate::sqlx_test]
    async fn test_db_failure(pool: PgPool) {
        let manager = start(
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
    async fn test_expiry(pool: PgPool) {
        let manager = start(
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
    }
}
