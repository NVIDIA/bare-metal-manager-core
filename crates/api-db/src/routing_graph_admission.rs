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

//! Transaction-scoped admission locking for routing-graph writes.
//!
//! A NICo database belongs to one site, so one stable database-local key
//! serializes only writers whose cross-table routing decisions must share a
//! committed view. This graph-wide boundary is initially conservative because
//! the participating routing-key set is not knowable until the transaction has
//! read the graph.

use std::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::time::Duration;

use sqlx::{PgPool, PgTransaction};
use tokio::sync::{Semaphore, SemaphorePermit};

use crate::{DatabaseError, DatabaseResult, Transaction};

const GLOBAL_DB_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(25);

/// Defines one database-global write lock.
pub trait GlobalDbLock {
    /// Returns the stable identifier used for the PostgreSQL advisory lock.
    fn lock_key() -> &'static str;

    /// Returns the process-local admission semaphore for the same lock.
    ///
    /// The semaphore must have one permit and must never be closed.
    fn semaphore() -> &'static Semaphore;
}

/// A transaction admitted to make writes protected by a database-global lock.
///
/// The transaction and in-process permit share one owner so callers cannot
/// release local admission before commit or rollback. Use [`Self::as_mut`] or
/// [`Self::as_pgconn`] with existing API-DB operations, then finish with
/// [`Self::commit`] or [`Self::rollback`].
#[must_use = "commit or roll back the globally locked transaction"]
pub struct GlobalLockedTransaction<'a, T: GlobalDbLock> {
    transaction: Transaction<'a>,
    _permit: SemaphorePermit<'static>,
    _lock: PhantomData<T>,
}

/// Routing-graph write lock configuration.
pub struct RoutingGraphGlobalDbLock;

impl GlobalDbLock for RoutingGraphGlobalDbLock {
    fn lock_key() -> &'static str {
        "routing_graph:write"
    }

    fn semaphore() -> &'static Semaphore {
        static ROUTING_GRAPH_WRITE_ADMISSION: Semaphore = Semaphore::const_new(1);

        &ROUTING_GRAPH_WRITE_ADMISSION
    }
}

/// A transaction admitted to make routing-graph writes.
pub type RoutingGraphWriteTransaction<'a> = GlobalLockedTransaction<'a, RoutingGraphGlobalDbLock>;

async fn try_lock_identifier(
    txn: &mut PgTransaction<'_>,
    identifier: &str,
) -> DatabaseResult<bool> {
    let query = "SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))";
    sqlx::query_scalar::<_, bool>(query)
        .bind(identifier)
        .fetch_one(txn.as_mut())
        .await
        .map_err(|error| DatabaseError::query(query, error))
}

impl<'a, T: GlobalDbLock> GlobalLockedTransaction<'a, T> {
    /// Begins a transaction holding both database-global admission boundaries.
    ///
    /// Same-process writers first queue without occupying a pool connection.
    /// Each cross-process lock attempt uses a short transaction; an unsuccessful
    /// attempt rolls back before the retry wait, so contention does not leave a
    /// pooled connection or transaction parked during that wait. The successful
    /// transaction acquires the global database lock before any resource-specific
    /// lock and retains it through commit or rollback.
    ///
    /// Total waiting is bounded by the caller's request deadline or controller
    /// task lifetime. The helper deliberately does not add another deadline.
    #[track_caller]
    pub fn begin(pool: &'a PgPool) -> impl Future<Output = DatabaseResult<Self>> + Send + 'a {
        let caller = std::panic::Location::caller();
        async move {
            let permit = T::semaphore()
                .acquire()
                .await
                .expect("global database lock admission semaphore is never closed");
            loop {
                let mut transaction = Transaction::begin_with_location(pool, caller).await?;
                if try_lock_identifier(transaction.as_mut(), T::lock_key()).await? {
                    return Ok(Self {
                        transaction,
                        _permit: permit,
                        _lock: PhantomData,
                    });
                }
                transaction.rollback().await?;
                tokio::time::sleep(GLOBAL_DB_LOCK_RETRY_INTERVAL).await;
            }
        }
    }

    /// Returns the underlying PostgreSQL connection for existing DB helpers.
    pub fn as_pgconn(&mut self) -> &mut sqlx::PgConnection {
        self.transaction.as_pgconn()
    }

    /// Commits the transaction before releasing in-process admission.
    ///
    /// The boxed future invokes the inner commit synchronously, preserving its
    /// `#[track_caller]` location.
    #[track_caller]
    pub fn commit(self) -> Pin<Box<dyn Future<Output = DatabaseResult<()>> + Send + 'a>> {
        let Self {
            transaction,
            _permit,
            _lock,
        } = self;
        let commit = transaction.commit();
        Box::pin(async move {
            let result = commit.await;
            drop(_permit);
            result
        })
    }

    /// Rolls back the transaction before releasing in-process admission.
    ///
    /// The boxed future invokes the inner rollback synchronously, preserving
    /// its `#[track_caller]` location.
    #[track_caller]
    pub fn rollback(self) -> Pin<Box<dyn Future<Output = DatabaseResult<()>> + Send + 'a>> {
        let Self {
            transaction,
            _permit,
            _lock,
        } = self;
        let rollback = transaction.rollback();
        Box::pin(async move {
            let result = rollback.await;
            drop(_permit);
            result
        })
    }
}

impl<'a, T: GlobalDbLock> AsMut<PgTransaction<'a>> for GlobalLockedTransaction<'a, T> {
    fn as_mut(&mut self) -> &mut PgTransaction<'a> {
        self.transaction.as_mut()
    }
}

#[cfg(test)]
mod tests {
    use sqlx::PgPool;
    use sqlx::postgres::PgPoolOptions;
    use tokio::task::JoinHandle;

    use super::*;

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);
    static TEST_SERIALIZATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn routing_graph_write_admission() -> SemaphorePermit<'static> {
        RoutingGraphGlobalDbLock::semaphore()
            .acquire()
            .await
            .expect("routing-graph write admission semaphore is never closed")
    }

    fn spawn_routing_graph_write(pool: PgPool) -> JoinHandle<Result<(), String>> {
        tokio::spawn(async move {
            let transaction = RoutingGraphWriteTransaction::begin(&pool)
                .await
                .map_err(|error| error.to_string())?;
            transaction
                .rollback()
                .await
                .map_err(|error| error.to_string())
        })
    }

    async fn hold_routing_graph_lock(txn: &mut PgTransaction<'_>) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(RoutingGraphGlobalDbLock::lock_key())
            .execute(txn.as_mut())
            .await?;
        Ok(())
    }

    async fn assert_writer_is_waiting(task: &mut JoinHandle<Result<(), String>>) {
        assert!(
            tokio::time::timeout(GLOBAL_DB_LOCK_RETRY_INTERVAL * 3, task)
                .await
                .is_err(),
            "routing-graph writer passed held admission"
        );
    }

    async fn await_routing_graph_write(
        mut task: JoinHandle<Result<(), String>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match tokio::time::timeout(TEST_TIMEOUT, &mut task).await {
            Ok(result) => {
                result
                    .map_err(|error| std::io::Error::other(error.to_string()))?
                    .map_err(std::io::Error::other)?;
                Ok(())
            }
            Err(_) => {
                task.abort();
                task.await.ok();
                Err(std::io::Error::other("routing-graph writer remained blocked").into())
            }
        }
    }

    async fn assert_pool_usable(pool: &PgPool) -> Result<(), sqlx::Error> {
        let value: i32 = sqlx::query_scalar("SELECT 1").fetch_one(pool).await?;
        assert_eq!(value, 1);
        Ok(())
    }

    #[crate::sqlx_test]
    async fn local_routing_graph_writers_serialize_until_commit(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _test_guard = TEST_SERIALIZATION.lock().await;
        let holder = RoutingGraphWriteTransaction::begin(&pool).await?;

        let mut waiter = spawn_routing_graph_write(pool.clone());
        assert_writer_is_waiting(&mut waiter).await;

        holder.commit().await?;
        await_routing_graph_write(waiter).await?;
        assert_pool_usable(&pool).await?;
        Ok(())
    }

    #[crate::sqlx_test]
    async fn local_routing_graph_writers_serialize_until_rollback(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _test_guard = TEST_SERIALIZATION.lock().await;
        let holder = RoutingGraphWriteTransaction::begin(&pool).await?;

        let mut waiter = spawn_routing_graph_write(pool.clone());
        assert_writer_is_waiting(&mut waiter).await;

        holder.rollback().await?;
        await_routing_graph_write(waiter).await?;
        assert_pool_usable(&pool).await?;
        Ok(())
    }

    #[crate::sqlx_test]
    async fn local_waiter_queues_before_pool_checkout(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _test_guard = TEST_SERIALIZATION.lock().await;
        let admission = routing_graph_write_admission().await;
        let limited_pool = PgPoolOptions::new()
            .max_connections(1)
            .connect_with(pool.connect_options().as_ref().clone())
            .await?;

        let mut waiter = spawn_routing_graph_write(limited_pool.clone());
        assert_writer_is_waiting(&mut waiter).await;
        assert_pool_usable(&limited_pool).await?;

        drop(admission);
        await_routing_graph_write(waiter).await?;
        limited_pool.close().await;
        Ok(())
    }

    #[crate::sqlx_test]
    async fn routing_graph_writer_waits_for_another_process(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _test_guard = TEST_SERIALIZATION.lock().await;
        let mut external_holder = pool.begin().await?;
        hold_routing_graph_lock(&mut external_holder).await?;

        let mut waiter = spawn_routing_graph_write(pool.clone());
        assert_writer_is_waiting(&mut waiter).await;

        external_holder.commit().await?;
        await_routing_graph_write(waiter).await?;
        assert_pool_usable(&pool).await?;
        Ok(())
    }

    #[crate::sqlx_test]
    async fn cancelled_routing_graph_waiter_returns_its_pool_connection(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _test_guard = TEST_SERIALIZATION.lock().await;
        let limited_pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(pool.connect_options().as_ref().clone())
            .await?;
        let mut holder = limited_pool.begin().await?;
        hold_routing_graph_lock(&mut holder).await?;

        let mut waiter = spawn_routing_graph_write(limited_pool.clone());
        assert_writer_is_waiting(&mut waiter).await;

        let value_while_waiting: i32 = tokio::time::timeout(
            TEST_TIMEOUT,
            sqlx::query_scalar("SELECT 1").fetch_one(&limited_pool),
        )
        .await
        .map_err(|_| std::io::Error::other("lock waiter kept its pool connection while idle"))??;
        assert_eq!(value_while_waiting, 1);

        waiter.abort();
        let cancellation = waiter
            .await
            .expect_err("aborted lock waiter task must report cancellation");
        assert!(cancellation.is_cancelled());

        let released_admission =
            tokio::time::timeout(TEST_TIMEOUT, routing_graph_write_admission())
                .await
                .expect("cancelled waiter must release local admission");
        drop(released_admission);

        holder.rollback().await?;

        let replacement = tokio::time::timeout(
            TEST_TIMEOUT,
            RoutingGraphWriteTransaction::begin(&limited_pool),
        )
        .await
        .map_err(|_| std::io::Error::other("cancelled waiter did not release admission"))??;
        replacement.rollback().await?;
        assert_pool_usable(&limited_pool).await?;
        limited_pool.close().await;
        Ok(())
    }

    #[crate::sqlx_test]
    async fn cancelled_routing_graph_holder_releases_admission(
        pool: PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let _test_guard = TEST_SERIALIZATION.lock().await;
        let holder_pool = pool.clone();
        let (ready_sender, ready_receiver) = tokio::sync::oneshot::channel();
        let holder = tokio::spawn(async move {
            let transaction = RoutingGraphWriteTransaction::begin(&holder_pool)
                .await
                .map_err(|error| error.to_string())?;
            ready_sender
                .send(())
                .map_err(|_| "could not report routing-graph holder readiness".to_string())?;
            // Rollback is deliberately unreachable so the transaction stays live until abort.
            std::future::pending::<()>().await;
            transaction
                .rollback()
                .await
                .map_err(|error| error.to_string())
        });

        match tokio::time::timeout(TEST_TIMEOUT, ready_receiver).await {
            Ok(readiness) => readiness?,
            Err(_) => {
                holder.abort();
                holder.await.ok();
                return Err(std::io::Error::other(
                    "routing-graph holder did not acquire admission",
                )
                .into());
            }
        }
        holder.abort();
        let cancellation = holder
            .await
            .expect_err("aborted routing-graph holder must report cancellation");
        assert!(cancellation.is_cancelled());

        let replacement =
            tokio::time::timeout(TEST_TIMEOUT, RoutingGraphWriteTransaction::begin(&pool))
                .await
                .map_err(|_| {
                    std::io::Error::other("cancelled holder did not release admission")
                })??;
        replacement.rollback().await?;
        assert_pool_usable(&pool).await?;
        Ok(())
    }
}
