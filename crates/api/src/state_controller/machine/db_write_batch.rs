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

use std::sync::Mutex;

use futures_util::FutureExt;
use futures_util::future::BoxFuture;
use sqlx::PgTransaction;

use crate::state_controller::state_handler::StateHandlerError;

/// A DbWriteBatch exists to allow state controllers to enqueue write operations until the end of
/// processing, so that they don't need to hold a database connection open across long-running work.
/// If the state handler returns an error, the write operations are discarded, similarly to how a
/// transaction is rolled back. If a state handler returns successfully, the write operations are
/// all done at once inside a transaction before committing.
///
/// # Usage
///
/// You can pass a FnOnce closure that accepts a transaction, that will be called when your state handler is successful. For example:
///
/// ```ignore
/// let write_batch = DbWriteBatch::new();
/// write_batch.push(move |txn| async move {
///     db::machine::find_by_ip(txn, &Ipv4Addr::new(17, 0, 0, 1)).await
/// }.boxed());
///
/// // Later the controller will do:
/// write_batch.apply_all(&mut txn);
/// ```
///
/// There is also a `write_op!` macro that allows you to pass a single expression as a write op, avoiding the need to do `async move { (...).await }.boxed()`:
///
/// ```ignore
/// write_batch.push(write_op!(|txn| db::machine::find_by_ip(txn, &Ipv4Addr::new(17, 0, 0, 1))));
/// ```
#[derive(Default)]
pub struct DbWriteBatch {
    writes: Mutex<Vec<WriteOp>>,
}

type WriteOp = Box<
    dyn for<'t> FnOnce(&'t mut PgTransaction) -> BoxFuture<'t, Result<(), StateHandlerError>>
        + Send
        + Sync
        + 'static,
>;

impl std::fmt::Debug for DbWriteBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DbWriteBatch")
            .field(
                "writes",
                &self.writes.lock().map(|w| w.len()).unwrap_or_default(),
            )
            .finish()
    }
}

impl DbWriteBatch {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push<OP, T, E>(&self, f: OP)
    where
        OP: for<'t> FnOnce(&'t mut PgTransaction) -> BoxFuture<'t, Result<T, E>>
            + Send
            + Sync
            + 'static,
        E: Into<StateHandlerError>,
    {
        self.writes
            .lock()
            .expect("lock poisoned")
            .push(Box::new(move |txn| {
                async move { f(txn).await.map_err(Into::into).map(|_| ()) }.boxed()
            }));
    }

    pub async fn apply_all(self, txn: &mut PgTransaction<'_>) -> Result<(), StateHandlerError> {
        let writes = self.writes.into_inner().expect("lock poisoned");
        for w in writes {
            w(txn).await?;
        }
        Ok(())
    }

    /// Move all pending writes out of self (making self empty) and return them as a new DbWriteBatch.
    pub fn take(&self) -> DbWriteBatch {
        let writes = std::mem::take(&mut *self.writes.lock().expect("lock poisoned"));
        DbWriteBatch::from(writes)
    }
}

impl From<Vec<WriteOp>> for DbWriteBatch {
    fn from(writes: Vec<WriteOp>) -> Self {
        Self {
            writes: Mutex::new(writes),
        }
    }
}

/// Macro to make it easier to express a single function call as a closure accepting a transaction
/// and returning a boxed future.
#[macro_export]
macro_rules! write_op {
    (|$txn:ident| $expr:expr) => {{
        #[allow(txn_held_across_await)]
        move |$txn| Box::pin(async move { $expr.await })
    }};
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;

    use sqlx::PgPool;

    use super::*;

    #[crate::sqlx_test]
    async fn test_delayed_writes(pool: PgPool) {
        let delayed_db_writes = DbWriteBatch::new();
        let called = Arc::new(AtomicBool::new(false));
        delayed_db_writes.push({
            let called = called.clone();
            move |_txn| {
                async move {
                    called.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok::<(), StateHandlerError>(())
                }
                .boxed()
            }
        });

        let mut txn = pool.begin().await.unwrap();
        delayed_db_writes.apply_all(&mut txn).await.unwrap();
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }
}
