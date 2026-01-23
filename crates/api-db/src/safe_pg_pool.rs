use std::ops::{Deref, DerefMut};
use std::panic::Location;

use futures_util::TryFutureExt;
use sqlx::Postgres;
use sqlx::pool::PoolConnection;

use crate::{DatabaseError, DatabaseResult};

/// A SafePgPool is one that only allows one transaction at a time. This is to prevent deadlocks
/// caused by beginning a transaction, writing to a row, then calling a function that tries to take
/// another transaction from the PgPool. The borrow checker will make this impossible, since a
/// SafeTransaction holds a mutable reference to the original pool, and so cannot be done more than
/// once at a time.
///
/// The safety is not perfect: SafePgPool implements Clone for practicality reasons, meaning that
/// transactions can still be unsafely started by cloning the pool and starting a transaction from
/// there.
#[derive(Clone)]
pub struct SafePgPool {
    pool: sqlx::PgPool,
}

impl SafePgPool {
    #[track_caller]
    pub fn begin<'pool>(
        &'pool mut self,
    ) -> impl Future<Output = DatabaseResult<SafeTransaction<'pool>>> + 'pool {
        let loc = Location::caller();
        async move {
            let txn = crate::Transaction::begin_with_location(&self.pool, loc).await?;
            Ok(SafeTransaction {
                inner: txn,
                _pool: std::marker::PhantomData,
            })
        }
    }

    pub async fn with_txn<'pool, T, E>(
        &'pool mut self,
        f: impl for<'txn> FnOnce(
            &'txn mut SafeTransaction<'pool>,
        ) -> futures::future::BoxFuture<'txn, Result<T, E>>,
    ) -> DatabaseResult<Result<T, E>>
    where
        T: Send + 'pool,
    {
        let mut t = self.begin().await?;
        match f(&mut t).await {
            Ok(output) => {
                t.commit().await?;
                Ok(Ok(output))
            }
            Err(e) => {
                t.rollback().await.ok();
                Ok(Err(e))
            }
        }
    }

    #[track_caller]
    pub fn acquire(&mut self) -> impl Future<Output = DatabaseResult<PoolConnection<Postgres>>> {
        self.pool.acquire().map_err(|e| DatabaseError::acquire(e))
    }
}

/// A Transaction that is borrowed mutably from a SafePgPool, preventing multiple transactions from
/// being started concurrently from the same pool.
pub struct SafeTransaction<'a> {
    inner: crate::Transaction<'a>,
    _pool: std::marker::PhantomData<&'a mut SafePgPool>,
}

impl<'a> SafeTransaction<'a> {
    #[track_caller]
    pub fn commit(self) -> impl Future<Output = DatabaseResult<()>> + use<'a> {
        self.inner.commit()
    }

    #[track_caller]
    pub fn rollback(self) -> impl Future<Output = DatabaseResult<()>> + use<'a> {
        self.inner.rollback()
    }
}

impl From<sqlx::PgPool> for SafePgPool {
    fn from(pool: sqlx::PgPool) -> Self {
        Self { pool }
    }
}

impl<'a> Deref for SafeTransaction<'a> {
    type Target = sqlx::PgTransaction<'a>;

    #[inline]
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for SafeTransaction<'_> {
    #[inline]
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}
