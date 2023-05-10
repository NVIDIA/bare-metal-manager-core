/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::{marker::PhantomData, str::FromStr};

use sqlx::{Postgres, Row, Transaction};

use super::{OwnerType, ResourcePoolError};
use crate::{
    db::DatabaseError,
    model::{config_version::ConfigVersion, resource_pool::ResourcePoolEntryState},
};

// Max values we can bind to a Postgres SQL statement;
const BIND_LIMIT: usize = 65535;

pub struct DbResourcePool<T>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    name: String,
    value_type: PhantomData<T>,
}

impl<T> DbResourcePool<T>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    pub fn new(name: String) -> DbResourcePool<T> {
        DbResourcePool {
            name,
            value_type: PhantomData,
        }
    }

    /// Put some resources into the pool, so they can be allocated later.
    /// This needs to be called before `allocate` can return anything.
    pub async fn populate(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        all_values: Vec<T>,
    ) -> Result<(), ResourcePoolError> {
        let free_state = ResourcePoolEntryState::Free;
        let initial_version = ConfigVersion::initial();
        let version_str = initial_version.to_string();

        for vals in all_values.chunks(BIND_LIMIT / 4) {
            let query = "INSERT INTO resource_pool(name, value, state, state_version) ";
            let mut qb = sqlx::QueryBuilder::new(query);
            qb.push_values(vals.iter(), |mut b, v| {
                b.push_bind(&self.name)
                    .push_bind(v.to_string())
                    .push_bind(sqlx::types::Json(&free_state))
                    .push_bind(&version_str);
            });
            qb.push("ON CONFLICT (name, value) DO NOTHING");
            let q = qb.build();
            q.execute(&mut *txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        }
        Ok(())
    }

    /// Get a resource from the pool
    pub async fn allocate<'c>(
        &self,
        txn: &mut Transaction<'c, Postgres>,
        owner_type: OwnerType,
        owner_id: &str,
    ) -> Result<T, ResourcePoolError> {
        if self.stats(&mut *txn).await?.free == 0 {
            return Err(ResourcePoolError::Empty);
        }
        let query = "
WITH allocate AS (
 SELECT id, value FROM resource_pool
    WHERE name = $1 AND state = $2
    ORDER BY random()
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
UPDATE resource_pool SET
    state=$3,
    allocated=NOW()
FROM allocate
WHERE resource_pool.id = allocate.id
RETURNING allocate.value
";
        let free_state = ResourcePoolEntryState::Free;
        let allocated_state = ResourcePoolEntryState::Allocated {
            owner: owner_id.to_string(),
            owner_type: owner_type.to_string(),
        };

        // TODO: We should probably update the `state_version` field too. But
        // it's hard to do this inside the SQL query.
        let (allocated,): (String,) = sqlx::query_as(query)
            .bind(&self.name)
            .bind(sqlx::types::Json(&free_state))
            .bind(sqlx::types::Json(&allocated_state))
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        let out = allocated
            .parse()
            .map_err(|e: <T as FromStr>::Err| ResourcePoolError::Parse {
                e: e.to_string(),
                v: allocated,
                pool_name: self.name.clone(),
                owner_type: owner_type.to_string(),
                owner_id: owner_id.to_string(),
            })?;
        Ok(out)
    }

    /// Return a resource to the pool
    pub async fn release(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        value: T,
    ) -> Result<(), ResourcePoolError> {
        // TODO: If we would get passed the current owner, we could guard on that
        // so that nothing else could release the value
        let query = "
UPDATE resource_pool SET
  allocated = NULL,
  state = $1
WHERE name = $2 AND value = $3
";
        sqlx::query(query)
            .bind(sqlx::types::Json(ResourcePoolEntryState::Free))
            .bind(&self.name)
            .bind(&value.to_string())
            .execute(txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    /// Count how many (used, unused) values are in the pool
    pub async fn stats<'c, E>(
        &self,
        executor: E,
    ) -> Result<super::ResourcePoolStats, ResourcePoolError>
    where
        E: sqlx::Executor<'c, Database = Postgres>,
    {
        // Will do an index scan on idx_resource_pools_name, same as without the FILTER, so doing
        // both at once is faster than two queries.
        let free_state = ResourcePoolEntryState::Free;
        let query = "SELECT COUNT(*) FILTER (WHERE state != $1) AS used,
                            COUNT(*) FILTER (WHERE state = $1) AS free
                    FROM resource_pool WHERE NAME = $2";
        let s: super::ResourcePoolStats = sqlx::query_as(query)
            .bind(sqlx::types::Json(free_state))
            .bind(&self.name)
            .fetch_one(executor)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(s)
    }

    /// Mark this value as already taken. Used during migration from K8s resource pools.
    pub async fn mark_allocated(
        &self,
        txn: &mut Transaction<'_, Postgres>,
        value: T,
        owner_type: OwnerType,
        owner_id: &str,
    ) -> Result<(), ResourcePoolError> {
        let state = ResourcePoolEntryState::Allocated {
            owner: owner_id.to_string(),
            owner_type: owner_type.to_string(),
        };
        let query =
            "UPDATE resource_pool SET allocated = NOW(), state = $1 WHERE name = $2 AND value = $3";
        sqlx::query(query)
            .bind(sqlx::types::Json(state))
            .bind(&self.name)
            .bind(&value.to_string())
            .execute(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for super::ResourcePoolStats {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let used: i64 = row.try_get("used")?;
        let free: i64 = row.try_get("free")?;
        Ok(super::ResourcePoolStats {
            used: used as usize,
            free: free as usize,
        })
    }
}
