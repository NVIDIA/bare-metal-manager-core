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

use sqlx::Row;

use super::{OwnerType, ResourcePool, ResourcePoolError};
use crate::db::DatabaseError;

// Max values we can bind to a Postgres SQL statement;
const BIND_LIMIT: usize = 65535;

pub struct DbResourcePool<T>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    name: String,
    database_connection: sqlx::PgPool,
    value_type: PhantomData<T>,
}

impl<T> DbResourcePool<T>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    pub fn new(name: String, db_pool: sqlx::PgPool) -> DbResourcePool<T> {
        DbResourcePool {
            name,
            database_connection: db_pool,
            value_type: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<T> ResourcePool<T> for DbResourcePool<T>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    async fn populate(&self, all_values: Vec<T>) -> Result<(), ResourcePoolError> {
        for vals in all_values.chunks(BIND_LIMIT / 2) {
            let query = "INSERT INTO resource_pool(name, value) ";
            let mut qb = sqlx::QueryBuilder::new(query);
            qb.push_values(vals.iter(), |mut b, v| {
                b.push_bind(&self.name).push_bind(v.to_string());
            });
            qb.push("ON CONFLICT (name, value) DO NOTHING");
            let q = qb.build();
            q.execute(&self.database_connection)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        }
        Ok(())
    }

    async fn allocate(
        &self,
        owner_type: OwnerType,
        owner_id: &str,
    ) -> Result<T, ResourcePoolError> {
        if self.stats().await?.free == 0 {
            return Err(ResourcePoolError::Empty);
        }
        let query = "
WITH allocate AS (
 SELECT value FROM resource_pool
    WHERE name = $1 AND owner_id IS NULL
    ORDER BY random()
    LIMIT 1
    FOR UPDATE SKIP LOCKED
)
UPDATE resource_pool SET
	owner_type=$2,
	owner_id=$3,
	allocated=NOW()
FROM allocate
WHERE name = $1 AND resource_pool.value = allocate.value
RETURNING allocate.value
";
        let (allocated,): (String,) = sqlx::query_as(query)
            .bind(&self.name)
            .bind(owner_type.to_string())
            .bind(owner_id)
            .fetch_one(&self.database_connection)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        let out =
            allocated
                .parse()
                .map_err(|e: <T as FromStr>::Err| ResourcePoolError::ParseError {
                    e: e.to_string(),
                    v: allocated,
                    pool_name: self.name.clone(),
                    owner_type: owner_type.to_string(),
                    owner_id: owner_id.to_string(),
                })?;
        Ok(out)
    }

    async fn release(&self, value: T) -> Result<(), ResourcePoolError> {
        let query = "
UPDATE resource_pool SET
  owner_type = NULL,
  owner_id = NULL,
  allocated = NULL
WHERE name = $1 AND value = $2
";
        sqlx::query(query)
            .bind(&self.name)
            .bind(&value.to_string())
            .execute(&self.database_connection)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    async fn stats(&self) -> Result<super::ResourcePoolStats, ResourcePoolError> {
        // Will do an index scan on idx_resource_pools_name, same as without the FILTER, so doing
        // both at once is faster than two queries.
        let query = "SELECT COUNT(*) FILTER (WHERE owner_id IS NOT NULL) AS used,
                            COUNT(*) FILTER (WHERE owner_id IS NULL) AS free
                    FROM resource_pool WHERE NAME = $1";
        let s: super::ResourcePoolStats = sqlx::query_as(query)
            .bind(&self.name)
            .fetch_one(&self.database_connection)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(s)
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
