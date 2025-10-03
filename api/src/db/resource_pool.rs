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

use std::str::FromStr;

use config_version::ConfigVersion;
use sqlx::{PgConnection, Postgres};

use super::BIND_LIMIT;
use crate::model::resource_pool::{
    OwnerType, ResourcePool, ResourcePoolEntry, ResourcePoolError, ResourcePoolSnapshot,
    ResourcePoolStats,
};
use crate::{db::DatabaseError, model::resource_pool::ResourcePoolEntryState};

/// Put some resources into the pool, so they can be allocated later.
/// This needs to be called before `allocate` can return anything.
pub async fn populate<T>(
    value: &ResourcePool<T>,
    txn: &mut PgConnection,
    all_values: Vec<T>,
) -> Result<(), ResourcePoolError>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    let free_state = ResourcePoolEntryState::Free;
    let initial_version = ConfigVersion::initial();

    for vals in all_values.chunks(BIND_LIMIT / 4) {
        let query = "INSERT INTO resource_pool(name, value, value_type, state, state_version) ";
        let mut qb = sqlx::QueryBuilder::new(query);
        qb.push_values(vals.iter(), |mut b, v| {
            b.push_bind(&value.name)
                .push_bind(v.to_string())
                .push_bind(value.value_type)
                .push_bind(sqlx::types::Json(&free_state))
                .push_bind(initial_version);
        });
        qb.push("ON CONFLICT (name, value) DO NOTHING");
        let q = qb.build();
        q.execute(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;
    }
    Ok(())
}

/// Get a resource from the pool
pub async fn allocate<T>(
    value: &ResourcePool<T>,
    txn: &mut PgConnection,
    owner_type: OwnerType,
    owner_id: &str,
) -> Result<T, ResourcePoolError>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    if stats(&mut *txn, value.name()).await?.free == 0 {
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
        .bind(&value.name)
        .bind(sqlx::types::Json(&free_state))
        .bind(sqlx::types::Json(&allocated_state))
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    let out = allocated
        .parse()
        .map_err(|e: <T as FromStr>::Err| ResourcePoolError::Parse {
            e: e.to_string(),
            v: allocated,
            pool_name: value.name.clone(),
            owner_type: owner_type.to_string(),
            owner_id: owner_id.to_string(),
        })?;
    Ok(out)
}

/// Return a resource to the pool
pub async fn release<T>(
    pool: &ResourcePool<T>,
    txn: &mut PgConnection,
    value: T,
) -> Result<(), ResourcePoolError>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
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
        .bind(&pool.name)
        .bind(value.to_string())
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn stats<'c, E>(executor: E, name: &str) -> Result<ResourcePoolStats, ResourcePoolError>
where
    E: sqlx::Executor<'c, Database = Postgres>,
{
    // Will do an index scan on idx_resource_pools_name, same as without the FILTER, so doing
    // both at once is faster than two queries.
    let free_state = ResourcePoolEntryState::Free;
    let query = "SELECT COUNT(*) FILTER (WHERE state != $1) AS used,
                            COUNT(*) FILTER (WHERE state = $1) AS free
                    FROM resource_pool WHERE NAME = $2";
    let s: ResourcePoolStats = sqlx::query_as(query)
        .bind(sqlx::types::Json(free_state))
        .bind(name)
        .fetch_one(executor)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(s)
}

pub async fn all(txn: &mut PgConnection) -> Result<Vec<ResourcePoolSnapshot>, ResourcePoolError> {
    let mut out = Vec::with_capacity(4);

    let query_int =
        "SELECT name, CAST(min(value::bigint) AS text), CAST(max(value::bigint) AS text),
            count(*) FILTER (WHERE state = '{\"state\": \"free\"}') AS free,
            count(*) FILTER (WHERE state != '{\"state\": \"free\"}') AS used
            FROM resource_pool WHERE value_type = 'integer' GROUP BY name";

    let query_ipv4 = "SELECT name, CAST(min(value::inet) AS text), CAST(max(value::inet) AS text),
            count(*) FILTER (WHERE state = '{\"state\": \"free\"}') AS free,
            count(*) FILTER (WHERE state != '{\"state\": \"free\"}') AS used
            FROM resource_pool WHERE value_type = 'ipv4' GROUP BY name";

    for query in &[query_int, query_ipv4] {
        let mut rows: Vec<ResourcePoolSnapshot> = sqlx::query_as(query)
            .fetch_all(&mut *txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;
        out.append(&mut rows);
    }
    out.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    Ok(out)
}

/// All the resource pool entries for the given value
pub async fn find_value(
    txn: &mut PgConnection,
    value: &str,
) -> Result<Vec<ResourcePoolEntry>, ResourcePoolError> {
    let query =
        "SELECT name, value, value_type, state, allocated FROM resource_pool WHERE value = $1";
    let entry: Vec<ResourcePoolEntry> = sqlx::query_as(query)
        .bind(value)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(entry)
}
