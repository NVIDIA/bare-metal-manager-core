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

use std::{fmt, marker::PhantomData, str::FromStr};

use chrono::{DateTime, Utc};
use sqlx::{Postgres, Row, Transaction};

use crate::{
    db::DatabaseError,
    model::{config_version::ConfigVersion, resource_pool::ResourcePoolEntryState},
    CarbideError,
};

// Max values we can bind to a Postgres SQL statement;
const BIND_LIMIT: usize = 65535;

#[derive(Debug)]
pub struct DbResourcePool<T>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    name: String,
    value_type: ValueType,
    rust_type: PhantomData<T>,
}

impl<T> DbResourcePool<T>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    pub fn new(name: String, value_type: ValueType) -> DbResourcePool<T> {
        DbResourcePool {
            name,
            value_type,
            rust_type: PhantomData,
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
            let query = "INSERT INTO resource_pool(name, value, value_type, state, state_version) ";
            let mut qb = sqlx::QueryBuilder::new(query);
            qb.push_values(vals.iter(), |mut b, v| {
                b.push_bind(&self.name)
                    .push_bind(v.to_string())
                    .push_bind(self.value_type)
                    .push_bind(sqlx::types::Json(&free_state))
                    .push_bind(&version_str);
            });
            qb.push("ON CONFLICT (name, value) DO NOTHING");
            let q = qb.build();
            q.execute(&mut **txn)
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
        if self.stats(&mut **txn).await?.free == 0 {
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
            .fetch_one(&mut **txn)
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
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    /// Count how many (used, unused) values are in the pool
    pub async fn stats<'c, E>(&self, executor: E) -> Result<ResourcePoolStats, ResourcePoolError>
    where
        E: sqlx::Executor<'c, Database = Postgres>,
    {
        stats(executor, &self.name).await
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
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }
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
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
    Ok(s)
}

pub async fn all(
    txn: &mut Transaction<'_, Postgres>,
) -> Result<Vec<ResourcePoolSnapshot>, ResourcePoolError> {
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
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        out.append(&mut rows);
    }
    out.sort_unstable_by(|a, b| a.name.cmp(&b.name));

    Ok(out)
}

/// All the resource pool entries for the given value
pub async fn find_value(
    txn: &mut Transaction<'_, Postgres>,
    value: &str,
) -> Result<Vec<ResourcePoolEntry>, ResourcePoolError> {
    let query =
        "SELECT name, value, value_type, state, allocated FROM resource_pool WHERE value = $1";
    let entry: Vec<ResourcePoolEntry> = sqlx::query_as(query)
        .bind(value)
        .fetch_all(&mut **txn)
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
    Ok(entry)
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ResourcePoolStats {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let used: i64 = row.try_get("used")?;
        let free: i64 = row.try_get("free")?;
        Ok(ResourcePoolStats {
            used: used as usize,
            free: free as usize,
        })
    }
}

pub struct ResourcePoolSnapshot {
    pub name: String,
    pub min: String,
    pub max: String,
    pub stats: ResourcePoolStats,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ResourcePoolSnapshot {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(ResourcePoolSnapshot {
            name: row.try_get("name")?,
            min: row.try_get("min")?,
            max: row.try_get("max")?,
            stats: ResourcePoolStats::from_row(row)?,
        })
    }
}

impl From<ResourcePoolSnapshot> for rpc::forge::ResourcePool {
    fn from(rp: ResourcePoolSnapshot) -> Self {
        rpc::forge::ResourcePool {
            name: rp.name,
            min: rp.min,
            max: rp.max,
            total: (rp.stats.free + rp.stats.used) as u64,
            allocated: rp.stats.used as u64,
        }
    }
}

#[derive(Debug)]
pub struct ResourcePoolEntry {
    pub pool_name: String,
    pub pool_type: ValueType,
    pub value: String,
    pub state: sqlx::types::Json<ResourcePoolEntryState>,
    pub allocated: Option<DateTime<Utc>>,
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ResourcePoolEntry {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(ResourcePoolEntry {
            pool_name: row.try_get("name")?,
            pool_type: row.try_get("value_type")?,
            value: row.try_get("value")?,
            state: row.try_get("state")?,
            allocated: row.try_get("allocated")?,
        })
    }
}

/// What kind of data does our resource pool store?
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
#[sqlx(type_name = "resource_pool_type")]
pub enum ValueType {
    Integer = 0,
    Ipv4,
}

impl fmt::Display for ValueType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Integer => write!(f, "Integer"),
            Self::Ipv4 => write!(f, "Ipv4"),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum OwnerType {
    /// owner_type for loopback_ip
    Machine,

    /// owner_type for vlan_id and vni
    NetworkSegment,

    /// owner_type for pkey
    IBSubnet,

    /// owner_type for vpc_cni
    Vpc,
}

impl FromStr for OwnerType {
    type Err = CarbideError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "machine" => Ok(Self::Machine),
            "network_segment" => Ok(Self::NetworkSegment),
            "ib_subnet" => Ok(Self::IBSubnet),
            "vpc" => Ok(Self::Vpc),
            x => Err(CarbideError::GenericError(format!(
                "Unknown owner_type '{}'",
                x
            ))),
        }
    }
}

impl fmt::Display for OwnerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Machine => write!(f, "machine"),
            Self::NetworkSegment => write!(f, "network_segment"),
            Self::IBSubnet => write!(f, "ib_subnet"),
            Self::Vpc => write!(f, "vpc"),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct ResourcePoolStats {
    /// Number of allocated values in this pool
    pub used: usize,

    /// Number of available values in this pool
    pub free: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ResourcePoolError {
    #[error("Resource pool is empty, cannot allocate")]
    Empty,
    #[error("Value is not currently allocated, cannot release")]
    NotAllocated,
    #[error("Value is not available for allocating, cannot mark as allocated")]
    NotAvailable,
    #[error("Internal database error: {0}")]
    Db(#[from] crate::db::DatabaseError),
    #[error("Cannot convert '{v}' to {pool_name}'s pool type for {owner_type} {owner_id}: {e}")]
    Parse {
        e: String,
        v: String,
        pool_name: String,
        owner_type: String,
        owner_id: String,
    },
}
