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
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use config_version::ConfigVersion;
use ipnetwork::Ipv6Network;
use model::resource_pool;
use model::resource_pool::common::{
    CommonPools, EXTERNAL_VPC_VNI, EthernetPools, FNN_ASN, IbPools, LOOPBACK_IP, SECONDARY_VTEP_IP,
    VLANID, VNI, VPC_DPU_LOOPBACK, VPC_VNI,
};
use model::resource_pool::define::{ResourcePoolDef, ResourcePoolType};
use model::resource_pool::{
    OwnerType, ResourcePool, ResourcePoolEntry, ResourcePoolEntryState, ResourcePoolError,
    ResourcePoolSnapshot, ResourcePoolStats, ValueType,
};
use sqlx::{PgConnection, Postgres};
use tokio::sync::oneshot;

use super::BIND_LIMIT;
use crate::DatabaseError;

/// Put some resources into the pool, so they can be allocated later.
/// This needs to be called before `allocate` can return anything.
pub async fn populate<T>(
    value: &ResourcePool<T>,
    txn: &mut PgConnection,
    all_values: Vec<T>,
    auto_assign: bool,
) -> Result<(), DatabaseError>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    let free_state = ResourcePoolEntryState::Free;
    let initial_version = ConfigVersion::initial();

    // Divide the bind limit by the number of parameters we're inserting in each tuple (currently 6)
    for vals in all_values.chunks(BIND_LIMIT / 6) {
        let query = "INSERT INTO resource_pool(name, value, value_type, state, state_version, auto_assign) ";
        let mut qb = sqlx::QueryBuilder::new(query);
        qb.push_values(vals.iter(), |mut b, v| {
            b.push_bind(&value.name)
                .push_bind(v.to_string())
                .push_bind(value.value_type)
                .push_bind(sqlx::types::Json(&free_state))
                .push_bind(initial_version)
                .push_bind(auto_assign);
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
    requested_value: Option<T>,
) -> Result<T, ResourcePoolDatabaseError>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    let stats = stats(&mut *txn, value.name()).await?;
    let auto_assign = requested_value.is_none();

    if (auto_assign && stats.auto_assign_free == 0)
        || (!auto_assign && stats.non_auto_assign_free == 0)
    {
        return Err(ResourcePoolError::Empty.into());
    }
    let query = "
WITH allocate AS (
 SELECT id, value FROM resource_pool
    WHERE
        name = $1
        AND state = $2
        AND auto_assign=$4
        -- Either auto_assign is true or we only want
        -- the requested value.
        AND (auto_assign='t' OR value=$5)
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

    let req = requested_value.map(|v| v.to_string());
    // TODO: We should probably update the `state_version` field too. But
    // it's hard to do this inside the SQL query.
    let (allocated,): (String,) = sqlx::query_as(query)
        .bind(&value.name)
        .bind(sqlx::types::Json(&free_state))
        .bind(sqlx::types::Json(&allocated_state))
        .bind(auto_assign)
        .bind(&req)
        .fetch_one(&mut *txn)
        .await
        .map_err(|e| match e {
            // A check for available allocations was done earlier.
            // If a value was explicitly requested but we made it here,
            // then it was either already allocated or it was not a value
            // that is allowed to be explictly requested.
            sqlx::Error::RowNotFound if !auto_assign => DatabaseError::FailedPrecondition(format!(
                "`{}` not an available value for resource-pool `{}`",
                req.unwrap_or_default(),
                value.name()
            )),
            e => DatabaseError::query(query, e),
        })?;
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
) -> Result<(), DatabaseError>
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

pub async fn stats<'c, E>(executor: E, name: &str) -> Result<ResourcePoolStats, DatabaseError>
where
    E: sqlx::Executor<'c, Database = Postgres>,
{
    // Will do an index scan on idx_resource_pools_name, same as without the FILTER, so doing
    // all at once is faster than two queries.
    let free_state = ResourcePoolEntryState::Free;
    let query = "SELECT
                            auto_assign_used,
                            auto_assign_free,
                            non_auto_assign_used,
                            non_auto_assign_free,
                            (auto_assign_used + non_auto_assign_used) AS used,
                            (auto_assign_free + non_auto_assign_free) AS free
                        FROM
                            (
                                SELECT
                                COUNT(*) FILTER (WHERE state != $1 AND auto_assign) AS auto_assign_used,
                                COUNT(*) FILTER (WHERE state = $1 AND auto_assign) AS auto_assign_free,
                                COUNT(*) FILTER (WHERE state != $1 AND NOT auto_assign) AS non_auto_assign_used,
                                COUNT(*) FILTER (WHERE state = $1 AND NOT auto_assign) AS non_auto_assign_free
                                FROM resource_pool WHERE NAME = $2
                        ) split_stats";
    let s: ResourcePoolStats = sqlx::query_as(query)
        .bind(sqlx::types::Json(free_state))
        .bind(name)
        .fetch_one(executor)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(s)
}

pub async fn all(txn: &mut PgConnection) -> Result<Vec<ResourcePoolSnapshot>, DatabaseError> {
    let mut out = Vec::with_capacity(4);

    let query_int = "
            SELECT
                name,
                min,
                max,
                auto_assign_free,
                auto_assign_used,
                non_auto_assign_free,
                non_auto_assign_used,
                (auto_assign_used + non_auto_assign_used) AS used,
                (auto_assign_free + non_auto_assign_free) AS free
            FROM
            (
                SELECT name, CAST(min(value::bigint) AS text), CAST(max(value::bigint) AS text),
                    count(*) FILTER (WHERE state = '{\"state\": \"free\"}' AND auto_assign) AS auto_assign_free,
                    count(*) FILTER (WHERE state != '{\"state\": \"free\"}' AND auto_assign) AS auto_assign_used,
                    count(*) FILTER (WHERE state = '{\"state\": \"free\"}' AND NOT auto_assign) AS non_auto_assign_free,
                    count(*) FILTER (WHERE state != '{\"state\": \"free\"}' AND NOT auto_assign) AS non_auto_assign_used
                FROM resource_pool WHERE value_type = 'integer' GROUP BY name
            ) snapshot";

    let query_ipv4 = "
            SELECT
                name,
                min,
                max,
                auto_assign_free,
                auto_assign_used,
                non_auto_assign_free,
                non_auto_assign_used,
                (auto_assign_used + non_auto_assign_used) AS used,
                (auto_assign_free + non_auto_assign_free) AS free
            FROM
            (
                SELECT name, CAST(min(value::bigint) AS text), CAST(max(value::bigint) AS text),
                    count(*) FILTER (WHERE state = '{\"state\": \"free\"}' AND auto_assign) AS auto_assign_free,
                    count(*) FILTER (WHERE state != '{\"state\": \"free\"}' AND auto_assign) AS auto_assign_used,
                    count(*) FILTER (WHERE state = '{\"state\": \"free\"}' AND NOT auto_assign) AS non_auto_assign_free,
                    count(*) FILTER (WHERE state != '{\"state\": \"free\"}' AND NOT auto_assign) AS non_auto_assign_used
                FROM resource_pool WHERE value_type = 'ipv4' GROUP BY name
            ) snapshot";

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
) -> Result<Vec<ResourcePoolEntry>, DatabaseError> {
    let query =
        "SELECT name, value, value_type, state, allocated FROM resource_pool WHERE value = $1";
    let entry: Vec<ResourcePoolEntry> = sqlx::query_as(query)
        .bind(value)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(entry)
}

/// Used for functions that may return a database error or may return a ResourcePoolError. This
/// keeps this DatabaseError out of the ResourcePoolError variants, so they can live in separate
/// crates.
#[derive(thiserror::Error, Debug)]
pub enum ResourcePoolDatabaseError {
    #[error(transparent)]
    ResourcePool(#[from] ResourcePoolError),
    #[error(transparent)]
    Database(#[from] Box<DatabaseError>),
}

impl From<DatabaseError> for ResourcePoolDatabaseError {
    fn from(e: DatabaseError) -> Self {
        ResourcePoolDatabaseError::Database(Box::new(e))
    }
}

/// A pool bigger than this is very likely a mistake
const MAX_POOL_SIZE: usize = 250_000;

#[derive(thiserror::Error, Debug)]
pub enum DefineResourcePoolError {
    #[error("Invalid TOML: {0}")]
    InvalidToml(#[from] toml::de::Error),

    #[error("{0}")]
    InvalidArgument(String),

    #[error("Resource pool error: {0}")]
    ResourcePoolError(#[from] model::resource_pool::ResourcePoolError),

    #[error("Max pool size exceeded. {0} > {1}")]
    TooBig(usize, usize),

    #[error("Database error: {0}")]
    DatabaseError(#[from] DatabaseError),
}

/// Create or edit the resource pools, making them match the given toml string.
/// Does not delete or shrink pools, is only additive.
pub async fn define_all_from(
    txn: &mut PgConnection,
    pools: &HashMap<String, ResourcePoolDef>,
) -> Result<(), DefineResourcePoolError> {
    for (ref name, def) in pools {
        define(txn, name, def).await?;
        tracing::info!(pool_name = name, "Pool populated");
    }
    Ok(())
}

pub async fn define(
    txn: &mut PgConnection,
    name: &str,
    def: &ResourcePoolDef,
) -> Result<(), DefineResourcePoolError> {
    if name == "pkey" {
        return Err(DefineResourcePoolError::InvalidArgument(
            "pkey pool is deprecated. Use ib_fabrics.default.pkeys as replacement".to_string(),
        ));
    }

    match (&def.prefix, &def.ranges) {
        // Neither is given
        (None, ranges) if ranges.is_empty() => {
            return Err(DefineResourcePoolError::InvalidArgument(
                "Please provide one of 'prefix' or 'ranges'".to_string(),
            ));
        }
        // Both are given
        (Some(_), ranges) if !ranges.is_empty() => {
            return Err(DefineResourcePoolError::InvalidArgument(
                "Please provide only one of 'prefix' or 'ranges'".to_string(),
            ));
        }
        // Just prefix
        (Some(prefix), _) => {
            define_by_prefix(txn, name, def.pool_type, prefix, def.delegate_prefix_len).await?;
        }
        // Just ranges
        (None, ranges) => {
            for range in ranges {
                define_by_range(
                    txn,
                    name,
                    def.pool_type,
                    &range.start,
                    &range.end,
                    range.auto_assign,
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn define_by_prefix(
    txn: &mut PgConnection,
    name: &str,
    pool_type: ResourcePoolType,
    prefix: &str,
    delegate_prefix_len: Option<u8>,
) -> Result<(), DefineResourcePoolError> {
    match pool_type {
        ResourcePoolType::Ipv4 => {
            let values = expand_ip_prefix(prefix)
                .map_err(|e| DefineResourcePoolError::InvalidArgument(e.to_string()))?;
            let num_values = values.len();
            if num_values > MAX_POOL_SIZE {
                return Err(DefineResourcePoolError::TooBig(num_values, MAX_POOL_SIZE));
            }
            let pool = model::resource_pool::ResourcePool::new(
                name.to_string(),
                model::resource_pool::ValueType::Ipv4,
            );
            populate(&pool, txn, values, true).await?;
            tracing::debug!(
                pool_name = name,
                prefix,
                num_values,
                "Populated IPv4 resource pool from prefix"
            );
        }
        ResourcePoolType::Ipv6 => {
            let values = expand_ipv6_prefix(prefix)?;
            let num_values = values.len();
            let pool = model::resource_pool::ResourcePool::new(
                name.to_string(),
                model::resource_pool::ValueType::Ipv6,
            );
            populate(&pool, txn, values, true).await?;
            tracing::debug!(
                pool_name = name,
                prefix,
                num_values,
                "Populated IPv6 resource pool from prefix"
            );
        }
        ResourcePoolType::Ipv6Prefix => {
            let delegate_len = delegate_prefix_len.ok_or_else(|| {
                DefineResourcePoolError::InvalidArgument(
                    "Pool type 'ipv6prefix' requires 'delegate_prefix_len'".to_string(),
                )
            })?;
            let values = expand_ipv6_prefix_delegation(prefix, delegate_len)?;
            let num_values = values.len();
            let pool = model::resource_pool::ResourcePool::new(
                name.to_string(),
                model::resource_pool::ValueType::Ipv6Prefix,
            );
            populate(&pool, txn, values, true).await?;
            tracing::debug!(
                pool_name = name,
                prefix,
                delegate_len,
                num_values,
                "Populated IPv6 prefix delegation pool"
            );
        }
        ResourcePoolType::Integer => {
            return Err(DefineResourcePoolError::InvalidArgument(
                "Pool type 'integer' cannot take a prefix".to_string(),
            ));
        }
    }

    Ok(())
}

async fn define_by_range(
    txn: &mut PgConnection,
    name: &str,
    pool_type: ResourcePoolType,
    range_start: &str,
    range_end: &str,
    auto_assign: bool,
) -> Result<(), DefineResourcePoolError> {
    match pool_type {
        ResourcePoolType::Ipv4 => {
            let values = expand_ip_range(range_start, range_end)
                .map_err(|e| DefineResourcePoolError::InvalidArgument(e.to_string()))?;
            let num_values = values.len();
            if num_values > MAX_POOL_SIZE {
                return Err(DefineResourcePoolError::TooBig(num_values, MAX_POOL_SIZE));
            }
            let pool = model::resource_pool::ResourcePool::new(
                name.to_string(),
                model::resource_pool::ValueType::Ipv4,
            );
            populate(&pool, txn, values, auto_assign).await?;
            tracing::debug!(
                pool_name = name,
                range_start,
                range_end,
                num_values,
                "Populated IPv4 resource pool from range"
            );
        }
        ResourcePoolType::Ipv6 => {
            let values = expand_ipv6_range(range_start, range_end)?;
            let num_values = values.len();
            let pool = model::resource_pool::ResourcePool::new(
                name.to_string(),
                model::resource_pool::ValueType::Ipv6,
            );
            populate(&pool, txn, values, auto_assign).await?;
            tracing::debug!(
                pool_name = name,
                range_start,
                range_end,
                num_values,
                "Populated IPv6 resource pool from range"
            );
        }
        ResourcePoolType::Ipv6Prefix => {
            let values = expand_ipv6_prefix_range(range_start, range_end)?;
            let num_values = values.len();
            let pool = model::resource_pool::ResourcePool::new(
                name.to_string(),
                model::resource_pool::ValueType::Ipv6Prefix,
            );
            populate(&pool, txn, values, auto_assign).await?;
            tracing::debug!(
                pool_name = name,
                range_start,
                range_end,
                num_values,
                "Populated IPv6 prefix pool from range"
            );
        }
        ResourcePoolType::Integer => {
            let values = expand_int_range(range_start, range_end)
                .map_err(|e| DefineResourcePoolError::InvalidArgument(e.to_string()))?;
            let num_values = values.len();
            if num_values > MAX_POOL_SIZE {
                return Err(DefineResourcePoolError::TooBig(num_values, MAX_POOL_SIZE));
            }
            let pool = model::resource_pool::ResourcePool::new(
                name.to_string(),
                model::resource_pool::ValueType::Integer,
            );
            populate(&pool, txn, values, auto_assign).await?;
            tracing::debug!(pool_name = name, num_values, "Populated int resource pool");
        }
    }
    Ok(())
}

// Expands a string like "10.180.62.1/26" into all the ip addresses it covers
fn expand_ip_prefix(network: &str) -> Result<Vec<Ipv4Addr>, eyre::Report> {
    let n: ipnetwork::IpNetwork = network.parse()?;
    let (start_addr, end_addr) = match (n.network(), n.broadcast()) {
        (IpAddr::V4(start), IpAddr::V4(end)) => (start, end),
        _ => {
            eyre::bail!("Invalid IPv4 network: {network}");
        }
    };
    let start: u32 = start_addr.into();
    let end: u32 = end_addr.into();
    Ok((start..end).map(Ipv4Addr::from).collect())
}

// All the IPv4 addresses between start_s and end_s
fn expand_ip_range(start_s: &str, end_s: &str) -> Result<Vec<Ipv4Addr>, eyre::Report> {
    let start_addr: Ipv4Addr = start_s.parse()?;
    let end_addr: Ipv4Addr = end_s.parse()?;
    let start: u32 = start_addr.into();
    let end: u32 = end_addr.into();
    Ok((start..end).map(Ipv4Addr::from).collect())
}

// expand_ipv6_prefix is the IPv6 variant of the expand_ip_prefix
// function, expanding an IPv6 prefix into all addresses it covers.
fn expand_ipv6_prefix(network: &str) -> Result<Vec<Ipv6Addr>, DefineResourcePoolError> {
    let n: ipnetwork::IpNetwork = network.parse().map_err(|e: ipnetwork::IpNetworkError| {
        DefineResourcePoolError::InvalidArgument(e.to_string())
    })?;
    let (start_addr, end_addr, prefix_len) = match n {
        ipnetwork::IpNetwork::V6(v6) => (v6.network(), v6.broadcast(), v6.prefix()),
        _ => {
            return Err(DefineResourcePoolError::InvalidArgument(format!(
                "Invalid IPv6 network: {network}"
            )));
        }
    };

    // Compute the number of addresses this prefix would produce
    // and reject if it exceeds MAX_POOL_SIZE -- there's no point
    // in attempting otherwise. I guess in theory there might also
    // be concerns for OOMing and such if a prefix was too small
    // and we ranged out like 18.4 quintillion addresses, so doing
    // a check against MAX_POOL_SIZE helps to keep that.. in check.
    let host_bits = 128 - prefix_len as u32;
    let num_addresses = 1u128.checked_shl(host_bits).unwrap_or(u128::MAX);
    if num_addresses > MAX_POOL_SIZE as u128 {
        return Err(DefineResourcePoolError::TooBig(
            usize::try_from(num_addresses).unwrap_or(usize::MAX),
            MAX_POOL_SIZE,
        ));
    }

    let start: u128 = start_addr.into();
    let end: u128 = end_addr.into();

    // Unlike IPv4, IPv6 has no broadcast address, so we include
    // all addresses in the prefix (inclusive range) -- this is
    // different from expand_ip_prefix_above, so worth calling
    // it out so someone doesn't think it's a bug.
    Ok((start..=end).map(Ipv6Addr::from).collect())
}

// expand_ipv6_range is the IPv6 variant of expand_ip_range,
// expanding the IPv6 addresses between start_s and end_s.
fn expand_ipv6_range(start_s: &str, end_s: &str) -> Result<Vec<Ipv6Addr>, DefineResourcePoolError> {
    let start_addr: Ipv6Addr = start_s.parse().map_err(|e: std::net::AddrParseError| {
        DefineResourcePoolError::InvalidArgument(e.to_string())
    })?;
    let end_addr: Ipv6Addr = end_s.parse().map_err(|e: std::net::AddrParseError| {
        DefineResourcePoolError::InvalidArgument(e.to_string())
    })?;
    let start: u128 = start_addr.into();
    let end: u128 = end_addr.into();

    let count = end.saturating_sub(start);
    if count > MAX_POOL_SIZE as u128 {
        return Err(DefineResourcePoolError::TooBig(
            usize::try_from(count).unwrap_or(usize::MAX),
            MAX_POOL_SIZE,
        ));
    }

    Ok((start..end).map(Ipv6Addr::from).collect())
}

// expand_ipv6_prefix_delegation expands a parent IPv6 prefix into
// sub-prefixes of the given delegation length. For example, "fd00::/48"
// with delegate_len=64 produces all 65,536 /64 sub-prefixes within that /48.
fn expand_ipv6_prefix_delegation(
    parent: &str,
    delegate_len: u8,
) -> Result<Vec<Ipv6Network>, DefineResourcePoolError> {
    let n: ipnetwork::IpNetwork = parent.parse().map_err(|e: ipnetwork::IpNetworkError| {
        DefineResourcePoolError::InvalidArgument(e.to_string())
    })?;
    let parent_net = match n {
        ipnetwork::IpNetwork::V6(v6) => v6,
        _ => {
            return Err(DefineResourcePoolError::InvalidArgument(format!(
                "Invalid IPv6 network: {parent}"
            )));
        }
    };

    let parent_len = parent_net.prefix();
    if delegate_len <= parent_len {
        return Err(DefineResourcePoolError::InvalidArgument(format!(
            "Delegation prefix length /{delegate_len} must be longer than parent prefix length /{parent_len}"
        )));
    }
    if delegate_len > 128 {
        return Err(DefineResourcePoolError::InvalidArgument(format!(
            "Delegation prefix length /{delegate_len} exceeds maximum /128"
        )));
    }

    // Number of sub-prefixes == 2^(delegate_len - parent_len).
    let sub_bits = (delegate_len - parent_len) as u32;
    let count = 1u128.checked_shl(sub_bits).unwrap_or(u128::MAX);
    if count > MAX_POOL_SIZE as u128 {
        return Err(DefineResourcePoolError::TooBig(
            usize::try_from(count).unwrap_or(usize::MAX),
            MAX_POOL_SIZE,
        ));
    }

    // And now step between consecutive sub-prefix network addresses.
    let step = 1u128 << (128 - delegate_len as u32);
    let base: u128 = parent_net.network().into();

    let mut prefixes = Vec::with_capacity(count as usize);
    for i in 0..count {
        let addr = Ipv6Addr::from(base + i * step);
        let net = Ipv6Network::new(addr, delegate_len)
            .map_err(|e| DefineResourcePoolError::InvalidArgument(e.to_string()))?;
        prefixes.push(net);
    }
    Ok(prefixes)
}

// expand_ipv6_prefix_range expands a range of IPv6 prefixes. Both
// endpoints must be CIDR notation with the same prefix length and
// properly aligned (no stray host bits). Uses exclusive end, matching
// the convention of the other type's range-expansion functions.
fn expand_ipv6_prefix_range(
    start_s: &str,
    end_s: &str,
) -> Result<Vec<Ipv6Network>, DefineResourcePoolError> {
    let start_net: Ipv6Network = start_s.parse().map_err(|e: ipnetwork::IpNetworkError| {
        DefineResourcePoolError::InvalidArgument(e.to_string())
    })?;
    let end_net: Ipv6Network = end_s.parse().map_err(|e: ipnetwork::IpNetworkError| {
        DefineResourcePoolError::InvalidArgument(e.to_string())
    })?;

    let prefix_len = start_net.prefix();
    if end_net.prefix() != prefix_len {
        return Err(DefineResourcePoolError::InvalidArgument(format!(
            "Range endpoints have different prefix lengths: /{} vs /{}",
            prefix_len,
            end_net.prefix()
        )));
    }

    // Verify alignment prefix alignment -- the specified IP must equal
    // the network address (i.e. no host bits set); Ipv6Network::parse()
    // accepts "fd00::1/64" but that's a host address, not a valid network
    // prefix.
    if start_net.ip() != start_net.network() {
        return Err(DefineResourcePoolError::InvalidArgument(format!(
            "Start prefix {start_s} has host bits set"
        )));
    }
    if end_net.ip() != end_net.network() {
        return Err(DefineResourcePoolError::InvalidArgument(format!(
            "End prefix {end_s} has host bits set"
        )));
    }

    let start_addr: u128 = start_net.network().into();
    let end_addr: u128 = end_net.network().into();
    let step = 1u128 << (128 - prefix_len as u32);

    if end_addr <= start_addr {
        return Err(DefineResourcePoolError::InvalidArgument(
            "End prefix must be greater than start prefix".to_string(),
        ));
    }

    let count = (end_addr - start_addr) / step;
    if count > MAX_POOL_SIZE as u128 {
        return Err(DefineResourcePoolError::TooBig(
            usize::try_from(count).unwrap_or(usize::MAX),
            MAX_POOL_SIZE,
        ));
    }

    let mut prefixes = Vec::with_capacity(count as usize);
    for i in 0..count {
        let addr = Ipv6Addr::from(start_addr + i * step);
        let net = Ipv6Network::new(addr, prefix_len)
            .map_err(|e| DefineResourcePoolError::InvalidArgument(e.to_string()))?;
        prefixes.push(net);
    }
    Ok(prefixes)
}

// All the numbers between start_s and end_s
fn expand_int_range(start_s: &str, end_s: &str) -> Result<Vec<i64>, eyre::Report> {
    let start: i64 = parse_int_range(start_s)?;
    let end: i64 = parse_int_range(end_s)?;
    Ok((start..end).collect())
}

const HEX_PRE: &str = "0x";

fn parse_int_range(data: &str) -> Result<i64, eyre::Report> {
    let data = data.to_lowercase();
    let base = if data.starts_with(HEX_PRE) { 16 } else { 10 };
    let p = data.trim_start_matches(HEX_PRE);

    i64::from_str_radix(p, base).map_err(eyre::Report::from)
}

/// How often to update the resource pool metrics
const METRICS_RESOURCEPOOL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

pub async fn create_common_pools(
    db: sqlx::PgPool,
    ib_fabric_ids: HashSet<String>,
) -> eyre::Result<Arc<CommonPools>> {
    let mut pool_names = Vec::new();
    let mut optional_pool_names = Vec::new();

    let pool_loopback_ip: Arc<ResourcePool<IpAddr>> =
        Arc::new(ResourcePool::new(LOOPBACK_IP.to_string(), ValueType::Ipv4));
    pool_names.push(pool_loopback_ip.name().to_string());
    let pool_vlan_id: Arc<ResourcePool<i16>> =
        Arc::new(ResourcePool::new(VLANID.to_string(), ValueType::Integer));
    pool_names.push(pool_vlan_id.name().to_string());
    let pool_vni: Arc<ResourcePool<i32>> =
        Arc::new(ResourcePool::new(VNI.to_string(), ValueType::Integer));
    pool_names.push(pool_vni.name().to_string());
    let pool_vpc_vni: Arc<ResourcePool<i32>> =
        Arc::new(ResourcePool::new(VPC_VNI.to_string(), ValueType::Integer));
    pool_names.push(pool_vpc_vni.name().to_string());
    let pool_fnn_asn: Arc<ResourcePool<u32>> =
        Arc::new(ResourcePool::new(FNN_ASN.to_string(), ValueType::Integer));
    optional_pool_names.push(pool_fnn_asn.name().to_string());

    let pool_vpc_dpu_loopback_ip: Arc<ResourcePool<IpAddr>> = Arc::new(ResourcePool::new(
        VPC_DPU_LOOPBACK.to_string(),
        ValueType::Ipv4,
    ));
    //  TODO: This should be removed from optional once FNN become mandatory.
    optional_pool_names.push(pool_vpc_dpu_loopback_ip.name().to_string());

    let pool_secondary_vtep_ip: Arc<ResourcePool<IpAddr>> = Arc::new(ResourcePool::new(
        SECONDARY_VTEP_IP.to_string(),
        ValueType::Ipv4,
    ));
    optional_pool_names.push(pool_secondary_vtep_ip.name().to_string());

    let pool_external_vpc_vni: Arc<ResourcePool<i32>> = Arc::new(ResourcePool::new(
        EXTERNAL_VPC_VNI.to_string(),
        ValueType::Integer,
    ));
    optional_pool_names.push(pool_external_vpc_vni.name().to_string());

    // We can't run if any of the mandatory pools are missing
    for name in &pool_names {
        if stats(&db, name).await?.free == 0 {
            eyre::bail!("Resource pool '{name}' missing or full. Edit config file and restart.");
        }
    }

    pool_names.extend(optional_pool_names);

    // It's ok for IB partition pools to be missing or full - as long as nobody tries to use partitions
    let pkey_pools: Arc<HashMap<String, ResourcePool<u16>>> = Arc::new(
        ib_fabric_ids
            .into_iter()
            .map(|fabric_id| {
                (
                    fabric_id.clone(),
                    ResourcePool::new(
                        resource_pool::common::ib_pkey_pool_name(&fabric_id),
                        ValueType::Integer,
                    ),
                )
            })
            .collect(),
    );
    pool_names.extend(pkey_pools.values().map(|pool| pool.name().to_string()));

    // Gather resource pool stats. A different thread sends them to Prometheus.
    let (stop_sender, mut stop_receiver) = oneshot::channel();
    let pool_stats: Arc<Mutex<HashMap<String, ResourcePoolStats>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let pool_stats_bg = pool_stats.clone();
    tokio::task::Builder::new()
        .name("resource_pool metrics")
        .spawn(async move {
            loop {
                let mut next_stats = HashMap::with_capacity(pool_names.len());
                for name in &pool_names {
                    if let Ok(st) = stats(&db, name).await {
                        next_stats.insert(name.to_string(), st);
                    }
                }
                *pool_stats_bg.lock().unwrap() = next_stats;

                tokio::select! {
                    _ = tokio::time::sleep(METRICS_RESOURCEPOOL_INTERVAL) => {},
                    _ = &mut stop_receiver => {
                        tracing::info!("CommonPool metrics stop was requested");
                        return;
                    }
                }
            }
        })?;

    Ok(Arc::new(CommonPools {
        ethernet: EthernetPools {
            pool_loopback_ip,
            pool_vlan_id,
            pool_vni,
            pool_vpc_vni,
            pool_external_vpc_vni,
            pool_fnn_asn,
            pool_vpc_dpu_loopback_ip,
            pool_secondary_vtep_ip,
        },
        infiniband: IbPools { pkey_pools },
        pool_stats,
        _stop_sender: stop_sender,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[crate::sqlx_test]
    async fn test_ipv6_pool_define_allocate_release(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use model::resource_pool::define::{ResourcePoolDef, ResourcePoolType};

        let mut txn = pool.begin().await?;

        // Define an IPv6 pool from a /120 prefix (256 addresses).
        define(
            &mut txn,
            "test-ipv6-pool",
            &ResourcePoolDef {
                prefix: Some("fd00:abcd::/120".to_string()),
                ranges: vec![],
                pool_type: ResourcePoolType::Ipv6,
                delegate_prefix_len: None,
            },
        )
        .await
        .unwrap();

        // Verify pool stats.
        // /120 == 256 usable IPv6 addresses.
        let pool_stats = stats(txn.as_mut(), "test-ipv6-pool").await?;
        assert_eq!(pool_stats.free, 256);

        // Allocate an address.
        let pool_handle =
            ResourcePool::<Ipv6Addr>::new("test-ipv6-pool".to_string(), ValueType::Ipv6);
        let addr: Ipv6Addr = allocate(
            &pool_handle,
            &mut txn,
            OwnerType::Machine,
            "test-owner",
            None,
        )
        .await?;
        assert!(addr.to_string().starts_with("fd00:abcd::"));

        // Stats should show 1 used.
        let pool_stats = stats(txn.as_mut(), "test-ipv6-pool").await?;
        assert_eq!(pool_stats.used, 1);
        assert_eq!(pool_stats.free, 255);

        // Release the address.
        release(&pool_handle, &mut txn, addr).await?;
        let pool_stats = stats(txn.as_mut(), "test-ipv6-pool").await?;
        assert_eq!(pool_stats.used, 0);
        assert_eq!(pool_stats.free, 256);

        txn.rollback().await?;
        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_ipv6_pool_define_by_range(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use model::resource_pool::define::{Range, ResourcePoolDef, ResourcePoolType};

        let mut txn = pool.begin().await?;

        // Define an IPv6 pool from a range.
        define(
            &mut txn,
            "test-ipv6-range",
            &ResourcePoolDef {
                prefix: None,
                ranges: vec![Range {
                    start: "fd00::1".to_string(),
                    end: "fd00::11".to_string(),
                    auto_assign: true,
                }],
                pool_type: ResourcePoolType::Ipv6,
                delegate_prefix_len: None,
            },
        )
        .await
        .unwrap();

        // Should have 16 addresses (fd00::1 through fd00::10).
        let pool_stats = stats(txn.as_mut(), "test-ipv6-range").await?;
        assert_eq!(pool_stats.free, 16);

        txn.rollback().await?;
        Ok(())
    }

    #[test]
    fn test_expand_ipv6_prefix_120() {
        // A /120 has 256 addresses, so make sure all 256 are included.
        let addrs = expand_ipv6_prefix("fd00::/120").unwrap();
        assert_eq!(addrs.len(), 256);
        assert_eq!(addrs[0], "fd00::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(addrs[255], "fd00::ff".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_expand_ipv6_prefix_rejects_large_prefix() {
        // A /64 would produce 2^64 addresses, which, as of this
        // writing, is beyond MAX_POOL_SIZE (and would cause us
        // to OOM anyway).
        let result = expand_ipv6_prefix("fd00::/64");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DefineResourcePoolError::TooBig(_, _)
        ));
    }

    #[test]
    fn test_expand_ipv6_prefix_boundary() {
        // A /111 == 2^17 = 131,072 addresses — under MAX_POOL_SIZE
        // (which is currently 250k as of this writing).
        let addrs = expand_ipv6_prefix("fd00::/111").unwrap();
        assert_eq!(addrs.len(), 131_072);

        // A /110 == 262,144 addresses — over MAX_POOL_SIZE, which
        // is currently 250k as of this writing.
        let result = expand_ipv6_prefix("fd00::/110");
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DefineResourcePoolError::TooBig(_, _)
        ));
    }

    #[test]
    fn test_expand_ipv6_prefix_rejects_ipv4() {
        let result = expand_ipv6_prefix("192.168.1.0/24");
        assert!(result.is_err());
    }

    #[test]
    fn test_expand_ipv6_range() {
        let addrs = expand_ipv6_range("fd00::1", "fd00::4").unwrap();
        assert_eq!(addrs.len(), 3);
        assert_eq!(addrs[0], "fd00::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(addrs[1], "fd00::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(addrs[2], "fd00::3".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn test_expand_ipv6_range_rejects_ipv4() {
        let result = expand_ipv6_range("192.168.1.1", "192.168.1.5");
        assert!(result.is_err());
    }

    #[test]
    fn test_expand_ipv6_prefix_delegation_48_to_64() {
        // /48 to /64 == 65,536 sub-prefixes.
        let prefixes = expand_ipv6_prefix_delegation("fd00:abcd::/48", 64).unwrap();
        assert_eq!(prefixes.len(), 65_536);
        assert_eq!(
            prefixes[0],
            "fd00:abcd::/64".parse::<Ipv6Network>().unwrap()
        );
        assert_eq!(
            prefixes[65_535],
            "fd00:abcd:0000:ffff::/64".parse::<Ipv6Network>().unwrap()
        );
    }

    #[test]
    fn test_expand_ipv6_prefix_delegation_112_to_120() {
        // /112 to /120 == 256 sub-prefixes.
        let prefixes = expand_ipv6_prefix_delegation("fd00:abcd::/112", 120).unwrap();
        assert_eq!(prefixes.len(), 256);
        assert_eq!(
            prefixes[0],
            "fd00:abcd::/120".parse::<Ipv6Network>().unwrap()
        );
        assert_eq!(
            prefixes[1],
            "fd00:abcd::100/120".parse::<Ipv6Network>().unwrap()
        );
        assert_eq!(
            prefixes[255],
            "fd00:abcd::ff00/120".parse::<Ipv6Network>().unwrap()
        );
    }

    #[test]
    fn test_expand_ipv6_prefix_delegation_rejects_invalid() {
        // Delegation prefix length cant be less than the parent prefix length.
        let result = expand_ipv6_prefix_delegation("fd00::/64", 64);
        assert!(matches!(
            result.unwrap_err(),
            DefineResourcePoolError::InvalidArgument(_)
        ));

        let result = expand_ipv6_prefix_delegation("fd00::/64", 48);
        assert!(matches!(
            result.unwrap_err(),
            DefineResourcePoolError::InvalidArgument(_)
        ));
    }

    #[test]
    fn test_expand_ipv6_prefix_delegation_rejects_too_large() {
        // /32 to /64 == 4 billion, which is over the MAX_POOL_SIZE,
        // at least as of this writing, which is 250k.
        let result = expand_ipv6_prefix_delegation("fd00::/32", 64);
        assert!(matches!(
            result.unwrap_err(),
            DefineResourcePoolError::TooBig(_, _)
        ));
    }

    #[test]
    fn test_expand_ipv6_prefix_delegation_rejects_ipv4() {
        let result = expand_ipv6_prefix_delegation("192.168.0.0/16", 24);
        assert!(matches!(
            result.unwrap_err(),
            DefineResourcePoolError::InvalidArgument(_)
        ));
    }

    #[test]
    fn test_expand_ipv6_prefix_range() {
        // Range of /120s -- fd00::100/120 to fd00::300/120 -- gives us 2,
        // since we exclude the ending prefix.
        let prefixes = expand_ipv6_prefix_range("fd00::100/120", "fd00::300/120").unwrap();
        assert_eq!(prefixes.len(), 2);
        assert_eq!(prefixes[0], "fd00::100/120".parse::<Ipv6Network>().unwrap());
        assert_eq!(prefixes[1], "fd00::200/120".parse::<Ipv6Network>().unwrap());
    }

    #[test]
    fn test_expand_ipv6_prefix_range_rejects_mismatched_len() {
        let result = expand_ipv6_prefix_range("fd00::/64", "fd00:1::/48");
        assert!(matches!(
            result.unwrap_err(),
            DefineResourcePoolError::InvalidArgument(_)
        ));
    }

    #[test]
    fn test_expand_ipv6_prefix_range_rejects_unaligned() {
        // In this case, fd00::1/120 has host bits set, so it's
        // not a valid network prefix.
        let result = expand_ipv6_prefix_range("fd00::1/120", "fd00::200/120");
        assert!(matches!(
            result.unwrap_err(),
            DefineResourcePoolError::InvalidArgument(_)
        ));
    }

    #[crate::sqlx_test]
    async fn test_ipv6_prefix_pool_define_allocate_release(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use model::resource_pool::define::{ResourcePoolDef, ResourcePoolType};

        let mut txn = pool.begin().await?;

        // Define pool w/ /112 and /120 delegation (giving us
        // 256 sub-prefixes).
        define(
            &mut txn,
            "test-ipv6prefix-pool",
            &ResourcePoolDef {
                prefix: Some("fd00:abcd::/112".to_string()),
                ranges: vec![],
                pool_type: ResourcePoolType::Ipv6Prefix,
                delegate_prefix_len: Some(120),
            },
        )
        .await
        .unwrap();

        // Verify pool stats.
        let pool_stats = stats(txn.as_mut(), "test-ipv6prefix-pool").await?;
        assert_eq!(pool_stats.free, 256);

        // Allocate a sub-prefix.
        let pool_handle = ResourcePool::<Ipv6Network>::new(
            "test-ipv6prefix-pool".to_string(),
            ValueType::Ipv6Prefix,
        );
        let prefix: Ipv6Network = allocate(
            &pool_handle,
            &mut txn,
            OwnerType::Machine,
            "test-owner",
            None,
        )
        .await?;
        assert_eq!(prefix.prefix(), 120);

        // Stats should show 1 used.
        let pool_stats = stats(txn.as_mut(), "test-ipv6prefix-pool").await?;
        assert_eq!(pool_stats.used, 1);
        assert_eq!(pool_stats.free, 255);

        // Release the sub-prefix.
        release(&pool_handle, &mut txn, prefix).await?;
        let pool_stats = stats(txn.as_mut(), "test-ipv6prefix-pool").await?;
        assert_eq!(pool_stats.used, 0);
        assert_eq!(pool_stats.free, 256);

        txn.rollback().await?;
        Ok(())
    }

    #[crate::sqlx_test]
    async fn test_ipv6_prefix_pool_define_by_range(
        pool: sqlx::PgPool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use model::resource_pool::define::{Range, ResourcePoolDef, ResourcePoolType};

        let mut txn = pool.begin().await?;

        // Define pool from a range of /120s.
        define(
            &mut txn,
            "test-ipv6prefix-range",
            &ResourcePoolDef {
                prefix: None,
                ranges: vec![Range {
                    start: "fd00::0/120".to_string(),
                    end: "fd00::1000/120".to_string(),
                    auto_assign: true,
                }],
                pool_type: ResourcePoolType::Ipv6Prefix,
                delegate_prefix_len: None,
            },
        )
        .await
        .unwrap();

        // Here we've got fd00::0/120 to fd00::1000/120 (with our current
        // exclusive end), which gives us 16 prefixes.
        let pool_stats = stats(txn.as_mut(), "test-ipv6prefix-range").await?;
        assert_eq!(pool_stats.free, 16);

        txn.rollback().await?;
        Ok(())
    }
}
