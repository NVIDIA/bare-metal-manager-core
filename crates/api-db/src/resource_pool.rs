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
use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use config_version::ConfigVersion;
use model::resource_pool;
use model::resource_pool::common::{
    CommonPools, DPA_VNI, DpaPools, EXTERNAL_VPC_VNI, EthernetPools, FNN_ASN, IbPools, LOOPBACK_IP,
    SECONDARY_VTEP_IP, VLANID, VNI, VPC_DPU_LOOPBACK, VPC_VNI,
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
) -> Result<(), DatabaseError>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    let free_state = ResourcePoolEntryState::Free;
    let initial_version = ConfigVersion::initial();

    // Divide the bind limit by the number of parameters we're inserting in each tuple (currently 5)
    for vals in all_values.chunks(BIND_LIMIT / 5) {
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
) -> Result<T, ResourcePoolDatabaseError>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    if stats(&mut *txn, value.name()).await?.free == 0 {
        return Err(ResourcePoolError::Empty.into());
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

pub async fn all(txn: &mut PgConnection) -> Result<Vec<ResourcePoolSnapshot>, DatabaseError> {
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
            define_by_prefix(txn, name, def.pool_type, prefix).await?;
        }
        // Just ranges
        (None, ranges) => {
            for range in ranges {
                define_by_range(txn, name, def.pool_type, &range.start, &range.end).await?;
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
) -> Result<(), DefineResourcePoolError> {
    if !matches!(pool_type, ResourcePoolType::Ipv4) {
        return Err(DefineResourcePoolError::InvalidArgument(
            "Only type 'ipv4' can take a prefix".to_string(),
        ));
    }
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
    populate(&pool, txn, values).await?;
    tracing::debug!(
        pool_name = name,
        num_values,
        "Populated IP resource pool from prefix"
    );

    Ok(())
}

async fn define_by_range(
    txn: &mut PgConnection,
    name: &str,
    pool_type: ResourcePoolType,
    range_start: &str,
    range_end: &str,
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
            populate(&pool, txn, values).await?;
            tracing::debug!(
                pool_name = name,
                num_values,
                "Populated IP resource pool from range"
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
            populate(&pool, txn, values).await?;
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

    let pool_loopback_ip: Arc<ResourcePool<Ipv4Addr>> =
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

    let pool_vpc_dpu_loopback_ip: Arc<ResourcePool<Ipv4Addr>> = Arc::new(ResourcePool::new(
        VPC_DPU_LOOPBACK.to_string(),
        ValueType::Ipv4,
    ));
    //  TODO: This should be removed from optional once FNN become mandatory.
    optional_pool_names.push(pool_vpc_dpu_loopback_ip.name().to_string());

    let pool_secondary_vtep_ip: Arc<ResourcePool<Ipv4Addr>> = Arc::new(ResourcePool::new(
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

    let pool_dpa_vni: Arc<ResourcePool<i32>> =
        Arc::new(ResourcePool::new(DPA_VNI.to_string(), ValueType::Integer));

    pool_names.extend(vec![pool_dpa_vni.name().to_string()]);

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
        dpa: DpaPools { pool_dpa_vni },
        pool_stats,
        _stop_sender: stop_sender,
    }))
}
