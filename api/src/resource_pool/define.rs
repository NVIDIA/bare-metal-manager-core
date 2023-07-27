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

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
};

use serde::{Deserialize, Serialize};
use sqlx::{Postgres, Transaction};
use tracing::info;

/// A pool bigger than this is very likely a mistake
const MAX_POOL_SIZE: usize = 250_000;

#[derive(thiserror::Error, Debug)]
pub enum DefineResourcePoolError {
    #[error("Invalid TOML: {0}")]
    InvalidToml(#[from] toml::de::Error),

    #[error("{0}")]
    InvalidArgument(String),

    #[error("Resource pool error: {0}")]
    ResourcePoolError(#[from] crate::resource_pool::ResourcePoolError),

    #[error("Max pool size exceeded. {0} > {1}")]
    TooBig(usize, usize),
}

/// Create or edit the resource pools, making them match the given toml string.
/// Does not delete or shrink pools, is only additive.
pub async fn define_all_from(
    txn: &mut Transaction<'_, Postgres>,
    pools: &HashMap<String, ResourcePoolDef>,
) -> Result<(), DefineResourcePoolError> {
    for (ref name, def) in pools {
        define(txn, name, def).await?;
        info!("Pool {name} populated.");
    }
    Ok(())
}

async fn define(
    txn: &mut Transaction<'_, Postgres>,
    name: &str,
    def: &ResourcePoolDef,
) -> Result<(), DefineResourcePoolError> {
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

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct ResourcePoolDef {
    #[serde(default)]
    pub ranges: Vec<Range>,
    #[serde(default)]
    pub prefix: Option<String>,
    #[serde(rename = "type")]
    pub pool_type: ResourcePoolType,
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq, Eq)]
pub struct Range {
    pub start: String,
    pub end: String,
}

#[derive(Debug, Deserialize, Serialize, Copy, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResourcePoolType {
    Ipv4,
    Integer,
}

async fn define_by_prefix(
    txn: &mut Transaction<'_, Postgres>,
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
    let pool = crate::resource_pool::DbResourcePool::new(
        name.to_string(),
        crate::resource_pool::ValueType::Ipv4,
    );
    pool.populate(txn, values).await?;
    tracing::debug!("Populated IP resource pool {name} with {num_values} values from prefix");

    Ok(())
}

async fn define_by_range(
    txn: &mut Transaction<'_, Postgres>,
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
            let pool = crate::resource_pool::DbResourcePool::new(
                name.to_string(),
                crate::resource_pool::ValueType::Ipv4,
            );
            pool.populate(txn, values).await?;
            tracing::debug!(
                "Populated IP resource pool {name} with {num_values} values from range"
            );
        }
        ResourcePoolType::Integer => {
            let values = expand_int_range(range_start, range_end)
                .map_err(|e| DefineResourcePoolError::InvalidArgument(e.to_string()))?;
            let num_values = values.len();
            if num_values > MAX_POOL_SIZE {
                return Err(DefineResourcePoolError::TooBig(num_values, MAX_POOL_SIZE));
            }
            let pool = crate::resource_pool::DbResourcePool::new(
                name.to_string(),
                crate::resource_pool::ValueType::Integer,
            );
            pool.populate(txn, values).await?;
            tracing::debug!("Populated int resource pool {name} with {num_values} values");
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
fn expand_int_range(start_s: &str, end_s: &str) -> Result<Vec<i32>, eyre::Report> {
    let start: i32 = start_s.parse()?;
    let end: i32 = end_s.parse()?;
    Ok((start..end).collect())
}
