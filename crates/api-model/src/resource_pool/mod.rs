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
pub mod common;
pub mod define;

use std::fmt;
use std::marker::PhantomData;
use std::str::FromStr;

use chrono::{DateTime, Utc};
pub use define::{Range, ResourcePoolDef, ResourcePoolType};
use rpc::errors::RpcDataConversionError;
use serde::{Deserialize, Serialize};
use sqlx::Row;

/// State of an entry inside the resource pool
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum ResourcePoolEntryState {
    /// The resource is not used
    Free,
    /// The resource is allocated by a certain owner
    Allocated { owner: String, owner_type: String },
}

#[derive(Debug)]
pub struct ResourcePool<T>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    pub name: String,
    pub value_type: ValueType,
    pub rust_type: PhantomData<T>,
}

impl<T> ResourcePool<T>
where
    T: ToString + FromStr + Send + Sync + 'static,
    <T as FromStr>::Err: std::error::Error,
{
    pub fn new(name: String, value_type: ValueType) -> ResourcePool<T> {
        ResourcePool {
            name,
            value_type,
            rust_type: PhantomData,
        }
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ResourcePoolStats {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        let used: i64 = row.try_get("used")?;
        let free: i64 = row.try_get("free")?;

        let auto_assign_used: i64 = row.try_get("auto_assign_used")?;
        let auto_assign_free: i64 = row.try_get("auto_assign_free")?;

        let non_auto_assign_used: i64 = row.try_get("non_auto_assign_used")?;
        let non_auto_assign_free: i64 = row.try_get("non_auto_assign_free")?;

        Ok(ResourcePoolStats {
            used: used as usize,
            free: free as usize,

            auto_assign_used: auto_assign_used as usize,
            auto_assign_free: auto_assign_free as usize,

            non_auto_assign_used: non_auto_assign_used as usize,
            non_auto_assign_free: non_auto_assign_free as usize,
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
    pub state: sqlx::types::Json<ResourcePoolEntryState>,
    pub allocated: Option<DateTime<Utc>>,
    // pub value: String, // currently unused
}

impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for ResourcePoolEntry {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        Ok(ResourcePoolEntry {
            pool_name: row.try_get("name")?,
            pool_type: row.try_get("value_type")?,
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
    IBPartition,

    /// owner_type for vpc_cni
    Vpc,

    /// owner_type for East West Networks
    Dpa,
}

impl FromStr for OwnerType {
    type Err = RpcDataConversionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "machine" => Ok(Self::Machine),
            "network_segment" => Ok(Self::NetworkSegment),
            "ib_partition" => Ok(Self::IBPartition),
            "vpc" => Ok(Self::Vpc),
            x => Err(RpcDataConversionError::InvalidArgument(format!(
                "Unknown owner_type '{x}'"
            ))),
        }
    }
}

impl fmt::Display for OwnerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Machine => write!(f, "machine"),
            Self::NetworkSegment => write!(f, "network_segment"),
            Self::IBPartition => write!(f, "ib_partition"),
            Self::Vpc => write!(f, "vpc"),
            Self::Dpa => write!(f, "dpa"),
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub struct ResourcePoolStats {
    /// Number of allocated values in this pool
    pub used: usize,

    /// Number of available values in this pool
    pub free: usize,

    /// Number of allocated auto-assignable values in this pool
    pub auto_assign_used: usize,

    /// Number of available auto-assignable  values in this pool
    pub auto_assign_free: usize,

    /// Number of allocated non-auto-assignable values in this pool
    pub non_auto_assign_used: usize,

    /// Number of available non-auto-assignable values in this pool
    pub non_auto_assign_free: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ResourcePoolError {
    #[error("Resource pool is empty, cannot allocate")]
    Empty,
    #[error("Cannot convert '{v}' to {pool_name}'s pool type for {owner_type} {owner_id}: {e}")]
    Parse {
        e: String,
        v: String,
        pool_name: String,
        owner_type: String,
        owner_id: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize_resource_pool_entry_state() {
        let state = ResourcePoolEntryState::Free;
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(serialized, r#"{"state":"free"}"#);
        assert_eq!(
            serde_json::from_str::<ResourcePoolEntryState>(&serialized).unwrap(),
            state
        );

        let state = ResourcePoolEntryState::Allocated {
            owner: "me".to_string(),
            owner_type: "my_stuff".to_string(),
        };
        let serialized = serde_json::to_string(&state).unwrap();
        assert_eq!(
            serialized,
            r#"{"state":"allocated","owner":"me","owner_type":"my_stuff"}"#
        );
        assert_eq!(
            serde_json::from_str::<ResourcePoolEntryState>(&serialized).unwrap(),
            state
        );
    }
}
