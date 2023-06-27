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

use std::fmt;
use std::str::FromStr;

use crate::CarbideError;

mod db;
pub use db::{all, DbResourcePool};
pub mod common;

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

/// What kind of data does our resource pool store?
#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
#[sqlx(type_name = "resource_pool_type")]
pub enum ValueType {
    Integer = 0,
    Ipv4,
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
