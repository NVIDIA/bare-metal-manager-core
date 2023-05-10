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
pub use db::DbResourcePool;

/// DPU VPC loopback IP pool
/// Must match a pool defined in dev/resource_pools.toml
pub const LOOPBACK_IP: &str = "lo-ip";

/// VNI pool. ResourceGroup / FabricNetworkConfiguration
/// Must match a pool defined in dev/resource_pools.toml
pub const VNI: &str = "vni";

/// vlan-id pool. ResourceGroup / FabricNetworkConfiguration
/// Must match a pool defined in dev/resource_pools.toml
pub const VLANID: &str = "vlan-id";

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum OwnerType {
    /// owner_type for loopback_ip
    Machine,

    /// owner_type for vlan_id and vni
    NetworkSegment,
}

impl FromStr for OwnerType {
    type Err = CarbideError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "machine" => Ok(Self::Machine),
            "network_segment" => Ok(Self::NetworkSegment),
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
