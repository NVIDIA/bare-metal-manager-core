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

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use tokio::sync::oneshot;

use super::{stats, DbResourcePool, ResourcePoolStats, ValueType};

/// DPU VPC loopback IP pool
/// Must match a pool defined in dev/resource_pools.toml
pub const LOOPBACK_IP: &str = "lo-ip";

/// VNI pool. FabricNetworkConfiguration
/// Must match a pool defined in dev/resource_pools.toml
pub const VNI: &str = "vni";

/// vlan-id pool. FabricNetworkConfiguration
/// Must match a pool defined in dev/resource_pools.toml
pub const VLANID: &str = "vlan-id";

/// vpc-vni pool: L3VNI for the whole VPC
/// Must match a pool defined in dev/resource_pools.toml
pub const VPC_VNI: &str = "vpc-vni";

/// IB Fabric partition key (pkey) pool
/// Must match a pool defined in dev/resource_pools.toml
pub const PKEY: &str = "pkey";

/// All the pools carbide-api needs.
/// We will validate they exist and monitor metrics for them.
const ALL_POOLS: [&str; 5] = [LOOPBACK_IP, VLANID, VNI, VPC_VNI, PKEY];

/// Pools that are not necessarily needed at startup
const OPTIONAL_POOLS: [&str; 1] = [PKEY];

/// How often to update the resource pool metrics
const METRICS_RESOURCEPOOL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// ResourcePools that are used throughout the application
pub struct CommonPools {
    pub ethernet: EthernetPools,
    pub infiniband: IbPools,
    pub pool_stats: Arc<Mutex<HashMap<String, ResourcePoolStats>>>,
    /// Instructs the metric task to stop.
    /// We rely on `CommonPools` being dropped to instruct the metric task to stop
    _stop_sender: oneshot::Sender<()>,
}

/// ResourcePools that are used for ethernet virtualization
pub struct EthernetPools {
    pub pool_loopback_ip: Arc<DbResourcePool<Ipv4Addr>>,
    pub pool_vlan_id: Arc<DbResourcePool<i16>>,
    pub pool_vni: Arc<DbResourcePool<i32>>,
    pub pool_vpc_vni: Arc<DbResourcePool<i32>>,
}

/// ResourcePools that are used for infiniband
pub struct IbPools {
    pub pool_pkey: Arc<DbResourcePool<i16>>,
}

impl CommonPools {
    pub async fn create(db: sqlx::PgPool) -> eyre::Result<Arc<Self>> {
        let pool_loopback_ip: Arc<DbResourcePool<Ipv4Addr>> = Arc::new(DbResourcePool::new(
            LOOPBACK_IP.to_string(),
            ValueType::Ipv4,
        ));
        let pool_vlan_id: Arc<DbResourcePool<i16>> =
            Arc::new(DbResourcePool::new(VLANID.to_string(), ValueType::Integer));
        let pool_vni: Arc<DbResourcePool<i32>> =
            Arc::new(DbResourcePool::new(VNI.to_string(), ValueType::Integer));
        let pool_vpc_vni: Arc<DbResourcePool<i32>> =
            Arc::new(DbResourcePool::new(VPC_VNI.to_string(), ValueType::Integer));
        let pool_pkey: Arc<DbResourcePool<i16>> =
            Arc::new(DbResourcePool::new(PKEY.to_string(), ValueType::Integer));

        // We can't run if any of the mandatory pools are missing
        for name in ALL_POOLS {
            if !OPTIONAL_POOLS.contains(&name) && stats(&db, name).await?.free == 0 {
                eyre::bail!(
                    "Resource pool '{name}' missing or full. Edit config file and restart."
                );
            }
        }

        // Gather resource pool stats. A different thread sends them to Prometheus.
        let (stop_sender, mut stop_receiver) = oneshot::channel();
        let pool_stats: Arc<Mutex<HashMap<String, ResourcePoolStats>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pool_stats_bg = pool_stats.clone();
        tokio::task::Builder::new()
            .name("resource_pool metrics")
            .spawn(async move {
                loop {
                    let mut next_stats = HashMap::with_capacity(ALL_POOLS.len());
                    for name in ALL_POOLS {
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

        Ok(Arc::new(Self {
            ethernet: EthernetPools {
                pool_loopback_ip,
                pool_vlan_id,
                pool_vni,
                pool_vpc_vni,
            },
            infiniband: IbPools { pool_pkey },
            pool_stats,
            _stop_sender: stop_sender,
        }))
    }
}
