/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2024 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::{HashMap, HashSet};
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

/// DPU Specific ASN for use with FNN
/// Must match a pool defined in dev/resource_pools.toml
pub const FNN_ASN: &str = "fnn-asn";

/// How often to update the resource pool metrics
const METRICS_RESOURCEPOOL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Returns the name of the resource pool used for a certain IB fabric
pub fn ib_pkey_pool_name(fabric: &str) -> String {
    format!("ib_fabrics.{fabric}.pkey")
}

/// ResourcePools that are used throughout the application
#[derive(Debug)]
pub struct CommonPools {
    pub ethernet: EthernetPools,
    pub infiniband: IbPools,
    pub pool_stats: Arc<Mutex<HashMap<String, ResourcePoolStats>>>,
    /// Instructs the metric task to stop.
    /// We rely on `CommonPools` being dropped to instruct the metric task to stop
    _stop_sender: oneshot::Sender<()>,
}

/// ResourcePools that are used for ethernet virtualization
#[derive(Debug)]
pub struct EthernetPools {
    pub pool_loopback_ip: Arc<DbResourcePool<Ipv4Addr>>,
    pub pool_vlan_id: Arc<DbResourcePool<i16>>,
    pub pool_vni: Arc<DbResourcePool<i32>>,
    pub pool_vpc_vni: Arc<DbResourcePool<i32>>,
    pub pool_fnn_asn: Arc<DbResourcePool<u32>>,
}

/// ResourcePools that are used for infiniband
#[derive(Clone, Debug, Default)]
pub struct IbPools {
    pub pkey_pools: Arc<HashMap<String, DbResourcePool<u16>>>,
}

impl CommonPools {
    pub async fn create(
        db: sqlx::PgPool,
        ib_fabric_ids: HashSet<String>,
    ) -> eyre::Result<Arc<Self>> {
        let mut pool_names = Vec::new();
        let mut optional_pool_names = Vec::new();

        let pool_loopback_ip: Arc<DbResourcePool<Ipv4Addr>> = Arc::new(DbResourcePool::new(
            LOOPBACK_IP.to_string(),
            ValueType::Ipv4,
        ));
        pool_names.push(pool_loopback_ip.name().to_string());
        let pool_vlan_id: Arc<DbResourcePool<i16>> =
            Arc::new(DbResourcePool::new(VLANID.to_string(), ValueType::Integer));
        pool_names.push(pool_vlan_id.name().to_string());
        let pool_vni: Arc<DbResourcePool<i32>> =
            Arc::new(DbResourcePool::new(VNI.to_string(), ValueType::Integer));
        pool_names.push(pool_vni.name().to_string());
        let pool_vpc_vni: Arc<DbResourcePool<i32>> =
            Arc::new(DbResourcePool::new(VPC_VNI.to_string(), ValueType::Integer));
        pool_names.push(pool_vpc_vni.name().to_string());
        let pool_fnn_asn: Arc<DbResourcePool<u32>> =
            Arc::new(DbResourcePool::new(FNN_ASN.to_string(), ValueType::Integer));
        optional_pool_names.push(pool_fnn_asn.name().to_string());

        // We can't run if any of the mandatory pools are missing
        for name in &pool_names {
            if stats(&db, name).await?.free == 0 {
                eyre::bail!(
                    "Resource pool '{name}' missing or full. Edit config file and restart."
                );
            }
        }

        pool_names.extend(optional_pool_names);

        // It's ok for IB partition pools to be missing or full - as long as nobody tries to use partitions
        let pkey_pools: Arc<HashMap<String, DbResourcePool<u16>>> = Arc::new(
            ib_fabric_ids
                .into_iter()
                .map(|fabric_id| {
                    (
                        fabric_id.clone(),
                        DbResourcePool::new(ib_pkey_pool_name(&fabric_id), ValueType::Integer),
                    )
                })
                .collect(),
        );
        pool_names.extend(
            pkey_pools
                .iter()
                .map(|(_fabric_id, pool)| pool.name().to_string()),
        );

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

        Ok(Arc::new(Self {
            ethernet: EthernetPools {
                pool_loopback_ip,
                pool_vlan_id,
                pool_vni,
                pool_vpc_vni,
                pool_fnn_asn,
            },
            infiniband: IbPools { pkey_pools },
            pool_stats,
            _stop_sender: stop_sender,
        }))
    }
}
