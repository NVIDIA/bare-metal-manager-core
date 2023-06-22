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

use super::{DbResourcePool, ResourcePoolStats, ValueType};

/// DPU VPC loopback IP pool
/// Must match a pool defined in dev/resource_pools.toml
pub const LOOPBACK_IP: &str = "lo-ip";

/// VNI pool. FabricNetworkConfiguration
/// Must match a pool defined in dev/resource_pools.toml
pub const VNI: &str = "vni";

/// vlan-id pool. FabricNetworkConfiguration
/// Must match a pool defined in dev/resource_pools.toml
pub const VLANID: &str = "vlan-id";

/// IB Fabric partition key (pkey) pool
/// Must match a pool defined in dev/resource_pools.toml
pub const PKEY: &str = "pkey";

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
}

/// ResourcePools that are used for infiniband
pub struct IbPools {
    pub pool_pkey: Arc<DbResourcePool<i16>>,
}

impl CommonPools {
    pub fn create(database_connection: sqlx::PgPool) -> Arc<Self> {
        let pool_loopback_ip: Arc<DbResourcePool<Ipv4Addr>> = Arc::new(DbResourcePool::new(
            LOOPBACK_IP.to_string(),
            ValueType::Ipv4,
        ));
        let pool_vlan_id: Arc<DbResourcePool<i16>> =
            Arc::new(DbResourcePool::new(VLANID.to_string(), ValueType::Integer));
        let pool_vni: Arc<DbResourcePool<i32>> =
            Arc::new(DbResourcePool::new(VNI.to_string(), ValueType::Integer));

        let pool_pkey: Arc<DbResourcePool<i16>> =
            Arc::new(DbResourcePool::new(PKEY.to_string(), ValueType::Integer));

        let (stop_sender, mut stop_receiver) = oneshot::channel();

        // resource pool metrics
        let pool_stats: Arc<Mutex<HashMap<String, ResourcePoolStats>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let pool_stats_bg = pool_stats.clone();
        let pool_l_ip_2 = pool_loopback_ip.clone();
        let pool_vlan_id_2 = pool_vlan_id.clone();
        let pool_vni_2 = pool_vni.clone();
        let pool_pkey_2 = pool_pkey.clone();
        tokio::spawn(async move {
            loop {
                let l_ip = pool_l_ip_2.stats(&database_connection).await;
                let vlan_id = pool_vlan_id_2.stats(&database_connection).await;
                let vni = pool_vni_2.stats(&database_connection).await;
                let pkey = pool_pkey_2.stats(&database_connection).await;
                {
                    let mut m = pool_stats_bg.lock().unwrap();
                    if let Ok(l_ip) = l_ip {
                        m.entry(LOOPBACK_IP.to_string())
                            .and_modify(|s| *s = l_ip)
                            .or_insert(l_ip);
                    }
                    if let Ok(vlan_id) = vlan_id {
                        m.entry(VLANID.to_string())
                            .and_modify(|s| *s = vlan_id)
                            .or_insert(vlan_id);
                    }
                    if let Ok(vni) = vni {
                        m.entry(VNI.to_string())
                            .and_modify(|s| *s = vni)
                            .or_insert(vni);
                    }
                    if let Ok(pkey) = pkey {
                        m.entry(PKEY.to_string())
                            .and_modify(|s| *s = pkey)
                            .or_insert(pkey);
                    }
                }

                tokio::select! {
                    _ = tokio::time::sleep(METRICS_RESOURCEPOOL_INTERVAL) => {},
                    _ = &mut stop_receiver => {
                        tracing::info!("CommonPool metrics stop was requested");
                        return;
                    }
                }
            }
        });

        Arc::new(Self {
            ethernet: EthernetPools {
                pool_loopback_ip,
                pool_vlan_id,
                pool_vni,
            },
            infiniband: IbPools { pool_pkey },
            pool_stats,
            _stop_sender: stop_sender,
        })
    }
}
