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
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

use crate::resource_pool::{self, DbResourcePool, ResourcePool, ResourcePoolStats};

/// How often to update the resource pool metrics
const METRICS_RESOURCEPOOL_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct VpcData {
    pub asn: u64,
    pub dhcp_servers: Vec<String>,
    pub pool_loopback_ip: Option<Arc<dyn ResourcePool<Ipv4Addr>>>,
    pub pool_vlan_id: Option<Arc<dyn ResourcePool<i16>>>,
    pub pool_vni: Option<Arc<dyn ResourcePool<i32>>>,
    pub rp_stats: Option<Arc<Mutex<HashMap<String, ResourcePoolStats>>>>,
}

/// Create VPC's resource pools (for loopback IP, VNI, etc) and
/// start background task to provide OpenTelemetry metrics.
///
/// Pools must also be created in the database: `forge-admin-cli resource-pool define`
pub async fn enable(database_connection: sqlx::PgPool) -> VpcData {
    let pool_loopback_ip: Option<Arc<dyn ResourcePool<Ipv4Addr>>> =
        Some(Arc::new(DbResourcePool::new(
            resource_pool::LOOPBACK_IP.to_string(),
            database_connection.clone(),
        )));
    let pool_vlan_id: Option<Arc<dyn ResourcePool<i16>>> = Some(Arc::new(DbResourcePool::new(
        resource_pool::VLANID.to_string(),
        database_connection.clone(),
    )));
    let pool_vni: Option<Arc<dyn ResourcePool<i32>>> = Some(Arc::new(DbResourcePool::new(
        resource_pool::VNI.to_string(),
        database_connection,
    )));

    // resource pool metrics
    let rp_stats: Arc<Mutex<HashMap<String, ResourcePoolStats>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let rp_stats_bg = rp_stats.clone();
    let pool_l_ip_2 = pool_loopback_ip.as_ref().unwrap().clone();
    let pool_vlan_id_2 = pool_vlan_id.as_ref().unwrap().clone();
    let pool_vni_2 = pool_vni.as_ref().unwrap().clone();
    tokio::spawn(async move {
        loop {
            let l_ip = pool_l_ip_2.stats().await;
            let vlan_id = pool_vlan_id_2.stats().await;
            let vni = pool_vni_2.stats().await;
            {
                let mut m = rp_stats_bg.lock().unwrap();
                if let Ok(l_ip) = l_ip {
                    m.entry(resource_pool::LOOPBACK_IP.to_string())
                        .and_modify(|s| *s = l_ip)
                        .or_insert(l_ip);
                }
                if let Ok(vlan_id) = vlan_id {
                    m.entry(resource_pool::VLANID.to_string())
                        .and_modify(|s| *s = vlan_id)
                        .or_insert(vlan_id);
                }
                if let Ok(vni) = vni {
                    m.entry(resource_pool::VNI.to_string())
                        .and_modify(|s| *s = vni)
                        .or_insert(vni);
                }
            }
            tokio::time::sleep(METRICS_RESOURCEPOOL_INTERVAL).await;
        }
    });

    VpcData {
        pool_loopback_ip,
        pool_vlan_id,
        pool_vni,
        rp_stats: Some(rp_stats),
        ..Default::default()
    }
}
