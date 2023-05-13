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

pub use ::rpc::forge as rpc;
use sqlx::{Postgres, Transaction};
use tonic::Status;

use crate::{
    db::{
        machine_interface::MachineInterface, machine_interface_address::MachineInterfaceAddress,
        network_segment::NetworkSegment,
    },
    model::machine::machine_id::MachineId,
    resource_pool::{self, DbResourcePool, ResourcePoolStats},
    CarbideError,
};

/// How often to update the resource pool metrics
const METRICS_RESOURCEPOOL_INTERVAL: Duration = Duration::from_secs(60);

#[derive(Default)]
pub struct EthVirtData {
    // true if carbide API owns VPC data
    pub is_enabled: bool,
    pub asn: u32,
    pub dhcp_servers: Vec<String>,
    pub pool_loopback_ip: Option<Arc<DbResourcePool<Ipv4Addr>>>,
    pub pool_vlan_id: Option<Arc<DbResourcePool<i16>>>,
    pub pool_vni: Option<Arc<DbResourcePool<i32>>>,
    pub rp_stats: Option<Arc<Mutex<HashMap<String, ResourcePoolStats>>>>,
}

/// Create ethernet virtualization resource pools (for loopback IP, VNI, etc) and
/// start background task to provide OpenTelemetry metrics.
///
/// Pools must also be created in the database: `forge-admin-cli resource-pool define`
pub async fn enable(database_connection: sqlx::PgPool) -> EthVirtData {
    let pool_loopback_ip: Option<Arc<DbResourcePool<Ipv4Addr>>> = Some(Arc::new(
        DbResourcePool::new(resource_pool::LOOPBACK_IP.to_string()),
    ));
    let pool_vlan_id: Option<Arc<DbResourcePool<i16>>> = Some(Arc::new(DbResourcePool::new(
        resource_pool::VLANID.to_string(),
    )));
    let pool_vni: Option<Arc<DbResourcePool<i32>>> = Some(Arc::new(DbResourcePool::new(
        resource_pool::VNI.to_string(),
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
            let l_ip = pool_l_ip_2.stats(&database_connection).await;
            let vlan_id = pool_vlan_id_2.stats(&database_connection).await;
            let vni = pool_vni_2.stats(&database_connection).await;
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

    EthVirtData {
        is_enabled: true,
        pool_loopback_ip,
        pool_vlan_id,
        pool_vni,
        rp_stats: Some(rp_stats),
        ..Default::default()
    }
}

pub async fn admin_network(
    txn: &mut Transaction<'_, Postgres>,
    host_machine_id: &MachineId,
) -> Result<(rpc::FlatInterfaceConfig, uuid::Uuid), tonic::Status> {
    let admin_segment = NetworkSegment::admin(txn)
        .await
        .map_err(CarbideError::from)?;

    let prefix = match admin_segment.prefixes.get(0) {
        Some(p) => p,
        None => {
            return Err(Status::internal(format!(
                "Admin network segment '{}' has no network_prefix, expected 1",
                admin_segment.id,
            )));
        }
    };

    let interface =
        MachineInterface::find_by_machine_and_segment(txn, host_machine_id, admin_segment.id)
            .await
            .map_err(CarbideError::from)?;

    let address = MachineInterfaceAddress::find_ipv4_for_interface(txn, interface.id)
        .await
        .map_err(CarbideError::from)?;

    let cfg = rpc::FlatInterfaceConfig {
        function: rpc::InterfaceFunctionType::PhysicalFunction.into(),
        vlan_id: admin_segment.vlan_id.unwrap_or_default() as u32,
        vni: 0, // admin isn't an overlay network, so no vni
        gateway: prefix.gateway_cidr().unwrap_or_default(),
        ip: address.address.ip().to_string(),
    };
    Ok((cfg, interface.id))
}
