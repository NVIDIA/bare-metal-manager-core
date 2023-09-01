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

use std::{fmt, net::IpAddr};

use ::rpc::protos::forge as rpc;
use forge_secrets::{certificates::CertificateProvider, credentials::CredentialProvider};

use crate::{
    api::Api,
    db::{
        instance_address::InstanceAddress, machine::Machine,
        machine_interface_address::MachineInterfaceAddress, machine_topology::MachineTopology,
        network_prefix::NetworkPrefix, DatabaseError,
    },
    model::resource_pool::ResourcePoolEntryState,
    CarbideError,
};

#[derive(Debug, Copy, Clone)]
enum Finder {
    StaticData,
    ResourcePools,
    InstanceAddresses,
    MachineAddresses,
    BmcIp,
    LoopbackIp,
    NetworkSegment,
    // TorLldp,
    // There is also this but seems currently unused / unpopulated:
    //  TopologyData->discovery_data(DiscoveryData)->info(HardwareInfo)
    //   ->dpu_info(Option<DpuData>)->tors(TolLldpData)->ip_address(Vec<String>)
}

impl fmt::Display for Finder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

pub async fn find<C1, C2>(
    api: &Api<C1, C2>,
    ip: &str,
) -> (Vec<rpc::IpAddressMatch>, Vec<CarbideError>)
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    use Finder::*;
    let futures = vec![
        search(StaticData, api, ip),
        search(ResourcePools, api, ip),
        search(InstanceAddresses, api, ip),
        search(MachineAddresses, api, ip),
        search(BmcIp, api, ip),
        search(LoopbackIp, api, ip),
        search(NetworkSegment, api, ip),
    ];
    let results = futures::future::join_all(futures).await;
    let mut out = vec![];
    let mut errs = vec![];
    for res in results {
        match res {
            // found
            Ok(Some(s)) => out.push(s),
            // not found
            Ok(None) => {}
            Err(err) => errs.push(err),
        }
    }

    (out, errs)
}

// A giant match statement mostly to get around every async function having a different type.
async fn search<C1, C2>(
    finder: Finder,
    api: &Api<C1, C2>,
    ip: &str,
) -> Result<Option<rpc::IpAddressMatch>, CarbideError>
where
    C1: CredentialProvider + 'static,
    C2: CertificateProvider + 'static,
{
    let addr: IpAddr = ip.parse()?;
    if addr.is_ipv6() {
        return Err(CarbideError::InvalidArgument(
            "Ipv6 not yet supported".to_string(),
        ));
    }

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| CarbideError::DatabaseError(file!(), "begin IP search", e))?;

    use Finder::*;
    let match_result = match finder {
        // Match against IP addresses defined in the config file
        StaticData => None
            .or_else(|| {
                api.eth_data
                    .dhcp_servers
                    .iter()
                    .find(|&dhcp| ip == *dhcp)
                    .map(|ip| rpc::IpAddressMatch {
                        ip_type: rpc::IpType::StaticDataDhcpServer as i32,
                        owner_id: None,
                        message: format!("{} is a static DHCP server", ip),
                    })
            })
            .or_else(|| {
                api.eth_data
                    .route_servers
                    .iter()
                    .find(|&route| ip == *route)
                    .map(|ip| rpc::IpAddressMatch {
                        ip_type: rpc::IpType::StaticDataRouteServer as i32,
                        owner_id: None,
                        message: format!("{} is a static route server", ip),
                    })
            }),

        // Look for IP address in resource pools
        ResourcePools => {
            let mut vec_out = crate::resource_pool::find_value(&mut txn, ip).await?;
            let entry = match vec_out.len() {
                0 => return Ok(None),
                1 => vec_out.remove(0),
                _ => {
                    tracing::warn!(
                        ip,
                        matched_pools = vec_out.len(),
                        "Multiple resource pools match this IP. This seems like a mistake. Using only first.",
                    );
                    vec_out.remove(0)
                }
            };
            let mut msg = format!(
                "{ip} is an {} in resource pool {}. ",
                entry.pool_type, entry.pool_name,
            );
            let mut maybe_owner = None;
            match entry.state.0 {
                ResourcePoolEntryState::Free => msg += "It is not allocated.",
                ResourcePoolEntryState::Allocated { owner, owner_type } => {
                    msg += &format!(
                        "Allocated to {owner_type} {owner} on {}",
                        entry.allocated.unwrap_or_default()
                    );
                    maybe_owner = Some(owner);
                }
            }
            Some(rpc::IpAddressMatch {
                ip_type: rpc::IpType::ResourcePool as i32,
                owner_id: maybe_owner,
                message: msg,
            })
        }

        // Look in instance_addresses
        InstanceAddresses => {
            let instance_address = InstanceAddress::find_by_address(&mut txn, addr).await?;

            instance_address.map(|e| {
                let message = format!(
                    "{ip} belongs to instance {} on circuit {}",
                    e.instance_id, e.circuit_id
                );
                rpc::IpAddressMatch {
                    ip_type: rpc::IpType::InstanceAddress as i32,
                    owner_id: Some(e.instance_id.to_string()),
                    message,
                }
            })
        }

        // Look in machine_interface_addresses
        MachineAddresses => {
            let out = MachineInterfaceAddress::find_by_address(&mut txn, addr).await?;
            out.map(|e| {
                let message = format!(
                    "{ip} belongs to machine {} (interface {}) on network segment {} of type {}",
                    e.machine_id, e.interface_id, e.segment_name, e.segment_type,
                );
                rpc::IpAddressMatch {
                    ip_type: rpc::IpType::MachineAddress as i32,
                    owner_id: Some(e.machine_id.to_string()),
                    message,
                }
            })
        }

        // BMC IP of the host
        BmcIp => {
            let out = MachineTopology::find_machine_id_by_bmc_ip(&mut txn, ip).await?;
            out.map(|machine_id| rpc::IpAddressMatch {
                ip_type: rpc::IpType::BmcIp as i32,
                owner_id: Some(machine_id.to_string()),
                message: format!("{ip} is the BMC IP of {machine_id}"),
            })
        }

        // Loopback IP of a DPU
        LoopbackIp => {
            let out = Machine::find_by_loopback_ip(&mut txn, ip).await?;
            out.map(|machine| rpc::IpAddressMatch {
                ip_type: rpc::IpType::LoopbackIp as i32,
                owner_id: Some(machine.id().to_string()),
                message: format!("{ip} is the loopback for {}", machine.id()),
            })
        }

        // Network segment that contains this IP address
        NetworkSegment => {
            let out = NetworkPrefix::containing_prefix(&mut txn, &format!("{ip}/32")).await?;
            out.map(|prefix| {
                let message = format!(
                    "{ip} is in prefix {} of segment {}, gateway {}, on circuit {}",
                    prefix.prefix,
                    prefix.segment_id,
                    prefix
                        .gateway
                        .map(|g| g.to_string())
                        .unwrap_or("(no gateway)".to_string()),
                    prefix.circuit_id.unwrap_or("(no circuit)".to_string())
                );
                rpc::IpAddressMatch {
                    ip_type: rpc::IpType::NetworkSegment as i32,
                    owner_id: Some(prefix.segment_id.to_string()),
                    message,
                }
            })
        }
    };

    // not strictly necessary, we could drop the txn and it would rollback
    txn.commit().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(file!(), line!(), "commit IP search", e))
    })?;

    Ok(match_result)
}
