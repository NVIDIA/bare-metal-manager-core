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

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use ::rpc::protos::{common as rpc_common, forge as rpc};
use carbide_uuid::domain::DomainId;
use carbide_uuid::dpa_interface::DpaInterfaceId;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::MachineInterfaceId;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use db::{DatabaseError, ObjectColumnFilter, instance, network_segment, vpc};
use model::network_segment::NetworkSegmentSearchConfig;
use model::resource_pool::ResourcePoolEntryState;
use model::route_server::RouteServerSourceType;

use crate::CarbideError;
use crate::api::Api;

pub(crate) async fn find_ip_address(
    api: &Api,
    request: tonic::Request<rpc::FindIpAddressRequest>,
) -> Result<tonic::Response<rpc::FindIpAddressResponse>, tonic::Status> {
    crate::api::log_request_data(&request);

    let req = request.into_inner();

    let ip = req.ip;
    let (matches, errors) = by_ip(api, &ip).await;
    if matches.is_empty() && errors.is_empty() {
        return Err(CarbideError::NotFoundError {
            kind: "ip",
            id: ip.to_string(),
        }
        .into());
    }
    Ok(tonic::Response::new(rpc::FindIpAddressResponse {
        matches,
        errors: errors.into_iter().map(|err| err.to_string()).collect(),
    }))
}

pub(crate) async fn identify_uuid(
    api: &Api,
    request: tonic::Request<rpc::IdentifyUuidRequest>,
) -> Result<tonic::Response<rpc::IdentifyUuidResponse>, tonic::Status> {
    crate::api::log_request_data(&request);
    let req = request.into_inner();

    let Some(u) = req.uuid else {
        return Err(tonic::Status::invalid_argument("UUID missing from query"));
    };
    match by_uuid(api, &u).await {
        Ok(Some(object_type)) => Ok(tonic::Response::new(rpc::IdentifyUuidResponse {
            uuid: Some(u),
            object_type: object_type.into(),
        })),
        Ok(None) => Err(CarbideError::NotFoundError {
            kind: "uuid",
            id: u.to_string(),
        }
        .into()),
        Err(err) => Err(err.into()),
    }
}

pub(crate) async fn identify_mac(
    api: &Api,
    request: tonic::Request<rpc::IdentifyMacRequest>,
) -> Result<tonic::Response<rpc::IdentifyMacResponse>, tonic::Status> {
    crate::api::log_request_data(&request);
    let req = request.into_inner();

    if req.mac_address.is_empty() {
        return Err(tonic::Status::invalid_argument("MAC missing from query"));
    };
    let Ok(mac) = mac_address::MacAddress::from_str(&req.mac_address) else {
        return Err(tonic::Status::invalid_argument(
            "Could not parse MAC address",
        ));
    };
    match by_mac(api, mac).await {
        Ok(Some((primary_key, object_type))) => {
            Ok(tonic::Response::new(rpc::IdentifyMacResponse {
                mac_address: req.mac_address,
                primary_key,
                object_type: object_type.into(),
            }))
        }
        Ok(None) => Err(CarbideError::NotFoundError {
            kind: "MAC",
            id: mac.to_string(),
        }
        .into()),
        Err(err) => Err(CarbideError::from(err).into()),
    }
}

pub(crate) async fn identify_serial(
    api: &Api,
    request: tonic::Request<rpc::IdentifySerialRequest>,
) -> Result<tonic::Response<rpc::IdentifySerialResponse>, tonic::Status> {
    crate::api::log_request_data(&request);
    let req = request.into_inner();

    let machine_ids = if req.exact {
        db::machine_topology::find_by_serial(&api.database_connection, &req.serial_number).await?
    } else {
        db::machine_topology::find_freetext(&api.database_connection, &req.serial_number).await?
    };

    if machine_ids.len() > 1 {
        tracing::warn!(
            matches = machine_ids.len(),
            serial_number = req.serial_number,
            "identify_serial: More than one match"
        );
    }

    Ok(tonic::Response::new(rpc::IdentifySerialResponse {
        serial_number: req.serial_number,
        machine_id: machine_ids.into_iter().next(),
    }))
}

#[derive(Debug, Copy, Clone)]
enum Finder {
    StaticData,
    ResourcePools,
    InstanceAddresses,
    MachineAddresses,
    BmcIp,
    ExploredEndpoint,
    LoopbackIp,
    NetworkSegment,
    RouteServers,
    DpaAddresses,
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

async fn by_ip(api: &Api, ip: &str) -> (Vec<rpc::IpAddressMatch>, Vec<CarbideError>) {
    use Finder::*;
    let futures = vec![
        search(StaticData, api, ip),
        search(ResourcePools, api, ip),
        search(InstanceAddresses, api, ip),
        search(MachineAddresses, api, ip),
        search(BmcIp, api, ip),
        search(ExploredEndpoint, api, ip),
        search(LoopbackIp, api, ip),
        search(NetworkSegment, api, ip),
        search(RouteServers, api, ip),
        search(DpaAddresses, api, ip),
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
async fn search(
    finder: Finder,
    api: &Api,
    ip: &str,
) -> Result<Option<rpc::IpAddressMatch>, CarbideError> {
    let addr: IpAddr = ip.parse()?;
    if addr.is_ipv6() {
        return Err(CarbideError::InvalidArgument(
            "Ipv6 not yet supported".to_string(),
        ));
    }

    let mut txn = api.txn_begin().await?;

    use Finder::*;
    let match_result = match finder {
        // Match against IP addresses defined in the config file
        StaticData => None.or_else(|| {
            api.eth_data
                .dhcp_servers
                .iter()
                .find(|&dhcp| ip == *dhcp)
                .map(|ip| rpc::IpAddressMatch {
                    ip_type: rpc::IpType::StaticDataDhcpServer as i32,
                    owner_id: None,
                    message: format!("{ip} is a static DHCP server"),
                })
        }),

        // Look for IP address in resource pools
        ResourcePools => {
            let mut vec_out = db::resource_pool::find_value(&mut txn, ip).await?;
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
            let instance_address = db::instance_address::find_by_address(&mut txn, addr).await?;

            instance_address.map(|e| {
                let message = format!(
                    "{ip} belongs to instance {} on segment {}",
                    e.instance_id, e.segment_id
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
            let out = db::machine_interface_address::find_by_address(&mut txn, addr).await?;
            out.map(|e| {
                let message = match e.machine_id.as_ref() {
                    Some(machine_id) => format!(
                        "{ip} belongs to machine {} (interface {}) on network segment {} of type {}",
                        machine_id, e.id, e.name, e.network_segment_type,
                    ),
                    None => format!(
                        "{ip} belongs to interface {} on network segment {} of type {}. It is not attached to a machine.",
                        e.id, e.name, e.network_segment_type,
                        ),
                };
                rpc::IpAddressMatch {
                    ip_type: rpc::IpType::MachineAddress as i32,
                    owner_id: e.machine_id.map(|id| id.to_string()),
                    message,
                }
            })
        }

        // BMC IP of the host
        BmcIp => {
            let out = db::machine_topology::find_machine_id_by_bmc_ip(&mut txn, ip).await?;
            out.map(|machine_id| rpc::IpAddressMatch {
                ip_type: rpc::IpType::BmcIp as i32,
                owner_id: Some(machine_id.to_string()),
                message: format!("{ip} is the BMC IP of {machine_id}"),
            })
        }
        ExploredEndpoint => {
            let out = db::explored_endpoints::find_by_ips(&mut txn, vec![addr]).await?;
            out.first().map(|ee| rpc::IpAddressMatch {
                ip_type: rpc::IpType::ExploredEndpoint as i32,
                owner_id: Some(ee.address.to_string()),
                message: format!("{ip}'s Redfish was explored by site explorer"),
            })
        }

        // Loopback IP of a DPU
        LoopbackIp => {
            let out = db::machine::find_by_loopback_ip(&mut txn, ip).await?;
            out.map(|machine| rpc::IpAddressMatch {
                ip_type: rpc::IpType::LoopbackIp as i32,
                owner_id: Some(machine.id.to_string()),
                message: format!("{ip} is the loopback for {}", &machine.id),
            })
        }

        // Network segment that contains this IP address
        NetworkSegment => {
            let out = db::network_prefix::containing_prefix(&mut txn, &format!("{ip}/32")).await?;
            out.first().map(|prefix| {
                let message = format!(
                    "{ip} is in prefix {} of segment {}, gateway {}",
                    prefix.prefix,
                    prefix.segment_id,
                    prefix
                        .gateway
                        .map(|g| g.to_string())
                        .unwrap_or("(no gateway)".to_string()),
                );
                rpc::IpAddressMatch {
                    ip_type: rpc::IpType::NetworkSegment as i32,
                    owner_id: Some(prefix.segment_id.to_string()),
                    message,
                }
            })
        }

        // Search the RouteServers table to see if it's a "config"
        // source (via the config TOML), or an "admin" source (via
        // forge-admin-cli).
        RouteServers => {
            let out = db::route_servers::find_by_address(&mut txn, addr).await?;
            out.map(|route_server| rpc::IpAddressMatch {
                ip_type: match route_server.source_type {
                    RouteServerSourceType::AdminApi => rpc::IpType::RouteServerFromAdminApi,
                    RouteServerSourceType::ConfigFile => rpc::IpType::RouteServerFromConfigFile,
                } as i32,
                owner_id: None,
                message: format!(
                    "{ip} is a route server with source type {:?}",
                    route_server.source_type
                ),
            })
        }

        DpaAddresses => {
            let out = db::dpa_interface::find_by_ip(&mut txn, addr).await?;

            out.first().map(|dpa| rpc::IpAddressMatch {
                ip_type: rpc::IpType::DpaInterface as i32,
                owner_id: Some(dpa.id.to_string()),
                message: format!("{ip} is underlay or overlay IP of DPA {0}", dpa.id),
            })
        }
    };

    // not strictly necessary, we could drop the txn and it would rollback
    txn.commit().await?;

    Ok(match_result)
}

async fn by_uuid(api: &Api, u: &rpc_common::Uuid) -> Result<Option<rpc::UuidType>, CarbideError> {
    let mut txn = api.txn_begin().await?;

    if let Ok(ns_id) = NetworkSegmentId::from_str(&u.value) {
        let segments = db::network_segment::find_by(
            &mut txn,
            ObjectColumnFilter::List(network_segment::IdColumn, &[ns_id]),
            NetworkSegmentSearchConfig {
                include_history: false,
                include_num_free_ips: false,
            },
        )
        .await?;
        if segments.len() == 1 {
            return Ok(Some(rpc::UuidType::NetworkSegment));
        }
    }

    if let Ok(instance_id) = InstanceId::from_str(&u.value) {
        let instances = db::instance::find(
            &mut txn,
            ObjectColumnFilter::One(instance::IdColumn, &instance_id),
        )
        .await?;
        if instances.len() == 1 {
            return Ok(Some(rpc::UuidType::Instance));
        }
    }

    if let Ok(mi_id) = MachineInterfaceId::from_str(&u.value)
        && db::machine_interface::find_one(&mut txn, mi_id)
            .await
            .is_ok()
    {
        return Ok(Some(rpc::UuidType::MachineInterface));
    }

    if let Ok(vpc_id) = VpcId::from_str(&u.value) {
        let vpcs =
            db::vpc::find_by(&mut txn, ObjectColumnFilter::One(vpc::IdColumn, &vpc_id)).await?;
        if vpcs.len() == 1 {
            return Ok(Some(rpc::UuidType::Vpc));
        }
    }

    if let Ok(id) = DpaInterfaceId::from_str(&u.value) {
        let dpas = db::dpa_interface::find_by_ids(&mut txn, &[id], false).await?;
        if dpas.len() == 1 {
            return Ok(Some(rpc::UuidType::DpaInterfaceId));
        }
    }

    if let Ok(domain_id) = DomainId::from_str(&u.value) {
        let domains = db::dns::domain::find_by(
            &mut txn,
            ObjectColumnFilter::One(db::dns::domain::IdColumn, &domain_id),
        )
        .await?;
        if domains.len() == 1 {
            return Ok(Some(rpc::UuidType::Domain));
        }
    }

    txn.commit().await?;

    Ok(None)
}

async fn by_mac(
    api: &Api,
    mac: mac_address::MacAddress,
) -> Result<Option<(String, rpc::MacOwner)>, DatabaseError> {
    let mut txn = api.txn_begin().await?;

    match db::machine_interface::find_by_mac_address(&mut txn, mac).await {
        Ok(interfaces) if interfaces.len() == 1 => {
            return Ok(Some((
                interfaces[0].id.to_string(),
                rpc::MacOwner::MachineInterface,
            )));
        }
        Ok(interfaces) if interfaces.is_empty() => {
            // expected, continue to search other object types
        }
        Ok(interfaces) => {
            tracing::error!(
                "Found {} MachineInterface entries for MAC address {mac}. Should be impossible",
                interfaces.len()
            );
        }
        Err(err) => {
            tracing::error!(%err, %mac, "DB error db::machine_interface::find_by_mac_address");
        }
    }

    let endpoints = db::explored_endpoints::find_by_mac_address(&mut txn, mac).await?;
    if endpoints.len() == 1 {
        return Ok(Some((
            endpoints[0].address.to_string(),
            rpc::MacOwner::ExploredEndpoint,
        )));
    }

    let expected = db::expected_machine::find_by_bmc_mac_address(&mut txn, mac).await?;
    if let Some(em) = expected {
        return Ok(Some((
            em.data.serial_number,
            rpc::MacOwner::ExpectedMachine,
        )));
    }

    match db::dpa_interface::find_by_mac_addr(&mut txn, &mac).await {
        Ok(ifs) => match ifs.as_slice() {
            [iface] => return Ok(Some((iface.id.to_string(), rpc::MacOwner::DpaInterface))),
            [] => {} // expected, continue to search other object types
            _ => tracing::error!(
                "Found {} DpaInterfaces entries for MAC address {mac}. Should be impossible",
                ifs.len()
            ),
        },
        Err(e) => tracing::error!("by_mac - Error from find_by_mac_addr for DPA: {e}"),
    };

    // Any other MAC addresses to search?
    txn.commit().await?;

    Ok(None)
}
