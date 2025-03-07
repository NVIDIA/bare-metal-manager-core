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

use std::{fmt, net::IpAddr, str::FromStr};

use ::rpc::protos::common as rpc_common;
use ::rpc::protos::forge as rpc;

use crate::db;
use crate::db::domain::{self, Domain};
use crate::db::expected_machine::ExpectedMachine;
use crate::db::instance::Instance;
use crate::db::network_segment::{NetworkSegment, NetworkSegmentSearchConfig};
use crate::db::vpc::Vpc;
use crate::db::{ObjectColumnFilter, instance, network_segment, vpc};
use crate::{
    CarbideError,
    api::Api,
    db::{
        DatabaseError, explored_endpoints::DbExploredEndpoint, instance_address::InstanceAddress,
        machine_interface_address::MachineInterfaceAddress, machine_topology::MachineTopology,
        network_prefix::NetworkPrefix,
    },
    model::resource_pool::ResourcePoolEntryState,
};
use forge_uuid::{
    domain::DomainId, instance::InstanceId, machine::MachineInterfaceId, network::NetworkSegmentId,
    vpc::VpcId,
};

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

    let mut txn = api.database_connection.begin().await.map_err(|e| {
        CarbideError::from(DatabaseError::new(
            file!(),
            line!(),
            "begin identify_serial",
            e,
        ))
    })?;

    let machine_ids = MachineTopology::find_freetext(&mut txn, &req.serial_number)
        .await
        .map_err(CarbideError::from)?;
    if machine_ids.len() == 1 {
        return Ok(tonic::Response::new(rpc::IdentifySerialResponse {
            serial_number: req.serial_number,
            machine_id: Some(machine_ids[0].into()),
        }));
    }

    if machine_ids.len() > 1 {
        tracing::warn!(
            matches = machine_ids.len(),
            serial_number = req.serial_number,
            "identify_serial: More than one match"
        );
    }

    Err(CarbideError::NotFoundError {
        kind: "serial_number",
        id: req.serial_number.to_string(),
    }
    .into())
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

    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin IP search", e))?;

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
            let out = MachineInterfaceAddress::find_by_address(&mut txn, addr).await?;
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
            let out = MachineTopology::find_machine_id_by_bmc_ip(&mut txn, ip).await?;
            out.map(|machine_id| rpc::IpAddressMatch {
                ip_type: rpc::IpType::BmcIp as i32,
                owner_id: Some(machine_id.to_string()),
                message: format!("{ip} is the BMC IP of {machine_id}"),
            })
        }
        ExploredEndpoint => {
            let out = DbExploredEndpoint::find_by_ips(&mut txn, vec![addr]).await?;
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
            let out = NetworkPrefix::containing_prefix(&mut txn, &format!("{ip}/32")).await?;
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
    };

    // not strictly necessary, we could drop the txn and it would rollback
    txn.commit()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "commit IP search", e))?;

    Ok(match_result)
}

async fn by_uuid(api: &Api, u: &rpc_common::Uuid) -> Result<Option<rpc::UuidType>, CarbideError> {
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin UUID search", e))?;

    if let Ok(ns_id) = NetworkSegmentId::try_from(u.clone()) {
        let segments = NetworkSegment::find_by(
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

    if let Ok(instance_id) = InstanceId::try_from(u.clone()) {
        let instances = Instance::find(
            &mut txn,
            ObjectColumnFilter::One(instance::IdColumn, &instance_id),
        )
        .await?;
        if instances.len() == 1 {
            return Ok(Some(rpc::UuidType::Instance));
        }
    }

    if let Ok(mi_id) = MachineInterfaceId::try_from(u.clone()) {
        if db::machine_interface::find_one(&mut txn, mi_id)
            .await
            .is_ok()
        {
            return Ok(Some(rpc::UuidType::MachineInterface));
        }
    }

    if let Ok(vpc_id) = VpcId::try_from(u.clone()) {
        let vpcs = Vpc::find_by(&mut txn, ObjectColumnFilter::One(vpc::IdColumn, &vpc_id)).await?;
        if vpcs.len() == 1 {
            return Ok(Some(rpc::UuidType::Vpc));
        }
    }

    if let Ok(domain_id) = DomainId::try_from(u.clone()) {
        let domains = Domain::find_by(
            &mut txn,
            ObjectColumnFilter::One(domain::IdColumn, &domain_id),
        )
        .await?;
        if domains.len() == 1 {
            return Ok(Some(rpc::UuidType::Domain));
        }
    }

    Ok(None)
}

async fn by_mac(
    api: &Api,
    mac: mac_address::MacAddress,
) -> Result<Option<(String, rpc::MacOwner)>, DatabaseError> {
    let mut txn = api
        .database_connection
        .begin()
        .await
        .map_err(|e| DatabaseError::new(file!(), line!(), "begin MAC search", e))?;

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

    let endpoints = DbExploredEndpoint::find_freetext_in_report(&mut txn, &mac.to_string()).await?;
    if endpoints.len() == 1 {
        return Ok(Some((
            endpoints[0].address.to_string(),
            rpc::MacOwner::ExploredEndpoint,
        )));
    }

    let expected = ExpectedMachine::find_by_bmc_mac_address(&mut txn, mac).await?;
    if let Some(em) = expected {
        return Ok(Some((em.serial_number, rpc::MacOwner::ExpectedMachine)));
    }

    // Any other MAC addresses to search?

    Ok(None)
}
