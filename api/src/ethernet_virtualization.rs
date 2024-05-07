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

use std::net::IpAddr;

pub use ::rpc::forge as rpc;
use ipnetwork::Ipv4Network;
use sqlx::{Postgres, Transaction};
use tonic::Status;

use crate::{
    db::{
        domain::Domain,
        machine_interface::MachineInterface,
        machine_interface_address::MachineInterfaceAddress,
        network_prefix::NetworkPrefix,
        network_segment::{NetworkSegment, NetworkSegmentSearchConfig},
        UuidKeyedObjectFilter,
    },
    model::{
        instance::config::network::{InstanceInterfaceConfig, InterfaceFunctionId},
        machine::machine_id::MachineId,
    },
    CarbideError,
};

#[derive(Default, Clone)]
pub struct EthVirtData {
    pub asn: u32,
    pub dhcp_servers: Vec<String>,
    pub route_servers: Vec<String>,
    pub route_servers_enabled: bool,
    pub deny_prefixes: Vec<Ipv4Network>,
}

pub async fn admin_network(
    txn: &mut Transaction<'_, Postgres>,
    host_machine_id: &MachineId,
) -> Result<rpc::FlatInterfaceConfig, tonic::Status> {
    let admin_segment = NetworkSegment::admin(txn)
        .await
        .map_err(CarbideError::from)?;

    let prefix = match admin_segment.prefixes.first() {
        Some(p) => p,
        None => {
            return Err(Status::internal(format!(
                "Admin network segment '{}' has no network_prefix, expected 1",
                admin_segment.id,
            )));
        }
    };

    let domain = match admin_segment.subdomain_id {
        Some(domain_id) => {
            Domain::find_by_uuid(txn, domain_id)
                .await
                .map_err(CarbideError::from)?
                .ok_or_else(|| CarbideError::NotFoundError {
                    kind: "domain",
                    id: domain_id.to_string(),
                })?
                .name
        }
        None => "unknowndomain".to_string(),
    };

    let interface =
        MachineInterface::find_by_machine_and_segment(txn, host_machine_id, admin_segment.id)
            .await
            .map_err(CarbideError::from)?;

    let address = MachineInterfaceAddress::find_ipv4_for_interface(txn, interface.id)
        .await
        .map_err(CarbideError::from)?;

    let cfg = rpc::FlatInterfaceConfig {
        function_type: rpc::InterfaceFunctionType::Physical.into(),
        virtual_function_id: None,
        vlan_id: admin_segment.vlan_id.unwrap_or_default() as u32,
        vni: 0, // admin isn't an overlay network, so no vni
        gateway: prefix.gateway_cidr().unwrap_or_default(),
        ip: address.address.to_string(),
        vpc_prefixes: vec![],
        prefix: prefix.prefix.to_string(),
        fqdn: format!("{}.{}", interface.hostname(), domain),
        booturl: None,
    };
    Ok(cfg)
}

pub async fn tenant_network(
    txn: &mut Transaction<'_, Postgres>,
    instance_id: uuid::Uuid,
    iface: &InstanceInterfaceConfig,
    physical_ip: IpAddr,
) -> Result<rpc::FlatInterfaceConfig, tonic::Status> {
    let segments = &NetworkSegment::find(
        txn,
        UuidKeyedObjectFilter::One(iface.network_segment_id),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .map_err(CarbideError::from)?;
    let Some(segment) = segments.first() else {
        return Err(Status::internal(format!(
            "Tenant network segment id '{}' matched more than one segment",
            iface.network_segment_id
        )));
    };

    let v4_prefix = segment
        .prefixes
        .iter()
        .find(|prefix| prefix.prefix.is_ipv4())
        .ok_or_else(|| {
            Status::internal(format!(
                "No IPv4 prefix is available for instance {} on segment {}",
                instance_id, segment.id
            ))
        })?;
    let address = iface.ip_addrs.get(&v4_prefix.id).ok_or_else(|| {
        Status::internal(format!(
            "No IPv4 address is available for instance {} on segment {}",
            instance_id, segment.id
        ))
    })?;

    // FIXME: Ideally, we would like the containing prefix that is assigned to
    // the tenant/VPC, but only the cloud tracks that information. Instead, we
    // have to collect all of the smaller prefixes that were created from it and
    // are attached to our VPC at the moment.
    let vpc_prefixes: Vec<_> = match segment.vpc_id {
        Some(vpc_id) => NetworkPrefix::find_by_vpc(txn, vpc_id)
            .await
            .map_err(CarbideError::from)?
            .into_iter()
            .map(|np| np.prefix.to_string())
            .collect(),
        None => vec![v4_prefix.prefix.to_string()],
    };

    let rpc_ft: rpc::InterfaceFunctionType = iface.function_id.function_type().into();

    let dashed_ip: String = physical_ip
        .to_string()
        .split('.')
        .collect::<Vec<&str>>()
        .join("-");

    Ok(rpc::FlatInterfaceConfig {
        function_type: rpc_ft.into(),
        virtual_function_id: match iface.function_id {
            InterfaceFunctionId::Physical {} => None,
            InterfaceFunctionId::Virtual { id } => Some(id.into()),
        },
        vlan_id: segment.vlan_id.unwrap_or_default() as u32,
        vni: segment.vni.unwrap_or_default() as u32,
        gateway: v4_prefix.gateway_cidr().unwrap_or_default(),
        ip: address.to_string(),
        vpc_prefixes,
        prefix: v4_prefix.prefix.to_string(),
        // FIXME: Right now we are sending instance IP as hostname. This should be replaced by
        // user's provided fqdn later.
        fqdn: dashed_ip,
        booturl: None,
    })
}
