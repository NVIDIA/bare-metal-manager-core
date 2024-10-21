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
use std::borrow::Borrow;

pub use ::rpc::forge as rpc;
use ipnetwork::{IpNetwork, Ipv4Network};
use sqlx::{Postgres, Transaction};
use tonic::Status;

use crate::db::{network_segment, ObjectColumnFilter};
use crate::{
    db::{
        self,
        domain::Domain,
        machine_interface_address::MachineInterfaceAddress,
        network_prefix::NetworkPrefix,
        network_segment::{NetworkSegment, NetworkSegmentSearchConfig},
        vpc::{self, Vpc},
    },
    model::instance::config::network::{InstanceInterfaceConfig, InterfaceFunctionId},
    CarbideError,
};
use forge_network::virtualization::{get_svi_ip, get_tenant_vrf_loopback_ip};
use forge_uuid::{instance::InstanceId, machine::MachineId, machine::MachineInterfaceId};

#[derive(Default, Clone)]
pub struct EthVirtData {
    pub asn: u32,
    pub dhcp_servers: Vec<String>,
    pub route_servers: Vec<String>,
    pub route_servers_enabled: bool,
    pub deny_prefixes: Vec<Ipv4Network>,
    pub site_fabric_prefixes: Option<SiteFabricPrefixList>,
}

#[derive(Clone)]
pub struct SiteFabricPrefixList {
    prefixes: Vec<IpNetwork>,
}

impl SiteFabricPrefixList {
    pub fn from_ipnetwork_vec(prefixes: Vec<IpNetwork>) -> Option<Self> {
        // Under the current configuration semantics, an empty
        // site_fabric_prefixes list in the site config means we are not using
        // the VPC isolation feature built on top of it, and it is better not
        // to construct one of these at all (and thus the Option-wrapped return
        // type).
        if prefixes.is_empty() {
            None
        } else {
            Some(Self { prefixes })
        }
    }

    pub fn from_ipv4_slice(ipv4_prefixes: &[Ipv4Network]) -> Option<Self> {
        let prefixes: Vec<_> = ipv4_prefixes
            .iter()
            .copied()
            .map(ipnetwork::IpNetwork::V4)
            .collect();
        Self::from_ipnetwork_vec(prefixes)
    }

    // Check whether the given network matches any of our site fabric prefixes.
    pub fn contains(&self, network: IpNetwork) -> bool {
        use IpNetwork::*;
        self.prefixes
            .iter()
            .copied()
            .any(|site_prefix| match (network, site_prefix) {
                (V4(network), V4(site_prefix)) => network.is_subnet_of(site_prefix),
                (V6(network), V6(site_prefix)) => network.is_subnet_of(site_prefix),
                _ => false,
            })
    }
}

pub async fn admin_network(
    txn: &mut Transaction<'_, Postgres>,
    host_machine_id: &MachineId,
    dpu_machine_id: &MachineId,
) -> Result<(rpc::FlatInterfaceConfig, MachineInterfaceId), tonic::Status> {
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

    let interfaces =
        db::machine_interface::find_by_machine_and_segment(txn, host_machine_id, admin_segment.id)
            .await
            .map_err(CarbideError::from)?;

    let interface = interfaces.into_iter().find(|x| {
        if let Some(id) = &x.attached_dpu_machine_id {
            id == dpu_machine_id
        } else {
            false
        }
    });

    let Some(interface) = interface else {
        return Err(CarbideError::InvalidArgument(format!(
            "No interface found attached on host: {host_machine_id} with dpu: {dpu_machine_id}"
        ))
        .into());
    };

    let address = MachineInterfaceAddress::find_ipv4_for_interface(txn, interface.id)
        .await
        .map_err(CarbideError::from)?;

    // On the admin network, the interface_prefix is always
    // just going to be a /32 derived from the machine interface
    // address.
    let address_prefix = IpNetwork::new(address.address, 32).map_err(|e| {
        Status::internal(format!(
            "failed to build default admin address prefix for {}/32: {}",
            address.address, e
        ))
    })?;

    // admin isn't an overlay network, so:
    //  - vni: 0 (because there's no VNI)
    //  - network: ip/32 (because there won't be an instance network allocation)
    //  - svi_ip: None (because there isn't an instance network allocation)
    let cfg = rpc::FlatInterfaceConfig {
        function_type: rpc::InterfaceFunctionType::Physical.into(),
        virtual_function_id: None,
        vlan_id: admin_segment.vlan_id.unwrap_or_default() as u32,
        vni: 0,
        vpc_vni: 0,
        gateway: prefix.gateway_cidr().unwrap_or_default(),
        ip: address.address.to_string(),
        interface_prefix: address_prefix.to_string(),
        vpc_prefixes: vec![],
        prefix: prefix.prefix.to_string(),
        fqdn: format!("{}.{}", interface.hostname, domain),
        booturl: None,
        svi_ip: None,
        tenant_vrf_loopback_ip: None,
    };
    Ok((cfg, interface.id))
}

pub async fn tenant_network(
    txn: &mut Transaction<'_, Postgres>,
    instance_id: InstanceId,
    iface: &InstanceInterfaceConfig,
    fqdn: String,
) -> Result<rpc::FlatInterfaceConfig, tonic::Status> {
    let segments = &NetworkSegment::find_by(
        txn,
        ObjectColumnFilter::One(network_segment::IdColumn, &iface.network_segment_id),
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

    let address = iface
        .ip_addrs
        .get(&v4_prefix.id.borrow().into())
        .ok_or_else(|| {
            Status::internal(format!(
                "No IPv4 address is available for instance {} on segment {}",
                instance_id, segment.id
            ))
        })?;

    // Assuming an `address` was found above, look to see if a prefix
    // is explicitly configured here. If not, default to a /32, which
    // is our default fallback for cases of instances which were configured
    // before interface_prefixes were introduced.
    //
    // TODO(chet): This can eventually be phased out once all of the
    // InstanceInterfaceConfigs stored contain the prefix.
    let default_prefix = IpNetwork::new(*address, 32).map_err(|e| {
        Status::internal(format!(
            "failed to build default interface_prefix for {}/32: {}",
            address, e
        ))
    })?;

    let interface_prefix = iface
        .interface_prefixes
        .get(&v4_prefix.id.borrow().into())
        .unwrap_or(&default_prefix);

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

    let vpc_vni = match segment.vpc_id {
        Some(vpc_id) => {
            let vpcs = Vpc::find_by(txn, ObjectColumnFilter::One(vpc::IdColumn, &vpc_id))
                .await
                .map_err(CarbideError::from)?;
            if vpcs.is_empty() {
                return Err(CarbideError::FindOneReturnedNoResultsError(vpc_id.into()).into());
            }
            match vpcs[0].vni {
                Some(vpc_vni) => vpc_vni as u32,
                None => 0,
            }
        }
        None => 0,
    };

    let rpc_ft: rpc::InterfaceFunctionType = iface.function_id.function_type().into();

    Ok(rpc::FlatInterfaceConfig {
        function_type: rpc_ft.into(),
        virtual_function_id: match iface.function_id {
            InterfaceFunctionId::Physical {} => None,
            InterfaceFunctionId::Virtual { id } => Some(id.into()),
        },
        vlan_id: segment.vlan_id.unwrap_or_default() as u32,
        vni: segment.vni.unwrap_or_default() as u32,
        vpc_vni,
        gateway: v4_prefix.gateway_cidr().unwrap_or_default(),
        ip: address.to_string(),
        interface_prefix: interface_prefix.to_string(),
        vpc_prefixes,
        prefix: v4_prefix.prefix.to_string(),
        // FIXME: Right now we are sending instance IP as hostname. This should be replaced by
        // user's provided fqdn later.
        fqdn,
        booturl: None,
        svi_ip: get_svi_ip(interface_prefix)
            .map_err(|e| {
                Status::internal(format!(
                    "failed to configure FlatInterfaceConfig.svi_ip: {}",
                    e
                ))
            })?
            .map(|ip| ip.to_string()),
        tenant_vrf_loopback_ip: get_tenant_vrf_loopback_ip(interface_prefix)
            .map_err(|e| {
                Status::internal(format!(
                    "failed to configure FlatInterfaceConfig.tenant_vrf_loopback_ip: {}",
                    e
                ))
            })?
            .map(|ip| ip.to_string()),
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_site_prefix_list() {
        let prefixes: Vec<IpNetwork> = vec![
            IpNetwork::V4("192.0.2.0/25".parse().unwrap()),
            IpNetwork::V6("2001:DB8::/64".parse().unwrap()),
        ];
        let site_prefix_list = SiteFabricPrefixList::from_ipnetwork_vec(prefixes).unwrap();

        let contained_smaller = IpNetwork::V4("192.0.2.64/26".parse().unwrap());
        let contained_equal = IpNetwork::V4("192.0.2.0/25".parse().unwrap());
        let uncontained_larger = IpNetwork::V4("192.0.2.0/24".parse().unwrap());
        let uncontained_different = IpNetwork::V4("198.51.100.0/24".parse().unwrap());
        assert!(site_prefix_list.contains(contained_smaller));
        assert!(site_prefix_list.contains(contained_equal));
        assert!(!site_prefix_list.contains(uncontained_larger));
        assert!(!site_prefix_list.contains(uncontained_different));

        assert!(SiteFabricPrefixList::from_ipnetwork_vec(vec![]).is_none());
    }
}
