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

use ::rpc::forge as rpc;
use ipnetwork::{IpNetwork, Ipv4Network};
use sqlx::{Postgres, Transaction};
use tonic::Status;

use crate::db::vpc::VpcDpuLoopback;
use crate::db::vpc_prefix::VpcPrefix;
use crate::db::{network_segment, ObjectColumnFilter};
use crate::model::network_security_group::NetworkSecurityGroupRuleNet;
use crate::resource_pool::common::CommonPools;
use crate::{
    db::{
        self,
        domain::Domain,
        machine_interface_address::MachineInterfaceAddress,
        network_prefix::NetworkPrefix,
        network_segment::{NetworkSegment, NetworkSegmentSearchConfig},
        vpc::{self, Vpc},
    },
    model::{
        instance::config::network::{InstanceInterfaceConfig, InterfaceFunctionId},
        network_security_group::NetworkSecurityGroup,
    },
    CarbideError,
};
use forge_network::virtualization::{get_svi_ip, VpcVirtualizationType};
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
    fnn_enabled_on_admin: bool,
    common_pools: &CommonPools,
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

    let svi_ip = if !fnn_enabled_on_admin {
        None
    } else {
        get_svi_ip(&prefix.prefix, VpcVirtualizationType::Fnn, true)
            .map_err(|e| {
                Status::internal(format!(
                    "failed to configure FlatInterfaceConfig.svi_ip: {}",
                    e
                ))
            })?
            .map(|ip| ip.to_string())
    };

    let (vpc_vni, tenant_vrf_loopback_ip) = if !fnn_enabled_on_admin {
        (0, None)
    } else {
        match admin_segment.vpc_id {
            Some(vpc_id) => {
                let mut vpcs = Vpc::find_by(txn, ObjectColumnFilter::One(vpc::IdColumn, &vpc_id))
                    .await
                    .map_err(CarbideError::from)?;
                if vpcs.is_empty() {
                    return Err(CarbideError::FindOneReturnedNoResultsError(vpc_id.into()).into());
                }
                let vpc = vpcs.remove(0);
                match vpc.vni {
                    Some(vpc_vni) => {
                        let tenant_loopback_ip =
                            VpcDpuLoopback::get_or_allocate_loopback_ip_for_vpc(
                                common_pools,
                                txn,
                                dpu_machine_id,
                                &vpc.id,
                            )
                            .await?;

                        (vpc_vni as u32, Some(tenant_loopback_ip.to_string()))
                    }
                    None => {
                        // if FNN is enabled, VPC must be created and updated in admin_segment.
                        return Err(CarbideError::internal(format!(
                            "Admin VPC is not found with id: {vpc_id}."
                        ))
                        .into());
                    }
                }
            }
            None => {
                // if FNN is enabled, VPC must be created and updated in admin_segment.
                return Err(CarbideError::internal(
                    "Admin VPC is not attached to admin segment.".to_string(),
                )
                .into());
            }
        }
    };

    let cfg = rpc::FlatInterfaceConfig {
        function_type: rpc::InterfaceFunctionType::Physical.into(),
        virtual_function_id: None,
        vlan_id: admin_segment.vlan_id.unwrap_or_default() as u32,
        vni: if fnn_enabled_on_admin {
            admin_segment.vni.unwrap_or_default() as u32
        } else {
            0
        },
        vpc_vni,
        gateway: prefix.gateway_cidr().unwrap_or_default(),
        ip: address.address.to_string(),
        interface_prefix: address_prefix.to_string(),
        vpc_prefixes: if fnn_enabled_on_admin {
            vec![format!("{}/32", address.address.to_string())]
        } else {
            vec![]
        },
        prefix: prefix.prefix.to_string(),
        fqdn: format!("{}.{}", interface.hostname, domain),
        booturl: None,
        svi_ip,
        tenant_vrf_loopback_ip,
        is_l2_segment: true,
        network_security_group: None,
    };
    Ok((cfg, interface.id))
}

#[allow(clippy::too_many_arguments)]
pub async fn tenant_network(
    txn: &mut Transaction<'_, Postgres>,
    instance_id: InstanceId,
    iface: &InstanceInterfaceConfig,
    fqdn: String,
    loopback_ip: Option<String>,
    is_l2_segment: bool,
    network_virtualization_type: VpcVirtualizationType,
    network_security_group_details: Option<(i32, NetworkSecurityGroup)>,
) -> Result<rpc::FlatInterfaceConfig, tonic::Status> {
    let Some(network_segment_id) = iface.network_segment_id else {
        return Err(CarbideError::NetworkSegmentNotAllocated.into());
    };

    let segments = &NetworkSegment::find_by(
        txn,
        ObjectColumnFilter::One(network_segment::IdColumn, &network_segment_id),
        NetworkSegmentSearchConfig::default(),
    )
    .await
    .map_err(CarbideError::from)?;
    let Some(segment) = segments.first() else {
        return Err(Status::internal(format!(
            "Tenant network segment id '{}' matched more than one segment",
            network_segment_id
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

    let vpc_prefixes: Vec<String> = match segment.vpc_id {
        Some(vpc_id) => {
            let vpc_prefixes = VpcPrefix::find_by_vpc(txn, vpc_id)
                .await
                .map_err(CarbideError::from)?
                .into_iter()
                .map(|vpc_prefix| vpc_prefix.prefix.to_string());
            let vpc_segment_prefixes = NetworkPrefix::find_by_vpc(txn, vpc_id)
                .await
                .map_err(CarbideError::from)?
                .into_iter()
                .map(|segment_prefix| segment_prefix.prefix.to_string());
            vpc_prefixes.chain(vpc_segment_prefixes).collect()
        }
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
        svi_ip: get_svi_ip(
            &v4_prefix.prefix,
            network_virtualization_type,
            is_l2_segment,
        )
        .map_err(|e| {
            Status::internal(format!(
                "failed to configure FlatInterfaceConfig.svi_ip: {}",
                e
            ))
        })?
        .map(|ip| ip.to_string()),
        tenant_vrf_loopback_ip: loopback_ip,
        is_l2_segment,
        network_security_group: network_security_group_details
            .map(|(source, nsg)| {
                Ok(
                        rpc::FlatInterfaceNetworkSecurityGroupConfig {
                            id: nsg.id.to_string(),
                            version: nsg.version.to_string(),
                            source,
                            rules:
                                nsg.rules
                                    .into_iter()
                                    .map(|r| {
                                        Ok(rpc::ResolvedNetworkSecurityGroupRule {
                                            // When we decide to allow object references,
                                            // they would be resolved to their actual prefix
                                            // lists and stored here.
                                            src_prefixes: match r.src_net {
                                                NetworkSecurityGroupRuleNet::Prefix(ref p) => {
                                                    vec![p.to_string()]
                                                }
                                            },
                                            dst_prefixes: match r.dst_net {
                                                NetworkSecurityGroupRuleNet::Prefix(ref p) => {
                                                    vec![p.to_string()]
                                                }
                                            },
                                            rule: Some(r.try_into().map_err(CarbideError::from)?),
                                        })
                                    })
                                    .collect::<Result<
                                        Vec<rpc::ResolvedNetworkSecurityGroupRule>,
                                        CarbideError,
                                    >>()?,
                        },
                    )
            })
            .transpose()
            .map_err(|e: CarbideError| {
                Status::internal(format!(
                    "failed to configure FlatInterfaceConfig.network_security_group: {}",
                    e
                ))
            })?,
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
