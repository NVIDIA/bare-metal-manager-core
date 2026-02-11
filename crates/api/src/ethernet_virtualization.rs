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
use ::rpc::forge as rpc;
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::{MachineId, MachineInterfaceId};
use db::vpc::{self};
use db::vpc_peering::get_prefixes_by_vpcs;
use db::{self, ObjectColumnFilter, network_security_group};
use forge_network::virtualization::{VpcVirtualizationType, get_svi_ip};
use ipnetwork::{IpNetwork, Ipv4Network};
use model::instance::config::network::{InstanceInterfaceConfig, InterfaceFunctionId};
use model::network_security_group::{
    NetworkSecurityGroup, NetworkSecurityGroupRule, NetworkSecurityGroupRuleNet,
};
use model::network_segment::NetworkSegment;
use model::resource_pool::common::CommonPools;
use sqlx::PgConnection;
use tonic::Status;

use crate::CarbideError;
use crate::cfg::file::VpcPeeringPolicy;

#[derive(Default, Clone)]
pub struct EthVirtData {
    pub asn: u32,
    pub dhcp_servers: Vec<String>,
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

    pub fn as_ip_slice(&self) -> &[IpNetwork] {
        &self.prefixes
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
    txn: &mut PgConnection,
    host_machine_id: &MachineId,
    dpu_machine_id: &MachineId,
    fnn_enabled_on_admin: bool,
    common_pools: &CommonPools,
    booturl: &Option<String>,
) -> Result<(rpc::FlatInterfaceConfig, MachineInterfaceId), tonic::Status> {
    let admin_segment = db::network_segment::admin(txn).await?;

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
            db::dns::domain::find_by_uuid(txn, domain_id)
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
            .await?;

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

    let address = db::machine_interface_address::find_ipv4_for_interface(txn, interface.id).await?;

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
        get_svi_ip(
            &prefix.svi_ip,
            VpcVirtualizationType::Fnn,
            true,
            prefix.prefix.prefix(),
        )
        .map_err(|e| {
            Status::internal(format!(
                "failed to configure FlatInterfaceConfig.svi_ip: {e}"
            ))
        })?
        .map(|ip| ip.to_string())
    };

    let (vpc_vni, tenant_vrf_loopback_ip) = if !fnn_enabled_on_admin {
        (0, None)
    } else {
        match admin_segment.vpc_id {
            Some(vpc_id) => {
                let mut vpcs =
                    db::vpc::find_by(&mut *txn, ObjectColumnFilter::One(vpc::IdColumn, &vpc_id))
                        .await?;
                if vpcs.is_empty() {
                    return Err(CarbideError::FindOneReturnedNoResultsError(vpc_id.into()).into());
                }
                let vpc = vpcs.remove(0);
                match vpc.vni {
                    Some(vpc_vni) => {
                        let tenant_loopback_ip =
                            db::vpc_dpu_loopback::get_or_allocate_loopback_ip_for_vpc(
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
        booturl: booturl.clone(),
        svi_ip,
        tenant_vrf_loopback_ip,
        is_l2_segment: true,
        vpc_peer_prefixes: vec![],
        vpc_peer_vnis: vec![],
        network_security_group: None,
        internal_uuid: None,
        mtu: u32::try_from(admin_segment.mtu).ok(),
    };
    Ok((cfg, interface.id))
}

#[allow(clippy::too_many_arguments)]
pub async fn tenant_network(
    txn: &mut PgConnection,
    instance_id: InstanceId,
    iface: &InstanceInterfaceConfig,
    fqdn: String,
    loopback_ip: Option<String>,
    nvue_enabled: bool,
    network_virtualization_type: VpcVirtualizationType,
    suppress_tenant_security_groups: bool,
    network_security_group_details: Option<(i32, NetworkSecurityGroup)>,
    segment: &NetworkSegment,
    vpc_peering_policy_on_existing: Option<VpcPeeringPolicy>,
    booturl: &Option<String>,
) -> Result<rpc::FlatInterfaceConfig, tonic::Status> {
    // Any stretchable segment is treated as L2 segment by FNN.
    let is_l2_segment = segment.can_stretch.unwrap_or(true);

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

    // Assuming an `address` was found above, look to see if a prefix
    // is explicitly configured here. If not, default to a /32, which
    // is our default fallback for cases of instances which were configured
    // before interface_prefixes were introduced.
    //
    // TODO(chet): This can eventually be phased out once all of the
    // InstanceInterfaceConfigs stored contain the prefix.
    let default_prefix = IpNetwork::new(*address, 32).map_err(|e| {
        Status::internal(format!(
            "failed to build default interface_prefix for {address}/32: {e}"
        ))
    })?;

    let interface_prefix = iface
        .interface_prefixes
        .get(&v4_prefix.id)
        .unwrap_or(&default_prefix);

    let vpc_prefixes: Vec<String> = match segment.vpc_id {
        Some(vpc_id) => {
            let vpc_prefixes = db::vpc_prefix::find_by_vpc(txn, vpc_id)
                .await?
                .into_iter()
                .map(|vpc_prefix| vpc_prefix.config.prefix.to_string());
            let vpc_segment_prefixes = db::network_prefix::find_by_vpc(txn, vpc_id)
                .await?
                .into_iter()
                .map(|segment_prefix| segment_prefix.prefix.to_string());
            vpc_prefixes.chain(vpc_segment_prefixes).collect()
        }
        None => vec![v4_prefix.prefix.to_string()],
    };

    let mut vpc_peer_vnis = vec![];
    let mut vpc_peer_prefixes = vec![];
    if let Some(policy) = vpc_peering_policy_on_existing
        && let Some(vpc_id) = segment.vpc_id
    {
        match policy {
            VpcPeeringPolicy::Exclusive => {
                // Under exclusive policy, VPC only allowed to peer with VPC of same network virtualization type.
                // If nvue_enabled, ETHERNET_VIRTUALIZER is same as ETHERNET_VIRTUALIZER_NVUE.
                let allowed_network_virtualization_types =
                    match (nvue_enabled, network_virtualization_type) {
                        (true, t) if t != VpcVirtualizationType::Fnn => {
                            vec![
                                VpcVirtualizationType::EthernetVirtualizer,
                                VpcVirtualizationType::EthernetVirtualizerWithNvue,
                            ]
                        }
                        _ => vec![network_virtualization_type],
                    };
                let vpc_peers = db::vpc_peering::get_vpc_peer_vnis(
                    txn,
                    vpc_id,
                    allowed_network_virtualization_types,
                )
                .await?;

                let vpc_peer_ids = vpc_peers.iter().map(|(vpc_id, _)| *vpc_id).collect();
                vpc_peer_prefixes = get_prefixes_by_vpcs(txn, &vpc_peer_ids).await?;
                if network_virtualization_type == VpcVirtualizationType::Fnn {
                    vpc_peer_vnis = vpc_peers.iter().map(|(_, vni)| *vni as u32).collect();
                }
            }
            VpcPeeringPolicy::Mixed => {
                // Any combination of VPC peering allowed
                let vpc_peer_ids = db::vpc_peering::get_vpc_peer_ids(txn, vpc_id).await?;
                vpc_peer_prefixes = get_prefixes_by_vpcs(txn, &vpc_peer_ids).await?;
                if network_virtualization_type == VpcVirtualizationType::Fnn {
                    // Get vnis of all FNN peers for route import
                    vpc_peer_vnis = db::vpc_peering::get_vpc_peer_vnis(
                        txn,
                        vpc_id,
                        vec![VpcVirtualizationType::Fnn],
                    )
                    .await?
                    .iter()
                    .map(|(_, vni)| *vni as u32)
                    .collect();
                }
            }
            VpcPeeringPolicy::None => {}
        }
    }

    let vpc = match segment.vpc_id {
        Some(vpc_id) => {
            let mut vpcs =
                db::vpc::find_by(&mut *txn, ObjectColumnFilter::One(vpc::IdColumn, &vpc_id))
                    .await?;
            if vpcs.is_empty() {
                return Err(CarbideError::FindOneReturnedNoResultsError(vpc_id.into()).into());
            }
            vpcs.pop()
        }
        None => None,
    };

    let vpc_vni = vpc.as_ref().and_then(|v| v.vni).unwrap_or_default() as u32;

    let rpc_ft: rpc::InterfaceFunctionType = iface.function_id.function_type().into();
    let svi_ip = get_svi_ip(
        &v4_prefix.svi_ip,
        network_virtualization_type,
        is_l2_segment,
        v4_prefix.prefix.prefix(),
    )
    .map_err(|e| {
        Status::internal(format!(
            "failed to configure FlatInterfaceConfig.svi_ip: {e}"
        ))
    })?
    .map(|ip| ip.to_string());

    let network_security_group_details = match (
        suppress_tenant_security_groups,
        network_security_group_details,
        vpc.as_ref(),
    ) {
        // If NSGs aren't being suppressed, and there are no
        // details coming from the parent instance,
        // see if there's an associated VPC (there should be),
        // and see if the VPC has an NSG attached.
        (false, None, Some(v)) => {
            match v.network_security_group_id.as_ref() {
                None => None,
                Some(vpc_nsg_id) => {
                    // Make our DB query for the IDs to get our NetworkSecurityGroup
                    let network_security_group = network_security_group::find_by_ids(
                        txn,
                        &[vpc_nsg_id.to_owned()],
                        Some(
                            &v.tenant_organization_id
                                .parse()
                                .map_err(|_| Status::internal("invalid tenant org in VPC data"))?,
                        ),
                        false,
                    )
                    .await?
                    .pop()
                    .ok_or(CarbideError::NotFoundError {
                        kind: "NetworkSecurityGroup",
                        id: v.tenant_organization_id.clone(),
                    })?;

                    Some((
                        i32::from(rpc::NetworkSecurityGroupSource::NsgSourceVpc),
                        network_security_group,
                    ))
                }
            }
        }

        // If NSGs aren't being suppressed and details are already coming from
        // the parent instance, use those.
        (false, d, _) => d,

        // Otherwise, we either have no details or we want no details.
        _ => None,
    };

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
        booturl: booturl.clone(),
        svi_ip,
        tenant_vrf_loopback_ip: loopback_ip,
        is_l2_segment,
        vpc_peer_prefixes,
        vpc_peer_vnis,
        network_security_group: network_security_group_details
            .map(|(source, nsg)| {
                Ok(
                        rpc::FlatInterfaceNetworkSecurityGroupConfig {
                            id: nsg.id.to_string(),
                            version: nsg.version.to_string(),
                            source,
                            stateful_egress: nsg.stateful_egress,
                            rules:
                                nsg.rules
                                    .into_iter()
                                    .map(resolve_security_group_rule)
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
                    "failed to configure FlatInterfaceConfig.network_security_group: {e}"
                ))
            })?,
        internal_uuid: Some(iface.internal_uuid.into()),
        mtu: u32::try_from(segment.mtu).ok(),
    })
}

pub fn resolve_security_group_rule(
    rule: NetworkSecurityGroupRule,
) -> Result<rpc::ResolvedNetworkSecurityGroupRule, CarbideError> {
    Ok(rpc::ResolvedNetworkSecurityGroupRule {
        // When we decide to allow object references,
        // they would be resolved to their actual prefix
        // lists and stored here.
        src_prefixes: match rule.src_net {
            NetworkSecurityGroupRuleNet::Prefix(ref p) => {
                vec![p.to_string()]
            }
        },
        dst_prefixes: match rule.dst_net {
            NetworkSecurityGroupRuleNet::Prefix(ref p) => {
                vec![p.to_string()]
            }
        },
        rule: Some(rule.try_into()?),
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

    #[test]
    fn test_site_prefix_list_ipv6_containment() {
        let prefixes: Vec<IpNetwork> = vec![IpNetwork::V6("2001:db8:abcd::/48".parse().unwrap())];
        let site_prefix_list = SiteFabricPrefixList::from_ipnetwork_vec(prefixes).unwrap();

        // Make sure a /64 subnet is contained within the /48.
        assert!(site_prefix_list.contains("2001:db8:abcd:1::/64".parse().unwrap()));
        // Make sure an exact match is contained.
        assert!(site_prefix_list.contains("2001:db8:abcd::/48".parse().unwrap()));
        // Make sure a larger prefix is NOT contained.
        assert!(!site_prefix_list.contains("2001:db8::/32".parse().unwrap()));
        // Make sure a completely different prefix is also not contained.
        assert!(!site_prefix_list.contains("2001:db8:ffff::/48".parse().unwrap()));
    }

    #[test]
    fn test_site_prefix_list_cross_family_never_matches() {
        // IPv4-only site fabric prefixes should never match IPv6
        // segments and vice versa.
        let ipv4_only = SiteFabricPrefixList::from_ipnetwork_vec(vec![IpNetwork::V4(
            "10.0.0.0/8".parse().unwrap(),
        )])
        .unwrap();
        assert!(!ipv4_only.contains("2001:db8::/32".parse().unwrap()));

        let ipv6_only = SiteFabricPrefixList::from_ipnetwork_vec(vec![IpNetwork::V6(
            "2001:db8::/32".parse().unwrap(),
        )])
        .unwrap();
        assert!(!ipv6_only.contains("10.0.0.0/24".parse().unwrap()));
    }

    #[test]
    fn test_site_prefix_list_dual_stack() {
        // A dual-stack site with both IPv4 and IPv6 fabric prefixes.
        let prefixes: Vec<IpNetwork> = vec![
            IpNetwork::V4("10.100.0.0/16".parse().unwrap()),
            IpNetwork::V6("fd00:100::/32".parse().unwrap()),
        ];
        let site_prefix_list = SiteFabricPrefixList::from_ipnetwork_vec(prefixes).unwrap();

        // This IPv4 subnet should be contained in the SiteFabricPrefixList.
        assert!(site_prefix_list.contains("10.100.1.0/24".parse().unwrap()));
        // ...and so should this IPv6 prefix.
        assert!(site_prefix_list.contains("fd00:100:1::/48".parse().unwrap()));
        // ...but not this IPv4 prefix.
        assert!(!site_prefix_list.contains("10.200.0.0/24".parse().unwrap()));
        // ...or this IPv6 prefix.
        assert!(!site_prefix_list.contains("fd00:200::/48".parse().unwrap()));
    }
}
