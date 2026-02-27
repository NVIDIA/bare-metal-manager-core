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

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use ::rpc::forge as rpc;
use eyre::WrapErr;
use forge_network::ip::prefix::Ipv4Net;
use forge_network::sanitized_mac;
use forge_network::virtualization::VpcVirtualizationType;
use gtmpl_derive::Gtmpl;
use mac_address::MacAddress;
use serde::Deserialize;

pub const PATH: &str = "var/support/nvue_startup.yaml";
pub const SAVE_PATH: &str = "etc/nvue.d/startup.yaml";
pub const PATH_ACL: &str = "etc/cumulus/acl/policy.d/70-forge_nvue.rules";

const TMPL_ETV_WITH_NVUE: &str = include_str!("../templates/nvue_startup_etv.conf");
const TMPL_FNN: &str = include_str!("../templates/nvue_startup_fnn.conf");

/// This value is added to the priority value specified
/// by users for their NSG rules.
const NETWORK_SECURITY_GROUP_RULE_PRIORITY_START: u32 = 2000;

/// This limits the number of rules we'll allow into the set for
/// nvue.  We do not expect to ever hit this as the rules should
/// have been limited before they reached the DPU.  It's purpose here
/// is defense-in-depth.
///
/// We have something similar on the controller side, though the limit
/// there is likely to stay in the hundreds.  The limit here will
/// likely always be far larger because we're only concerned with
/// protecting the DPU from getting a rule set that would expand
/// into something big enough to exhaust its physical resources.
/// We want a limit small enough to protect us but big enough that we
/// don't have to remember to keep bumping this up as we decide nvue
/// can handle more rules.
///
/// *_NOTE: This is a limit per unique NSG.  Multiple interfaces could
/// each have a unique NSG associated, either directly or via different VPC
/// associations per interface._*
const NETWORK_SECURITY_GROUP_RULE_COUNT_MAX: usize = 10000;

pub fn build(conf: NvueConfig) -> eyre::Result<String> {
    if !conf.vpc_virtualization_type.supports_nvue() {
        return Err(eyre::eyre!(
            "cannot nvue::build. provided virtualizaton type does not support nvue: {}",
            conf.vpc_virtualization_type,
        ));
    }

    let host_interfaces: Vec<TmplHostInterfaces> = conf
        .ct_access_vlans
        .into_iter()
        .map(|vl| TmplHostInterfaces {
            ID: vl.vlan_id,
            HostIP: vl.ip,
            HostRoute: vl.network,
        })
        .collect();

    // This assumes that the routing profile is expected to be same for
    // all VPCs of a tenant _and_ for all VPCs that an instance might span.
    // That should be ok for now, and a smaller MR later that moves
    // profiles into FlatInterfaceConfig could change that.
    // For now, we clone later so that we can put this into each TmplVpc
    // and make a later transition easier.
    let routing_profile = conf
        .ct_routing_profile
        .as_ref()
        .map(|rt| TmplRoutingProfile {
            RouteTargetImports: rt
                .route_target_imports
                .iter()
                .map(|rt| TmplRouteTargetConfig {
                    ASN: rt.asn,
                    VNI: rt.vni,
                })
                .collect(),
            RouteTargetsOnExports: rt
                .route_targets_on_exports
                .iter()
                .map(|rt| TmplRouteTargetConfig {
                    ASN: rt.asn,
                    VNI: rt.vni,
                })
                .collect(),
        });

    // There are two assumptions about pre-FNN...
    // 1 - ManagedHostNetworkConfigResponse only has rules inherited either from VPC or Instance,
    //     and VPC-spanning per-interface isn't possible.
    // 2 - There is only one DPU.
    //
    // Both of these are valid assumptions right now because L3 EVPN and multi-DPU are only possible with FNN,
    // We probably shouldn't warn anymore, but we probably should drop info for now.

    if conf.network_security_groups.len() > 1 {
        tracing::info!(
            "Found more than one interface with network security group applied in ManagedHostNetworkConfigResponse, so rules will be merged when FNN is not in use.",
        );
    }

    let mut nsg_id_index_map = HashMap::<String, u16>::new();
    let mut network_security_groups =
        Vec::<TmplNetworkSecurityGroup>::with_capacity(conf.network_security_groups.len());

    // Pre-FNN will still expect a merged/flattened version.
    let mut merged_ingress_ipv4_nsg_rules = vec![];
    let mut merged_ingress_ipv6_nsg_rules = vec![];
    let mut merged_egress_ipv4_nsg_rules = vec![];
    let mut merged_egress_ipv6_nsg_rules = vec![];

    let has_network_security_group = !conf.network_security_groups.is_empty();

    for (i, nsg) in conf.network_security_groups.into_iter().enumerate() {
        let idx = i.try_into().wrap_err(format!(
            "number of unique network security groups exceeds {} limit",
            u16::MAX
        ))?;

        nsg_id_index_map.insert(nsg.id, idx);

        let (ingress_ipv4_rules, egress_ipv4_rules, ingress_ipv6_rules, egress_ipv6_rules) =
            prepare_network_security_group_rules(nsg.rules)?;

        merged_ingress_ipv4_nsg_rules.extend_from_slice(&ingress_ipv4_rules);
        merged_ingress_ipv6_nsg_rules.extend_from_slice(&ingress_ipv6_rules);
        merged_egress_ipv4_nsg_rules.extend_from_slice(&egress_ipv4_rules);
        merged_egress_ipv6_nsg_rules.extend_from_slice(&egress_ipv6_rules);

        network_security_groups.push(TmplNetworkSecurityGroup {
            Index: idx,
            StatefulEgress: nsg.stateful_egress,
            IngressNetworkSecurityGroupRulesIpv4: ingress_ipv4_rules,
            IngressNetworkSecurityGroupRulesIpv6: ingress_ipv6_rules,
            EgressNetworkSecurityGroupRulesIpv4: egress_ipv4_rules,
            EgressNetworkSecurityGroupRulesIpv6: egress_ipv6_rules,
        });
    }

    let mut port_configs = Vec::with_capacity(conf.ct_port_configs.len());
    let mut vpc_configs = HashMap::<u32, TmplVpc>::new();

    let mut has_vpc_peer_prefixes = false;
    let mut vpc_peer_prefixes = vec![];
    let mut has_vpc_peer_vnis = false;
    let mut vpc_peer_vnis = vec![];
    for (base_i, network) in conf.ct_port_configs.into_iter().enumerate() {
        // If the instance is NOT in an FNN VPC, We make an assumption
        // here that there is only one tenant interface or at least
        // the same VPC for all interfaces if there are multiple
        // interfaces.
        // Log if multiple interfaces are seen.
        // This could be removed if we stop supporting non-FNN sites.
        if has_vpc_peer_prefixes {
            tracing::info!(
                "Found more than one tenant interface, so VPC peering details of only the first found will be used when FNN is not in use."
            );
        }
        if !has_vpc_peer_prefixes && !network.vpc_peer_prefixes.is_empty() {
            has_vpc_peer_prefixes = true;
            vpc_peer_prefixes = network
                .vpc_peer_prefixes
                .iter()
                .enumerate()
                .map(|(i, prefix)| Prefix {
                    Index: format!("{}", i + 1),
                    Prefix: prefix.to_string(),
                })
                .collect();
        }
        if !has_vpc_peer_vnis && !network.vpc_peer_vnis.is_empty() {
            has_vpc_peer_vnis = true;
            vpc_peer_vnis = network
                .vpc_peer_vnis
                .iter()
                .map(|vni| TmplVni { Vni: *vni })
                .collect()
        }

        let svi_mac = vni_to_svi_mac(network.vni.unwrap_or(0))?.to_string();
        let port = TmplConfigPort {
            InterfaceName: network.interface_name.clone(),
            Index: format!("{}", (base_i + 1) * 10),
            VlanID: network.vlan,
            IsPhy: network.is_phy,
            L2VNI: network.vni.map(|x| x.to_string()).unwrap_or("".to_string()),
            IPs: vec![network.gateway_cidr.clone()],
            SviIP: network.svi_ip.unwrap_or("".to_string()), // FNN only
            SviMAC: svi_mac,
            VrfLoopback: network.tenant_vrf_loopback_ip.unwrap_or_default(),
            VrfName: format!("vpc_{}", network.l3_vni.unwrap_or_default()),
            HasVpcPeerPrefixes: !network.vpc_peer_prefixes.is_empty(),
            HasVpcPrefixes: !network.vpc_prefixes.is_empty(),
            VpcPrefixes: network
                .vpc_prefixes
                .iter()
                .enumerate()
                .map(|(i, prefix)| Prefix {
                    Index: format!("{}", (base_i + 1) * 10 + i),
                    Prefix: prefix.to_string(),
                })
                .collect(),
            IsL2Segment: network.is_l2_segment,
            StorageTarget: false, // XXX (Classic, L3)
            HasNetworkSecurityGroup: network.network_security_group_id.is_some(),
            NetworkSecurityGroupIndex: network
                .network_security_group_id
                .as_ref()
                .map(|nid| {
                    nsg_id_index_map
                    .get(nid)
                    .copied()
                    .ok_or_else(|| {
                    eyre::eyre!(
                        "BUG: PortConfig references network security group ID that does not exist",
                    )
                    })
                })
                .transpose()?,
        };

        vpc_configs
            .entry(network.l3_vni.unwrap_or_default())
            .and_modify(|v| v.PortPrefixes.extend_from_slice(&port.VpcPrefixes))
            .or_insert_with(|| TmplVpc {
                VrfName: port.VrfName.clone(),
                L3VNI: network.l3_vni.unwrap_or_default(),
                VrfLoopback: port.VrfLoopback.clone(),
                // TODO: This is wasteful because it should be specific to a VPC.
                // Otherwise, all VPCs will have a BGP peer config for each
                // interface, regardless of whether the interface is owned by
                // that VPC.
                HostInterfaces: host_interfaces.clone(),
                HasVpcPeerPrefixes: !network.vpc_peer_prefixes.is_empty(),
                VpcPeerPrefixes: network
                    .vpc_peer_prefixes
                    .iter()
                    .enumerate()
                    .map(|(i, prefix)| Prefix {
                        Index: format!("{}", i + 1),
                        Prefix: prefix.to_string(),
                    })
                    .collect(),
                HasVpcPeerVnis: !network.vpc_peer_vnis.is_empty(),
                VpcPeerVnis: network
                    .vpc_peer_vnis
                    .iter()
                    .map(|vni| TmplVni { Vni: *vni })
                    .collect(),
                RoutingProfile: routing_profile.clone(),
                PortPrefixes: port.VpcPrefixes.clone(),
            });

        port_configs.push(port);
    }

    if port_configs.is_empty() {
        return Err(eyre::eyre!(
            "cannot configure VrfLoopback; no address allocations",
        ));
    }

    let vrf_loopback = port_configs[0].VrfLoopback.clone();
    let include_bridge = port_configs.iter().fold(true, |a, b| a & b.IsL2Segment);

    let (
        ingress_ipv4_override_rules,
        egress_ipv4_override_rules,
        ingress_ipv6_override_rules,
        egress_ipv6_override_rules,
    ) = prepare_network_security_group_rules(conf.network_security_policy_override_rules)?;

    // The original VPC isolation would add site fabric prefixes to deny prefixes,
    // with site_fabric_prefixes coming first.
    // This is just an easy way to maintain the ordering of the original behavior.
    let deny_prefix_index_offset = conf.site_fabric_prefixes.len();

    let has_static_advertisements = conf.secondary_overlay_vtep_ip.is_some();

    let (
        has_internal_bridging,
        vf_intercept_bridge_ip,
        vf_intercept_hbn_representor_ip,
        public_prefix_internal_next_hop,
        intercept_bridge_prefix_len,
        // IPv4 only for now. Internal HBN bridge plumbing uses 169.254.x.x
        // link-local addressing for DPU to HBN communication. An IPv6 equivalent
        // (fe80:: or similar) may be needed in the future for dual-stack bridging.
    ) = if let Some(bridge_prefix) = conf
        .internal_bridge_routing_prefix
        .map(|p| p.parse::<Ipv4Net>())
        .transpose()?
    {
        let prefix_len = bridge_prefix.prefix_len();
        let mut hosts = bridge_prefix.hosts();

        // 1st host is for the VF intercept bridge.
        let Some(vf_intercept_bridge_ip) = hosts.next() else {
            return Err(eyre::eyre!(
                "expected VF intercept bridge IP not found in bridge routing prefix supplied by internal_bridge_routing_prefix",
            ));
        };

        // 2nd host address is used within the HBN container on the SF being used for
        // intercepted VF traffic.
        let Some(vf_intercept_hbn_representor_ip) = hosts.next() else {
            return Err(eyre::eyre!(
                "expected VF intercept HBN representor IP not found in bridge routing prefix supplied by internal_bridge_routing_prefix",
            ));
        };

        // 3rd host is for use by a traffic intercept user.  This lets the user know, a priori, of an IP
        // within the stretched L2 domain of the combined br-hbn and custom bridges.
        // This allows them to route traffic directly to and out of the HBN pod.
        let Some(public_prefix_internal_next_hop) = hosts.next() else {
            return Err(eyre::eyre!(
                "expected public_prefix_internal_next_hop bridge IP not found in bridge routing prefix supplied by internal_bridge_routing_prefix",
            ));
        };

        // >= 4th host is currently unused.

        (
            true,
            format!("{vf_intercept_bridge_ip}"),
            format!("{vf_intercept_hbn_representor_ip}"),
            format!("{public_prefix_internal_next_hop}"),
            prefix_len,
        )
    } else {
        (
            false,
            String::default(),
            String::default(),
            String::default(),
            0,
        )
    };

    let mut vpcs = vpc_configs.into_values().collect::<Vec<TmplVpc>>();
    vpcs.sort_by(|a, b| a.L3VNI.cmp(&b.L3VNI));

    let params = TmplNvue {
        UseAdminNetwork: conf.use_admin_network,
        LoopbackIP: conf.loopback_ip,
        HasSiteGlobalVpcVni: conf.site_global_vpc_vni.is_some(),
        SiteGlobalVpcVni: conf.site_global_vpc_vni.unwrap_or_default(),
        HasStaticAdvertisements: has_static_advertisements,
        HasSecondaryOverlayVTEP: conf.secondary_overlay_vtep_ip.is_some(),
        SecondaryOverlayVtepIP: conf.secondary_overlay_vtep_ip.unwrap_or_default(),
        HasInternalBridgeRouting: has_internal_bridging,
        VfInterceptBridgeIP: vf_intercept_bridge_ip,
        InterceptBridgePrefixLen: intercept_bridge_prefix_len,
        PublicPrefixInternalNextHop: public_prefix_internal_next_hop,
        VfInterceptHbnRepresentorIp: vf_intercept_hbn_representor_ip,
        VfInterceptBridgeSf: conf.vf_intercept_bridge_sf.unwrap_or_default(),
        TrafficInterceptPublicPrefixes: conf
            .traffic_intercept_public_prefixes
            .iter()
            .enumerate()
            .map(|(i, s)| Prefix {
                Index: format!("{}", 1 + i),
                Prefix: s.to_string(),
            })
            .collect(),
        ASN: conf.asn,
        DatacenterASN: conf.datacenter_asn,
        UseCommonInternalTenantRouteTarget: conf.common_internal_route_target.is_some(),
        CommonInternalRouteTarget: conf.common_internal_route_target.map(|rt| {
            TmplRouteTargetConfig {
                ASN: rt.asn,
                VNI: rt.vni,
            }
        }),
        AdditionalRouteTargetImports: conf
            .additional_route_target_imports
            .iter()
            .map(|rt| TmplRouteTargetConfig {
                ASN: rt.asn,
                VNI: rt.vni,
            })
            .collect(),
        DPUHostname: conf.dpu_hostname,
        SearchDomain: conf.dpu_search_domain,
        Uplinks: conf.uplinks.clone(),
        RouteServers: conf.route_servers.clone(),
        DHCPServers: conf.dhcp_servers.clone(),
        AnycastSitePrefixes: conf
            .anycast_site_prefixes
            .iter()
            .enumerate()
            .map(|(i, s)| Prefix {
                Index: format!("{}", 1000 + i),
                Prefix: s.to_string(),
            })
            .collect(),
        HasSiteFabricPrefixes: !conf.site_fabric_prefixes.is_empty(),
        SiteFabricPrefixes: conf
            .site_fabric_prefixes
            .iter()
            .enumerate()
            .map(|(i, s)| Prefix {
                Index: format!("{}", 1000 + i),
                Prefix: s.to_string(),
            })
            .collect(),
        HasDenyPrefixes: !conf.deny_prefixes.is_empty(),
        DenyPrefixes: conf
            .deny_prefixes
            .iter()
            .enumerate()
            .map(|(i, s)| Prefix {
                Index: format!("{}", 1000 + deny_prefix_index_offset + i),
                Prefix: s.to_string(),
            })
            .collect(),
        StatefulAclsEnabled: conf.stateful_acls_enabled,
        UseVpcIsolation: conf.use_vpc_isolation,
        HasIpv4IngressSecurityPolicyOverrideRules: !ingress_ipv4_override_rules.is_empty(),
        HasIpv4EgressSecurityPolicyOverrideRules: !egress_ipv4_override_rules.is_empty(),
        HasIpv6IngressSecurityPolicyOverrideRules: !ingress_ipv6_override_rules.is_empty(),
        HasIpv6EgressSecurityPolicyOverrideRules: !egress_ipv6_override_rules.is_empty(),
        Ipv4IngressNetworkSecurityPolicyOverrideRules: ingress_ipv4_override_rules,
        Ipv4EgressNetworkSecurityPolicyOverrideRules: egress_ipv4_override_rules,
        Ipv6IngressNetworkSecurityPolicyOverrideRules: ingress_ipv6_override_rules,
        Ipv6EgressNetworkSecurityPolicyOverrideRules: egress_ipv6_override_rules,
        HbnVersion: conf.hbn_version,
        Tenant: TmplComputeTenant {
            RoutingProfile: routing_profile,
            Vpcs: vpcs,
            VrfName: conf.ct_vrf_name,
            L3VNI: conf.ct_l3_vni.unwrap_or_default().to_string(),
            VrfLoopback: vrf_loopback,
            PortConfigs: port_configs,
            HasHostASN: conf.tenant_host_asn.is_some(),
            HostASN: conf.tenant_host_asn.unwrap_or_default(),
            HostInterfaces: host_interfaces,
            NetworkSecurityGroups: network_security_groups,
            HasNetworkSecurityGroup: has_network_security_group,
            HasIpv4IngressSecurityGroupRules: !merged_ingress_ipv4_nsg_rules.is_empty(),
            HasIpv4EgressSecurityGroupRules: !merged_egress_ipv4_nsg_rules.is_empty(),
            HasIpv6IngressSecurityGroupRules: !merged_ingress_ipv6_nsg_rules.is_empty(),
            HasIpv6EgressSecurityGroupRules: !merged_egress_ipv6_nsg_rules.is_empty(),
            IngressNetworkSecurityGroupRulesIpv4: merged_ingress_ipv4_nsg_rules,
            EgressNetworkSecurityGroupRulesIpv4: merged_egress_ipv4_nsg_rules,
            IngressNetworkSecurityGroupRulesIpv6: merged_ingress_ipv6_nsg_rules,
            EgressNetworkSecurityGroupRulesIpv6: merged_egress_ipv6_nsg_rules,
            HasVpcPeerPrefixes: has_vpc_peer_prefixes,
            VpcPeerPrefixes: vpc_peer_prefixes,
            HasVpcPeerVnis: has_vpc_peer_vnis,
            VpcPeerVnis: vpc_peer_vnis,
        },
        // XXX: Unused placeholders for later.
        IsStorageClient: false,                   // XXX (Classic, L3)
        StorageDpuIP: "127.9.9.9".to_string(),    // XXX (Classic, L3)
        l3vnistorageVLAN: "vlan1337".to_string(), // XXX (Classic, L3)
        StorageL3VNI: 0,                          // XXX (Classic, L3)
        StorageLoopback: "127.8.8.8".to_string(), // XXX (Classic, L3)
        DPUstorageprefix: "127.7.7.7/32".to_string(),
        IncludeBridge: include_bridge,
    };

    // Returns the full content of the nvue template for the forge-dpu-agent
    // to load for the given virtualization type. Since `EthernetVirtualizer`
    // (non-nvue) is still in the mix, this is an Option<String>. However, once
    // we're fully moved away from ETV (and everything is nvue), this can simply
    // become a String.
    let virtualization_template = match conf.vpc_virtualization_type {
        VpcVirtualizationType::EthernetVirtualizer => None,
        VpcVirtualizationType::EthernetVirtualizerWithNvue => Some(TMPL_ETV_WITH_NVUE),
        VpcVirtualizationType::Fnn => Some(TMPL_FNN),
    };

    if let Some(template) = virtualization_template {
        gtmpl::template(template, params).map_err(|e| {
            println!("ERR filling template: {e}",);
            e.into()
        })
    } else {
        Err(eyre::eyre!(
            "cannot nvue::build. no nvue template configured for virtualization type: {}",
            conf.vpc_virtualization_type
        ))
    }
}

/// Prepares a set of network security groups rules for template use.
/// In the process, it expands the rules and evaluates whether they
/// exceed predefined limits.
///
/// * `rules` - A list of network security group rules
///
#[allow(clippy::type_complexity)]
fn prepare_network_security_group_rules(
    rules: Vec<NetworkSecurityGroupRule>,
) -> Result<
    (
        Vec<TmplNetworkSecurityGroupRule>,
        Vec<TmplNetworkSecurityGroupRule>,
        Vec<TmplNetworkSecurityGroupRule>,
        Vec<TmplNetworkSecurityGroupRule>,
    ),
    eyre::Error,
> {
    let mut ingress_ipv4_rules: Vec<&NetworkSecurityGroupRule> = vec![];
    let mut egress_ipv4_rules: Vec<&NetworkSecurityGroupRule> = vec![];
    let mut ingress_ipv6_rules: Vec<&NetworkSecurityGroupRule> = vec![];
    let mut egress_ipv6_rules: Vec<&NetworkSecurityGroupRule> = vec![];

    let mut total_rule_count: usize = 0;

    for rule in rules.iter() {
        // Calculate and accumulate what the number of rules
        // would be after expansion so we can cut things off
        // and err if we got a bad payload that could risk
        // the DPU itself.
        total_rule_count = match total_rule_count.overflowing_add(
            rule.src_prefixes
                .len()
                .saturating_mul(rule.dst_prefixes.len())
                .saturating_mul(
                    (rule
                        .src_port_end
                        .unwrap_or_default()
                        .saturating_sub(rule.src_port_start.unwrap_or_default())
                        + 1) as usize,
                )
                .saturating_mul(
                    (rule
                        .dst_port_end
                        .unwrap_or_default()
                        .saturating_sub(rule.dst_port_start.unwrap_or_default())
                        + 1) as usize,
                ),
        ) {
            (_, true) => {
                return Err(eyre::eyre!(
                    "supplied network security group rule count exceeds limit of {}",
                    NETWORK_SECURITY_GROUP_RULE_COUNT_MAX
                ));
            }
            (v, false) => v,
        };

        if total_rule_count > NETWORK_SECURITY_GROUP_RULE_COUNT_MAX {
            return Err(eyre::eyre!(
                "supplied network security group rule count exceeds limit of {}",
                NETWORK_SECURITY_GROUP_RULE_COUNT_MAX
            ));
        }

        match (rule.ingress, rule.ipv6) {
            (true, false) => ingress_ipv4_rules.push(rule),
            (false, false) => egress_ipv4_rules.push(rule),
            (true, true) => ingress_ipv6_rules.push(rule),
            (false, true) => egress_ipv6_rules.push(rule),
        }
    }

    // Order the rules by priority
    ingress_ipv4_rules.sort_by_key(|nsg| nsg.priority);
    egress_ipv4_rules.sort_by_key(|nsg| nsg.priority);
    ingress_ipv6_rules.sort_by_key(|nsg| nsg.priority);
    egress_ipv6_rules.sort_by_key(|nsg| nsg.priority);

    Ok((
        expand_network_security_group_rules(ingress_ipv4_rules),
        expand_network_security_group_rules(egress_ipv4_rules),
        expand_network_security_group_rules(ingress_ipv6_rules),
        expand_network_security_group_rules(egress_ipv6_rules),
    ))
}

/// Expands a set of network security group rules.
/// Source and destination port ranges and prefix lists will
/// be expanded to a set of individual rules.
/// A new vector of template-ready expanded network security
/// groups will be returned.
///
/// * `nsgs` - A list of references to network security groups to expand.
///
fn expand_network_security_group_rules(
    rules: Vec<&NetworkSecurityGroupRule>,
) -> Vec<TmplNetworkSecurityGroupRule> {
    let mut tmpl_rules: Vec<TmplNetworkSecurityGroupRule> = vec![];

    // NVUE config keys rules on priority, meaning no two rules can
    // have the same priority in a given list.
    // NOTE: This implicitly gives us at least one rule limit:
    // If no two rules in a list can have the same priority, and the
    // priority value max in nvue is limited to an unsigned 16-bit value,
    // that u16 max priority number becomes the max number of rules in a
    // given list.

    for rule in rules {
        for src_prefix in &rule.src_prefixes {
            for dst_prefix in &rule.dst_prefixes {
                if let (Some(src_start), Some(src_end)) = (rule.src_port_start, rule.src_port_end) {
                    if let (Some(dst_start), Some(dst_end)) =
                        (rule.dst_port_start, rule.dst_port_end)
                    {
                        for si in src_start..=src_end {
                            for di in dst_start..=dst_end {
                                tmpl_rules.push(TmplNetworkSecurityGroupRule {
                                    Id: rule.id.clone(),
                                    HasSrcPort: true,
                                    SrcPort: si,
                                    HasDstPort: true,
                                    DstPort: di,
                                    CanMatchAnyProtocol: rule.can_match_any_protocol,
                                    CanBeStateful: rule.can_be_stateful,
                                    Protocol: rule.protocol.clone(),
                                    Action: rule.action.clone(),
                                    SrcPrefix: src_prefix.clone(),
                                    DstPrefix: dst_prefix.clone(),
                                    OriginalPriority: rule.priority,
                                    Priority: tmpl_rules.len() as u32
                                        + NETWORK_SECURITY_GROUP_RULE_PRIORITY_START,
                                });
                            }
                        }
                    } else {
                        for si in src_start..=src_end {
                            tmpl_rules.push(TmplNetworkSecurityGroupRule {
                                Id: rule.id.clone(),
                                HasSrcPort: true,
                                SrcPort: si,
                                HasDstPort: false,
                                DstPort: 0,
                                CanMatchAnyProtocol: rule.can_match_any_protocol,
                                CanBeStateful: rule.can_be_stateful,
                                Protocol: rule.protocol.clone(),
                                Action: rule.action.clone(),
                                SrcPrefix: src_prefix.clone(),
                                DstPrefix: dst_prefix.clone(),
                                OriginalPriority: rule.priority,
                                Priority: tmpl_rules.len() as u32
                                    + NETWORK_SECURITY_GROUP_RULE_PRIORITY_START,
                            });
                        }
                    }
                } else if let (Some(dst_start), Some(dst_end)) =
                    (rule.dst_port_start, rule.dst_port_end)
                {
                    for di in dst_start..=dst_end {
                        tmpl_rules.push(TmplNetworkSecurityGroupRule {
                            Id: rule.id.clone(),
                            HasSrcPort: false,
                            SrcPort: 0,
                            HasDstPort: true,
                            DstPort: di,
                            CanMatchAnyProtocol: rule.can_match_any_protocol,
                            CanBeStateful: rule.can_be_stateful,
                            Protocol: rule.protocol.clone(),
                            Action: rule.action.clone(),
                            SrcPrefix: src_prefix.clone(),
                            DstPrefix: dst_prefix.clone(),
                            OriginalPriority: rule.priority,
                            Priority: tmpl_rules.len() as u32
                                + NETWORK_SECURITY_GROUP_RULE_PRIORITY_START,
                        });
                    }
                } else {
                    tmpl_rules.push(TmplNetworkSecurityGroupRule {
                        Id: rule.id.clone(),
                        HasSrcPort: false,
                        SrcPort: 0,
                        HasDstPort: false,
                        DstPort: 0,
                        CanMatchAnyProtocol: rule.can_match_any_protocol,
                        CanBeStateful: rule.can_be_stateful,
                        Protocol: rule.protocol.clone(),
                        Action: rule.action.clone(),
                        SrcPrefix: src_prefix.clone(),
                        DstPrefix: dst_prefix.clone(),
                        OriginalPriority: rule.priority,
                        Priority: tmpl_rules.len() as u32
                            + NETWORK_SECURITY_GROUP_RULE_PRIORITY_START,
                    });
                }
            }
        }
    }

    tmpl_rules
}

// Add a hack to completely overwrite the cl-platform check. New hardware has decided to change a
// value in sys_vendor, and this causes the cl-platform script to fail and not detect the vendor
// which causes nvued to fail as well.
pub async fn hack_platform_config_for_nvue() -> eyre::Result<()> {
    let container_id = super::hbn::get_hbn_container_id().await?;

    let stdout = super::hbn::run_in_container(&container_id, &["platform-detect"], true).await?;

    // the bug in new hardware causes the previous command to emit nothing, so if it is not emitting
    // anything, assume the hack needs to be applied.
    if stdout.is_empty() {
        let stdout = super::hbn::run_in_container(
            &container_id,
            &[
                "bash",
                "-c",
                "echo echo -n mlnx,bluefield > /usr/lib/cumulus/cl-platform", // yes, thats two echo on purpose
            ],
            true,
        )
        .await?;
        if !stdout.is_empty() {
            tracing::info!("config hack to replace platform: {stdout}");
        }
    }

    Ok(())
}

// Apply the config at `config_path`.
pub async fn apply(hbn_root: &Path, config_path: &super::FPath) -> eyre::Result<()> {
    match run_apply(hbn_root, &config_path.0).await {
        Ok(_) => {
            config_path.del("BAK");
            Ok(())
        }
        Err(err) => {
            tracing::error!("update_nvue post command failed: {err:#}");

            // If the config apply failed, we won't be using it, so move it out
            // of the way to an .error file for others to enjoy (while attempting
            // to remove any previous .error file in the process).
            let path_error = config_path.with_ext("error");
            if path_error.exists()
                && let Err(e) = fs::remove_file(path_error.clone())
            {
                tracing::warn!(
                    "Failed to remove previous error file ({}): {e}",
                    path_error.display()
                );
            }

            if let Err(err) = fs::rename(config_path, &path_error) {
                eyre::bail!(
                    "rename {config_path} to {} on error: {err:#}",
                    path_error.display()
                );
            }
            // .. and copy the old one back.
            // This also ensures that we retry writing the config on subsequent runs.
            let path_bak = config_path.backup();
            if path_bak.exists()
                && let Err(err) = fs::rename(&path_bak, config_path)
            {
                eyre::bail!(
                    "rename {} to {config_path}, reverting on error: {err:#}",
                    path_bak.display(),
                );
            }

            Err(err)
        }
    }
}

// Ask NVUE to use the config at `path`
async fn run_apply(hbn_root: &Path, path: &Path) -> eyre::Result<()> {
    let mut in_container_path = path
        .strip_prefix(hbn_root)
        .wrap_err("Stripping hbn_root prefix from path to make in-container path")?
        .to_path_buf();
    // If hbn_root ends with "/", the stripped path will have it removed from start. Add back.
    if !in_container_path.has_root() {
        in_container_path = Path::new("/").join(in_container_path);
    }
    let container_id = super::hbn::get_hbn_container_id().await?;

    // Set this config as the pending one. This is where we'd get yaml parse errors and
    // other validation errors. Stores the pending config internally somewhere.
    let stdout = super::hbn::run_in_container(
        &container_id,
        &[
            "nv",
            "config",
            "replace",
            &in_container_path.to_string_lossy(),
        ],
        true,
    )
    .await?;
    if !stdout.is_empty() {
        tracing::info!("nv config replace: {stdout}");
    }

    // Apply the pending config.
    //
    // - Writes:
    //   . /etc/frr/frr.conf
    //   . /etc/network/interfaces
    //   . /etc/frr/daemons
    //   . /etc/supervisor/conf.d/isc-dhcp-relay-default
    //   . and others (acls, nginx, ...)
    // - Restarts necessary services.
    // - Log is in /var/lib/hbn/var/lib/nvue/config/apply_log.txt
    // Once this returns networking should be ready to use.
    let stdout =
        super::hbn::run_in_container(&container_id, &["nv", "config", "apply", "-y"], true).await?;
    if !stdout.is_empty() {
        tracing::info!("nv config apply: {stdout}");
    }

    Ok(())
}

/// vni_to_svimac takes an VNI (which is a 24 bit integer whose range
/// is 0-16777215), pads it with zeroes (so its 12 characters long), and
/// then turns it into a MAC address for the purpose of having a consistent
/// SVI MAC address value for all DPUs in a given VPC.
///
/// e.g, an L2VNI of 1637817 would result in an SviMAC of 00:00:01:63:78:17
/// for all DPUs in the VPC.
fn vni_to_svi_mac(vni: u32) -> eyre::Result<MacAddress> {
    sanitized_mac(&format!("{vni:012}"))
}

#[derive(Clone, Deserialize, Debug)]
pub struct RouteTargetConfig {
    pub asn: u32,
    pub vni: u32,
}

// What we need to configure NVUE
pub struct NvueConfig {
    pub is_fnn: bool,
    pub vpc_virtualization_type: VpcVirtualizationType,
    pub use_admin_network: bool,
    pub loopback_ip: String,
    pub asn: u32,
    pub datacenter_asn: u32,
    pub site_global_vpc_vni: Option<u32>,
    pub common_internal_route_target: Option<RouteTargetConfig>,
    pub additional_route_target_imports: Vec<RouteTargetConfig>,

    pub secondary_overlay_vtep_ip: Option<String>,
    pub vf_intercept_bridge_port_name: Option<String>,
    pub vf_intercept_bridge_sf: Option<String>,
    pub host_intercept_bridge_port_name: Option<String>,
    pub internal_bridge_routing_prefix: Option<String>,
    pub traffic_intercept_public_prefixes: Vec<String>,

    pub dpu_hostname: String,
    pub dpu_search_domain: String,
    pub hbn_version: Option<String>,
    pub uplinks: Vec<String>,
    pub route_servers: Vec<String>,
    pub dhcp_servers: Vec<String>,
    pub l3_domains: Vec<L3Domain>,
    pub deny_prefixes: Vec<String>,
    pub site_fabric_prefixes: Vec<String>,
    pub anycast_site_prefixes: Vec<String>,
    pub tenant_host_asn: Option<u32>,
    pub use_vpc_isolation: bool,
    pub stateful_acls_enabled: bool,

    pub network_security_groups: Vec<NetworkSecurityGroup>,

    pub network_security_policy_override_rules: Vec<NetworkSecurityGroupRule>,

    // Currently we have a single tenant, hence the single ct_ prefix.
    // Later this will be Vec<ComputeTenant>.

    // ct_vrf_name is the VRF name. This value needs to be 15 characters
    // or less, somehow derived from the VPC, and is the same for all
    // DPUs in a VPC. To achieve this, we currently take the L3VNI of the
    // VPC, and assign this as "vrf_<l3vni>". This ensures we keep the
    // character count below 15, and by using the L3VNI, we're able to
    // directly correlate that back to the VPC.
    pub ct_vrf_name: String,
    pub ct_l3_vni: Option<u32>,
    pub ct_vrf_loopback: String,
    pub ct_port_configs: Vec<PortConfig>,
    pub ct_access_vlans: Vec<VlanConfig>,
    pub ct_routing_profile: Option<RoutingProfile>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct RoutingProfile {
    pub route_target_imports: Vec<RouteTargetConfig>,
    pub route_targets_on_exports: Vec<RouteTargetConfig>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct NetworkSecurityGroup {
    pub id: String,
    pub stateful_egress: bool,
    pub rules: Vec<NetworkSecurityGroupRule>,
}

#[derive(Clone, Deserialize, Debug)]
pub struct NetworkSecurityGroupRule {
    pub id: String,
    pub ingress: bool,
    pub ipv6: bool,
    pub priority: u32,
    pub src_port_start: Option<u32>,
    pub src_port_end: Option<u32>,
    pub dst_port_start: Option<u32>,
    pub dst_port_end: Option<u32>,
    pub can_match_any_protocol: bool,
    pub can_be_stateful: bool,
    pub protocol: String,
    pub action: String,
    pub src_prefixes: Vec<String>,
    pub dst_prefixes: Vec<String>,
}

impl TryFrom<&rpc::ResolvedNetworkSecurityGroupRule> for NetworkSecurityGroupRule {
    type Error = eyre::Error;

    fn try_from(
        resolved_rule: &rpc::ResolvedNetworkSecurityGroupRule,
    ) -> Result<Self, Self::Error> {
        let Some(ref rule) = resolved_rule.rule else {
            return Err(eyre::eyre!("BUG: attempting to convert empty NSG rule"));
        };

        Ok(NetworkSecurityGroupRule {
            id: rule.id.clone().unwrap_or_default(),
            ingress: rule.direction()
                == rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress,
            can_match_any_protocol: rule.protocol()
                == rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoAny,
            // We'll only automatically handle stateful tracking for egress rules
            // that specify TCP/UDP, a dst port, and NO src port because it becomes
            // extremely difficult for users to get rule combinations for common
            // use-cases if the stateful option isn't narrowly implemented.
            // ICMP is _technically_ documented as valid for stateful tracking,
            // but it's not throroughly tested/validated, and the user would have
            // no way to achieve non-stateful ICMP if stateful is enabled for the
            // NSG, so it's being left out.
            can_be_stateful: rule.direction()
                == rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionEgress
                && matches!(
                    rule.protocol(),
                    rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp
                        | rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoUdp
                )
                && rule.dst_port_start.is_some()
                && rule.src_port_start.is_none(),
            ipv6: rule.ipv6,
            priority: rule.priority,
            src_port_start: rule.src_port_start,
            src_port_end: rule.src_port_end,
            dst_port_start: rule.dst_port_start,
            dst_port_end: rule.dst_port_end,
            protocol: rpc::NetworkSecurityGroupRuleProtocol::to_string_from_enum_i32(
                rule.protocol,
            )?
            .to_lowercase(),
            action: rpc::NetworkSecurityGroupRuleAction::to_string_from_enum_i32(rule.action)?
                .to_lowercase(),
            src_prefixes: resolved_rule.src_prefixes.clone(),
            dst_prefixes: resolved_rule.dst_prefixes.clone(),
        })
    }
}

pub struct VlanConfig {
    pub vlan_id: u32,
    pub network: String,
    pub ip: String,
}

#[derive(Deserialize, Debug)]
pub struct L3Domain {
    pub l3_domain_name: String,
    pub services: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct PortConfig {
    pub interface_name: String,
    pub vlan: u16,
    pub vni: Option<u32>, // In FNN, admin network has both an l2vni and an l3vni
    pub l3_vni: Option<u32>,
    pub gateway_cidr: String,
    pub vpc_prefixes: Vec<String>,
    pub vpc_peer_prefixes: Vec<String>,
    pub vpc_peer_vnis: Vec<u32>,
    pub svi_ip: Option<String>,
    pub tenant_vrf_loopback_ip: Option<String>,
    pub is_l2_segment: bool,
    pub is_phy: bool,
    pub network_security_group_id: Option<String>,
}

//
// Go template objects, hence allow(non_snake_case)
//

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplNvue {
    UseAdminNetwork: bool, // akak service network
    HasSiteGlobalVpcVni: bool,
    SiteGlobalVpcVni: u32,
    LoopbackIP: String,
    HasSecondaryOverlayVTEP: bool,
    HasStaticAdvertisements: bool,
    SecondaryOverlayVtepIP: String,
    HasInternalBridgeRouting: bool,
    /// This IP is used in a static route in NVUE
    /// to send traffic over to a bridge used by a traffic
    /// intercept user for further processing.
    VfInterceptBridgeIP: String,
    /// This _might_ be the same IP as VfInterceptBridgeIP,
    /// or it might not.  See the details of VfInterceptBridgeIP.
    PublicPrefixInternalNextHop: String,
    /// An IP from the same subnet as VfInterceptBridgeIP
    VfInterceptHbnRepresentorIp: String,
    /// The SF used to route traffic VF traffic to the HBN pod.
    VfInterceptBridgeSf: String,

    /// The size of the of the prefix used for the internal
    /// bridge routing.
    InterceptBridgePrefixLen: u8,

    TrafficInterceptPublicPrefixes: Vec<Prefix>,

    ASN: u32,
    DatacenterASN: u32,
    UseCommonInternalTenantRouteTarget: bool,
    CommonInternalRouteTarget: Option<TmplRouteTargetConfig>,
    AdditionalRouteTargetImports: Vec<TmplRouteTargetConfig>,

    DPUHostname: String,  // The first part of the FQDN
    SearchDomain: String, // The rest of the FQDN
    Uplinks: Vec<String>,
    RouteServers: Vec<String>,

    /// Format: IPv4 address of (per tenant) dhcp server
    DHCPServers: Vec<String>, // Previously 'Servers'

    /// Format: CIDR of the infastructure prefixes to block. Origin is carbide-api config file.
    DenyPrefixes: Vec<Prefix>,

    HasDenyPrefixes: bool,

    /// Format: CIDR of the site prefixes for tenant use.  If VPC isolation is applied,
    /// and there is no network security group applied overriding the behavior,
    /// these will be blocked as well.
    SiteFabricPrefixes: Vec<Prefix>,

    HasSiteFabricPrefixes: bool,

    /// Format: CIDR of the site prefixes that tenants are allowed to
    /// from the host to the DPU.
    AnycastSitePrefixes: Vec<Prefix>,

    // Whether VPC-isolation should be applied.
    UseVpcIsolation: bool,

    HbnVersion: Option<String>,

    /// Whether stateful ACLs are possible and we
    /// should perform any extra config to prepare
    /// for them.
    StatefulAclsEnabled: bool,

    /// Whether there are global policies that should be evaluated
    /// after deny prefixes but before any tenant-defined rules.
    HasIpv4IngressSecurityPolicyOverrideRules: bool,
    HasIpv4EgressSecurityPolicyOverrideRules: bool,
    HasIpv6IngressSecurityPolicyOverrideRules: bool,
    HasIpv6EgressSecurityPolicyOverrideRules: bool,
    Ipv4IngressNetworkSecurityPolicyOverrideRules: Vec<TmplNetworkSecurityGroupRule>,
    Ipv4EgressNetworkSecurityPolicyOverrideRules: Vec<TmplNetworkSecurityGroupRule>,
    Ipv6IngressNetworkSecurityPolicyOverrideRules: Vec<TmplNetworkSecurityGroupRule>,
    Ipv6EgressNetworkSecurityPolicyOverrideRules: Vec<TmplNetworkSecurityGroupRule>,

    /// For when we have more than one tenant
    Tenant: TmplComputeTenant,

    // XXX: These are unused placeholders for later.
    // StorageDpuIP is an interface that should exist on
    // client nodes that are NOT storage targets, so in the
    // case where StorageTarget is false, we would expect
    // there to be a StorageDpuIP.
    IsStorageClient: bool,    // XXX (Classic, L3)
    StorageDpuIP: String,     // XXX (Classic, L3)
    l3vnistorageVLAN: String, // XXX (Classic, L3)
    StorageL3VNI: u32,        // XXX (Classic, L3)
    StorageLoopback: String,  // XXX (Classic, L3)
    DPUstorageprefix: String, // XXX (Classic, L3)
    IncludeBridge: bool,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplRouteTargetConfig {
    ASN: u32,
    VNI: u32,
}

/// Template-ready representation of a network security group rule.
/// Direction (ingress/egress), ipv (4/6), and priority
/// ordering will be grouped and ordered in advance.
/// Priority is still included mostly as a convenience,
/// but we'll also pad the value to a minimum of 100
/// so that there's room for low-priority "system rules"
/// to be inserted if needed.
#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplNetworkSecurityGroupRule {
    Id: String,
    HasSrcPort: bool,
    SrcPort: u32,
    HasDstPort: bool,
    DstPort: u32,
    CanMatchAnyProtocol: bool,
    CanBeStateful: bool,
    Protocol: String,
    Action: String,
    SrcPrefix: String,
    DstPrefix: String,
    Priority: u32,
    OriginalPriority: u32,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplRoutingProfile {
    RouteTargetImports: Vec<TmplRouteTargetConfig>,
    RouteTargetsOnExports: Vec<TmplRouteTargetConfig>,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplComputeTenant {
    Vpcs: Vec<TmplVpc>,
    PortConfigs: Vec<TmplConfigPort>,
    NetworkSecurityGroups: Vec<TmplNetworkSecurityGroup>,

    // TODO:  Everything thing from here down should remain for pre-FNN purposes,
    //        but they now live in the Vecs above to support multiple VPCs per DPU.
    //
    /// Tenant name/id with a max of 15 chars, because it's also used for the interface name.
    /// Linux is limited to 15 chars for interface names.
    VrfName: String,

    /// L3VNI VPC-specifc VNI, which is globally unique. GNI allocates us
    /// a pool of VNIs to assign as we see fit, so we carve out blocks
    /// per-site, and then manage them via the VPC_VNI (vpc-vni) resource
    /// pool.
    ///
    // TODO(chet): Does this need to be a string?
    L3VNI: String,

    /// VrfLoopback is the tenant loopback IP assigned to each DPU.
    /// It was originally expected to be allocated from an interface-specific
    /// /30 (as the first IP in the allocation), but it's actually allocated
    /// from a dedicated resource-pool, handed out as un-related /32s, and
    /// interfaces in FNN get /31s.
    VrfLoopback: String, // XXX: This is in the Classic template -- where does the IP come from?

    HasHostASN: bool,
    /// An ASN allocated for tenants to use
    /// when they peer with the DPU.
    /// If configured, the DPU will expect the host
    /// to peer with this ASN.  If left unset
    /// remote-as external will be used, allowing
    /// any ASN.
    HostASN: u32,

    HostInterfaces: Vec<TmplHostInterfaces>,

    HasVpcPeerPrefixes: bool,
    VpcPeerPrefixes: Vec<Prefix>,

    HasVpcPeerVnis: bool,
    VpcPeerVnis: Vec<TmplVni>,

    RoutingProfile: Option<TmplRoutingProfile>,

    HasNetworkSecurityGroup: bool,
    IngressNetworkSecurityGroupRulesIpv4: Vec<TmplNetworkSecurityGroupRule>,
    IngressNetworkSecurityGroupRulesIpv6: Vec<TmplNetworkSecurityGroupRule>,
    EgressNetworkSecurityGroupRulesIpv4: Vec<TmplNetworkSecurityGroupRule>,
    EgressNetworkSecurityGroupRulesIpv6: Vec<TmplNetworkSecurityGroupRule>,
    HasIpv4IngressSecurityGroupRules: bool,
    HasIpv4EgressSecurityGroupRules: bool,
    HasIpv6IngressSecurityGroupRules: bool,
    HasIpv6EgressSecurityGroupRules: bool,
    // /////////////
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplNetworkSecurityGroup {
    Index: u16,
    StatefulEgress: bool,
    IngressNetworkSecurityGroupRulesIpv4: Vec<TmplNetworkSecurityGroupRule>,
    IngressNetworkSecurityGroupRulesIpv6: Vec<TmplNetworkSecurityGroupRule>,
    EgressNetworkSecurityGroupRulesIpv4: Vec<TmplNetworkSecurityGroupRule>,
    EgressNetworkSecurityGroupRulesIpv6: Vec<TmplNetworkSecurityGroupRule>,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplVpc {
    /// Tenant name/id with a max of 15 chars, because it's also used for the interface name.
    /// Linux is limited to 15 chars for interface names.
    VrfName: String,

    /// VPC-specifc VNI, which must be unique within a given site but
    /// not necessarily globally unique.
    L3VNI: u32,

    // VrfLoopback is the tenant loopback IP assigned to each DPU.
    // It was originally expected to be allocated from an interface-specific
    // /30 (as the first IP in the allocation), but it's actually allocated
    // from a dedicated resource-pool, handed out as un-related /32s, and
    // interfaces in FNN get /31s.
    /// The tenant loopback IP assigned to each DPU.
    VrfLoopback: String,

    HostInterfaces: Vec<TmplHostInterfaces>,

    HasVpcPeerPrefixes: bool,
    VpcPeerPrefixes: Vec<Prefix>,

    // The relationship between interface:VPC is 1:1 but VPC:interface is 1:M.
    // So, a single VPC could have multiple, per-port, VpcPrefixes.  We can
    // accumulate these and pass them into the template for ease-of-use.
    /// The list of prefixes for all ports/interfaces that belong to this VPC.
    PortPrefixes: Vec<Prefix>,

    HasVpcPeerVnis: bool,
    VpcPeerVnis: Vec<TmplVni>,

    RoutingProfile: Option<TmplRoutingProfile>,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Gtmpl)]
struct TmplHostInterfaces {
    ID: u32,
    HostIP: String,

    // HostRoute in the context of FNN-L3 is the /30 prefix allocation.
    // This used to be populated as the HostIP + "/32", but then with
    // the advent of interface prefix allocations (where ETV is just a /32,
    // and FNN-L3 is a /31), HostRoute became the allocation (which was
    // a drop-in replacement for ETV/Classic environments).
    HostRoute: String,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplConfigPort {
    InterfaceName: String,
    Index: String,
    VlanID: u16,

    /// Format: 24bit integer (usable range: 4096 to 16777215).
    /// Empty string if no tenant
    L2VNI: String, // Previously called VNIDevice
    IPs: Vec<String>, // with mask, 1.1.1.1/20

    /// In a symmetrical EVPN configuration, an SVI (vlan interfaces) requires a separate IP that
    /// is not the gateway address. Typically the 2nd usable ip in the prefix is being used,
    /// e.g 10.1.1.2 in the 10.1.1.0/24 prefix.
    /// Format: Standard IPv4 notation
    SviIP: String,

    /// VRR, the distributed gateway, needs a manually defined MAC address. This can be overlapping
    /// on the different VTEPs, but it is very convenient to be unique on the same VTEP.
    ///
    /// In other words, this is the same value for all DPUs in a given VPC.
    ///
    /// TO MAKE THIS THE SAME FOR A GIVEN VPC, we take the L2VNI (which is a 24bit integer),
    /// pad it with zeroes so its 12 characters long, and then shove some colons in there.
    ///
    /// For example, for a VPC with an L2VNI of 1683714, the SviMAC would
    /// be configured as 00:00:01:68:37:14.
    ///
    /// Format: 48bit mac address in standard hex notation, e.g: 00:00:00:00:00:10
    SviMAC: String,

    VrfLoopback: String,

    /// The name of the VRF this interface belongs to.
    VrfName: String,

    HasVpcPrefixes: bool,

    /// Tenant VPCs we should allow them to access
    VpcPrefixes: Vec<Prefix>,

    // XXX: all of these added so the L3 template can build, need
    // to really actually wire them up.
    StorageTarget: bool, // XXX (Classic, L3)

    // does this segment support L2?
    IsL2Segment: bool,

    IsPhy: bool,

    HasVpcPeerPrefixes: bool,

    HasNetworkSecurityGroup: bool,
    NetworkSecurityGroupIndex: Option<u16>,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct Prefix {
    Index: String,
    Prefix: String,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplVni {
    Vni: u32,
}
