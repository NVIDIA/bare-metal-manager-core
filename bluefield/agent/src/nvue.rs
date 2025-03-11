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

use std::fs;
use std::path::Path;

use eyre::WrapErr;
use forge_network::{sanitized_mac, virtualization::VpcVirtualizationType};
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
const NETWORK_SECURITY_GROUP_RULE_COUNT_MAX: usize = 10000;

pub fn build(conf: NvueConfig) -> eyre::Result<String> {
    if !conf.vpc_virtualization_type.supports_nvue() {
        return Err(eyre::eyre!(
            "cannot nvue::build. provided virtualizaton type does not support nvue: {}",
            conf.vpc_virtualization_type,
        ));
    }

    let mut l3_domains = Vec::with_capacity(conf.l3_domains.len());
    for d in conf.l3_domains {
        l3_domains.push(TmplL3Domain {
            L3DomainName: d.l3_domain_name,
            Services: d.services.clone(),
        });
    }
    let infra = vec![TmplInfra {
        L3Domains: l3_domains,
    }];

    let mut port_configs = Vec::with_capacity(conf.ct_port_configs.len());

    for (base_i, network) in conf.ct_port_configs.into_iter().enumerate() {
        let svi_mac = vni_to_svi_mac(network.vni.unwrap_or(0))?.to_string();
        port_configs.push(TmplConfigPort {
            InterfaceName: network.interface_name.clone(),
            Index: format!("{}", (base_i + 1) * 10),
            VlanID: network.vlan,
            L2VNI: network.vni.map(|x| x.to_string()).unwrap_or("".to_string()),
            IP: network.gateway_cidr.clone(),
            SviIP: network.svi_ip.unwrap_or("".to_string()), // FNN only
            SviMAC: svi_mac,
            VrfLoopback: network.tenant_vrf_loopback_ip.unwrap_or_default(),
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
        });
    }

    if port_configs.is_empty() {
        return Err(eyre::eyre!(
            "cannot configure VrfLoopback; no address allocations",
        ));
    }

    let vrf_loopback = port_configs[0].VrfLoopback.clone();
    let include_bridge = port_configs.iter().fold(true, |a, b| a & b.IsL2Segment);

    let (
        has_network_security_group,
        ingress_ipv4_rules,
        egress_ipv4_rules,
        ingress_ipv6_rules,
        egress_ipv6_rules,
    ) = if let Some(rules) = conf.ct_network_security_group_rules {
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

        (
            true,
            expand_network_security_group_rules(ingress_ipv4_rules),
            expand_network_security_group_rules(egress_ipv4_rules),
            expand_network_security_group_rules(ingress_ipv6_rules),
            expand_network_security_group_rules(egress_ipv6_rules),
        )
    } else {
        (false, vec![], vec![], vec![], vec![])
    };

    // The original VPC isolation would add site fabric prefixes to deny prefixes,
    // with site_fabric_prefixes coming first.
    // This is just an easy way to maintain the ordering of the original behavior.
    let deny_prefix_index_offset = conf.site_fabric_prefixes.len();

    let params = TmplNvue {
        UseAdminNetwork: conf.use_admin_network,
        LoopbackIP: conf.loopback_ip,
        ASN: conf.asn,
        DPUHostname: conf.dpu_hostname,
        SearchDomain: conf.dpu_search_domain,
        Uplinks: conf.uplinks.clone(),
        RouteServers: conf.route_servers.clone(),
        UseLocalDHCP: conf.use_local_dhcp,
        DHCPServers: conf.dhcp_servers.clone(),
        SiteFabricPrefixes: conf
            .site_fabric_prefixes
            .iter()
            .enumerate()
            .map(|(i, s)| Prefix {
                Index: format!("{}", 1000 + i),
                Prefix: s.to_string(),
            })
            .collect(),
        DenyPrefixes: conf
            .deny_prefixes
            .iter()
            .enumerate()
            .map(|(i, s)| Prefix {
                Index: format!("{}", 1000 + deny_prefix_index_offset + i),
                Prefix: s.to_string(),
            })
            .collect(),
        UseVpcIsolation: conf.use_vpc_isolation,
        Infrastructure: infra,
        HbnVersion: conf.hbn_version,
        ComputeTENANTs: vec![TmplComputeTenant {
            VrfName: conf.ct_vrf_name,
            L3VNI: conf.ct_l3_vni.unwrap_or_default().to_string(),
            l3vniVLAN: 0, // unused -- TODO(chet): unique per DPU within a VPC
            VrfLoopback: vrf_loopback,
            PortConfigs: port_configs,
            ExternalAccess: conf.ct_external_access,
            HostInterfaces: conf
                .ct_access_vlans
                .into_iter()
                .map(|vl| TmplHostInterfaces {
                    ID: vl.vlan_id,
                    HostIP: vl.ip,
                    HostRoute: vl.network,
                })
                .collect(),
            HasNetworkSecurityGroup: has_network_security_group,
            HasIpv4IngressSecurityGroupRules: !ingress_ipv4_rules.is_empty(),
            HasIpv4EgressSecurityGroupRules: !egress_ipv4_rules.is_empty(),
            HasIpv6IngressSecurityGroupRules: !ingress_ipv6_rules.is_empty(),
            HasIpv6EgressSecurityGroupRules: !egress_ipv6_rules.is_empty(),
            IngressNetworkSecurityGroupRulesIpv4: ingress_ipv4_rules,
            EgressNetworkSecurityGroupRulesIpv4: egress_ipv4_rules,
            IngressNetworkSecurityGroupRulesIpv6: ingress_ipv6_rules,
            EgressNetworkSecurityGroupRulesIpv6: egress_ipv6_rules,
        }],
        InternetL3VNI: conf.ct_internet_l3_vni.unwrap_or_default(),
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
            println!("ERR filling template: {}", e,);
            e.into()
        })
    } else {
        Err(eyre::eyre!(
            "cannot nvue::build. no nvue template configured for virtualization type: {}",
            conf.vpc_virtualization_type
        ))
    }
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
            if path_error.exists() {
                if let Err(e) = fs::remove_file(path_error.clone()) {
                    tracing::warn!(
                        "Failed to remove previous error file ({}): {e}",
                        path_error.display()
                    );
                }
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
            if path_bak.exists() {
                if let Err(err) = fs::rename(&path_bak, config_path) {
                    eyre::bail!(
                        "rename {} to {config_path}, reverting on error: {err:#}",
                        path_bak.display(),
                    );
                }
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
    sanitized_mac(format!("{:012}", vni))
}

// What we need to configure NVUE
pub struct NvueConfig {
    pub is_fnn: bool,
    pub vpc_virtualization_type: VpcVirtualizationType,
    pub use_admin_network: bool,
    pub loopback_ip: String,
    pub asn: u32,
    pub dpu_hostname: String,
    pub dpu_search_domain: String,
    pub hbn_version: Option<String>,
    pub uplinks: Vec<String>,
    pub route_servers: Vec<String>,
    pub dhcp_servers: Vec<String>,
    pub l3_domains: Vec<L3Domain>,
    pub use_local_dhcp: bool,
    pub deny_prefixes: Vec<String>,
    pub site_fabric_prefixes: Vec<String>,
    pub use_vpc_isolation: bool,

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
    pub ct_external_access: Vec<String>,
    pub ct_access_vlans: Vec<VlanConfig>,
    pub ct_internet_l3_vni: Option<u32>,
    pub ct_network_security_group_rules: Option<Vec<NetworkSecurityGroupRule>>,
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
    pub protocol: String,
    pub action: String,
    pub src_prefixes: Vec<String>,
    pub dst_prefixes: Vec<String>,
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
    pub vni: Option<u32>,    // admin network doesn't have one
    pub l3_vni: Option<u32>, // admin network doesn't have one
    pub gateway_cidr: String,
    pub vpc_prefixes: Vec<String>,
    pub svi_ip: Option<String>,
    pub tenant_vrf_loopback_ip: Option<String>,
    pub is_l2_segment: bool,
}

//
// Go template objects, hence allow(non_snake_case)
//

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplNvue {
    UseAdminNetwork: bool, // akak service network
    LoopbackIP: String,
    ASN: u32,
    DPUHostname: String,  // The first part of the FQDN
    SearchDomain: String, // The rest of the FQDN
    Uplinks: Vec<String>,
    RouteServers: Vec<String>,

    // true to use dhcp-server in HBN container (new)
    // false to use dhcp-relay (old)
    UseLocalDHCP: bool,

    /// Format: IPv4 address of (per tenant) dhcp server
    DHCPServers: Vec<String>, // Previously 'Servers'

    /// Format: CIDR of the infastructure prefixes to block. Origin is carbide-api config file.
    DenyPrefixes: Vec<Prefix>,

    /// Format: CIDR of the site prefixes for tenant use.  If VPC isolation is applied,
    /// and there is no network security group applied overriding the behavior,
    /// these will be blocked as well.
    SiteFabricPrefixes: Vec<Prefix>,

    // Whether VPC-isolation should be applied.
    UseVpcIsolation: bool,

    HbnVersion: Option<String>,

    // A structure to hold infra wide information to be used in the configuration. It would need
    // to hold multiple levels.
    Infrastructure: Vec<TmplInfra>,

    /// For when we have more than one tenant
    ComputeTENANTs: Vec<TmplComputeTenant>,

    // InternetL3VNI is the side-wide GNI-supplied VNI to use so VPCs
    // can access the Internet. This is sent down via the internet_l3_vni
    // field from the ManagedHostNetworkConfigResponse as an optional
    // value, and defaults to 0 if unset.
    InternetL3VNI: u32,

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
    Protocol: String,
    Action: String,
    SrcPrefix: String,
    DstPrefix: String,
    Priority: u32,
    OriginalPriority: u32,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplComputeTenant {
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

    /// XXX: unused placeholder for later. In the template, this
    /// will go right within an `evpn` block next to the `vni`
    /// config as `vlan: {{ .l3vniVLAN }}`.
    l3vniVLAN: u32,

    /// VrfLoopback is the tenant loopback IP assigned to each DPU,
    /// which is allocated from the interface-specific /30 (it's the
    /// first IP in the allocation).
    VrfLoopback: String, // XXX: This is in the Classic template -- where does the IP come from?

    PortConfigs: Vec<TmplConfigPort>,

    /// Per tenant access to external networks needs to be defined. Based on this route leaking
    /// will occur to the specific tenant VRFs.
    /// Format: Slice with strings equal to {{ .L3domain }}
    ExternalAccess: Vec<String>,

    HostInterfaces: Vec<TmplHostInterfaces>,

    HasNetworkSecurityGroup: bool,
    IngressNetworkSecurityGroupRulesIpv4: Vec<TmplNetworkSecurityGroupRule>,
    IngressNetworkSecurityGroupRulesIpv6: Vec<TmplNetworkSecurityGroupRule>,
    EgressNetworkSecurityGroupRulesIpv4: Vec<TmplNetworkSecurityGroupRule>,
    EgressNetworkSecurityGroupRulesIpv6: Vec<TmplNetworkSecurityGroupRule>,
    HasIpv4IngressSecurityGroupRules: bool,
    HasIpv4EgressSecurityGroupRules: bool,
    HasIpv6IngressSecurityGroupRules: bool,
    HasIpv6EgressSecurityGroupRules: bool,
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Gtmpl)]
struct TmplHostInterfaces {
    ID: u32,
    HostIP: String,

    // HostRoute in the context of FNN-L3 is the /30 prefix allocation.
    // This used to be populated as the HostIP + "/32", but then with
    // the advent of interface prefix allocations (where ETV is just a /32,
    // and FNN-L3 is a /30), HostRoute became the allocation (which was
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
    IP: String, // with mask, 1.1.1.1/20

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

    /// Tenant VPCs we should allow them to access
    VpcPrefixes: Vec<Prefix>,

    // XXX: all of these added so the L3 template can build, need
    // to really actually wire them up.
    StorageTarget: bool, // XXX (Classic, L3)

    // does this segment support L2?
    IsL2Segment: bool,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplInfra {
    /// Information to configure L3VNIs and the details of it
    L3Domains: Vec<TmplL3Domain>,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct TmplL3Domain {
    L3DomainName: String,
    Services: Vec<String>,
}

#[allow(non_snake_case)]
#[derive(Clone, Gtmpl, Debug)]
struct Prefix {
    Index: String,
    Prefix: String,
}
