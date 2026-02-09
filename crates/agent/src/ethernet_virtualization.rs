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

use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use std::{fmt, fs, io};

use ::rpc::InterfaceFunctionType;
use ::rpc::forge::{
    self as rpc, FlatInterfaceConfig, ManagedHostNetworkConfigResponse,
    NetworkSecurityGroupRuleAction, NetworkSecurityGroupRuleProtocol,
};
use eyre::WrapErr;
use forge_network::ip::prefix::Ipv4Net;
use forge_network::virtualization::VpcVirtualizationType;
use mac_address::MacAddress;
use serde::Deserialize;
use tokio::process::Command as TokioCommand;
use tokio::time::timeout;

use crate::nvue::NetworkSecurityGroupRule;
use crate::{
    HBNDeviceNames, acl_rules, daemons, dhcp, frr, hbn, interfaces, nvue,
    traffic_intercept_bridging,
};

/// None of the files we deal with should be bigger than this
const MAX_EXPECTED_SIZE: u64 = 1048576; // 1 MiB

/// ACL to prevent access to nvued's API
const NVUED_BLOCK_RULE: &str = r"
[iptables]
# Block access to nvued API
-A INPUT -p tcp --dport 8765 -j DROP
";

struct EthernetVirtualizerPaths {
    interfaces: FPath,
    frr: FPath,
    daemons: FPath,
    acl_rules: FPath,
}

#[derive(PartialEq, Debug, Clone)]
pub enum InterfaceState {
    Up,
    Down,
}

impl FromStr for InterfaceState {
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains("DOWN") {
            return Ok(InterfaceState::Down);
        }
        Ok(InterfaceState::Up)
    }

    type Err = eyre::Report;
}

impl InterfaceState {
    pub fn command(&self, hbn_device_names: &HBNDeviceNames) -> String {
        if InterfaceState::Up == *self {
            format!("ifup {}", hbn_device_names.reps[0])
        } else {
            format!("ifdown {}", hbn_device_names.reps[0])
        }
    }

    pub async fn update_state(
        needed_state: &Self,
        hbn_device_names: &HBNDeviceNames,
        current_state: &Option<InterfaceState>,
    ) -> eyre::Result<Option<InterfaceState>> {
        let current_state = if let Some(current_state) = current_state {
            current_state
        } else {
            // Let's try to find out.
            &get_interface_state(hbn_device_names).await?
        };

        if current_state != needed_state {
            // Execute command only if interface state is changed.
            let cmd = needed_state.command(hbn_device_names);
            tracing::info!(
                "Updating interface state from {:?} to {:?} with command: {}",
                current_state,
                needed_state,
                cmd
            );
            hbn::run_in_container_shell(&cmd).await?;

            // Let's check if interface state is updated or not.
            let new_state = get_interface_state(hbn_device_names).await?;
            if &new_state != needed_state {
                return Err(eyre::eyre!(
                    r#"State is not updated after command execution. Will try in next iteration. 
                Needed {needed_state:?}, After updating {new_state:?}, Interface: {}"#,
                    hbn_device_names.reps[0]
                ));
            }
        }

        // Return new state.
        Ok(Some(needed_state.clone()))
    }
}

impl EthernetVirtualizerPaths {
    /// Delete old .TEST, .BAK and .TMP files
    fn cleanup(&self) -> bool {
        let mut did_delete = false;
        for p in [&self.interfaces, &self.frr, &self.daemons, &self.acl_rules] {
            did_delete = did_delete || p.cleanup();
        }
        did_delete
    }
}

struct DhcpServerPaths {
    server: FPath,
    config: FPath,
    host_config: FPath,
}

/// Stores addresses of dependent services that the DHCP module announces
pub struct ServiceAddresses {
    pub pxe_ip: Ipv4Addr,
    pub ntpservers: Vec<Ipv4Addr>,
    pub nameservers: Vec<IpAddr>,
}

/// How we tell HBN to notice the new file we wrote
#[derive(Debug)]
struct PostAction {
    cmd: &'static str,
    path: FPath,
}

fn paths(hbn_root: &Path) -> EthernetVirtualizerPaths {
    let ps = EthernetVirtualizerPaths {
        interfaces: FPath(hbn_root.join(interfaces::PATH)),
        frr: FPath(hbn_root.join(frr::PATH)),
        daemons: FPath(hbn_root.join(daemons::PATH)),
        acl_rules: FPath(hbn_root.join(acl_rules::PATH)),
    };
    ps.cleanup();
    ps
}

// Update network config using nvue (`nv`). Return Ok(true) if the config change, Ok(false) if not.
pub async fn update_nvue(
    vpc_virtualization_type: VpcVirtualizationType,
    hbn_root: &Path,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    // if true don't run the `nv` commands after writing the file
    skip_post: bool,
    hbn_device_names: HBNDeviceNames,
) -> eyre::Result<bool> {
    let hbn_version = hbn::read_version().await?;

    let l_ip_str = match &nc.managed_host_config {
        None => {
            return Err(eyre::eyre!("Missing managed_host_config in response"));
        }
        Some(cfg) => {
            if cfg.loopback_ip.is_empty() {
                return Err(eyre::eyre!("Missing loopback IP"));
            }
            &cfg.loopback_ip
        }
    };
    let loopback_ip = l_ip_str.parse().wrap_err_with(|| l_ip_str.clone())?;

    let access_vlans = if nc.use_admin_network {
        let admin_interface = nc
            .admin_interface
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Missing admin_interface"))?;
        vec![nvue::VlanConfig {
            vlan_id: admin_interface.vlan_id,
            network: admin_interface.interface_prefix.clone(),
            ip: admin_interface.ip.clone(),
        }]
    } else {
        let mut access_vlans = Vec::with_capacity(nc.tenant_interfaces.len());
        for net in &nc.tenant_interfaces {
            access_vlans.push(nvue::VlanConfig {
                vlan_id: net.vlan_id,
                network: net.interface_prefix.clone(),
                ip: net.ip.clone(),
            });
        }
        access_vlans
    };

    let (has_stateful_nsg, network_security_groups) =
        build_network_security_group_rules(&nc.tenant_interfaces)?;

    let physical_name = hbn_device_names.reps[0].to_string();
    let networks = if nc.use_admin_network {
        let admin_interface = nc
            .admin_interface
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Missing admin_interface"))?;
        vec![nvue::PortConfig {
            interface_name: physical_name,
            is_phy: true,
            vlan: admin_interface.vlan_id as u16,
            vni: if nc.network_virtualization_type() == ::rpc::forge::VpcVirtualizationType::Fnn {
                Some(admin_interface.vni)
            } else {
                None
            },
            l3_vni: if nc.network_virtualization_type() == ::rpc::forge::VpcVirtualizationType::Fnn
            {
                Some(admin_interface.vpc_vni)
            } else {
                None
            },
            gateway_cidr: admin_interface.gateway.clone(),
            vpc_prefixes: admin_interface.vpc_prefixes.clone(),
            vpc_peer_prefixes: admin_interface.vpc_peer_prefixes.clone(),
            vpc_peer_vnis: admin_interface.vpc_peer_vnis.clone(),
            svi_ip: admin_interface.svi_ip.clone(),
            tenant_vrf_loopback_ip: admin_interface.tenant_vrf_loopback_ip.clone(),
            network_security_group_id: None, // NSGs are not applied on the admin network.
            is_l2_segment: if nc.network_virtualization_type()
                == ::rpc::forge::VpcVirtualizationType::Fnn
            {
                admin_interface.is_l2_segment
            } else {
                // Why false in legacy case? ¯\_(ツ)_/¯
                false
            },
        }]
    } else {
        let mut ifs = Vec::with_capacity(nc.tenant_interfaces.len());
        for net in &nc.tenant_interfaces {
            let name = if net.function_type == rpc::InterfaceFunctionType::Physical as i32 {
                physical_name.clone()
            } else {
                match net.virtual_function_id {
                    Some(id) => hbn_device_names.build_virt(id),
                    None => {
                        eyre::bail!("Missing virtual function id");
                    }
                }
            };

            ifs.push(nvue::PortConfig {
                interface_name: name,
                is_phy: net.function_type == rpc::InterfaceFunctionType::Physical as i32,
                vlan: net.vlan_id as u16,
                vni: Some(net.vni), // TODO should this be nc.vni_device?
                l3_vni: Some(net.vpc_vni),
                gateway_cidr: net.gateway.clone(),
                vpc_prefixes: net.vpc_prefixes.clone(),
                vpc_peer_prefixes: net.vpc_peer_prefixes.clone(),
                vpc_peer_vnis: net.vpc_peer_vnis.clone(),
                svi_ip: net.svi_ip.clone(),
                tenant_vrf_loopback_ip: net.tenant_vrf_loopback_ip.clone(),
                network_security_group_id: net
                    .network_security_group
                    .as_ref()
                    .map(|n| n.id.clone()),
                is_l2_segment: net.is_l2_segment,
            });
        }
        ifs
    };

    // Currently there's only one quarantine mode, BlockAllTraffic, so we block everything if it's set at all.
    let is_quarantined = nc
        .managed_host_config
        .as_ref()
        .is_some_and(|c| c.quarantine_state.is_some());

    let network_security_policy_override_rules = if is_quarantined {
        tracing::info!("managed host is quarantined! Disabling network access via nvue");

        build_quarantined_network_security_group_rules()
    } else {
        nc.network_security_policy_overrides
            .iter()
            .map(|r| r.try_into())
            .collect::<Result<Vec<NetworkSecurityGroupRule>, eyre::Error>>()?
    };

    let hostname = hostname().wrap_err("gethostname error")?;
    let conf = nvue::NvueConfig {
        is_fnn: false,
        vpc_virtualization_type,
        site_global_vpc_vni: nc.site_global_vpc_vni,
        use_admin_network: nc.use_admin_network,
        loopback_ip,
        vf_intercept_bridge_port_name: nc.traffic_intercept_config.as_ref().and_then(|vc| {
            vc.bridging
                .as_ref()
                .map(|b| b.vf_intercept_bridge_port.clone())
        }),
        vf_intercept_bridge_sf: nc.traffic_intercept_config.as_ref().and_then(|vc| {
            vc.bridging
                .as_ref()
                .map(|b| b.vf_intercept_bridge_sf.clone())
        }),
        host_intercept_bridge_port_name: nc.traffic_intercept_config.as_ref().and_then(|vc| {
            vc.bridging
                .as_ref()
                .map(|b| b.host_intercept_bridge_port.clone())
        }),
        secondary_overlay_vtep_ip: nc
            .traffic_intercept_config
            .as_ref()
            .and_then(|vc| vc.additional_overlay_vtep_ip.clone()),
        internal_bridge_routing_prefix: nc.traffic_intercept_config.as_ref().and_then(|vc| {
            vc.bridging
                .as_ref()
                .map(|b| b.internal_bridge_routing_prefix.clone())
        }),
        traffic_intercept_public_prefixes: nc
            .traffic_intercept_config
            .as_ref()
            .map(|vc| vc.public_prefixes.clone())
            .unwrap_or_default(),
        asn: nc.asn,
        datacenter_asn: nc.datacenter_asn,
        common_internal_route_target: nc.common_internal_route_target.map(|rt| {
            nvue::RouteTargetConfig {
                asn: rt.asn,
                vni: rt.vni,
            }
        }),
        additional_route_target_imports: nc
            .additional_route_target_imports
            .iter()
            .map(|rt| nvue::RouteTargetConfig {
                asn: rt.asn,
                vni: rt.vni,
            })
            .collect(),
        dpu_hostname: hostname.hostname,
        dpu_search_domain: hostname.search_domain,
        hbn_version: Some(hbn_version),
        uplinks: hbn_device_names
            .uplinks
            .into_iter()
            .map(String::from)
            .collect(),
        dhcp_servers: nc.dhcp_servers.clone(),
        route_servers: nc.route_servers.clone(),
        ct_port_configs: networks,
        ct_vrf_name: format!("vpc_{}", nc.vpc_vni.unwrap_or_default()),
        ct_access_vlans: access_vlans,
        deny_prefixes: nc.deny_prefixes.clone(),
        site_fabric_prefixes: nc.site_fabric_prefixes.clone(),
        anycast_site_prefixes: nc.anycast_site_prefixes.clone(),
        tenant_host_asn: nc.tenant_host_asn,
        stateful_acls_enabled: nc.stateful_acls_enabled && has_stateful_nsg,

        // For now, the isolation options boil down to a boolean,
        // but the match will make sure we catch and adjust accordingly
        // if that changes in the future.
        use_vpc_isolation: match nc.vpc_isolation_behavior() {
            rpc::VpcIsolationBehaviorType::VpcIsolationInvalid => {
                return Err(eyre::eyre!("received invalid VPC-isolation config"));
            }
            rpc::VpcIsolationBehaviorType::VpcIsolationMutual => true,
            //  There's no isolation.
            rpc::VpcIsolationBehaviorType::VpcIsolationOpen => false,
        },

        network_security_policy_override_rules,
        network_security_groups,
        ct_l3_vni: nc.vpc_vni,
        ct_vrf_loopback: "FNN".to_string(),
        l3_domains: vec![],
        ct_routing_profile: if nc.network_virtualization_type()
            == ::rpc::forge::VpcVirtualizationType::Fnn
            && nc.routing_profile.is_none()
        {
            return Err(eyre::eyre!(
                "BUG: FNN config provided without routing-profile"
            ));
        } else {
            nc.routing_profile.as_ref().map(|rp| nvue::RoutingProfile {
                route_target_imports: rp
                    .route_target_imports
                    .iter()
                    .map(|rt| nvue::RouteTargetConfig {
                        asn: rt.asn,
                        vni: rt.vni,
                    })
                    .collect(),
                route_targets_on_exports: rp
                    .route_targets_on_exports
                    .iter()
                    .map(|rt| nvue::RouteTargetConfig {
                        asn: rt.asn,
                        vni: rt.vni,
                    })
                    .collect(),
            })
        },
    };

    // Cleanup any left over non-NVUE temp files
    let _ = paths(hbn_root);

    // Cleanup non-NVUE ACL files
    // We can remove this once az01 is upgraded
    cleanup_old_acls(hbn_root);

    // Write the extra ACL config
    let path_acl = FPath(hbn_root.join(nvue::PATH_ACL));
    path_acl.cleanup();
    let mut rules = NVUED_BLOCK_RULE.to_string();
    rules.push_str(acl_rules::ARP_SUPPRESSION_RULE);
    match write(rules, &path_acl, "NVUE ACL", false) {
        Ok(true) => {
            if !skip_post {
                let cmd = acl_rules::RELOAD_CMD;
                if let Err(err) = hbn::run_in_container_shell(cmd).await {
                    tracing::error!("running nvue extra acl post '{}': {err:#}", cmd);
                }
                path_acl.del("BAK");
            }
        }
        // ACLs didn't need changing, should be always this except on first boot
        Ok(false) => {}
        // Log the error but continue so that we get network working
        Err(err) => tracing::error!("write nvue extra ACL: {err:#}"),
    }

    // nvue can save a copy of the config here. If that exists nvue uses it on boot.
    // We always want to use the most recent `nv config apply`, so ensure this doesn't exist.
    let saved_config = hbn_root.join(nvue::SAVE_PATH);
    if saved_config.exists()
        && let Err(err) = fs::remove_file(&saved_config)
    {
        tracing::warn!(
            "Failed removing old startup.yaml at {}: {err:#}",
            saved_config.display()
        );
    }

    // Write the config we're going to apply
    let next_contents = nvue::build(conf)?;
    let path = FPath(hbn_root.join(nvue::PATH));
    path.cleanup();
    // If switching to the admin network, we want to just force the write.
    // We've seen a past incident where a tenant managed to create a config
    // that exceeded MAX_EXPECTED_SIZE.  Because of the diff check failing, it
    // also prevented a successful termination because the NVUE config couldn't
    // be switched to the admin network.
    if !write(
        next_contents,
        &path,
        "NVUE",
        nc.use_admin_network && path.0.exists() && path.0.metadata()?.len() > MAX_EXPECTED_SIZE,
    )
    .wrap_err(format!("NVUE config at {path}"))?
    {
        // config didn't change OR we are switching to the admin network.
        return Ok(false);
    };

    if !skip_post {
        // Make it so
        nvue::apply(hbn_root, &path).await?;
    }
    Ok(true)
}

// Update internal bridge configuration for traffic-intercept routing and bridging.
pub async fn update_traffic_intercept_bridging(
    nc: &rpc::ManagedHostNetworkConfigResponse,
    skip_post: bool,
) -> eyre::Result<bool> {
    let (bridge_config, secondary_overlay_vtep_ip) = match nc
        .traffic_intercept_config
        .as_ref()
        .map(|vc| (vc.bridging.as_ref(), vc.additional_overlay_vtep_ip.as_ref()))
    {
        Some((b, s)) => (
            match b {
                Some(b) => b,
                _ => eyre::bail!("traffic_intercept bridging config not provided"),
            },
            match s {
                Some(s) => s.to_owned(),
                _ => eyre::bail!(
                    "secondary_overlay_vtep_ip required by traffic_intercept bridging not found"
                ),
            },
        ),
        _ => {
            eyre::bail!("traffic_intercept config not provided")
        }
    };

    let bridge_prefix = bridge_config
        .internal_bridge_routing_prefix
        .parse::<Ipv4Net>()?;

    let mut bridge_prefix_hosts = bridge_prefix.hosts();

    // First host address in bridge_prefix_hosts is for VF-intercept bridge, often called 'br-dpu' in various diagrams.
    let Some(vf_intercept_bridge_ip) = bridge_prefix_hosts.next() else {
        eyre::bail!(
            "too few hosts in internal bridge routing prefix config to support VF intercept bridge"
        )
    };

    let conf = traffic_intercept_bridging::TrafficInterceptBridgingConfig {
        secondary_overlay_vtep_ip,
        vf_intercept_bridge_ip: vf_intercept_bridge_ip.to_string(),
        intercept_bridge_prefix_len: bridge_prefix.prefix_len(),
        // We use the bridge name here because the OVS will create a link/dev on the
        // DPU OS side of that name.
        vf_intercept_bridge_name: bridge_config.vf_intercept_bridge_name.clone(),
    };

    // Write the config we're going to apply
    let next_contents = traffic_intercept_bridging::build(conf)?;
    let path = FPath(PathBuf::from(traffic_intercept_bridging::SAVE_PATH));
    path.cleanup();

    if nc.use_admin_network
        || !write(next_contents, &path, "TRAFFIC_INTERCEPT_BRIDGING", false)
            .wrap_err(format!("NVUE config at {path}"))?
    {
        // config didn't change OR we are switching to the admin network.
        return Ok(false);
    };

    if !skip_post {
        // Make it so
        traffic_intercept_bridging::apply(&path).await?;
    }

    Ok(true)
}

fn build_network_security_group_rules(
    interfaces: &[FlatInterfaceConfig],
) -> eyre::Result<(bool, Vec<nvue::NetworkSecurityGroup>)> {
    let mut network_security_groups = HashMap::<String, nvue::NetworkSecurityGroup>::new();
    let mut has_stateful = false;
    for iface in interfaces {
        if let Some(ref nsg) = iface.network_security_group {
            let rules = nsg
                .rules
                .iter()
                .map(NetworkSecurityGroupRule::try_from)
                .collect::<Result<Vec<NetworkSecurityGroupRule>, _>>()?;

            has_stateful |= nsg.stateful_egress;

            network_security_groups
                .entry(nsg.id.clone())
                .or_insert_with(|| nvue::NetworkSecurityGroup {
                    id: nsg.id.clone(),
                    rules,
                    stateful_egress: nsg.stateful_egress,
                });
        }
    }
    Ok((
        has_stateful,
        network_security_groups.into_values().collect(),
    ))
}

/// Build a set of security group rules that deny all traffic.
///
/// Builds rules for ipv6 and ipv4, both ingress and ingress, denying traffic to all address
/// prefixes.
fn build_quarantined_network_security_group_rules() -> Vec<NetworkSecurityGroupRule> {
    let build_rule = |ingress, ipv6| {
        let catchall_prefix = if ipv6 {
            vec!["::/0".to_string()]
        } else {
            vec!["0.0.0.0/0".to_string()]
        };

        nvue::NetworkSecurityGroupRule {
            id: format!(
                "quarantine_{}_{}",
                if ipv6 { "ipv6" } else { "ipv4" },
                if ingress { "ingress" } else { "egress" }
            ),
            ingress,
            ipv6,
            priority: 0,
            src_port_start: None,
            src_port_end: None,
            dst_port_start: None,
            dst_port_end: None,
            can_match_any_protocol: true,
            can_be_stateful: false,
            protocol: NetworkSecurityGroupRuleProtocol::to_string_from_enum_i32(
                NetworkSecurityGroupRuleProtocol::NsgRuleProtoAny.into(),
            )
            .expect("BUG: cannot convert `any` protocol to string?")
            .to_lowercase(),
            action: NetworkSecurityGroupRuleAction::to_string_from_enum_i32(
                NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
            )
            .expect("BUG: cannot convert deny action to string?")
            .to_lowercase(),
            src_prefixes: catchall_prefix.clone(),
            dst_prefixes: catchall_prefix,
        }
    };

    vec![
        build_rule(false, false),
        build_rule(false, true),
        build_rule(true, false),
        build_rule(true, true),
    ]
}

/// Write out all the network config files.
/// Returns true if any of them changed.
pub async fn update_files(
    hbn_root: &Path,
    network_config: &rpc::ManagedHostNetworkConfigResponse,
    // if true don't run the reload/restart commands after file update
    skip_post: bool,
    hbn_device_names: HBNDeviceNames,
) -> eyre::Result<bool> {
    // Cleanup old NVUE files
    FPath(hbn_root.join(nvue::PATH_ACL)).cleanup();
    FPath(hbn_root.join(nvue::PATH)).cleanup();
    // In case we switch from NVUE back to ETV, delete NVUE ACLs
    cleanup_new_acls(hbn_root);

    let paths = paths(hbn_root);

    let mut errs = vec![];
    let mut post_actions = vec![];
    match write_interfaces(&paths.interfaces, network_config, hbn_device_names.clone()) {
        Ok(true) => {
            post_actions.push(PostAction {
                path: paths.interfaces.clone(),
                cmd: interfaces::RELOAD_CMD,
            });
        }
        Ok(false) => {}
        Err(err) => errs.push(format!("write_interfaces: {err:#}")),
    }
    match write_frr(&paths.frr, network_config, hbn_device_names.clone()) {
        Ok(true) => {
            post_actions.push(PostAction {
                path: paths.frr.clone(),
                cmd: frr::RELOAD_CMD,
            });
        }
        Ok(false) => {}
        Err(err) => errs.push(format!("write_frr: {err:#}")),
    }
    match write_daemons(&paths.daemons) {
        Ok(true) => {
            post_actions.push(PostAction {
                path: paths.daemons,
                cmd: daemons::RESTART_CMD,
            });
        }
        Ok(false) => {}
        Err(err) => errs.push(format!("write_daemons: {err:#}")),
    }
    match write_acl_rules(&paths.acl_rules, network_config, hbn_device_names.clone()) {
        Ok(true) => {
            post_actions.push(PostAction {
                path: paths.acl_rules,
                cmd: acl_rules::RELOAD_CMD,
            });
        }
        Ok(false) => {}
        Err(err) => errs.push(format!("write_acl_rules: {err:#}")),
    }

    do_post(skip_post, post_actions, errs).await
}

async fn do_post(
    skip_post: bool,
    post_actions: Vec<PostAction>,
    mut errs: Vec<String>,
) -> eyre::Result<bool> {
    let has_changes = !post_actions.is_empty();
    if !skip_post {
        for post in post_actions {
            match hbn::run_in_container_shell(post.cmd).await {
                Ok(_) => {
                    let path_bak = post.path.backup();
                    if path_bak.exists()
                        && let Err(err) = fs::remove_file(&path_bak)
                    {
                        errs.push(format!(
                            "remove .BAK on success {}: {err:#}",
                            path_bak.display()
                        ));
                    }
                }
                Err(err) => {
                    errs.push(format!("running reload cmd '{}': {err:#}", post.cmd));

                    // If reload failed we won't be using the new config. Move it out of the way..
                    let path_tmp = post.path.temp();
                    if let Err(err) = fs::rename(&post.path, &path_tmp) {
                        errs.push(format!(
                            "rename {} to {} on error: {err:#}",
                            post.path,
                            path_tmp.display()
                        ));
                    }
                    // .. and copy the old one back.
                    // This also ensures that we retry writing the config on subsequent runs.
                    let path_bak = post.path.backup();
                    if path_bak.exists()
                        && let Err(err) = fs::rename(&path_bak, &post.path)
                    {
                        errs.push(format!(
                            "rename {} to {}, reverting on error: {err:#}",
                            path_bak.display(),
                            post.path
                        ));
                    }
                }
            }
        }
    }

    let err_message = errs.join(", ");
    if !err_message.is_empty() {
        eyre::bail!(err_message);
    }
    Ok(has_changes)
}

async fn get_interface_state(hbn_device_names: &HBNDeviceNames) -> eyre::Result<InterfaceState> {
    let cmd = format!("ip link show {}", hbn_device_names.reps[0]);
    let output = hbn::run_in_container(
        &hbn::get_hbn_container_id().await?,
        &["bash", "-c", &cmd],
        true,
    )
    .await?;

    InterfaceState::from_str(&output)
}

fn needed_interface_state(is_primary_dpu: bool, use_admin_network: bool) -> InterfaceState {
    // Interface is always UP on primary DPU.
    if is_primary_dpu {
        return InterfaceState::Up;
    }

    // If secondary DPU and on tenant network, enable the interface.
    if !use_admin_network {
        return InterfaceState::Up;
    }

    // If secondary DPU and on admin network, disable the interface.
    InterfaceState::Down
}

pub async fn update_interface_state(
    nc: &ManagedHostNetworkConfigResponse,
    skip_reload: bool,
    hbn_device_names: &HBNDeviceNames,
    current_state: &Option<InterfaceState>,
) -> eyre::Result<Option<InterfaceState>> {
    if skip_reload {
        return Ok(current_state.clone());
    }

    let needed_state = needed_interface_state(nc.is_primary_dpu, nc.use_admin_network);

    InterfaceState::update_state(&needed_state, hbn_device_names, current_state).await
}

pub async fn update_dhcp(
    hbn_root: &Path,
    network_config: &rpc::ManagedHostNetworkConfigResponse,
    // if true don't run the reload/restart commands after file update
    skip_post: bool,
    service_addrs: &ServiceAddresses,
    hbn_device_names: HBNDeviceNames,
) -> eyre::Result<bool> {
    let path_dhcp_relay = FPath(hbn_root.join(dhcp::RELAY_PATH));
    let path_dhcp_relay_nvue = FPath(hbn_root.join(dhcp::RELAY_PATH_NVUE));
    let paths_dhcp_server = DhcpServerPaths {
        server: FPath(hbn_root.join(dhcp::SERVER_PATH)),
        config: FPath(hbn_root.join(dhcp::SERVER_CONFIG_PATH)),
        host_config: FPath(hbn_root.join(dhcp::SERVER_HOST_CONFIG_PATH)),
    };
    let mut has_cleaned_dhcp_relay_config = path_dhcp_relay.cleanup();
    has_cleaned_dhcp_relay_config = has_cleaned_dhcp_relay_config || path_dhcp_relay_nvue.cleanup();

    // Delete NVUE relay config in case we used that previously
    let _ = fs::remove_file(path_dhcp_relay_nvue);

    // Start DHCP Server in HBN.
    let post_action = match write_dhcp_server_config(
        &path_dhcp_relay,
        &paths_dhcp_server,
        network_config,
        service_addrs,
        &hbn_device_names,
    ) {
        Ok(true) => PostAction {
            path: paths_dhcp_server.server,
            cmd: dhcp::RELOAD_DHCP_SERVER,
        },
        Ok(false) => {
            // If we deleted an old relay config we need to reload to stop the relay running
            if has_cleaned_dhcp_relay_config {
                PostAction {
                    path: paths_dhcp_server.server,
                    cmd: dhcp::RELOAD_DHCP_SERVER,
                }
            } else {
                return Ok(false);
            }
        }
        Err(err) => eyre::bail!("write dhcp server config file: {err:#}"),
    };

    do_post(skip_post, vec![post_action], vec![]).await
}

/// Interfaces to report back to server
pub async fn interfaces(
    network_config: &rpc::ManagedHostNetworkConfigResponse,
    factory_mac_address: MacAddress,
) -> eyre::Result<Vec<rpc::InstanceInterfaceStatusObservation>> {
    let mut interfaces = vec![];
    if network_config.use_admin_network {
        let Some(iface) = network_config.admin_interface.as_ref() else {
            eyre::bail!("use_admin_network is true but admin interface is missing");
        };
        interfaces.push(rpc::InstanceInterfaceStatusObservation {
            function_type: iface.function_type,
            virtual_function_id: None,
            mac_address: Some(factory_mac_address.to_string()),
            addresses: vec![iface.ip.clone()],
            prefixes: vec![iface.interface_prefix.clone()],
            gateways: vec![iface.gateway.clone()],
            network_security_group: None,
            internal_uuid: iface.internal_uuid.clone(),
        });
    } else {
        // Only load virtual interface details if there are any
        let fdb = if network_config
            .tenant_interfaces
            .iter()
            .any(|iface| iface.function_type == rpc::InterfaceFunctionType::Virtual as i32)
        {
            let fdb_json = hbn::run_in_container(
                &hbn::get_hbn_container_id().await?,
                &["bridge", "-j", "fdb", "show"],
                true,
            )
            .await?;
            parse_fdb(&fdb_json)?
        } else {
            HashMap::new()
        };

        for iface in network_config.tenant_interfaces.iter() {
            let mac = if iface.function_type == rpc::InterfaceFunctionType::Physical as i32 {
                Some(factory_mac_address.to_string())
            } else {
                match fdb.get(&iface.vlan_id) {
                    Some(vlan_fdb) => match tenant_vf_mac(vlan_fdb).await {
                        Ok(mac) => Some(mac.to_string()),
                        Err(err) => {
                            tracing::error!(%err, vlan_id=iface.vlan_id, "Error fetching tenant VF MAC");
                            None
                        }
                    },
                    None => {
                        tracing::error!(
                            vlan_id = iface.vlan_id,
                            "Missing fdb bridge info for vlan"
                        );
                        None
                    }
                }
            };

            let network_security_group =
                iface
                    .network_security_group
                    .as_ref()
                    .map(|nsg| rpc::NetworkSecurityGroupStatus {
                        id: nsg.id.clone(),
                        // If a network security group was set, then this
                        // field must be be a valid non-default value.
                        // The default value will be (correctly) rejected by
                        // the server.
                        source: nsg.source().into(),
                        version: nsg.version.clone(),
                    });

            interfaces.push(rpc::InstanceInterfaceStatusObservation {
                function_type: iface.function_type,
                virtual_function_id: iface.virtual_function_id,
                mac_address: mac,
                addresses: vec![iface.ip.clone()],
                prefixes: vec![iface.interface_prefix.clone()],
                gateways: vec![iface.gateway.clone()],
                network_security_group,
                internal_uuid: iface.internal_uuid.clone(),
            });
        }
    }
    Ok(interfaces)
}

pub fn tenant_peers(network_config: &rpc::ManagedHostNetworkConfigResponse) -> Vec<&str> {
    network_config
        .tenant_interfaces
        .iter()
        .map(|iface| iface.ip.as_str())
        .collect()
}

/// Reset networking to blank.
/// Replace all networking files with their blank version.
pub async fn reset(
    hbn_root: &Path,
    // if true don't run the reload/restart commands after file update
    skip_post: bool,
) {
    tracing::debug!("Setting network config to blank");
    let paths = paths(hbn_root);

    let mut errs = vec![];
    let mut post_actions = vec![];
    let dhcp_relay_path = FPath(hbn_root.join(dhcp::RELAY_PATH));
    match write(dhcp::blank(), &dhcp_relay_path, "DHCP relay", false) {
        Ok(true) => post_actions.push(PostAction {
            path: dhcp_relay_path,
            cmd: dhcp::RELOAD_CMD,
        }),
        Ok(false) => {}
        Err(err) => errs.push(format!("Write blank DHCP relay: {err:#}")),
    }
    let dhcp_server_path = FPath(hbn_root.join(dhcp::SERVER_PATH));
    match write(dhcp::blank(), &dhcp_server_path, "DHCP server", false) {
        Ok(true) => post_actions.push(PostAction {
            path: dhcp_server_path,
            cmd: dhcp::RELOAD_CMD,
        }),
        Ok(false) => {}
        Err(err) => errs.push(format!("Write blank DHCP server: {err:#}")),
    }
    match write(
        interfaces::blank(),
        &paths.interfaces,
        "/etc/network/interfaces",
        false,
    ) {
        Ok(true) => post_actions.push(PostAction {
            path: paths.interfaces,
            cmd: interfaces::RELOAD_CMD,
        }),
        Ok(false) => {}
        Err(err) => errs.push(format!("write blank interfaces: {err:#}")),
    }
    match write(frr::blank(), &paths.frr, "frr.conf", false) {
        Ok(true) => post_actions.push(PostAction {
            path: paths.frr,
            cmd: frr::RELOAD_CMD,
        }),
        Ok(false) => {}
        Err(err) => errs.push(format!("write blank frr: {err:#}")),
    }
    match write_daemons(&paths.daemons) {
        Ok(true) => post_actions.push(PostAction {
            path: paths.daemons,
            cmd: daemons::RESTART_CMD,
        }),
        Ok(false) => {}
        Err(err) => errs.push(format!("write_daemons: {err:#}")),
    }

    if !skip_post {
        for post in post_actions {
            if let Err(err) = hbn::run_in_container_shell(post.cmd).await {
                errs.push(format!("reload '{}': {err}", post.cmd))
            }
        }
    }

    let err_message = errs.join(", ");
    if !err_message.is_empty() {
        tracing::error!(err_message);
    }
}

// In case DHCP server has to be configured in HBN,
// 1. stop dhcp-relay
// 2. Copy dhcp_config file
// 3. Copy host_config file
// 4. Reload supervisord
fn write_dhcp_server_config(
    dhcp_relay_path: &FPath,
    dhcp_server_path: &DhcpServerPaths,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    service_addrs: &ServiceAddresses,
    hbn_device_names: &HBNDeviceNames,
) -> eyre::Result<bool> {
    match write(dhcp::blank(), dhcp_relay_path, "blank DHCP relay", false) {
        Ok(true) => {
            dhcp_relay_path.del("BAK");
        }
        Ok(false) => {}
        Err(err) => tracing::warn!("Write blank DHCP relay {dhcp_relay_path}: {err:#}"),
    }

    let interfaces = if nc.use_admin_network {
        let vlan_intf = nc
            .admin_interface
            .as_ref()
            .map(|x| format!("vlan{}", x.vlan_id))
            .ok_or_else(|| eyre::eyre!("Admin interface missing on admin network."))?;
        vec![vlan_intf]
    } else {
        let mut interfaces = Vec::with_capacity(nc.tenant_interfaces.len());
        for interface in &nc.tenant_interfaces {
            let interface_name = if nc.network_virtualization_type()
                == ::rpc::forge::VpcVirtualizationType::Fnn
                && !interface.is_l2_segment
            {
                if interface.function_type() == InterfaceFunctionType::Physical {
                    // pf0hpf_sf/if
                    hbn_device_names.reps[0].to_string()
                } else {
                    // pf0vf{0-15}_sf/if
                    format!(
                        "{}{}{}",
                        hbn_device_names.virt_rep_begin,
                        interface.virtual_function_id(),
                        hbn_device_names.sf_id
                    )
                }
            } else {
                format!("vlan{}", interface.vlan_id)
            };
            interfaces.push(interface_name);
        }

        if interfaces.is_empty() {
            // In case of secondary DPU, tenant interface will be empty.
            // To keep the dhcp-server alive, we need to pass a valid interface.
            interfaces.push("lo".to_string());
        }

        interfaces
    };

    let Some(mh_nc) = &nc.managed_host_config else {
        return Err(eyre::eyre!(
            "Loopback IP is missing. Can't write dhcp-server config."
        ));
    };

    let loopback_ip = mh_nc.loopback_ip.parse()?;

    let nameservers = service_addrs
        .nameservers
        .iter()
        .filter_map(|x| match x {
            IpAddr::V4(x) => Some(*x),
            _ => None,
        })
        .collect::<Vec<Ipv4Addr>>();

    let mut has_changes = false;

    let next_contents =
        dhcp::build_server_supervisord_config(dhcp::DhcpServerSupervisordConfig { interfaces })?;
    match write(
        next_contents,
        &dhcp_server_path.server,
        "DHCP server",
        false,
    ) {
        Ok(true) => {
            has_changes = true;
            dhcp_server_path.server.del("BAK");
        }
        Ok(false) => {}
        Err(err) => tracing::error!("Write DHCP server {}: {err:#}", dhcp_server_path.server),
    }

    let next_contents = dhcp::build_server_config(
        service_addrs.pxe_ip,
        service_addrs.ntpservers.clone(),
        nameservers,
        loopback_ip,
    )?;
    match write(
        next_contents,
        &dhcp_server_path.config,
        "DHCP server config",
        false,
    ) {
        Ok(true) => {
            has_changes = true;
            dhcp_server_path.config.del("BAK");
        }
        Ok(false) => {}
        Err(err) => tracing::error!(
            "Write DHCP server config {}: {err:#}",
            dhcp_server_path.config
        ),
    }

    let next_contents = dhcp::build_server_host_config(nc.clone(), hbn_device_names)?;
    match write(
        next_contents,
        &dhcp_server_path.host_config,
        "DHCP server host config",
        false,
    ) {
        Ok(true) => {
            has_changes = true;
            dhcp_server_path.host_config.del("BAK");
        }
        Ok(false) => {}
        Err(err) => tracing::error!(
            "Write DHCP server host config {}: {err:#}",
            dhcp_server_path.host_config
        ),
    }

    Ok(has_changes)
}

fn write_interfaces(
    path: &FPath,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    hbn_device_names: HBNDeviceNames,
) -> eyre::Result<bool> {
    let l_ip_str = match &nc.managed_host_config {
        None => {
            return Err(eyre::eyre!("Missing managed_host_config in response"));
        }
        Some(cfg) => {
            if cfg.loopback_ip.is_empty() {
                return Err(eyre::eyre!("Missing loopback IP"));
            }
            &cfg.loopback_ip
        }
    };
    let loopback_ip = l_ip_str.parse().wrap_err_with(|| l_ip_str.clone())?;

    let physical_name = hbn_device_names.reps[0].to_string();
    let networks = if nc.use_admin_network {
        let admin_interface = nc
            .admin_interface
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Missing admin_interface"))?;
        vec![interfaces::Network {
            interface_name: physical_name,
            vlan: admin_interface.vlan_id as u16,
            vni: admin_interface.vni,
            gateway_cidr: admin_interface.gateway.clone(),
        }]
    } else {
        let mut ifs = Vec::with_capacity(nc.tenant_interfaces.len());
        for (i, net) in nc.tenant_interfaces.iter().enumerate() {
            let name = if net.function_type == rpc::InterfaceFunctionType::Physical as i32 {
                physical_name.clone()
            } else {
                match net.virtual_function_id {
                    Some(id) => hbn_device_names.build_virt(id),
                    None => {
                        // This is for backward compatibility with the old
                        // version of site controller which didn't send the ID
                        // TODO: Remove this in the future and make it an error
                        hbn_device_names.build_virt(i.saturating_sub(1) as u32)
                    }
                }
            };
            ifs.push(interfaces::Network {
                interface_name: name,
                vlan: net.vlan_id as u16,
                vni: net.vni,
                gateway_cidr: net.gateway.clone(),
            });
        }
        ifs
    };

    let next_contents = interfaces::build(interfaces::InterfacesConfig {
        uplinks: hbn_device_names
            .uplinks
            .into_iter()
            .map(String::from)
            .collect(),
        vni_device: nc.vni_device.clone(),
        loopback_ip,
        networks,
    })?;
    write(next_contents, path, "/etc/network/interfaces", false)
}

fn write_frr(
    path: &FPath,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    hbn_device_names: HBNDeviceNames,
) -> eyre::Result<bool> {
    let l_ip_str = match &nc.managed_host_config {
        None => {
            return Err(eyre::eyre!("Missing managed_host_config in response"));
        }
        Some(cfg) => {
            if cfg.loopback_ip.is_empty() {
                return Err(eyre::eyre!("Missing loopback IP"));
            }
            &cfg.loopback_ip
        }
    };
    let loopback_ip = l_ip_str.parse().wrap_err_with(|| l_ip_str.clone())?;

    let access_vlans = if nc.use_admin_network {
        let admin_interface = nc
            .admin_interface
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Missing admin_interface"))?;
        vec![frr::FrrVlanConfig {
            vlan_id: admin_interface.vlan_id,
            network: admin_interface.interface_prefix.clone(),
            ip: admin_interface.ip.clone(),
        }]
    } else {
        let mut access_vlans = Vec::with_capacity(nc.tenant_interfaces.len());
        for net in &nc.tenant_interfaces {
            access_vlans.push(frr::FrrVlanConfig {
                vlan_id: net.vlan_id,
                network: net.interface_prefix.clone(),
                ip: net.ip.clone(),
            });
        }
        access_vlans
    };

    let next_contents = frr::build(frr::FrrConfig {
        asn: nc.asn,
        uplinks: hbn_device_names
            .uplinks
            .into_iter()
            .map(String::from)
            .collect(),
        loopback_ip,
        access_vlans,
        vpc_vni: nc.vpc_vni,
        route_servers: nc.route_servers.clone(),
        use_admin_network: nc.use_admin_network,
    })?;
    write(next_contents, path, "frr.conf", false)
}

/// The etc/frr/daemons file has no templated parts
fn write_daemons(path: &FPath) -> eyre::Result<bool> {
    write(daemons::build(), path, "etc/frr/daemons", false)
}

fn write_acl_rules(
    path: &FPath,
    dpu_network_config: &rpc::ManagedHostNetworkConfigResponse,
    hbn_device_names: HBNDeviceNames,
) -> eyre::Result<bool> {
    let rules_by_interface =
        instance_interface_acls_by_name(&dpu_network_config.tenant_interfaces, hbn_device_names);
    // let ingress_interfaces = instance_interface_names(&dpu_network_config.tenant_interfaces);

    let deny_prefixes = match dpu_network_config.vpc_isolation_behavior() {
        rpc::VpcIsolationBehaviorType::VpcIsolationInvalid => {
            return Err(eyre::eyre!("received invalid VPC isolation behavior"));
        }
        rpc::VpcIsolationBehaviorType::VpcIsolationMutual => [
            dpu_network_config.site_fabric_prefixes.as_slice(),
            dpu_network_config.deny_prefixes.as_slice(),
        ]
        .concat(),
        rpc::VpcIsolationBehaviorType::VpcIsolationOpen => dpu_network_config.deny_prefixes.clone(),
    };

    let config = acl_rules::AclConfig {
        interfaces: rules_by_interface,
        deny_prefixes,
    };
    let contents = acl_rules::build(config)?;
    write(contents, path, "forge-acl.rules", false)
}

// Compute the interface names along with the specific ACL config for each
// tenant-facing interface.
fn instance_interface_acls_by_name(
    intf_configs: &[FlatInterfaceConfig],
    hbn_device_names: HBNDeviceNames,
) -> BTreeMap<String, acl_rules::InterfaceRules> {
    intf_configs
        .iter()
        .enumerate()
        .map(|(i, conf)| {
            let interface_name = match conf.function_type() {
                ::rpc::InterfaceFunctionType::Physical => hbn_device_names.reps[0].to_string(),

                ::rpc::InterfaceFunctionType::Virtual => {
                    let vfid = conf
                        .virtual_function_id
                        .unwrap_or_else(|| (i as u32).saturating_sub(1));
                    hbn_device_names.build_virt(vfid)
                }
            };
            let vpc_prefixes = conf
                .vpc_prefixes
                .iter()
                .map(|prefix| prefix.parse().unwrap())
                .collect();
            let interface_rules = acl_rules::InterfaceRules { vpc_prefixes };
            (interface_name, interface_rules)
        })
        .collect()
}

// Update configuration file
// Returns true if the file has changes, false otherwise.
fn write(
    // What to write into the file
    next_contents: String,
    // The file to write to
    path: &FPath,
    // Human readable description of the file, for error messages
    file_type: &str,
    force: bool,
) -> eyre::Result<bool> {
    let path_tmp = path.temp();
    fs::write(&path_tmp, next_contents.clone())
        .wrap_err_with(|| format!("fs::write {}", path_tmp.display()))?;

    if !force {
        let path_tmp_size = path_tmp.metadata()?.len();
        if path_tmp_size > MAX_EXPECTED_SIZE {
            return Err(eyre::eyre!(
                "new content for '{}' would exceed MAX_EXPECTED_SIZE: {} > {}",
                path_tmp.display(),
                path_tmp_size,
                MAX_EXPECTED_SIZE
            ));
        }
    }

    let has_changed = if !force && path.0.exists() {
        let current = read_limited(path).wrap_err_with(|| format!("read_limited {path}"))?;
        current != next_contents
    } else {
        true
    };
    if !has_changed {
        return Ok(false);
    }
    tracing::debug!("Applying new {file_type} config");

    let path_bak = path.backup();
    if path.0.exists() {
        fs::copy(&path.0, path_bak).wrap_err("copying file to .BAK")?;
    }

    fs::rename(&path_tmp, path).wrap_err("rename")?;

    Ok(true)
}

#[derive(Deserialize, Debug, Clone)]
struct Fdb {
    mac: String,
    ifname: String,
    state: String,
    vlan: Option<u32>,
}

#[derive(Deserialize, Debug)]
// This has many more fields, only parse the one we check
struct IpShow {
    address: String,
}

fn parse_fdb(fdb_json: &str) -> eyre::Result<HashMap<u32, Vec<Fdb>>> {
    let all_fdb: Vec<Fdb> = serde_json::from_str(fdb_json)?;
    let mut out: HashMap<u32, Vec<Fdb>> = HashMap::new();
    for fdb in all_fdb.into_iter() {
        if fdb.vlan.is_none() || fdb.state == "permanent" {
            continue;
        }
        out.entry(fdb.vlan.unwrap())
            .and_modify(|v| v.push(fdb.clone()))
            .or_insert_with(|| vec![fdb]);
    }

    Ok(out)
}

/// The host/tenant side MAC address of a VF
///
/// To use a VF a tenant needs to do this on their host:
///  - echo 16 > /sys/class/net/eth0/device/sriov_numvfs
///  - ip link set <name> up
///    DPU side this must say 16 but discovery should take care of that:
///    mlxconfig -d /dev/mst/mt41686_pciconf0 query NUM_OF_VFS
async fn tenant_vf_mac(vlan_fdb: &[Fdb]) -> eyre::Result<&str> {
    // We're expecting only the host side and our side
    if vlan_fdb.len() != 2 {
        eyre::bail!("Expected two fdb entries, got {vlan_fdb:?}");
    }
    if vlan_fdb[0].ifname != vlan_fdb[1].ifname {
        eyre::bail!(
            "Both entries must have the same ifname, got '{}' and '{}'",
            vlan_fdb[0].ifname,
            vlan_fdb[1].ifname
        );
    }

    // Find our side - both will have the same ifname
    let ovs_side = format!("{}_r", vlan_fdb[0].ifname);
    let mut cmd = TokioCommand::new("ip");
    cmd.kill_on_drop(true);
    let cmd = cmd.args(["-j", "address", "show", &ovs_side.to_string()]);
    let cmd_str = super::pretty_cmd(cmd.as_std());

    let cmd_res = timeout(Duration::from_secs(5), cmd.output())
        .await
        .wrap_err_with(|| format!("timeout calling {cmd_str}"))?;
    let ip_out = cmd_res.wrap_err(cmd_str.to_string())?;

    if !ip_out.status.success() {
        tracing::debug!(
            "STDERR {}: {}",
            super::pretty_cmd(cmd.as_std()),
            String::from_utf8_lossy(&ip_out.stderr)
        );
        return Err(eyre::eyre!(
            "{} for cmd '{}'",
            ip_out.status, // includes the string "exit status"
            super::pretty_cmd(cmd.as_std())
        ));
    }

    let ip_json = String::from_utf8_lossy(&ip_out.stdout).to_string();
    let ip_show: Vec<IpShow> = serde_json::from_str(&ip_json)?;
    if ip_show.len() != 1 {
        eyre::bail!("Getting local side MAC should return 1 entry, got {ip_show:?}");
    }

    // Ignore our side
    let remote_side: Vec<&Fdb> = vlan_fdb
        .iter()
        .filter(|&f| f.mac != ip_show[0].address)
        .collect();

    if remote_side.len() != 1 {
        eyre::bail!("After all removals there should be 1 entry, got {remote_side:?}");
    }
    Ok(&remote_side[0].mac)
}

// std::fs::read_to_string but limited to 4k bytes for safety
fn read_limited<P: AsRef<Path>>(path: P) -> io::Result<String> {
    let f = File::open(path)?;
    let l = f.metadata()?.len();
    if l > MAX_EXPECTED_SIZE {
        return Err(io::Error::other(
            // ErrorKind::FileTooLarge but it's nightly only
            format!("{l} > {MAX_EXPECTED_SIZE} bytes"),
        ));
    }
    // in case it changes as we read
    let mut f_limit = f.take(MAX_EXPECTED_SIZE);
    let mut s = String::with_capacity(l as usize);
    f_limit.read_to_string(&mut s)?;
    Ok(s)
}

// Ask the OS for its hostname.
//
// On a DPU this is correctly set to the DB hostname of the first interface, the hyphenated
// two-word randomly generated name.
fn hostname() -> eyre::Result<Hostname> {
    let mut buf = vec![0u8; 64 + 1]; // Linux HOST_NAME_MAX is 64
    let res = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if res != 0 {
        return Err(io::Error::last_os_error().into());
    }
    let cstr = CStr::from_bytes_until_nul(&buf)?;
    let fqdn = cstr.to_string_lossy().into_owned();
    let hostname = fqdn
        .split('.')
        .next()
        .map(|s| s.to_owned())
        .ok_or(eyre::eyre!("Empty hostname?"))?;
    let search_domain = fqdn.split('.').skip(1).collect::<Vec<&str>>().join(".");
    Ok(Hostname {
        hostname,
        search_domain,
        #[cfg(test)]
        fqdn,
    })
}

struct Hostname {
    hostname: String,
    search_domain: String,
    #[cfg(test)]
    fqdn: String,
}

#[derive(Debug, Clone)]
pub struct FPath(pub PathBuf);
impl FPath {
    /// The previous config, in case we need to revert
    pub fn backup(&self) -> PathBuf {
        self.with_ext("BAK")
    }

    /// The new config before we apply it
    pub fn temp(&self) -> PathBuf {
        self.with_ext("TMP")
    }

    /// `.TEST` is an old path that was used when migrating from Go VPC,
    /// and briefly re-appears in Jan/Feb 2024. Clean it up.
    ///
    /// `.TMP` is the pending config before it is applied. It should be removed
    /// on drop.
    ///
    /// `.BAK` is the backup so that we can rollback if the reload command fails.
    /// It should either be removed (success) or renamed back to the main file (failure).
    pub fn cleanup(&self) -> bool {
        let mut has_deleted = self.del("TEST");
        has_deleted = has_deleted || self.del("TMP");
        has_deleted = has_deleted || self.del("BAK");
        has_deleted
    }

    pub fn del(&self, ext: &'static str) -> bool {
        let p = self.with_ext(ext);
        if p.exists() {
            match fs::remove_file(&p) {
                Ok(_) => true,
                Err(err) => {
                    tracing::warn!("Failed removing {}: {err}.", p.display());
                    false
                }
            }
        } else {
            false
        }
    }

    pub fn with_ext(&self, ext: &'static str) -> PathBuf {
        let mut p = self.0.clone();
        p.set_extension(ext);
        p
    }
}

impl AsRef<Path> for FPath {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

impl Drop for FPath {
    fn drop(&mut self) {
        self.del("TMP");
    }
}

impl fmt::Display for FPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// Delete the non-NVUE ACL rules so that they don't interfere with NVUE.
/// Also delete the very old VPC migration ACL rules, which used a non-standard naming convention
fn cleanup_old_acls(hbn_root: &Path) {
    let old_acls = hbn_root.join(acl_rules::PATH);

    let mut old_acls_test = old_acls.clone();
    old_acls_test.as_mut_os_string().push(".TEST");

    let mut old_acls_tmp = old_acls.clone();
    old_acls_tmp.as_mut_os_string().push(".TMP");

    // not see in the wild, but just in case
    let mut old_acls_bak = old_acls.clone();
    old_acls_bak.as_mut_os_string().push(".BAK");

    for p in [&old_acls, &old_acls_test, &old_acls_tmp, &old_acls_bak] {
        if p.exists() {
            match fs::remove_file(p) {
                Ok(_) => {
                    tracing::info!("Cleaned up old ACL file {}", p.display());
                }
                Err(err) => {
                    tracing::warn!("Failed removing old ACL file {}: {err}.", p.display());
                }
            }
        }
    }
}

fn cleanup_new_acls(hbn_root: &Path) {
    // NVUE creates these
    let nvue_default_acls = hbn_root.join("etc/cumulus/acl/policy.d/50_nvue.rules");
    // We create these
    let nvue_extra_acls = hbn_root.join(nvue::PATH_ACL);

    for p in [&nvue_default_acls, &nvue_extra_acls] {
        if p.exists() {
            match fs::remove_file(p) {
                Ok(_) => {
                    tracing::info!("Cleaned up NVUE ACL file {}", p.display());
                }
                Err(err) => {
                    tracing::warn!("Failed removing NVUE ACL file {}: {err}.", p.display());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::{Path, PathBuf};
    use std::str::FromStr;

    use ::rpc::{common as rpc_common, forge as rpc};
    use eyre::WrapErr;
    use forge_network::virtualization::{VpcVirtualizationType, get_svi_ip};
    use ipnetwork::IpNetwork;
    use utils::models::dhcp::{DhcpConfig, HostConfig};

    use super::FPath;
    use crate::ethernet_virtualization::{
        InterfaceState, ServiceAddresses, needed_interface_state,
    };
    use crate::{HBNDeviceNames, dhcp, nvue};
    #[ctor::ctor]
    fn setup() {
        carbide_host_support::init_logging().unwrap();
    }

    #[test]
    fn test_hostname() -> Result<(), Box<dyn std::error::Error>> {
        let syscall_h = super::hostname()?;
        match std::env::var("HOSTNAME") {
            Ok(env_h) => assert_eq!(
                syscall_h.fqdn, env_h,
                "libc::gethostname output should match shell's $HOSTNAME"
            ),
            Err(_) => tracing::debug!("Env var $HOSTNAME missing, skipping test, not important"),
        }
        Ok(())
    }

    // Pretend we received a new config from API server. Apply it and check the resulting files.
    #[test]
    fn test_with_tenant_etv() -> Result<(), Box<dyn std::error::Error>> {
        let network_config = netconf(
            VpcVirtualizationType::EthernetVirtualizer,
            32,
            24,
            true,
            None,
        );

        let f = tempfile::NamedTempFile::new()?;
        let fp = FPath(f.path().to_owned());

        // What we're testing
        match super::write_interfaces(&fp, &network_config, HBNDeviceNames::hbn_23()) {
            Err(err) => {
                panic!("write_interfaces error: {err}");
            }
            Ok(false) => {
                panic!("write_interfaces says the config didn't change, that's wrong");
            }
            Ok(true) => {
                // success
            }
        }
        let expected = include_str!("../templates/tests/tenant_interfaces");
        compare(&fp, expected)?;

        match super::write_frr(&fp, &network_config, HBNDeviceNames::hbn_23()) {
            Err(err) => {
                panic!("write_frr error: {err}");
            }
            Ok(false) => {
                panic!("write_frr says the config didn't change, that's wrong");
            }
            Ok(true) => {
                // success
            }
        }
        let expected = include_str!("../templates/tests/tenant_frr.conf");
        compare(&fp, expected)?;

        match super::write_acl_rules(&fp, &network_config, HBNDeviceNames::hbn_23()) {
            Err(err) => {
                panic!("write_acl_rules error: {err}");
            }
            Ok(false) => {
                panic!("write_acl_rules says the config didn't change, that's wrong");
            }
            Ok(true) => {
                // success
            }
        }
        let expected = include_str!("../templates/tests/tenant_acl_rules");
        compare_diffed(&fp, expected)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_with_tenant_nvue() -> Result<(), Box<dyn std::error::Error>> {
        let virtualization_type = VpcVirtualizationType::EthernetVirtualizerWithNvue;

        // Test without an NSG to make sure there are no changes for pre-FNN users
        // if they don't opt-in to a network security group.
        let network_config = netconf(virtualization_type, 32, 24, false, None);

        let td = tempfile::tempdir()?;
        let hbn_root = td.path();
        fs::create_dir_all(hbn_root.join("var/support"))?;
        fs::create_dir_all(hbn_root.join("etc/cumulus/acl/policy.d"))?;

        let has_changes = super::update_nvue(
            virtualization_type,
            hbn_root,
            &network_config,
            true,
            HBNDeviceNames::hbn_23(),
        )
        .await?;
        assert!(
            has_changes,
            "update_nvue should have written the file, there should be changes"
        );

        // check ACLs
        let expected = include_str!("../templates/tests/70-forge_nvue.rules.expected");
        compare_diffed(hbn_root.join(nvue::PATH_ACL), expected)?;

        // check startup.yaml
        let expected = include_str!("../templates/tests/nvue_startup.yaml.expected");
        compare_diffed(hbn_root.join(nvue::PATH), expected)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_with_tenant_nvue_quarantined() -> Result<(), Box<dyn std::error::Error>> {
        let virtualization_type = VpcVirtualizationType::EthernetVirtualizerWithNvue;

        let network_config = {
            let mut cfg = netconf(virtualization_type, 32, 24, true, None);
            match cfg.managed_host_config.as_mut() {
                Some(c) => {
                    c.quarantine_state = Some(rpc::ManagedHostQuarantineState {
                        mode: rpc::ManagedHostQuarantineMode::BlockAllTraffic.into(),
                        reason: Some("test".to_string()),
                    })
                }
                None => panic!("missing managed_host_config"),
            }
            cfg
        };

        let td = tempfile::tempdir()?;
        let hbn_root = td.path();
        fs::create_dir_all(hbn_root.join("var/support"))?;
        fs::create_dir_all(hbn_root.join("etc/cumulus/acl/policy.d"))?;

        let has_changes = super::update_nvue(
            virtualization_type,
            hbn_root,
            &network_config,
            true,
            HBNDeviceNames::hbn_23(),
        )
        .await?;
        assert!(
            has_changes,
            "update_nvue should have written the file, there should be changes"
        );

        // check ACLs
        let expected = include_str!("../templates/tests/70-forge_nvue.rules.expected");
        compare_diffed(hbn_root.join(nvue::PATH_ACL), expected)?;

        // check startup.yaml
        let expected = include_str!("../templates/tests/nvue_startup_quarantined.yaml.expected");
        compare_diffed(hbn_root.join(nvue::PATH), expected)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_with_tenant_fnn_quarantined() -> Result<(), Box<dyn std::error::Error>> {
        let virtualization_type = VpcVirtualizationType::Fnn;

        let network_config = {
            let mut cfg = netconf(virtualization_type, 32, 24, true, None);
            match cfg.managed_host_config.as_mut() {
                Some(c) => {
                    c.quarantine_state = Some(rpc::ManagedHostQuarantineState {
                        mode: rpc::ManagedHostQuarantineMode::BlockAllTraffic.into(),
                        reason: Some("test".to_string()),
                    })
                }
                None => panic!("missing managed_host_config"),
            }
            cfg
        };

        let td = tempfile::tempdir()?;
        let hbn_root = td.path();
        fs::create_dir_all(hbn_root.join("var/support"))?;
        fs::create_dir_all(hbn_root.join("etc/cumulus/acl/policy.d"))?;

        let has_changes = super::update_nvue(
            virtualization_type,
            hbn_root,
            &network_config,
            true,
            HBNDeviceNames::hbn_23(),
        )
        .await?;
        assert!(
            has_changes,
            "update_nvue should have written the file, there should be changes"
        );

        // check ACLs
        let expected = include_str!("../templates/tests/70-forge_nvue.rules.expected");
        compare_diffed(hbn_root.join(nvue::PATH_ACL), expected)?;

        // check startup.yaml
        let expected =
            include_str!("../templates/tests/nvue_startup_quarantined_fnn.yaml.expected");
        compare_diffed(hbn_root.join(nvue::PATH), expected)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_with_tenant_nvue_with_nsg() -> Result<(), Box<dyn std::error::Error>> {
        // Test WITH an NSG
        let virtualization_type = VpcVirtualizationType::EthernetVirtualizerWithNvue;

        let network_config = netconf(virtualization_type, 32, 24, true, None);

        let td = tempfile::tempdir()?;
        let hbn_root = td.path();
        fs::create_dir_all(hbn_root.join("var/support"))?;
        fs::create_dir_all(hbn_root.join("etc/cumulus/acl/policy.d"))?;

        let has_changes = super::update_nvue(
            virtualization_type,
            hbn_root,
            &network_config,
            true,
            HBNDeviceNames::hbn_23(),
        )
        .await?;
        assert!(
            has_changes,
            "update_nvue should have written the file, there should be changes"
        );

        // check ACLs
        let expected = include_str!("../templates/tests/70-forge_nvue.rules.expected");
        compare_diffed(hbn_root.join(nvue::PATH_ACL), expected)?;

        // check startup.yaml
        let expected = include_str!("../templates/tests/nvue_startup_with_nsg.yaml.expected");
        compare_diffed(hbn_root.join(nvue::PATH), expected)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_with_tenant_nvue_with_empty_nsg_default_deny()
    -> Result<(), Box<dyn std::error::Error>> {
        let virtualization_type = VpcVirtualizationType::EthernetVirtualizerWithNvue;
        let mut network_config = netconf(virtualization_type, 32, 24, true, None);

        // Empty out all NSG rules.  This should result in config that
        // just has a single default deny.
        for iface in network_config.tenant_interfaces.iter_mut() {
            if let Some(nsg) = iface.network_security_group.as_mut() {
                nsg.rules = vec![];
            }
        }

        let td = tempfile::tempdir()?;
        let hbn_root = td.path();
        fs::create_dir_all(hbn_root.join("var/support"))?;
        fs::create_dir_all(hbn_root.join("etc/cumulus/acl/policy.d"))?;

        let has_changes = super::update_nvue(
            virtualization_type,
            hbn_root,
            &network_config,
            true,
            HBNDeviceNames::hbn_23(),
        )
        .await?;
        assert!(
            has_changes,
            "update_nvue should have written the file, there should be changes"
        );

        // check ACLs
        let expected = include_str!("../templates/tests/70-forge_nvue.rules.expected");
        compare_diffed(hbn_root.join(nvue::PATH_ACL), expected)?;

        // check startup.yaml.
        let expected = include_str!(
            "../templates/tests/nvue_startup_with_empty_nsg_default_deny.yaml.expected"
        );
        compare_diffed(hbn_root.join(nvue::PATH), expected)?;

        const ERR_FILE: &str = "/tmp/test_nvue_startup.yaml";
        let startup_yaml = fs::read_to_string(hbn_root.join(nvue::PATH))?;
        let _: Vec<serde_yaml::Value> = serde_yaml::from_str(&startup_yaml)
            .inspect_err(|_| {
                let mut f = fs::File::create(ERR_FILE).unwrap();
                f.write_all(startup_yaml.as_bytes()).unwrap();
            })
            .wrap_err(format!("YAML parser error. Output written to {ERR_FILE}"))?;

        Ok(())
    }

    #[tokio::test]
    async fn test_with_tenant_nvue_fnn_classic_with_nsg() -> Result<(), Box<dyn std::error::Error>>
    {
        let virtualization_type = VpcVirtualizationType::Fnn;
        let network_config = netconf(virtualization_type, 32, 24, true, None);

        let td = tempfile::tempdir()?;
        let hbn_root = td.path();
        fs::create_dir_all(hbn_root.join("var/support"))?;
        fs::create_dir_all(hbn_root.join("etc/cumulus/acl/policy.d"))?;

        let has_changes = super::update_nvue(
            virtualization_type,
            hbn_root,
            &network_config,
            true,
            HBNDeviceNames::hbn_23(),
        )
        .await?;
        assert!(
            has_changes,
            "update_nvue should have written the file, there should be changes"
        );

        // check ACLs
        let expected = include_str!("../templates/tests/70-forge_nvue.rules.expected");
        compare_diffed(hbn_root.join(nvue::PATH_ACL), expected)?;

        // check startup.yaml.
        // TODO: This should be fixed when new template is merged.
        //
        // let expected = include_str!("../templates/tests/nvue_startup_fnn_classic.yaml.expected");
        // compare_diffed(hbn_root.join(nvue::PATH), expected)?;
        // Until then... let's at least confirm valid YAML...
        const ERR_FILE: &str = "/tmp/test_nvue_startup.yaml";
        let startup_yaml = fs::read_to_string(hbn_root.join(nvue::PATH))?;
        let _: Vec<serde_yaml::Value> = serde_yaml::from_str(&startup_yaml)
            .inspect_err(|_| {
                let mut f = fs::File::create(ERR_FILE).unwrap();
                f.write_all(startup_yaml.as_bytes()).unwrap();
            })
            .wrap_err(format!("YAML parser error. Output written to {ERR_FILE}"))?;

        Ok(())
    }

    #[tokio::test]
    async fn test_with_tenant_nvue_fnn_classic_with_empty_nsg_default_deny()
    -> Result<(), Box<dyn std::error::Error>> {
        let virtualization_type = VpcVirtualizationType::Fnn;
        let mut network_config = netconf(virtualization_type, 32, 24, true, Some(3109));

        // Empty out all NSG rules.  This should result in config that
        // just has a single default deny.
        for iface in network_config.tenant_interfaces.iter_mut() {
            if let Some(nsg) = iface.network_security_group.as_mut() {
                nsg.rules = vec![];
            }
        }

        let td = tempfile::tempdir()?;
        let hbn_root = td.path();
        fs::create_dir_all(hbn_root.join("var/support"))?;
        fs::create_dir_all(hbn_root.join("etc/cumulus/acl/policy.d"))?;

        let has_changes = super::update_nvue(
            virtualization_type,
            hbn_root,
            &network_config,
            true,
            HBNDeviceNames::hbn_23(),
        )
        .await?;
        assert!(
            has_changes,
            "update_nvue should have written the file, there should be changes"
        );

        // check ACLs
        let expected = include_str!("../templates/tests/70-forge_nvue.rules.expected");
        compare_diffed(hbn_root.join(nvue::PATH_ACL), expected)?;

        // check startup.yaml.
        let expected = include_str!(
            "../templates/tests/nvue_startup_fnn_classic_with_empty_nsg_default_deny.yaml.expected"
        );
        compare_diffed(hbn_root.join(nvue::PATH), expected)?;

        const ERR_FILE: &str = "/tmp/test_nvue_startup.yaml";
        let startup_yaml = fs::read_to_string(hbn_root.join(nvue::PATH))?;
        let _: Vec<serde_yaml::Value> = serde_yaml::from_str(&startup_yaml)
            .inspect_err(|_| {
                let mut f = fs::File::create(ERR_FILE).unwrap();
                f.write_all(startup_yaml.as_bytes()).unwrap();
            })
            .wrap_err(format!("YAML parser error. Output written to {ERR_FILE}"))?;

        Ok(())
    }

    #[tokio::test]
    async fn test_with_tenant_nvue_fnn_classic() -> Result<(), Box<dyn std::error::Error>> {
        let virtualization_type = VpcVirtualizationType::Fnn;
        let network_config = netconf(virtualization_type, 32, 24, false, None);

        let td = tempfile::tempdir()?;
        let hbn_root = td.path();
        fs::create_dir_all(hbn_root.join("var/support"))?;
        fs::create_dir_all(hbn_root.join("etc/cumulus/acl/policy.d"))?;

        let has_changes = super::update_nvue(
            virtualization_type,
            hbn_root,
            &network_config,
            true,
            HBNDeviceNames::hbn_23(),
        )
        .await?;
        assert!(
            has_changes,
            "update_nvue should have written the file, there should be changes"
        );

        // check ACLs
        let expected = include_str!("../templates/tests/70-forge_nvue.rules.expected");
        compare_diffed(hbn_root.join(nvue::PATH_ACL), expected)?;

        // check startup.yaml.
        let expected = include_str!("../templates/tests/nvue_startup_fnn_classic.yaml.expected");
        compare_diffed(hbn_root.join(nvue::PATH), expected)?;
        const ERR_FILE: &str = "/tmp/test_nvue_startup.yaml";
        let startup_yaml = fs::read_to_string(hbn_root.join(nvue::PATH))?;
        let _: Vec<serde_yaml::Value> = serde_yaml::from_str(&startup_yaml)
            .inspect_err(|_| {
                let mut f = fs::File::create(ERR_FILE).unwrap();
                f.write_all(startup_yaml.as_bytes()).unwrap();
            })
            .wrap_err(format!("YAML parser error. Output written to {ERR_FILE}"))?;

        Ok(())
    }

    fn netconf(
        virtualization_type: VpcVirtualizationType,
        interface_prefix_length: u8,
        network_prefix_length: u8,
        include_network_security_group: bool,
        site_global_vpc_vni: Option<u32>,
    ) -> rpc::ManagedHostNetworkConfigResponse {
        // The config we received from API server
        // Admin won't be used
        let admin_interface_prefix: IpNetwork = "10.217.5.123/32".parse().unwrap();
        let admin_interface = rpc::FlatInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical.into(),
            virtual_function_id: None,
            vlan_id: 1,
            vni: 1001,
            vpc_vni: 1002,
            gateway: "10.217.5.123/28".to_string(),
            ip: "10.217.5.123".to_string(),
            interface_prefix: admin_interface_prefix.to_string(),
            vpc_prefixes: vec![],
            vpc_peer_prefixes: vec![],
            vpc_peer_vnis: vec![],
            prefix: "10.217.5.123/28".to_string(),
            fqdn: "myhost.forge".to_string(),
            booturl: Some("test".to_string()),
            svi_ip: None,
            tenant_vrf_loopback_ip: Some("10.217.5.124".to_string()),
            is_l2_segment: true,
            network_security_group: None,
            internal_uuid: None,
            mtu: None,
        };
        assert_eq!(admin_interface.svi_ip, None);

        let interface_prefix_1: IpNetwork = format!("10.217.5.170/{interface_prefix_length}")
            .parse()
            .unwrap();
        let interface_prefix_2: IpNetwork = format!("10.217.5.162/{interface_prefix_length}")
            .parse()
            .unwrap();

        let svi_ip1: IpAddr = IpAddr::from_str("10.217.5.172").unwrap();
        let svi_ip2: IpAddr = IpAddr::from_str("10.217.5.164").unwrap();

        let vpc_peer_vnis = match virtualization_type {
            VpcVirtualizationType::EthernetVirtualizer
            | VpcVirtualizationType::EthernetVirtualizerWithNvue => {
                vec![]
            }
            _ => {
                vec![1025186, 1025187]
            }
        };
        let tenant_interfaces = vec![
            rpc::FlatInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual.into(),
                virtual_function_id: Some(0),
                vlan_id: 196,
                vni: 1025196,
                vpc_vni: 1025197,
                gateway: "10.217.5.169/29".to_string(),
                ip: "10.217.5.170".to_string(),
                interface_prefix: interface_prefix_1.to_string(),
                vpc_prefixes: vec!["10.217.5.160/30".to_string(), "10.217.5.168/29".to_string()],
                vpc_peer_prefixes: vec!["10.217.6.176/29".to_string()],
                vpc_peer_vnis,
                prefix: "10.217.5.169/29".to_string(),
                fqdn: "myhost.forge.1".to_string(),
                booturl: None,
                svi_ip: get_svi_ip(
                    &Some(svi_ip1),
                    virtualization_type,
                    true,
                    network_prefix_length,
                )
                .unwrap()
                .map(|ip| ip.to_string()),
                tenant_vrf_loopback_ip: Some("10.217.5.124".to_string()),
                is_l2_segment: true,
                network_security_group: None,
                internal_uuid: None,
                mtu: None,
            },
            rpc::FlatInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical.into(),
                virtual_function_id: None,
                vlan_id: 185,
                vni: 1025185,
                vpc_vni: 1025186,
                gateway: "10.217.5.161/30".to_string(),
                ip: "10.217.5.162".to_string(),
                interface_prefix: interface_prefix_2.to_string(),
                vpc_prefixes: vec!["10.217.5.160/30".to_string(), "10.217.5.168/29".to_string()],
                vpc_peer_prefixes: vec!["10.217.6.176/29".to_string()],
                vpc_peer_vnis: vec![],
                prefix: "10.217.5.162/30".to_string(),
                fqdn: "myhost.forge.2".to_string(),
                booturl: None,
                svi_ip: get_svi_ip(
                    &Some(svi_ip2),
                    virtualization_type,
                    false,
                    network_prefix_length,
                )
                .unwrap()
                .map(|ip| ip.to_string()),
                tenant_vrf_loopback_ip: Some("10.217.5.125".to_string()),
                is_l2_segment: false,
                network_security_group: if !include_network_security_group {
                    None
                } else {
                    Some(rpc::FlatInterfaceNetworkSecurityGroupConfig {
                    id: "5b931164-d9c6-11ef-8292-232e57575621".to_string(),
                    version: "V1-1".to_string(),
                    source: rpc::NetworkSecurityGroupSource::NsgSourceVpc.into(),
                    stateful_egress: true,
                    rules: vec![rpc::ResolvedNetworkSecurityGroupRule {
                        src_prefixes: vec!["0.0.0.0/0".to_string()],
                        dst_prefixes: vec!["1.0.0.0/0".to_string()],
                        rule: Some(rpc::NetworkSecurityGroupRuleAttributes {
                            id: Some("anything".to_string()),
                            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                                .into(),
                            ipv6: false,
                            src_port_start: Some(80),
                            src_port_end: Some(81),
                            dst_port_start: Some(80),
                            dst_port_end: Some(81),
                            protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                            action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                            priority: 9001,
                            source_net: Some(
                                rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                                    "0.0.0.0/0".to_string(),
                                ),
                            ),
                            destination_net: Some(
                                rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                                    "0.0.0.0/0".to_string(),
                                ),
                            ),
                        }),
                    },
                    rpc::ResolvedNetworkSecurityGroupRule {
                        src_prefixes: vec!["0.0.0.0/0".to_string()],
                        dst_prefixes: vec!["1.0.0.0/0".to_string()],
                        rule: Some(rpc::NetworkSecurityGroupRuleAttributes {
                            id: Some("anything".to_string()),
                            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionEgress
                                .into(),
                            ipv6: false,
                            src_port_start: Some(80),
                            src_port_end: Some(81),
                            dst_port_start: Some(80),
                            dst_port_end: Some(81),
                            protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                            action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                            priority: 9001,
                            source_net: Some(
                                rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                                    "1.0.0.0/0".to_string(),
                                ),
                            ),
                            destination_net: Some(
                                rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                                    "1.0.0.0/0".to_string(),
                                ),
                            ),
                        }),
                    },
                    rpc::ResolvedNetworkSecurityGroupRule {
                        src_prefixes: vec!["0.0.0.0/0".to_string()],
                        dst_prefixes: vec!["1.0.0.0/0".to_string()],
                        rule: Some(rpc::NetworkSecurityGroupRuleAttributes {
                            id: Some("anything".to_string()),
                            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionEgress
                                .into(),
                            ipv6: false,
                            src_port_start: None,
                            src_port_end: None,
                            dst_port_start: Some(8080),
                            dst_port_end: Some(8080),
                            protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                            action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                            priority: 9001,
                            source_net: Some(
                                rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                                    "1.0.0.0/0".to_string(),
                                ),
                            ),
                            destination_net: Some(
                                rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                                    "1.0.0.0/0".to_string(),
                                ),
                            ),
                        }),
                    },
                    rpc::ResolvedNetworkSecurityGroupRule {
                        src_prefixes: vec!["2001:db8:3333:4444:5555:6666:7777:8888/128".to_string()],
                        dst_prefixes: vec!["2001:db8:3333:4444:5555:6666:7777:9999/128".to_string()],
                        rule: Some(rpc::NetworkSecurityGroupRuleAttributes {
                            id: Some("anything".to_string()),
                            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                                .into(),
                            ipv6: true,
                            src_port_start: Some(80),
                            src_port_end: Some(81),
                            dst_port_start: Some(80),
                            dst_port_end: Some(81),
                            protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                            action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                            priority: 9001,
                            source_net: Some(
                                rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                                    "2001:db8:3333:4444:5555:6666:7777:8888/128".to_string(),
                                ),
                            ),
                            destination_net: Some(
                                rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                                    "2001:db8:3333:4444:5555:6666:7777:9999/128".to_string(),
                                ),
                            ),
                        }),
                    },
                    rpc::ResolvedNetworkSecurityGroupRule {
                        src_prefixes: vec!["2001:db8:3333:4444:5555:6666:7777:8888/128".to_string()],
                        dst_prefixes: vec!["2001:db8:3333:4444:5555:6666:7777:9999/128".to_string()],
                        rule: Some(rpc::NetworkSecurityGroupRuleAttributes {
                            id: Some("anything".to_string()),
                            direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionEgress
                                .into(),
                            ipv6: true,
                            src_port_start: Some(80),
                            src_port_end: Some(81),
                            dst_port_start: Some(80),
                            dst_port_end: Some(81),
                            protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                            action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                            priority: 9001,
                            source_net: Some(
                                rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                                    "2001:db8:3333:4444:5555:6666:7777:8888/128".to_string(),
                                ),
                            ),
                            destination_net: Some(
                                rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                                    "2001:db8:3333:4444:5555:6666:7777:9999/128".to_string(),
                                ),
                            ),
                        }),
                    }],
                })
                },
                internal_uuid: None,
                mtu: None,
            },
        ];

        let svi_is_some = virtualization_type == VpcVirtualizationType::Fnn;
        assert_eq!(
            tenant_interfaces[0].svi_ip.is_some(),
            svi_is_some && tenant_interfaces[0].is_l2_segment,
            "got svi_ip: {:?}",
            tenant_interfaces[0].svi_ip
        );
        assert_eq!(
            tenant_interfaces[1].svi_ip.is_some(),
            svi_is_some && tenant_interfaces[1].is_l2_segment,
            "got svi_ip 1: {:?}",
            tenant_interfaces[1].svi_ip
        );

        let netconf = rpc::ManagedHostNetworkConfig {
            loopback_ip: "10.217.5.39".to_string(),
            quarantine_state: None,
        };
        rpc::ManagedHostNetworkConfigResponse {
            asn: 4259912557,
            datacenter_asn: 11414,
            site_global_vpc_vni,
            anycast_site_prefixes: vec!["5.255.255.0/24".to_string()],
            tenant_host_asn: Some(65100),
            common_internal_route_target: Some(rpc_common::RouteTarget {
                asn: 11415,
                vni: 200,
            }),
            additional_route_target_imports: vec![rpc_common::RouteTarget {
                asn: 11111,
                vni: 22222,
            }],
            routing_profile: Some(rpc::RoutingProfile {
                route_target_imports: vec![rpc_common::RouteTarget {
                    asn: 44444,
                    vni: 55555,
                }],
                route_targets_on_exports: vec![rpc_common::RouteTarget {
                    asn: 77415,
                    vni: 800,
                }],
            }),
            network_security_policy_overrides: vec![rpc::ResolvedNetworkSecurityGroupRule {
                src_prefixes: vec!["7.7.7.0/24".to_string()],
                dst_prefixes: vec!["7.7.7.0/24".to_string()],
                rule: Some(rpc::NetworkSecurityGroupRuleAttributes {
                    id: Some("anything".to_string()),
                    direction: rpc::NetworkSecurityGroupRuleDirection::NsgRuleDirectionIngress
                        .into(),
                    ipv6: false,
                    src_port_start: Some(80),
                    src_port_end: Some(81),
                    dst_port_start: Some(80),
                    dst_port_end: Some(81),
                    protocol: rpc::NetworkSecurityGroupRuleProtocol::NsgRuleProtoTcp.into(),
                    action: rpc::NetworkSecurityGroupRuleAction::NsgRuleActionDeny.into(),
                    priority: 0,
                    source_net: Some(
                        rpc::network_security_group_rule_attributes::SourceNet::SrcPrefix(
                            "0.0.0.0/0".to_string(),
                        ),
                    ),
                    destination_net: Some(
                        rpc::network_security_group_rule_attributes::DestinationNet::DstPrefix(
                            "0.0.0.0/0".to_string(),
                        ),
                    ),
                }),
            }],

            // yes it's in there twice I dunno either
            dhcp_servers: vec!["10.217.5.197".to_string(), "10.217.5.197".to_string()],
            vni_device: "vxlan48".to_string(),

            managed_host_config: Some(netconf),
            managed_host_config_version: "V1-T1666644937952267".to_string(),

            use_admin_network: false,
            admin_interface: Some(admin_interface),

            traffic_intercept_config: Some(rpc::TrafficInterceptConfig {
                bridging: Some(rpc::TrafficInterceptBridging {
                    vf_intercept_bridge_port: "dpuVf0mg".to_string(),
                    host_intercept_bridge_port: "dpuVf1mg".to_string(),
                    host_intercept_bridge_name: "br-host".to_string(),
                    vf_intercept_bridge_name: "br-dpu".to_string(),
                    vf_intercept_bridge_sf: "pf0dpu5".to_string(),
                    internal_bridge_routing_prefix: "10.10.10.0/29".to_string(),
                }),
                additional_overlay_vtep_ip: Some("10.255.254.253".to_string()),
                public_prefixes: vec!["7.6.5.0/24".to_string()],
            }),

            tenant_interfaces,
            instance_network_config_version: "V1-T1666644937952999".to_string(),

            instance_id: Some(
                uuid::Uuid::try_from("60cef902-9779-4666-8362-c9bb4b37184f")
                    .unwrap()
                    .into(),
            ),
            remote_id: "test".to_string(),

            // For NetworkMonitor
            dpu_network_pinger_type: None,

            // For ETV:
            network_virtualization_type: None,
            vpc_vni: None,
            route_servers: vec!["172.43.0.1".to_string(), "172.43.0.2".to_string()],
            deny_prefixes: vec!["192.0.2.0/24".into(), "198.51.100.0/24".into()],
            site_fabric_prefixes: vec!["10.217.0.0/16".into()],
            deprecated_deny_prefixes: vec![],
            enable_dhcp: true,
            vpc_isolation_behavior: rpc::VpcIsolationBehaviorType::VpcIsolationMutual.into(),
            host_interface_id: Some("60cef902-9779-4666-8362-c9bb4b37185f".to_string()),
            is_primary_dpu: true,
            min_dpu_functioning_links: None,
            internet_l3_vni: Some(1337),
            stateful_acls_enabled: true,
            instance: None,
            dpu_extension_services: vec![],
        }
    }

    #[tokio::test]
    async fn test_reset() -> Result<(), Box<dyn std::error::Error>> {
        // setup
        let td = tempfile::tempdir()?;
        let hbn_root = td.path();
        fs::create_dir_all(hbn_root.join("etc/frr"))?;
        fs::create_dir_all(hbn_root.join("etc/network"))?;
        fs::create_dir_all(hbn_root.join("etc/supervisor/conf.d"))?;
        fs::create_dir_all(hbn_root.join("var/support/forge-dhcp/conf"))?;

        // test
        super::reset(hbn_root, true).await;

        // check
        let frr_path = hbn_root.join("etc/frr/frr.conf");
        let frr_contents =
            super::read_limited(&frr_path).wrap_err(format!("Failed reading {frr_path:?}"))?;
        assert_eq!(frr_contents, crate::frr::TMPL_EMPTY);

        // check dhcp server
        let dhcp_path = hbn_root.join("etc/supervisor/conf.d/default-forge-dhcp-server.conf");
        let dhcp_contents =
            super::read_limited(&dhcp_path).wrap_err(format!("Failed reading {dhcp_path:?}"))?;
        assert_eq!(dhcp_contents, crate::dhcp::TMPL_EMPTY);
        Ok(())
    }

    #[test]
    fn test_parse_fdb() -> Result<(), Box<dyn std::error::Error>> {
        let json = include_str!("hbn_bridge_fdb.json");
        let out = super::parse_fdb(json)?;
        let twenty_one = out.get(&21).unwrap();
        assert_eq!(twenty_one.len(), 2); // interface both sides
        if !twenty_one.iter().any(|f| f.mac == "7e:f6:b2:b2:f0:97") {
            panic!("Expected MAC not found in vlan 21's parsed fdb");
        }
        // "permanent" were filtered out already
        assert!(!twenty_one.iter().any(|f| f.state == "permanent"));
        Ok(())
    }

    #[test]
    fn test_parse_ip_show() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"[{"ifindex":26,"ifname":"pf0vf0_if_r","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":9216,"qdisc":"mq","master":"ovs-system","operstate":"UP","group":"default","txqlen":1000,"link_type":"ether","address":"4e:1f:bd:97:23:3e","broadcast":"ff:ff:ff:ff:ff:ff","altnames":["enp3s0f0npf0sf131072"],"addr_info":[{"family":"inet6","local":"fe80::4c1f:bdff:fe97:233e","prefixlen":64,"scope":"link","valid_life_time":4294967295,"preferred_life_time":4294967295}]}]"#;
        let out: Vec<super::IpShow> = serde_json::from_str(json)?;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].address, "4e:1f:bd:97:23:3e");
        Ok(())
    }

    #[test]
    fn test_nvue_is_yaml_etv() -> Result<(), Box<dyn std::error::Error>> {
        test_nvue_is_yaml_inner(false)
    }

    #[test]
    fn test_nvue_is_yaml_fnnv() -> Result<(), Box<dyn std::error::Error>> {
        test_nvue_is_yaml_inner(true)
    }

    fn test_nvue_is_yaml_inner(is_fnn: bool) -> Result<(), Box<dyn std::error::Error>> {
        let vpc_virtualization_type = VpcVirtualizationType::EthernetVirtualizerWithNvue;

        let network_security_groups = vec![nvue::NetworkSecurityGroup {
            id: "7777f270-dd02-11ef-80d2-9f8689fc7df7".to_string(),
            stateful_egress: true,
            rules: vec![nvue::NetworkSecurityGroupRule {
                id: "6313f270-dd02-11ef-80d2-9f8689fc7df7".to_string(),
                ingress: true,
                ipv6: true,
                priority: 1001,
                can_match_any_protocol: false,
                can_be_stateful: true,
                protocol: "TCP".to_string(),
                src_prefixes: vec!["2.2.2.2/24".to_string()],
                dst_prefixes: vec!["3.3.3.3/24".to_string()],
                src_port_start: Some(5),
                src_port_end: Some(50),
                dst_port_start: Some(8),
                dst_port_end: Some(80),
                action: "PERMIT".to_string(),
            }],
        }];

        let networks = vec![nvue::PortConfig {
            network_security_group_id: Some(network_security_groups[0].id.clone()),
            interface_name: HBNDeviceNames::hbn_23().reps[0].to_string(),
            is_phy: true,
            vlan: 123u16,
            vni: Some(5555),
            l3_vni: Some(7777),
            gateway_cidr: "10.217.4.65/26".to_string(),
            svi_ip: if is_fnn {
                Some("10.217.4.66/26".to_string())
            } else {
                None
            },
            tenant_vrf_loopback_ip: if is_fnn {
                Some("10.217.4.67".to_string())
            } else {
                None
            },
            vpc_prefixes: vec!["10.217.4.168/29".to_string()],
            vpc_peer_prefixes: vec![],
            vpc_peer_vnis: vec![],
            is_l2_segment: true,
        }];
        let hostname = super::hostname().wrap_err("gethostname error")?;
        let vpc_vni = 7777;
        let conf = nvue::NvueConfig {
            is_fnn,
            vpc_virtualization_type,
            use_admin_network: true,
            site_global_vpc_vni: None,
            loopback_ip: "10.217.5.39".to_string(),
            secondary_overlay_vtep_ip: Some("10.255.254.253".to_string()),
            internal_bridge_routing_prefix: Some("10.255.255.0/29".to_string()),
            vf_intercept_bridge_port_name: Some("pfdpu0".to_string()),
            vf_intercept_bridge_sf: Some("pf0dpu5".to_string()),
            host_intercept_bridge_port_name: Some("pfdpu1".to_string()),
            traffic_intercept_public_prefixes: vec!["7.6.5.0/24".to_string()],
            asn: 65535,
            datacenter_asn: 11414,
            anycast_site_prefixes: vec!["5.255.255.0/24".to_string()],
            tenant_host_asn: Some(65100),
            common_internal_route_target: Some(nvue::RouteTargetConfig {
                asn: 11415,
                vni: 200,
            }),
            additional_route_target_imports: vec![nvue::RouteTargetConfig {
                asn: 44444,
                vni: 55555,
            }],
            dpu_hostname: hostname.hostname,
            dpu_search_domain: hostname.search_domain,
            hbn_version: None,
            uplinks: HBNDeviceNames::hbn_23()
                .uplinks
                .into_iter()
                .map(String::from)
                .collect(),
            dhcp_servers: vec!["10.217.5.197".to_string()],
            route_servers: vec!["172.43.0.1".to_string(), "172.43.0.2".to_string()],
            deny_prefixes: vec![],
            use_vpc_isolation: false,
            site_fabric_prefixes: vec!["10.217.4.128/26".to_string()],
            stateful_acls_enabled: true,
            ct_port_configs: networks,
            ct_vrf_name: format!("vpc_{vpc_vni}"),
            ct_access_vlans: vec![nvue::VlanConfig {
                vlan_id: 123,
                network: "10.217.4.70/32".to_string(),
                ip: "10.217.4.70".to_string(),
            }],
            ct_routing_profile: Some(nvue::RoutingProfile {
                route_target_imports: vec![nvue::RouteTargetConfig {
                    asn: 44444,
                    vni: 55555,
                }],
                route_targets_on_exports: vec![nvue::RouteTargetConfig {
                    asn: 11415,
                    vni: 200,
                }],
            }),

            network_security_policy_override_rules: vec![nvue::NetworkSecurityGroupRule {
                id: "5553f270-dd02-11ef-80d2-9f8689fc7df7".to_string(),
                ingress: true,
                ipv6: false,
                priority: 1,
                can_match_any_protocol: true,
                can_be_stateful: true,
                protocol: "ANY".to_string(),
                src_prefixes: vec!["7.7.7.0/24".to_string()],
                dst_prefixes: vec!["6.6.6.0/24".to_string()],
                src_port_start: Some(5),
                src_port_end: Some(50),
                dst_port_start: Some(8),
                dst_port_end: Some(80),
                action: "DENY".to_string(),
            }],

            ct_l3_vni: Some(vpc_vni),
            ct_vrf_loopback: "FNN".to_string(),
            l3_domains: vec![],
            network_security_groups,
        };
        let startup_yaml = nvue::build(conf)?;

        const ERR_FILE: &str = "/tmp/test_nvue_startup.yaml";
        let yaml_obj: Vec<serde_yaml::Value> = serde_yaml::from_str(&startup_yaml)
            .inspect_err(|_| {
                let mut f = fs::File::create(ERR_FILE).unwrap();
                f.write_all(startup_yaml.as_bytes()).unwrap();
            })
            .wrap_err(format!("YAML parser error. Output written to {ERR_FILE}"))?;
        assert_eq!(yaml_obj.len(), 2); // 'header' and 'set'
        Ok(())
    }

    fn compare<P: AsRef<Path>>(p1: P, expected: &str) -> Result<(), Box<dyn std::error::Error>> {
        let contents = super::read_limited(p1.as_ref())?;
        // trim white space at end of line to match Go version
        let output = contents
            .lines()
            .map(|l| l.trim_end())
            .collect::<Vec<&str>>()
            .join("\n")
            + "\n";
        let mut has_error = false;
        if output != expected {
            for (g, e) in output.lines().zip(expected.lines()) {
                if g != e {
                    has_error = true;
                    println!("Line differs:");
                    println!("GOT: {g}");
                    println!("EXP: {e}");
                }
            }
        }
        assert!(!has_error);

        Ok(())
    }

    fn compare_diffed<P: AsRef<Path>>(
        p1: P,
        expected: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let left_contents = super::read_limited(p1.as_ref())?;
        let left_contents = left_contents.as_str();
        let right_contents = expected;
        let r = crate::util::compare_lines(left_contents, right_contents, None);
        eprint!("Diff output:\n{}", r.report());
        assert!(r.is_identical());
        Ok(())
    }

    fn validate_dhcp_config(received: DhcpConfig, expected: DhcpConfig) {
        assert_eq!(received.lease_time_secs, expected.lease_time_secs);
        assert_eq!(received.renewal_time_secs, expected.renewal_time_secs);
        assert_eq!(received.rebinding_time_secs, expected.rebinding_time_secs);
        assert_eq!(received.carbide_nameservers, expected.carbide_nameservers);
        assert_eq!(received.carbide_api_url, expected.carbide_api_url);
        assert_eq!(received.carbide_ntpservers, expected.carbide_ntpservers);
        assert_eq!(
            received.carbide_provisioning_server_ipv4,
            expected.carbide_provisioning_server_ipv4
        );
        assert_eq!(received.carbide_dhcp_server, expected.carbide_dhcp_server);
    }

    fn validate_host_config(received: HostConfig, expected: HostConfig) {
        assert_eq!(received.host_interface_id, expected.host_interface_id);

        let mut vlans_received = received.host_ip_addresses.keys().collect::<Vec<&String>>();
        let mut vlans_expected = expected.host_ip_addresses.keys().collect::<Vec<&String>>();

        vlans_expected.sort();
        vlans_received.sort();

        assert_eq!(vlans_received, vlans_expected);

        for vlan in vlans_received {
            let ip_config_received = received.host_ip_addresses.get(vlan).unwrap();
            let ip_config_expected = expected.host_ip_addresses.get(vlan).unwrap();

            assert_eq!(ip_config_received.fqdn, ip_config_expected.fqdn);
            assert_eq!(ip_config_received.booturl, ip_config_expected.booturl);
            assert_eq!(ip_config_received.gateway, ip_config_expected.gateway);
            assert_eq!(ip_config_received.address, ip_config_expected.address);
            assert_eq!(ip_config_received.prefix, ip_config_expected.prefix);
        }
    }

    #[test]
    fn test_with_tenant_dhcp_server() -> Result<(), Box<dyn std::error::Error>> {
        // The config we received from API server
        // Admin won't be used
        let admin_interface_prefix: IpNetwork = "10.217.5.123/32".parse().unwrap();
        let admin_interface = rpc::FlatInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical.into(),
            virtual_function_id: None,
            vlan_id: 1,
            vni: 1001,
            vpc_vni: 1002,
            gateway: "10.217.5.123".to_string(),
            ip: "10.217.5.123".to_string(),
            interface_prefix: admin_interface_prefix.to_string(),
            vpc_prefixes: vec![],
            vpc_peer_prefixes: vec![],
            vpc_peer_vnis: vec![],
            prefix: "10.217.5.123".to_string(),
            fqdn: "myhost.forge".to_string(),
            booturl: Some("test".to_string()),
            svi_ip: None,
            tenant_vrf_loopback_ip: Some("10.213.2.1".to_string()),
            is_l2_segment: true,
            network_security_group: None,
            internal_uuid: None,
            mtu: None,
        };

        let mut admin_interface_with_mtu = admin_interface.clone();
        admin_interface_with_mtu.mtu = Some(1500);

        assert_eq!(admin_interface.svi_ip, None);

        let interface_prefix_1: IpNetwork = "10.217.5.170/32".parse().unwrap();
        let interface_prefix_2: IpNetwork = "10.217.5.162/32".parse().unwrap();
        let svi_ip: IpAddr = IpAddr::from_str("10.217.5.2").unwrap();

        let tenant_interfaces = vec![
            rpc::FlatInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual.into(),
                virtual_function_id: Some(0),
                vlan_id: 196,
                vni: 1025196,
                vpc_vni: 1025197,
                gateway: "10.217.5.169".to_string(),
                ip: "10.217.5.170".to_string(),
                interface_prefix: interface_prefix_1.to_string(),
                vpc_prefixes: vec!["10.217.5.160/30".to_string(), "10.217.5.168/29".to_string()],
                vpc_peer_prefixes: vec!["10.217.6.176/29".to_string()],
                vpc_peer_vnis: vec![],
                prefix: "10.217.5.169/29".to_string(),
                fqdn: "myhost.forge.1".to_string(),
                booturl: None,
                svi_ip: get_svi_ip(&Some(svi_ip), VpcVirtualizationType::Fnn, true, 24)
                    .unwrap()
                    .map(|x| x.to_string()),
                tenant_vrf_loopback_ip: Some("10.213.2.1".to_string()),
                is_l2_segment: true,
                network_security_group: None,
                internal_uuid: None,
                mtu: None,
            },
            rpc::FlatInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical.into(),
                virtual_function_id: None,
                vlan_id: 185,
                vni: 1025185,
                vpc_vni: 1025186,
                gateway: "10.217.5.161".to_string(),
                ip: "10.217.5.162".to_string(),
                interface_prefix: interface_prefix_2.to_string(),
                vpc_prefixes: vec!["10.217.5.160/30".to_string(), "10.217.5.168/29".to_string()],
                vpc_peer_prefixes: vec!["10.217.6.176/29".to_string()],
                vpc_peer_vnis: vec![],
                prefix: "10.217.5.162/30".to_string(),
                fqdn: "myhost.forge.2".to_string(),
                booturl: None,
                svi_ip: get_svi_ip(&Some(svi_ip), VpcVirtualizationType::Fnn, false, 24)
                    .unwrap()
                    .map(|x| x.to_string()),
                tenant_vrf_loopback_ip: Some("10.213.2.1".to_string()),
                is_l2_segment: true,
                network_security_group: None,
                internal_uuid: None,
                mtu: None,
            },
        ];

        assert_eq!(
            tenant_interfaces[0].svi_ip,
            Some("10.217.5.2/24".to_string())
        );
        assert_eq!(tenant_interfaces[1].svi_ip, None);

        let netconf = rpc::ManagedHostNetworkConfig {
            loopback_ip: "10.217.5.39".to_string(),
            quarantine_state: None,
        };

        let dhcp_config = DhcpConfig {
            carbide_nameservers: vec![Ipv4Addr::from([10, 1, 1, 1])],
            carbide_ntpservers: vec![
                Ipv4Addr::from([127, 0, 0, 1]),
                Ipv4Addr::from([127, 0, 0, 2]),
                Ipv4Addr::from([127, 0, 0, 3]),
            ],
            carbide_provisioning_server_ipv4: Ipv4Addr::from([10, 0, 0, 1]),
            lease_time_secs: 604800,
            renewal_time_secs: 3600,
            rebinding_time_secs: 432000,
            carbide_api_url: None,
            carbide_dhcp_server: Ipv4Addr::from([10, 217, 5, 39]),
        };

        let mut network_config = rpc::ManagedHostNetworkConfigResponse {
            site_global_vpc_vni: None,
            asn: 4259912557,
            datacenter_asn: 11414,
            common_internal_route_target: Some(rpc_common::RouteTarget {
                asn: 11415,
                vni: 200,
            }),
            additional_route_target_imports: vec![rpc_common::RouteTarget {
                asn: 11111,
                vni: 22222,
            }],

            anycast_site_prefixes: vec!["5.255.255.0/24".to_string()],
            tenant_host_asn: Some(65100),
            routing_profile: Some(rpc::RoutingProfile {
                route_target_imports: vec![rpc_common::RouteTarget {
                    asn: 44444,
                    vni: 55555,
                }],
                route_targets_on_exports: vec![rpc_common::RouteTarget {
                    asn: 77415,
                    vni: 800,
                }],
            }),
            traffic_intercept_config: None,

            // yes it's in there twice I dunno either
            dhcp_servers: vec!["10.217.5.197".to_string(), "10.217.5.197".to_string()],
            vni_device: "vxlan48".to_string(),

            managed_host_config: Some(netconf),
            managed_host_config_version: "V1-T1666644937952267".to_string(),

            use_admin_network: true,
            admin_interface: Some(admin_interface),

            tenant_interfaces,
            instance_network_config_version: "V1-T1666644937952999".to_string(),

            network_security_policy_overrides: vec![],
            instance_id: Some(
                uuid::Uuid::try_from("60cef902-9779-4666-8362-c9bb4b37184f")
                    .wrap_err("Uuid::try_from")?
                    .into(),
            ),
            remote_id: "test".to_string(),

            dpu_network_pinger_type: None,

            network_virtualization_type: None,
            vpc_vni: None,
            route_servers: vec!["172.43.0.1".to_string(), "172.43.0.2".to_string()],
            deny_prefixes: vec!["192.0.2.0/24".into(), "198.51.100.0/24".into()],
            site_fabric_prefixes: vec!["10.217.0.0/16".into()],
            vpc_isolation_behavior: rpc::VpcIsolationBehaviorType::VpcIsolationMutual.into(),
            deprecated_deny_prefixes: vec![],
            enable_dhcp: true,
            host_interface_id: Some("60cef902-9779-4666-8362-c9bb4b37185f".to_string()),
            min_dpu_functioning_links: None,
            is_primary_dpu: true,
            internet_l3_vni: Some(1337),
            stateful_acls_enabled: true,
            instance: None,
            dpu_extension_services: vec![],
        };

        let f = tempfile::NamedTempFile::new()?;
        let fp = FPath(f.path().to_owned());

        let g = tempfile::NamedTempFile::new()?;
        let gp = FPath(PathBuf::from(g.path()));

        let h = tempfile::NamedTempFile::new()?;
        let hp = FPath(PathBuf::from(h.path()));

        let i = tempfile::NamedTempFile::new()?;
        let ip = FPath(PathBuf::from(i.path()));

        let service_addrs = ServiceAddresses {
            pxe_ip: Ipv4Addr::from([10, 0, 0, 1]),
            ntpservers: vec![
                Ipv4Addr::from([127, 0, 0, 1]),
                Ipv4Addr::from([127, 0, 0, 2]),
                Ipv4Addr::from([127, 0, 0, 3]),
            ],
            nameservers: vec![IpAddr::from([10, 1, 1, 1])],
        };

        let mut host_config_str =
            dhcp::build_server_host_config(network_config.clone(), &HBNDeviceNames::pre_23())?;
        assert!(!host_config_str.contains("mtu"));

        let mut network_config2 = network_config.clone();
        network_config2.admin_interface = Some(admin_interface_with_mtu);

        host_config_str =
            dhcp::build_server_host_config(network_config2.clone(), &HBNDeviceNames::pre_23())?;
        assert!(host_config_str.contains("mtu: 1500"));
        match super::write_dhcp_server_config(
            &fp,
            &super::DhcpServerPaths {
                server: gp.clone(),
                config: hp.clone(),
                host_config: ip.clone(),
            },
            &network_config,
            &service_addrs,
            &HBNDeviceNames::pre_23(),
        ) {
            Err(err) => {
                panic!("write_dhcp_server error: {err}");
            }
            Ok(false) => {
                panic!("write_dhcp_server says the config didn't change, that's wrong");
            }
            Ok(true) => {
                // success
            }
        }
        let dhcp_contents = super::read_limited(g.path())?;
        assert!(dhcp_contents.contains("vlan1"));

        let dhcp_config_received: DhcpConfig =
            serde_yaml::from_str(&super::read_limited(h.path())?)?;
        validate_dhcp_config(dhcp_config_received, dhcp_config);

        let dhcp_host_config: HostConfig = serde_yaml::from_str(&super::read_limited(i.path())?)?;
        validate_host_config(
            dhcp_host_config,
            HostConfig::try_from(network_config.clone(), "pf0hpf_sf", "pf0vf", "_sf")?,
        );

        // tenant host config.
        network_config.use_admin_network = false;

        host_config_str =
            dhcp::build_server_host_config(network_config.clone(), &HBNDeviceNames::pre_23())?;
        assert!(!host_config_str.contains("mtu"));

        network_config2 = network_config.clone();
        network_config2.tenant_interfaces[0].mtu = Some(1500);
        network_config2.tenant_interfaces[1].mtu = Some(1500);
        host_config_str =
            dhcp::build_server_host_config(network_config2, &HBNDeviceNames::pre_23())?;
        assert!(host_config_str.contains("mtu: 1500"));

        let service_addrs = ServiceAddresses {
            pxe_ip: Ipv4Addr::from([10, 0, 0, 1]),
            ntpservers: vec![],
            nameservers: vec![IpAddr::from([10, 1, 1, 1])],
        };
        match super::write_dhcp_server_config(
            &fp,
            &super::DhcpServerPaths {
                server: gp,
                config: hp,
                host_config: ip,
            },
            &network_config,
            &service_addrs,
            &HBNDeviceNames::pre_23(),
        ) {
            Err(err) => {
                panic!("write_dhcp_server error: {err}");
            }
            Ok(false) => {
                panic!("write_dhcp_server says the config didn't change, that's wrong");
            }
            Ok(true) => {
                // success
            }
        }
        let dhcp_config = DhcpConfig {
            carbide_nameservers: vec![Ipv4Addr::from([10, 1, 1, 1])],
            carbide_ntpservers: vec![],
            carbide_provisioning_server_ipv4: Ipv4Addr::from([10, 0, 0, 1]),
            lease_time_secs: 604800,
            renewal_time_secs: 3600,
            rebinding_time_secs: 432000,
            carbide_api_url: None,
            carbide_dhcp_server: Ipv4Addr::from([10, 217, 5, 39]),
        };
        let dhcp_contents = super::read_limited(g.path())?;
        assert!(dhcp_contents.contains("vlan196"));
        assert!(dhcp_contents.contains("vlan185"));

        let dhcp_config_received: DhcpConfig =
            serde_yaml::from_str(&super::read_limited(h.path())?)?;
        validate_dhcp_config(dhcp_config_received, dhcp_config);

        let dhcp_host_config: HostConfig = serde_yaml::from_str(&super::read_limited(i.path())?)?;
        validate_host_config(
            dhcp_host_config,
            HostConfig::try_from(network_config, "pf0hpf_sf", "pf0vf", "_sf")?,
        );

        Ok(())
    }

    #[test]
    fn test_cmd_return_val() {
        // Primary dpu admin network
        assert_eq!(needed_interface_state(true, true), InterfaceState::Up);

        // Primary dpu tenant network
        assert_eq!(needed_interface_state(true, false), InterfaceState::Up);

        // Primary dpu admin network
        assert_eq!(needed_interface_state(true, true), InterfaceState::Up);

        // Secondary dpu admin network
        assert_eq!(needed_interface_state(false, true), InterfaceState::Down);

        // Secondary dpu tenant network
        assert_eq!(needed_interface_state(false, false), InterfaceState::Up);
    }
}
