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

use std::collections::{BTreeMap, HashMap};
use std::ffi::CStr;
use std::fs::File;
use std::io::Read;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::{fs, io, net::Ipv4Addr};

use ::rpc::forge::{self as rpc, FlatInterfaceConfig};
use eyre::WrapErr;
use serde::Deserialize;
use tokio::process::Command as TokioCommand;

use crate::command_line::NetworkVirtualizationType;
use crate::{acl_rules, daemons, dhcp, frr, hbn, interfaces, nvue};

// VPC writes these to various HBN config files
const UPLINKS: [&str; 2] = ["p0_sf", "p1_sf"];

const DPU_PHYSICAL_NETWORK_INTERFACE: &str = "pf0hpf";
const DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER: &str = "pf0vf";

/// None of the files we deal with should be bigger than this
const MAX_EXPECTED_SIZE: u64 = 4096;

struct Paths {
    dhcp_relay: PathBuf,
    interfaces: PathBuf,
    frr: PathBuf,
    daemons: PathBuf,
    acl_rules: PathBuf,
    dhcp_server: DhcpServerPaths,
}

struct DhcpServerPaths {
    server: PathBuf,
    config: PathBuf,
    host_config: PathBuf,
}

/// How we tell HBN to notice the new file we wrote
#[derive(Debug)]
struct PostAction {
    cmd: Option<&'static str>,
    path: PathBuf,
    path_bak: PathBuf,
    path_tmp: PathBuf,
}

fn paths(hbn_root: &Path, is_prod_mode: bool) -> Paths {
    let (mut dhcp_relay, mut interfaces, mut frr, mut daemons, mut acl_rules) = (
        hbn_root.join(dhcp::RELAY_PATH),
        hbn_root.join(interfaces::PATH),
        hbn_root.join(frr::PATH),
        hbn_root.join(daemons::PATH),
        hbn_root.join(acl_rules::PATH),
    );

    let mut server = hbn_root.join(dhcp::SERVER_PATH);
    let mut config = hbn_root.join(dhcp::SERVER_CONFIG_PATH);
    let mut host_config = hbn_root.join(dhcp::SERVER_HOST_CONFIG_PATH);

    if is_prod_mode {
        tracing::trace!("Ethernet virtualization running in production mode");
    } else {
        tracing::trace!("Ethernet virtualization running in test mode");
        dhcp_relay.set_extension("TEST");
        interfaces.set_extension("TEST");
        frr.set_extension("TEST");
        daemons.set_extension("TEST");
        acl_rules.as_mut_os_string().push(".TEST");
        server.set_extension("TEST");
        config.set_extension("TEST");
        host_config.set_extension("TEST");
    }
    Paths {
        dhcp_relay,
        interfaces,
        frr,
        daemons,
        acl_rules,
        dhcp_server: DhcpServerPaths {
            server,
            config,
            host_config,
        },
    }
}

// Update network config using nvue (`nv`). Return Ok(true) if the config change, Ok(false) if not.
pub async fn update_nvue(
    hbn_root: &Path,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    // if true don't run the `nv` commands after writing the file
    skip_post: bool,
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

    let physical_name = DPU_PHYSICAL_NETWORK_INTERFACE.to_string() + "_sf";
    let networks = if nc.use_admin_network {
        let admin_interface = nc
            .admin_interface
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Missing admin_interface"))?;
        vec![nvue::PortConfig {
            interface_name: physical_name,
            vlan: admin_interface.vlan_id as u16,
            vni: None,
            gateway_cidr: admin_interface.gateway.clone(),
        }]
    } else {
        let mut ifs = Vec::with_capacity(nc.tenant_interfaces.len());
        for net in &nc.tenant_interfaces {
            let name = if net.function_type == rpc::InterfaceFunctionType::Physical as i32 {
                physical_name.clone()
            } else {
                format!(
                    "{}{}_sf",
                    DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER,
                    match net.virtual_function_id {
                        Some(id) => id,
                        None => {
                            eyre::bail!("Missing virtual function id");
                        }
                    }
                )
            };
            ifs.push(nvue::PortConfig {
                interface_name: name,
                vlan: net.vlan_id as u16,
                vni: Some(net.vni), // TODO should this be nc.vni_device?
                gateway_cidr: net.gateway.clone(),
            });
        }
        ifs
    };

    let hostname = hostname().wrap_err("gethostname error")?;
    let conf = nvue::NvueConfig {
        loopback_ip,
        asn: nc.asn,
        dpu_hostname: hostname.hostname,
        dpu_search_domain: hostname.search_domain,
        uplinks: UPLINKS.into_iter().map(String::from).collect(),
        dhcp_servers: nc.dhcp_servers.clone(),
        route_servers: nc.route_servers.clone(),
        ct_port_configs: networks,
        ct_name: UPLINKS[0].to_string(),

        // FNN only, not used yet
        ct_l3_vni: "FNN".to_string(),
        ct_vrf_loopback: "FNN".to_string(),
        ct_external_access: vec![],
        l3_domains: vec![],
    };
    let next_contents = nvue::build(conf)?;

    let path = hbn_root.join(nvue::PATH);
    let Some(post) = write(next_contents, &path, "NVUE", None).wrap_err(format!("NVUE config at {}", path.display()))? else {
        // config didn't change
        return Ok(false);
    };

    if !skip_post {
        nvue::apply(hbn_root, &path, &post.path_bak, &post.path_tmp).await?;
    }
    Ok(true)
}

/// Write out all the network config files.
/// Returns true if any of them changed.
pub async fn update_files(
    hbn_root: &Path,
    network_config: &rpc::ManagedHostNetworkConfigResponse,
    // if true don't run the reload/restart commands after file update
    skip_post: bool,
    pxe_ip: Ipv4Addr,
    ntp_ip: Option<Ipv4Addr>,
    nameservers: Vec<IpAddr>,
    network_virtualization_type: NetworkVirtualizationType,
) -> eyre::Result<bool> {
    let paths = paths(hbn_root, network_config.is_production_mode);

    let mut errs = vec![];
    let mut post_actions = vec![];
    match write_interfaces(
        paths.interfaces,
        network_config,
        network_virtualization_type,
    ) {
        Ok(Some(post_action)) => {
            post_actions.push(post_action);
        }
        Ok(None) => {}
        Err(err) => errs.push(format!("write_interfaces: {err:#}")),
    }
    match write_frr(paths.frr, network_config, network_virtualization_type) {
        Ok(Some(post_action)) => {
            post_actions.push(post_action);
        }
        Ok(None) => {}
        Err(err) => errs.push(format!("write_frr: {err:#}")),
    }

    // Dhcp server listen on vlan interfaces, so interface must be up before running dhcp server.
    if network_config.enable_dhcp {
        // Start DHCP Server in hbn.
        match write_dhcp_server_config(
            paths.dhcp_relay,
            &paths.dhcp_server,
            network_config,
            pxe_ip,
            ntp_ip,
            nameservers,
        ) {
            Ok(Some((post_action, err))) => {
                post_actions.extend(post_action);
                errs.extend(err);
            }
            Ok(None) => {}
            Err(err) => errs.push(format!("write dhcp server config file: {err:#}")),
        }
    } else {
        match write_dhcp_relay_config(
            paths.dhcp_relay,
            paths.dhcp_server.server,
            network_config,
            network_virtualization_type,
        ) {
            Ok(Some((post_action, err))) => {
                post_actions.extend(post_action);
                errs.extend(err);
            }
            Ok(None) => {}
            Err(err) => errs.push(format!("write_dhcp_relay_config: {err:#}")),
        }
    }
    match write_daemons(paths.daemons) {
        Ok(Some(post_action)) => {
            post_actions.push(post_action);
        }
        Ok(None) => {}
        Err(err) => errs.push(format!("write_daemons: {err:#}")),
    }
    match write_acl_rules(paths.acl_rules, network_config) {
        Ok(Some(post_action)) => {
            post_actions.push(post_action);
        }
        Ok(None) => {}
        Err(err) => errs.push(format!("write_acl_rules: {err:#}")),
    }

    let has_changes = !post_actions.is_empty();
    if !skip_post {
        for post in post_actions {
            let cmd = post.cmd.unwrap_or("");
            match hbn::run_in_container_shell(cmd).await {
                Ok(_) => {
                    if post.path_bak.exists() {
                        if let Err(err) = fs::remove_file(&post.path_bak) {
                            errs.push(format!(
                                "remove .BAK on success {}: {err:#}",
                                post.path_bak.display()
                            ));
                        }
                    }
                }
                Err(err) => {
                    errs.push(format!("running reload cmd '{}': {err:#}", cmd));

                    // If reload failed we won't be using the new config. Move it out of the way..
                    if let Err(err) = fs::rename(&post.path, &post.path_tmp) {
                        errs.push(format!(
                            "rename {} to {} on error: {err:#}",
                            post.path.display(),
                            post.path_tmp.display()
                        ));
                    }
                    // .. and copy the old one back.
                    // This also ensures that we retry writing the config on subsequent runs.
                    if post.path_bak.exists() {
                        if let Err(err) = fs::rename(&post.path_bak, &post.path) {
                            errs.push(format!(
                                "rename {} to {}, reverting on error: {err:#}",
                                post.path_bak.display(),
                                post.path.display()
                            ));
                        }
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

/// Interfaces to report back to server
pub async fn interfaces(
    network_config: &rpc::ManagedHostNetworkConfigResponse,
    factory_mac_address: &str,
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
            interfaces.push(rpc::InstanceInterfaceStatusObservation {
                function_type: iface.function_type,
                virtual_function_id: iface.virtual_function_id,
                mac_address: mac,
                addresses: vec![iface.ip.clone()],
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
    let paths = paths(hbn_root, true);
    dhcp::blank();

    let mut errs = vec![];
    let mut post_actions = vec![];
    match write(
        dhcp::blank(),
        paths.dhcp_relay,
        "DHCP relay",
        Some(dhcp::RELOAD_CMD),
    ) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("Write blank DHCP relay: {err:#}")),
    }
    match write(
        dhcp::blank(),
        paths.dhcp_server.server,
        "DHCP server",
        Some(dhcp::RELOAD_CMD),
    ) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("Write blank DHCP server: {err:#}")),
    }
    match write(
        interfaces::blank(),
        paths.interfaces,
        "/etc/network/interfaces",
        Some(interfaces::RELOAD_CMD),
    ) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("write blank interfaces: {err:#}")),
    }
    match write(frr::blank(), paths.frr, "frr.conf", Some(frr::RELOAD_CMD)) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("write blank frr: {err:#}")),
    }
    match write_daemons(paths.daemons) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("write_daemons: {err:#}")),
    }

    if !skip_post {
        for post in post_actions {
            let cmd = post.cmd.unwrap_or("");
            if let Err(err) = hbn::run_in_container_shell(cmd).await {
                errs.push(format!("reload '{}': {err}", cmd))
            }
        }
    }

    let err_message = errs.join(", ");
    if !err_message.is_empty() {
        tracing::error!(err_message);
    }
}

fn dhcp_servers(nc: &rpc::ManagedHostNetworkConfigResponse) -> Vec<Ipv4Addr> {
    let mut dhcp_servers: Vec<Ipv4Addr> = Vec::with_capacity(nc.dhcp_servers.len());
    for server in &nc.dhcp_servers {
        match server.parse() {
            Ok(s) => dhcp_servers.push(s),
            Err(err) => {
                tracing::error!("Invalid DHCP server from remote: {server}. {err:#}");
            }
        }
    }
    dhcp_servers
}

type WriteResult = Result<Option<(Vec<PostAction>, Vec<String>)>, eyre::Report>;

// In case DHCP server has to be configured in HBN,
// 1. stop dhcp-relay
// 2. Copy dhcp_config file
// 3. Copy host_config file
// 4. Reload supervisord
fn write_dhcp_server_config<P: AsRef<Path>>(
    dhcp_relay_path: P,
    dhcp_server_path: &DhcpServerPaths,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    pxe_ip: Ipv4Addr,
    ntp_ip: Option<Ipv4Addr>,
    nameservers: Vec<IpAddr>,
) -> WriteResult {
    let mut errs = vec![];
    let mut post_actions = vec![];
    match write(dhcp::blank(), dhcp_relay_path, "DHCP relay", None) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("Write blank DHCP relay: {err:#}")),
    }

    let vlan_ids = if nc.use_admin_network {
        let vlan_intf = nc
            .admin_interface
            .as_ref()
            .map(|x| format!("vlan{}", x.vlan_id))
            .ok_or_else(|| eyre::eyre!("Admin interface missing on admin network."))?;
        vec![vlan_intf]
    } else {
        nc.tenant_interfaces
            .iter()
            .map(|x| format!("vlan{}", x.vlan_id))
            .collect()
    };

    let Some(mh_nc) = &nc.managed_host_config else {
        return Err(eyre::eyre!("Loopback IP is missing. Can't write dhcp-server config."))
    };

    let loopback_ip = mh_nc.loopback_ip.parse()?;

    let next_contents =
        dhcp::build_server_supervisord_config(dhcp::DhcpServerSupervisordConfig { vlan_ids })?;
    match write(
        next_contents,
        dhcp_server_path.server.clone(),
        "DHCP server",
        None,
    ) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("Write DHCP server: {err:#}")),
    }

    let nameservers = nameservers
        .iter()
        .filter_map(|x| match x {
            IpAddr::V4(x) => Some(*x),
            _ => None,
        })
        .collect::<Vec<Ipv4Addr>>();

    let next_contents = dhcp::build_server_config(pxe_ip, ntp_ip, nameservers, loopback_ip)?;
    match write(
        next_contents,
        dhcp_server_path.config.clone(),
        "DHCP server config",
        None,
    ) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("Write DHCP server config: {err:#}")),
    }

    let next_contents = dhcp::build_server_host_config(nc.clone())?;
    match write(
        next_contents,
        dhcp_server_path.host_config.clone(),
        "DHCP server host config",
        None,
    ) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("Write DHCP server host config: {err:#}")),
    }

    // Reboot dhcp-server.
    if let Some(val) = post_actions.last_mut() {
        val.cmd = Some(dhcp::RELOAD_DHCP_SERVER);
    }

    Ok(Some((post_actions, errs)))
}

fn write_dhcp_relay_config<P: AsRef<Path>>(
    path: P,
    dhcp_server_path: P,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    network_virtualization_type: NetworkVirtualizationType,
) -> WriteResult {
    let mut errs = vec![];
    let mut post_actions = vec![];

    // Stop dhcp server if running.
    match write(dhcp::blank(), dhcp_server_path, "DHCP server blank", None) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("Write blank DHCP relay: {err:#}")),
    }

    let vlan_ids = if nc.use_admin_network {
        let admin_interface = nc
            .admin_interface
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Missing admin_interface"))?;
        vec![admin_interface.vlan_id]
    } else {
        nc.tenant_interfaces.iter().map(|n| n.vlan_id).collect()
    };
    let next_contents = dhcp::build_relay_config(dhcp::DhcpRelayConfig {
        dhcp_servers: dhcp_servers(nc),
        uplinks: UPLINKS.into_iter().map(String::from).collect(),
        vlan_ids,
        remote_id: nc.remote_id.clone(),
        network_virtualization_type,
    })?;

    match write(next_contents, path, "DHCP relay", None) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("Write blank DHCP relay: {err:#}")),
    };

    // Run supervisorctl reload only once.
    if let Some(val) = post_actions.last_mut() {
        val.cmd = Some(dhcp::RELOAD_CMD);
    }

    Ok(Some((post_actions, errs)))
}

fn write_interfaces<P: AsRef<Path>>(
    path: P,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    network_virtualization_type: NetworkVirtualizationType,
) -> Result<Option<PostAction>, eyre::Report> {
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

    let physical_name = DPU_PHYSICAL_NETWORK_INTERFACE.to_string() + "_sf";
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
                format!(
                    "{}{}_sf",
                    DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER,
                    match net.virtual_function_id {
                        Some(id) => id,
                        None => {
                            // This is for backward compatibility with the old
                            // version of site controller which didn't send the ID
                            // TODO: Remove this in the future and make it an error
                            i.saturating_sub(1) as u32
                        }
                    }
                )
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
        uplinks: UPLINKS.into_iter().map(String::from).collect(),
        vni_device: nc.vni_device.clone(),
        loopback_ip,
        networks,
        network_virtualization_type,
    })?;
    write(
        next_contents,
        path,
        "/etc/network/interfaces",
        Some(interfaces::RELOAD_CMD),
    )
}

fn write_frr<P: AsRef<Path>>(
    path: P,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    network_virtualization_type: NetworkVirtualizationType,
) -> Result<Option<PostAction>, eyre::Report> {
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
            network: admin_interface.ip.clone() + "/32",
            ip: admin_interface.ip.clone(),
        }]
    } else {
        let mut access_vlans = Vec::with_capacity(nc.tenant_interfaces.len());
        for net in &nc.tenant_interfaces {
            access_vlans.push(frr::FrrVlanConfig {
                vlan_id: net.vlan_id,
                network: net.ip.clone() + "/32",
                ip: net.ip.clone(),
            });
        }
        access_vlans
    };

    let next_contents = frr::build(frr::FrrConfig {
        asn: nc.asn,
        uplinks: UPLINKS.into_iter().map(String::from).collect(),
        loopback_ip,
        access_vlans,
        network_virtualization_type,
        vpc_vni: nc.vpc_vni,
        route_servers: nc.route_servers.clone(),
        use_admin_network: nc.use_admin_network,
    })?;
    write(next_contents, path, "frr.conf", Some(frr::RELOAD_CMD))
}

/// The etc/frr/daemons file has no templated parts
fn write_daemons<P: AsRef<Path>>(path: P) -> Result<Option<PostAction>, eyre::Report> {
    write(
        daemons::build(),
        path,
        "etc/frr/daemons",
        Some(daemons::RESTART_CMD),
    )
}

fn write_acl_rules<P: AsRef<Path>>(
    path: P,
    dpu_network_config: &rpc::ManagedHostNetworkConfigResponse,
) -> Result<Option<PostAction>, eyre::Report> {
    let rules_by_interface = instance_interface_acls_by_name(&dpu_network_config.tenant_interfaces);
    // let ingress_interfaces = instance_interface_names(&dpu_network_config.tenant_interfaces);
    let config = acl_rules::AclConfig {
        interfaces: rules_by_interface,
        deny_prefixes: dpu_network_config.deny_prefixes.clone(),
    };
    let contents = acl_rules::build(config)?;
    write(
        contents,
        path,
        "forge-acl.rules",
        Some(acl_rules::RELOAD_CMD),
    )
}

// Compute the interface names along with the specific ACL config for each
// tenant-facing interface.
fn instance_interface_acls_by_name(
    intf_configs: &[FlatInterfaceConfig],
) -> BTreeMap<String, acl_rules::InterfaceRules> {
    intf_configs
        .iter()
        .enumerate()
        .map(|(i, conf)| {
            let interface_name = match conf.function_type() {
                ::rpc::InterfaceFunctionType::Physical => {
                    format!("{}_sf", DPU_PHYSICAL_NETWORK_INTERFACE)
                }
                ::rpc::InterfaceFunctionType::Virtual => {
                    let vfid = conf
                        .virtual_function_id
                        .unwrap_or_else(|| (i as u32).saturating_sub(1));
                    format!("{}{}_sf", DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER, vfid)
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
fn write<P: AsRef<Path>>(
    // What to write into the file
    next_contents: String,
    // The file to write to
    path: P,
    // Human readable description of the file, for error messages
    file_type: &str,
    // Reload or restart command to run after updating the file
    post_cmd: Option<&'static str>,
) -> Result<Option<PostAction>, eyre::Report> {
    // later we will remove the tmp file on drop, but for now it may help with debugging
    let mut path_tmp = path.as_ref().to_path_buf();
    path_tmp.set_extension("TMP");
    fs::write(&path_tmp, next_contents.clone())
        .wrap_err_with(|| format!("fs::write {}", path_tmp.display()))?;

    let path = path.as_ref();
    let has_changed = if path.exists() {
        let current =
            read_limited(path).wrap_err_with(|| format!("read_limited {}", path.display()))?;
        current != next_contents
    } else {
        true
    };
    if !has_changed {
        return Ok(None);
    }
    tracing::debug!("Applying new {file_type} config");

    let mut path_bak = path.to_path_buf();
    path_bak.set_extension("BAK");
    if path.exists() {
        fs::copy(path, path_bak.clone()).wrap_err("copying file to .BAK")?;
    }

    fs::rename(path_tmp.clone(), path).wrap_err("rename")?;

    Ok(Some(PostAction {
        cmd: post_cmd,
        path: path.to_path_buf(),
        path_bak,
        path_tmp,
    }))
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
/// DPU side this must say 16 but discovery should take care of that:
///  mlxconfig -d /dev/mst/mt41686_pciconf0 query NUM_OF_VFS
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
    let cmd = cmd.args(["-j", "address", "show", &ovs_side.to_string()]);
    let ip_out = cmd.output().await?;
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
        return Err(io::Error::new(
            // ErrorKind::FileTooLarge but it's nightly only
            io::ErrorKind::Other,
            format!("{l} > {MAX_EXPECTED_SIZE} bytes"),
        ));
    }
    // in case it changes as we read
    let mut f_limit = f.take(MAX_EXPECTED_SIZE);
    let mut s = String::with_capacity(l as usize);
    f_limit.read_to_string(&mut s)?;
    Ok(s)
}

// Ask the OS for it's hostname.
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
        fqdn,
        hostname,
        search_domain,
    })
}

struct Hostname {
    #[allow(dead_code)]
    fqdn: String,
    hostname: String,
    search_domain: String,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::{Path, PathBuf};

    use eyre::WrapErr;
    use rpc::forge as rpc;
    use utils::models::dhcp::{DhcpConfig, HostConfig};

    use crate::nvue;

    #[ctor::ctor]
    fn setup() {
        forge_host_support::init_logging().unwrap();
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
    fn test_with_tenant() -> Result<(), Box<dyn std::error::Error>> {
        // The config we received from API server
        // Admin won't be used
        let admin_interface = rpc::FlatInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical.into(),
            virtual_function_id: None,
            vlan_id: 1,
            vni: 1001,
            gateway: "10.217.5.123/28".to_string(),
            ip: "10.217.5.123".to_string(),
            vpc_prefixes: vec![],
            prefix: "10.217.5.123/28".to_string(),
            fqdn: "myhost.forge".to_string(),
            booturl: Some("test".to_string()),
        };
        let tenant_interfaces = vec![
            rpc::FlatInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual.into(),
                virtual_function_id: Some(0),
                vlan_id: 196,
                vni: 1025196,
                gateway: "10.217.5.169/29".to_string(),
                ip: "10.217.5.170".to_string(),
                vpc_prefixes: vec!["10.217.5.160/30".to_string(), "10.217.5.168/29".to_string()],
                prefix: "10.217.5.169/29".to_string(),
                fqdn: "myhost.forge.1".to_string(),
                booturl: None,
            },
            rpc::FlatInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical.into(),
                virtual_function_id: None,
                vlan_id: 185,
                vni: 1025185,
                gateway: "10.217.5.161/30".to_string(),
                ip: "10.217.5.162".to_string(),
                vpc_prefixes: vec!["10.217.5.160/30".to_string(), "10.217.5.168/29".to_string()],
                prefix: "10.217.5.162/30".to_string(),
                fqdn: "myhost.forge.2".to_string(),
                booturl: None,
            },
        ];
        let netconf = rpc::ManagedHostNetworkConfig {
            loopback_ip: "10.217.5.39".to_string(),
        };
        let network_config = rpc::ManagedHostNetworkConfigResponse {
            is_production_mode: false,
            asn: 4259912557,
            // yes it's in there twice I dunno either
            dhcp_servers: vec!["10.217.5.197".to_string(), "10.217.5.197".to_string()],
            vni_device: "vxlan5555".to_string(),

            managed_host_config: Some(netconf),
            managed_host_config_version: "V1-T1666644937952267".to_string(),

            use_admin_network: false,
            admin_interface: Some(admin_interface),

            tenant_interfaces,
            instance_config_version: "V1-T1666644937952999".to_string(),

            instance_id: Some(
                uuid::Uuid::try_from("60cef902-9779-4666-8362-c9bb4b37184f")
                    .wrap_err("Uuid::try_from")?
                    .into(),
            ),
            remote_id: "test".to_string(),

            // For FNN:
            // vpc_vni: Some(2024500),
            // route_servers: vec![],

            // For ETV:
            network_virtualization_type: None,
            vpc_vni: None,
            route_servers: vec!["172.43.0.1".to_string(), "172.43.0.2".to_string()],
            deny_prefixes: vec!["192.0.2.0/24".into(), "198.51.100.0/24".into()],
            enable_dhcp: false,
            host_interface_id: Some("60cef902-9779-4666-8362-c9bb4b37185f".to_string()),
        };

        let f = tempfile::NamedTempFile::new()?;
        let g = tempfile::NamedTempFile::new()?;

        // What we're testing

        match super::write_dhcp_relay_config(
            &f,
            &g,
            &network_config,
            crate::DEFAULT_NETWORK_VIRTUALIZATION_TYPE,
        ) {
            Err(err) => {
                panic!("write_dhcp_relay_config error: {err}");
            }
            Ok(None) => {
                panic!("write_dhcp_relay_config says the config didn't change, that's wrong");
            }
            Ok(Some(_)) => {
                // success
            }
        }
        let expected = include_str!("../templates/tests/tenant_dhcp-relay.conf");
        compare(&f, expected)?;

        match super::write_interfaces(
            &f,
            &network_config,
            crate::DEFAULT_NETWORK_VIRTUALIZATION_TYPE,
        ) {
            Err(err) => {
                panic!("write_interfaces error: {err}");
            }
            Ok(None) => {
                panic!("write_interfaces says the config didn't change, that's wrong");
            }
            Ok(Some(_)) => {
                // success
            }
        }
        let expected = include_str!("../templates/tests/tenant_interfaces");
        compare(&f, expected)?;

        match super::write_frr(
            &f,
            &network_config,
            crate::DEFAULT_NETWORK_VIRTUALIZATION_TYPE,
        ) {
            Err(err) => {
                panic!("write_frr error: {err}");
            }
            Ok(None) => {
                panic!("write_frr says the config didn't change, that's wrong");
            }
            Ok(Some(_)) => {
                // success
            }
        }
        let expected = include_str!("../templates/tests/tenant_frr.conf");
        compare(&f, expected)?;

        match super::write_acl_rules(&f, &network_config) {
            Err(err) => {
                panic!("write_acl_rules error: {err}");
            }
            Ok(None) => {
                panic!("write_acl_rules says the config didn't change, that's wrong");
            }
            Ok(Some(_)) => {
                // success
            }
        }
        let expected = include_str!("../templates/tests/tenant_acl_rules");
        compare_diffed(&f, expected)?;

        Ok(())
    }

    #[tokio::test]
    async fn test_reset() -> Result<(), Box<dyn std::error::Error>> {
        // setup
        let td = tempfile::tempdir()?;
        let hbn_root = td.path();
        fs::create_dir_all(hbn_root.join("etc/frr"))?;
        fs::create_dir_all(hbn_root.join("etc/network"))?;
        fs::create_dir_all(hbn_root.join("etc/supervisor/conf.d"))?;

        // test
        super::reset(hbn_root, true).await;

        // check
        let frr_path = hbn_root.join("etc/frr/frr.conf");
        let frr_contents = super::read_limited(frr_path)?;
        assert_eq!(frr_contents, crate::frr::TMPL_EMPTY);

        // check dhcp server
        let dhcp_path = hbn_root.join("etc/supervisor/conf.d/default-forge-dhcp-server.conf");
        let dhcp_contents = super::read_limited(dhcp_path)?;
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
        let json = r#"[{"ifindex":26,"ifname":"pf0vf0_sf_r","flags":["BROADCAST","MULTICAST","UP","LOWER_UP"],"mtu":9216,"qdisc":"mq","master":"ovs-system","operstate":"UP","group":"default","txqlen":1000,"link_type":"ether","address":"4e:1f:bd:97:23:3e","broadcast":"ff:ff:ff:ff:ff:ff","altnames":["enp3s0f0npf0sf131072"],"addr_info":[{"family":"inet6","local":"fe80::4c1f:bdff:fe97:233e","prefixlen":64,"scope":"link","valid_life_time":4294967295,"preferred_life_time":4294967295}]}]"#;
        let out: Vec<super::IpShow> = serde_json::from_str(json)?;
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].address, "4e:1f:bd:97:23:3e");
        Ok(())
    }

    #[test]
    fn test_nvue_is_yaml() -> Result<(), Box<dyn std::error::Error>> {
        let networks = vec![nvue::PortConfig {
            interface_name: super::DPU_PHYSICAL_NETWORK_INTERFACE.to_string() + "_sf",
            vlan: 123u16,
            vni: Some(5555),
            gateway_cidr: "10.217.4.65/26".to_string(),
        }];
        let hostname = super::hostname().wrap_err("gethostname error")?;
        let conf = nvue::NvueConfig {
            loopback_ip: "10.217.5.39".to_string(),
            asn: 65535,
            dpu_hostname: hostname.hostname,
            dpu_search_domain: hostname.search_domain,
            uplinks: super::UPLINKS.into_iter().map(String::from).collect(),
            dhcp_servers: vec!["10.217.5.197".to_string()],
            route_servers: vec!["172.43.0.1".to_string(), "172.43.0.2".to_string()],
            ct_port_configs: networks,
            ct_name: super::UPLINKS[0].to_string(),

            // FNN only, not used yet
            ct_l3_vni: "FNN".to_string(),
            ct_vrf_loopback: "FNN".to_string(),
            ct_external_access: vec![],
            l3_domains: vec![],
        };
        let startup_yaml = nvue::build(conf)?;
        const ERR_FILE: &str = "/tmp/test_nvue_startup.yaml";
        let yaml_obj: Vec<serde_yaml::Value> = serde_yaml::from_str(&startup_yaml)
            .map_err(|err| {
                let mut f = fs::File::create(ERR_FILE).unwrap();
                f.write_all(startup_yaml.as_bytes()).unwrap();
                err
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
                    println!("GOT: {}", g);
                    println!("EXP: {}", e);
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
        assert_eq!(received.carbide_ntpserver, expected.carbide_ntpserver);
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
        let admin_interface = rpc::FlatInterfaceConfig {
            function_type: rpc::InterfaceFunctionType::Physical.into(),
            virtual_function_id: None,
            vlan_id: 1,
            vni: 1001,
            gateway: "10.217.5.123".to_string(),
            ip: "10.217.5.123".to_string(),
            vpc_prefixes: vec![],
            prefix: "10.217.5.123".to_string(),
            fqdn: "myhost.forge".to_string(),
            booturl: Some("test".to_string()),
        };
        let tenant_interfaces = vec![
            rpc::FlatInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual.into(),
                virtual_function_id: Some(0),
                vlan_id: 196,
                vni: 1025196,
                gateway: "10.217.5.169".to_string(),
                ip: "10.217.5.170".to_string(),
                vpc_prefixes: vec!["10.217.5.160/30".to_string(), "10.217.5.168/29".to_string()],
                prefix: "10.217.5.169/29".to_string(),
                fqdn: "myhost.forge.1".to_string(),
                booturl: None,
            },
            rpc::FlatInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical.into(),
                virtual_function_id: None,
                vlan_id: 185,
                vni: 1025185,
                gateway: "10.217.5.161".to_string(),
                ip: "10.217.5.162".to_string(),
                vpc_prefixes: vec!["10.217.5.160/30".to_string(), "10.217.5.168/29".to_string()],
                prefix: "10.217.5.162/30".to_string(),
                fqdn: "myhost.forge.2".to_string(),
                booturl: None,
            },
        ];
        let netconf = rpc::ManagedHostNetworkConfig {
            loopback_ip: "10.217.5.39".to_string(),
        };

        let dhcp_config = DhcpConfig {
            carbide_nameservers: vec![Ipv4Addr::from([10, 1, 1, 1])],
            carbide_ntpserver: Some(Ipv4Addr::from([127, 0, 0, 1])),
            carbide_provisioning_server_ipv4: Ipv4Addr::from([10, 0, 0, 1]),
            lease_time_secs: 604800,
            renewal_time_secs: 3600,
            rebinding_time_secs: 432000,
            carbide_api_url: None,
            carbide_dhcp_server: Ipv4Addr::from([10, 217, 5, 39]),
        };

        let mut network_config = rpc::ManagedHostNetworkConfigResponse {
            is_production_mode: false,
            asn: 4259912557,
            // yes it's in there twice I dunno either
            dhcp_servers: vec!["10.217.5.197".to_string(), "10.217.5.197".to_string()],
            vni_device: "vxlan5555".to_string(),

            managed_host_config: Some(netconf),
            managed_host_config_version: "V1-T1666644937952267".to_string(),

            use_admin_network: true,
            admin_interface: Some(admin_interface),

            tenant_interfaces,
            instance_config_version: "V1-T1666644937952999".to_string(),

            instance_id: Some(
                uuid::Uuid::try_from("60cef902-9779-4666-8362-c9bb4b37184f")
                    .wrap_err("Uuid::try_from")?
                    .into(),
            ),
            remote_id: "test".to_string(),

            network_virtualization_type: None,
            vpc_vni: None,
            route_servers: vec!["172.43.0.1".to_string(), "172.43.0.2".to_string()],
            deny_prefixes: vec!["192.0.2.0/24".into(), "198.51.100.0/24".into()],
            enable_dhcp: true,
            host_interface_id: Some("60cef902-9779-4666-8362-c9bb4b37185f".to_string()),
        };

        let f = tempfile::NamedTempFile::new()?;
        let g = tempfile::NamedTempFile::new()?;
        let h = tempfile::NamedTempFile::new()?;
        let i = tempfile::NamedTempFile::new()?;

        match super::write_dhcp_server_config(
            &f,
            &super::DhcpServerPaths {
                server: PathBuf::from(g.path()),
                config: PathBuf::from(h.path()),
                host_config: PathBuf::from(i.path()),
            },
            &network_config,
            Ipv4Addr::from([10, 0, 0, 1]),
            Some(Ipv4Addr::from([127, 0, 0, 1])),
            vec![IpAddr::from([10, 1, 1, 1])],
        ) {
            Err(err) => {
                panic!("write_dhcp_server error: {err}");
            }
            Ok(None) => {
                panic!("write_dhcp_server says the config didn't change, that's wrong");
            }
            Ok(Some(_)) => {
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
            HostConfig::try_from(network_config.clone())?,
        );

        // tenant host config.
        network_config.use_admin_network = false;

        match super::write_dhcp_server_config(
            &f,
            &super::DhcpServerPaths {
                server: PathBuf::from(g.path()),
                config: PathBuf::from(h.path()),
                host_config: PathBuf::from(i.path()),
            },
            &network_config,
            Ipv4Addr::from([10, 0, 0, 1]),
            None,
            vec![IpAddr::from([10, 1, 1, 1])],
        ) {
            Err(err) => {
                panic!("write_dhcp_server error: {err}");
            }
            Ok(None) => {
                panic!("write_dhcp_server says the config didn't change, that's wrong");
            }
            Ok(Some(_)) => {
                // success
            }
        }
        let dhcp_config = DhcpConfig {
            carbide_nameservers: vec![Ipv4Addr::from([10, 1, 1, 1])],
            carbide_ntpserver: None,
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
            HostConfig::try_from(network_config.clone())?,
        );

        Ok(())
    }
}
