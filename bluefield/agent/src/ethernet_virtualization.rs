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

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::{fs, io, net::Ipv4Addr, process::Command};

use ::rpc::forge::{self as rpc, FlatInterfaceConfig};
use eyre::WrapErr;
use serde::Deserialize;
use tracing::{debug, error, trace};

use crate::{acl_rules, daemons, dhcp, frr, hbn, interfaces};

// VPC writes these to various HBN config files
const UPLINKS: [&str; 2] = ["p0_sf", "p1_sf"];

const DPU_PHYSICAL_NETWORK_INTERFACE: &str = "pf0hpf";
const DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER: &str = "pf0vf";

/// None of the files we deal with should be bigger than this
const MAX_EXPECTED_SIZE: u64 = 4096;

struct Paths {
    dhcp: PathBuf,
    interfaces: PathBuf,
    frr: PathBuf,
    daemons: PathBuf,
    acl_rules: PathBuf,
}

/// How we tell HBN to notice the new file we wrote
#[derive(Debug)]
struct PostAction {
    cmd: &'static str,
    path: PathBuf,
    path_bak: PathBuf,
    path_tmp: PathBuf,
}

fn paths(hbn_root: &Path, is_prod_mode: bool) -> Paths {
    let (mut dhcp, mut interfaces, mut frr, mut daemons, mut acl_rules) = (
        hbn_root.join(dhcp::PATH),
        hbn_root.join(interfaces::PATH),
        hbn_root.join(frr::PATH),
        hbn_root.join(daemons::PATH),
        hbn_root.join(acl_rules::PATH),
    );
    if is_prod_mode {
        trace!("Ethernet virtualization running in production mode");
    } else {
        trace!("Ethernet virtualization running in test mode");
        dhcp.set_extension("TEST");
        interfaces.set_extension("TEST");
        frr.set_extension("TEST");
        daemons.set_extension("TEST");
        acl_rules.as_mut_os_string().push(".TEST");
    }
    Paths {
        dhcp,
        interfaces,
        frr,
        daemons,
        acl_rules,
    }
}

/// Write out all the network config files.
/// Returns true if any of them changed.
pub fn update(
    hbn_root: &Path,
    network_config: &rpc::ManagedHostNetworkConfigResponse,
    // if true don't run the reload/restart commands after file update
    skip_post: bool,
) -> eyre::Result<bool> {
    trace!("Desired network config is {:?}", network_config);
    let paths = paths(hbn_root, network_config.is_production_mode);

    let mut errs = vec![];
    let mut post_actions = vec![];
    match write_dhcp_relay_config(paths.dhcp, network_config) {
        Ok(Some(post_action)) => {
            post_actions.push(post_action);
        }
        Ok(None) => {}
        Err(err) => errs.push(format!("write_dhcp_relay_config: {err:#}")),
    }
    match write_interfaces(paths.interfaces, network_config) {
        Ok(Some(post_action)) => {
            post_actions.push(post_action);
        }
        Ok(None) => {}
        Err(err) => errs.push(format!("write_interfaces: {err:#}")),
    }
    match write_frr(paths.frr, network_config) {
        Ok(Some(post_action)) => {
            post_actions.push(post_action);
        }
        Ok(None) => {}
        Err(err) => errs.push(format!("write_frr: {err:#}")),
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
            match in_container_shell(post.cmd) {
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
                    errs.push(format!("running reload cmd '{}': {err:#}", post.cmd));

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
        error!(err_message);
        eyre::bail!(err_message);
    }
    Ok(has_changes)
}

/// Interfaces to report back to server
pub fn interfaces(
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
        let container_id = hbn::get_hbn_container_id()?;
        for iface in network_config.tenant_interfaces.iter() {
            let mac = if iface.function_type == rpc::InterfaceFunctionType::Physical as i32 {
                Some(factory_mac_address.to_string())
            } else {
                match tenant_vf_mac(&container_id, iface.vlan_id) {
                    Ok(mac) => Some(mac),
                    Err(err) => {
                        tracing::error!(%err, vlan_id=iface.vlan_id, "Error fetching tenant VF MAC");
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
pub fn reset(
    hbn_root: &Path,
    // if true don't run the reload/restart commands after file update
    skip_post: bool,
) {
    debug!("Setting network config to blank");
    let paths = paths(hbn_root, true);
    dhcp::blank();

    let mut errs = vec![];
    let mut post_actions = vec![];
    match write(dhcp::blank(), paths.dhcp, "DHCP relay", dhcp::RELOAD_CMD) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("Write blank DHCP relay: {err:#}")),
    }
    match write(
        interfaces::blank(),
        paths.interfaces,
        "/etc/network/interfaces",
        interfaces::RELOAD_CMD,
    ) {
        Ok(Some(post)) => post_actions.push(post),
        Ok(None) => {}
        Err(err) => errs.push(format!("write blank interfaces: {err:#}")),
    }
    match write(frr::blank(), paths.frr, "frr.conf", frr::RELOAD_CMD) {
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
            if let Err(err) = in_container_shell(post.cmd) {
                errs.push(format!("reload '{}': {err}", post.cmd))
            }
        }
    }

    let err_message = errs.join(", ");
    if !err_message.is_empty() {
        error!(err_message);
    }
}

fn dhcp_servers(nc: &rpc::ManagedHostNetworkConfigResponse) -> Vec<Ipv4Addr> {
    let mut dhcp_servers: Vec<Ipv4Addr> = Vec::with_capacity(nc.dhcp_servers.len());
    for server in &nc.dhcp_servers {
        match server.parse() {
            Ok(s) => dhcp_servers.push(s),
            Err(err) => {
                error!("Invalid DHCP server from remote: {server}. {err:#}");
            }
        }
    }
    dhcp_servers
}

fn write_dhcp_relay_config<P: AsRef<Path>>(
    path: P,
    nc: &rpc::ManagedHostNetworkConfigResponse,
) -> Result<Option<PostAction>, eyre::Report> {
    let vlan_ids = if nc.use_admin_network {
        let admin_interface = nc
            .admin_interface
            .as_ref()
            .ok_or_else(|| eyre::eyre!("Missing admin_interface"))?;
        vec![admin_interface.vlan_id]
    } else {
        nc.tenant_interfaces.iter().map(|n| n.vlan_id).collect()
    };
    let next_contents = dhcp::build(dhcp::DhcpConfig {
        dhcp_servers: dhcp_servers(nc),
        uplinks: UPLINKS.into_iter().map(String::from).collect(),
        vlan_ids,
        remote_id: nc.remote_id.clone(),
        network_virtualization_type: nc.network_virtualization_type,
    })?;
    write(next_contents, path, "DHCP relay", dhcp::RELOAD_CMD)
}

fn write_interfaces<P: AsRef<Path>>(
    path: P,
    nc: &rpc::ManagedHostNetworkConfigResponse,
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
        network_virtualization_type: nc.network_virtualization_type,
    })?;
    write(
        next_contents,
        path,
        "/etc/network/interfaces",
        interfaces::RELOAD_CMD,
    )
}

fn write_frr<P: AsRef<Path>>(
    path: P,
    nc: &rpc::ManagedHostNetworkConfigResponse,
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
        network_virtualization_type: nc.network_virtualization_type,
        vpc_vni: nc.vpc_vni,
        route_servers: nc.route_servers.clone(),
        use_admin_network: nc.use_admin_network,
    })?;
    write(next_contents, path, "frr.conf", frr::RELOAD_CMD)
}

/// The etc/frr/daemons file has no templated parts
fn write_daemons<P: AsRef<Path>>(path: P) -> Result<Option<PostAction>, eyre::Report> {
    write(
        daemons::build(),
        path,
        "etc/frr/daemons",
        daemons::RESTART_CMD,
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
    write(contents, path, "forge-acl.rules", acl_rules::RELOAD_CMD)
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
// Returns true if the file has changes, false othewise.
fn write<P: AsRef<Path>>(
    // What to write into the file
    next_contents: String,
    // The file to write to
    path: P,
    // Human readable description of the file, for error messages
    file_type: &str,
    // Reload or restart command to run after updating the file
    post_cmd: &'static str,
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
    debug!("Applying new {file_type} config");

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

#[derive(Deserialize, Debug)]
struct Fdb {
    mac: String,
    ifname: String,
    state: String,
}

#[derive(Deserialize, Debug)]
// This has many more fields, only parse the one we check
struct IpShow {
    address: String,
}

/// The host/tenant side MAC address of a VF
///
/// To use a VF a tenant needs to do this on their host:
///  - echo 16 > /sys/class/net/eth0/device/sriov_numvfs
///  - ip link set <name> up
/// DPU side this must say 16 but discovery should take care of that:
///  mlxconfig -d /dev/mst/mt41686_pciconf0 query NUM_OF_VFS
fn tenant_vf_mac(container_id: &str, vlan_id: u32) -> eyre::Result<String> {
    // This should give us four elements
    let fdb_json = hbn::run_in_container(
        container_id,
        &["bridge", "-j", "fdb", "show", "vlan", &vlan_id.to_string()],
        true,
    )?;
    let mut fdb: Vec<Fdb> = serde_json::from_str(&fdb_json)?;

    // Two of them were permanent, ignore them, leaving only the host side and our side
    fdb.retain(|f| f.state != "permanent");
    if fdb.len() != 2 {
        eyre::bail!("After 'permanent' removal expected 2 remaining elements, got {fdb:?}");
    }
    if fdb[0].ifname != fdb[1].ifname {
        eyre::bail!(
            "After 'permanent' removal expected two entries with same ifname, got '{}' and '{}'",
            fdb[0].ifname,
            fdb[1].ifname
        );
    }

    // Find our side - both will have the same ifname
    let ovs_side = format!("{}_r", fdb[0].ifname);
    let mut cmd = Command::new("ip");
    let cmd = cmd.args(["-j", "address", "show", &ovs_side.to_string()]);
    let ip_out = cmd.output()?;
    if !ip_out.status.success() {
        debug!(
            "STDERR {}: {}",
            super::pretty_cmd(cmd),
            String::from_utf8_lossy(&ip_out.stderr)
        );
        return Err(eyre::eyre!(
            "{} for cmd '{}'",
            ip_out.status, // includes the string "exit status"
            super::pretty_cmd(cmd)
        ));
    }

    let ip_json = String::from_utf8_lossy(&ip_out.stdout).to_string();
    let ip_show: Vec<IpShow> = serde_json::from_str(&ip_json)?;
    if ip_show.len() != 1 {
        eyre::bail!("Getting local side MAC should return 1 entry, got {ip_show:?}");
    }

    // And ignore our side
    fdb.retain(|f| f.mac != ip_show[0].address);

    // And then there was one
    if fdb.len() != 1 {
        eyre::bail!("After all removals there should be 1 entry, {fdb:?}");
    }
    Ok(fdb.remove(0).mac) // And then there were none
}

// Run the given command inside HBN container in a shell. Ignore the output.
fn in_container_shell(cmd: &'static str) -> Result<(), eyre::Report> {
    let container_id = hbn::get_hbn_container_id()?;
    let out = Command::new("/usr/bin/crictl")
        .args(["exec", &container_id, "bash", "-c", cmd])
        .output()
        .wrap_err(cmd)?;
    if !out.status.success() {
        return Err(eyre::eyre!(
            "Failed executing '{cmd}' in container. Check logs in /var/log/doca/hbn/frr/frr-reload.log. \nSTDOUT: {}\nSTDERR: {}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        ));
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use ::rpc::forge as rpc;
    use eyre::WrapErr;

    #[ctor::ctor]
    fn setup() {
        forge_host_support::init_logging().unwrap();
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
            },
            rpc::FlatInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical.into(),
                virtual_function_id: None,
                vlan_id: 185,
                vni: 1025185,
                gateway: "10.217.5.161/30".to_string(),
                ip: "10.217.5.162".to_string(),
                vpc_prefixes: vec!["10.217.5.160/30".to_string(), "10.217.5.168/29".to_string()],
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
            // network_virtualization_type: Some(rpc::VpcVirtualizationType::ForgeNativeNetworking as i32),
            // vpc_vni: Some(2024500),
            // route_servers: vec![],

            // For ETV:
            network_virtualization_type: None,
            vpc_vni: None,
            route_servers: vec!["172.43.0.1".to_string(), "172.43.0.2".to_string()],
            deny_prefixes: vec!["192.0.2.0/24".into(), "198.51.100.0/24".into()],
        };

        let f = tempfile::NamedTempFile::new()?;

        // What we're testing

        match super::write_dhcp_relay_config(&f, &network_config) {
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

        match super::write_interfaces(&f, &network_config) {
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

        match super::write_frr(&f, &network_config) {
            Err(err) => {
                panic!("write_frr error: {err}");
            }
            Ok(None) => {
                panic!("write_free says the config didn't change, that's wrong");
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

    #[test]
    fn test_reset() -> Result<(), Box<dyn std::error::Error>> {
        // setup
        let td = tempfile::tempdir()?;
        let hbn_root = td.path();
        fs::create_dir_all(hbn_root.join("etc/frr"))?;
        fs::create_dir_all(hbn_root.join("etc/network"))?;
        fs::create_dir_all(hbn_root.join("etc/supervisor/conf.d"))?;

        // test
        super::reset(hbn_root, true);

        // check
        let frr_path = hbn_root.join("etc/frr/frr.conf");
        let frr_contents = super::read_limited(frr_path)?;
        assert_eq!(frr_contents, crate::frr::TMPL_EMPTY);

        Ok(())
    }

    #[test]
    fn test_parse_fdb() -> Result<(), Box<dyn std::error::Error>> {
        let json = r#"[{"mac":"7e:f6:b2:b2:f0:97","ifname":"pf0vf0_sf","vlan":21,"flags":[],"master":"br_default","state":""},{"mac":"4e:1f:bd:97:23:3e","ifname":"pf0vf0_sf","vlan":21,"flags":[],"master":"br_default","state":""},{"mac":"00:04:4b:b7:e5:00","ifname":"br_default","vlan":21,"flags":[],"master":"br_default","state":"permanent"},{"mac":"16:3c:3d:a8:81:40","ifname":"vxlan5555","vlan":21,"flags":[],"master":"br_default","state":"permanent"}]"#;
        let out: Vec<super::Fdb> = serde_json::from_str(json)?;
        assert_eq!(out.len(), 4);
        assert_eq!(out[0].mac, "7e:f6:b2:b2:f0:97");
        assert_eq!(out[2].state, "permanent");
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
}
