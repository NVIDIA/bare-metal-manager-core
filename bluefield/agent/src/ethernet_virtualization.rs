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

use std::path::{Path, PathBuf};
use std::{fs, net::Ipv4Addr, process::Command};

use ::rpc::forge as rpc;
use eyre::WrapErr;
use tracing::{debug, error, trace};

use crate::{daemons, dhcp, frr, hbn, interfaces};

// VPC writes these to various HBN config files
const UPLINKS: [&str; 2] = ["p0_sf", "p1_sf"];

const DPU_PHYSICAL_NETWORK_INTERFACE: &str = "pf0hpf";
const DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER: &str = "pf0vf";

struct Paths {
    dhcp: PathBuf,
    interfaces: PathBuf,
    frr: PathBuf,
    daemons: PathBuf,
}

fn paths(hbn_root: &Path, is_prod_mode: bool) -> Paths {
    let (mut dhcp, mut interfaces, mut frr, mut daemons) = (
        hbn_root.join(dhcp::PATH),
        hbn_root.join(interfaces::PATH),
        hbn_root.join(frr::PATH),
        hbn_root.join(daemons::PATH),
    );
    if is_prod_mode {
        trace!("Ethernet virtualization running in production mode");
    } else {
        trace!("Ethernet virtualization running in test mode");
        dhcp.set_extension("TEST");
        interfaces.set_extension("TEST");
        frr.set_extension("TEST");
        daemons.set_extension("TEST");
    }
    Paths {
        dhcp,
        interfaces,
        frr,
        daemons,
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
    debug!("Desired network config is {:?}", network_config);
    let paths = paths(hbn_root, network_config.is_production_mode);

    let mut has_changes = false;
    let mut errs = vec![];
    match write_dhcp_relay_config(paths.dhcp, network_config, skip_post) {
        Ok(dhcp_changed) => has_changes |= dhcp_changed,
        Err(err) => errs.push(format!("write_dhcp_relay_config: {err:#}")),
    }
    match write_interfaces(paths.interfaces, network_config, skip_post) {
        Ok(eni_changed) => has_changes |= eni_changed,
        Err(err) => errs.push(format!("write_interfaces: {err:#}")),
    }
    match write_frr(paths.frr, network_config, skip_post) {
        Ok(frr_changed) => has_changes |= frr_changed,
        Err(err) => errs.push(format!("write_frr: {err:#}")),
    }
    match write_daemons(paths.daemons, skip_post) {
        Ok(daemons_changed) => has_changes |= daemons_changed,
        Err(err) => errs.push(format!("write_daemons: {err:#}")),
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
) -> eyre::Result<Vec<rpc::InstanceInterfaceStatusObservation>> {
    let mut interfaces = vec![];
    if network_config.use_admin_network {
        let Some(iface) = network_config.admin_interface.as_ref() else {
            eyre::bail!("use_admin_network is true but admin interface is missing");
        };
        interfaces.push(rpc::InstanceInterfaceStatusObservation {
            function_type: iface.function_type,
            virtual_function_id: None,
            mac_address: None, // TODO get this?
            addresses: vec![iface.ip.clone()],
        });
    } else {
        for iface in network_config.tenant_interfaces.iter() {
            interfaces.push(rpc::InstanceInterfaceStatusObservation {
                function_type: iface.function_type,
                virtual_function_id: iface.virtual_function_id,
                mac_address: None, // TODO get this?
                addresses: vec![iface.ip.clone()],
            });
        }
    }
    Ok(interfaces)
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
    if let Err(err) = write(
        dhcp::blank(),
        paths.dhcp,
        "DHCP relay",
        if skip_post {
            None
        } else {
            Some(dhcp::RELOAD_CMD)
        },
    ) {
        errs.push(format!("Write blank DHCP relay: {err:#}"));
    }
    if let Err(err) = write(
        interfaces::blank(),
        paths.interfaces,
        "/etc/network/interfaces",
        if skip_post {
            None
        } else {
            Some(interfaces::RELOAD_CMD)
        },
    ) {
        errs.push(format!("write blank interfaces: {err:#}"));
    }
    if let Err(err) = write(
        frr::blank(),
        paths.frr,
        "frr.conf",
        if skip_post {
            None
        } else {
            Some(frr::RELOAD_CMD)
        },
    ) {
        errs.push(format!("write blank frr: {err:#}"));
    }
    if let Err(err) = write_daemons(paths.daemons, skip_post) {
        errs.push(format!("write_daemons: {err:#}"));
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
    skip_post: bool,
) -> Result<bool, eyre::Report> {
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
    write(
        next_contents,
        path,
        "DHCP relay",
        if skip_post {
            None
        } else {
            Some(dhcp::RELOAD_CMD)
        },
    )
}

fn write_interfaces<P: AsRef<Path>>(
    path: P,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    skip_post: bool,
) -> Result<bool, eyre::Report> {
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
        if skip_post {
            None
        } else {
            Some(interfaces::RELOAD_CMD)
        },
    )
}

fn write_frr<P: AsRef<Path>>(
    path: P,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    skip_post: bool,
) -> Result<bool, eyre::Report> {
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
            ip: admin_interface.ip.clone() + "/32",
        }]
    } else {
        let mut access_vlans = Vec::with_capacity(nc.tenant_interfaces.len());
        for net in &nc.tenant_interfaces {
            access_vlans.push(frr::FrrVlanConfig {
                vlan_id: net.vlan_id,
                ip: net.ip.clone() + "/32",
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
    })?;
    write(
        next_contents,
        path,
        "frr.conf",
        if skip_post {
            None
        } else {
            Some(frr::RELOAD_CMD)
        },
    )
}

/// The etc/frr/daemons file has no templated parts
fn write_daemons<P: AsRef<Path>>(path: P, skip_post: bool) -> Result<bool, eyre::Report> {
    write(
        daemons::build(),
        path,
        "etc/frr/daemons",
        if skip_post {
            None
        } else {
            Some(daemons::RESTART_CMD)
        },
    )
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
    post_cmd: Option<&'static str>,
) -> Result<bool, eyre::Report> {
    // later we will remove the tmp file on drop, but for now it may help with debugging
    let mut path_tmp = path.as_ref().to_path_buf();
    path_tmp.set_extension("TMP");
    fs::write(&path_tmp, next_contents.clone())
        .wrap_err_with(|| format!("fs::write {}", path_tmp.display()))?;

    let path = path.as_ref();
    let has_changed = if path.exists() {
        let current = fs::read_to_string(path)
            .wrap_err_with(|| format!("fs::read_to_string {}", path.display()))?;
        current != next_contents
    } else {
        true
    };
    if has_changed {
        debug!("Applying new {file_type} config");

        let mut path_bak = path.to_path_buf();
        path_bak.set_extension("BAK");
        if path.exists() {
            fs::copy(path, path_bak.clone()).wrap_err("copying file to .BAK")?;
        }

        fs::rename(path_tmp.clone(), path).wrap_err("rename")?;

        match post_cmd {
            Some(post_cmd) => match in_container(post_cmd) {
                Ok(_) => {
                    if path_bak.exists() {
                        std::fs::remove_file(path_bak).wrap_err("removing .BAK on success")?;
                    }
                }
                Err(err) => {
                    // If reload failed we won't be using the new config, so copy the old one back.
                    // This also ensures that we fail on subsequent runs.
                    fs::rename(path, path_tmp).wrap_err("rename path back to TMP")?;
                    if path_bak.exists() {
                        fs::rename(path_bak, path).wrap_err("rename revert from BAK")?;
                    }
                    return Err(err);
                }
            },
            None => {
                tracing::trace!("Skipping reload command");
                if path_bak.exists() {
                    std::fs::remove_file(path_bak).wrap_err("removing .BAK on skip reload")?;
                }
            }
        }
    }

    Ok(has_changed)
}

// Run the given command inside HBN container
fn in_container(cmd: &'static str) -> Result<(), eyre::Report> {
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
        };
        let tenant_interfaces = vec![
            rpc::FlatInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Virtual.into(),
                virtual_function_id: Some(0),
                vlan_id: 196,
                vni: 1025196,
                gateway: "10.217.5.169/29".to_string(),
                ip: "10.217.5.170".to_string(),
            },
            rpc::FlatInterfaceConfig {
                function_type: rpc::InterfaceFunctionType::Physical.into(),
                virtual_function_id: None,
                vlan_id: 185,
                vni: 1025185,
                gateway: "10.217.5.161/30".to_string(),
                ip: "10.217.5.162".to_string(),
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
        };

        let f = tempfile::NamedTempFile::new()?;

        // What we're testing

        let Ok(true) = super::write_dhcp_relay_config(&f, &network_config, true) else {
            panic!("write_dhcp_relay_config either Err-ed or didn't say it wrote");
        };
        let expected = include_str!("../templates/tests/tenant_dhcp-relay.conf");
        compare(&f, expected)?;

        let Ok(true) = super::write_interfaces(&f, &network_config, true) else {
            panic!("write_interfaces either Err-ed or didn't say it wrote");
        };
        let expected = include_str!("../templates/tests/tenant_interfaces");
        compare(&f, expected)?;

        let Ok(true) = super::write_frr(&f, &network_config, true) else {
            panic!("write_frr either Err-ed or didn't say it wrote");
        };
        let expected = include_str!("../templates/tests/tenant_frr.conf");
        compare(&f, expected)?;

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
        let frr_contents = fs::read_to_string(frr_path)?;
        assert_eq!(frr_contents, crate::frr::TMPL_EMPTY);

        Ok(())
    }

    fn compare<P: AsRef<Path>>(p1: P, expected: &str) -> Result<(), Box<dyn std::error::Error>> {
        let contents = fs::read_to_string(p1.as_ref())?;
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
}
