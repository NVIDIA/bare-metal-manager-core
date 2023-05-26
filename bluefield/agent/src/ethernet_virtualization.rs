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

use std::{fs, net::Ipv4Addr, path::Path, process::Command};

use ::rpc::forge as rpc;
use eyre::WrapErr;
use tracing::{debug, error, trace};

use crate::{dhcp, frr, hbn, interfaces};

/// HBN container root
pub const HBN_ROOT: &str = "/var/lib/hbn";

// VPC writes these to various HBN config files
const UPLINKS: [&str; 2] = ["p0_sf", "p1_sf"];

const DPU_PHYSICAL_NETWORK_INTERFACE: &str = "pf0hpf";
const DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER: &str = "pf0vf";

pub fn update(
    hbn_root: &str,
    network_config: &rpc::ManagedHostNetworkConfigResponse,
    status_out: &mut rpc::DpuNetworkStatus,
    skip_reload: bool,
) {
    let hbn_root = Path::new(hbn_root);
    let (mut dhcp_path, mut interfaces_path, mut frr_path) = (
        hbn_root.join(dhcp::PATH),
        hbn_root.join(interfaces::PATH),
        hbn_root.join(frr::PATH),
    );

    if network_config.is_production_mode {
        trace!("Ethernet virtualization running in production mode");
    } else {
        trace!("Ethernet virtualization running in test mode");
        dhcp_path.set_extension("TEST");
        interfaces_path.set_extension("TEST");
        frr_path.set_extension("TEST");
    }
    debug!("Desired network config is {:?}", network_config);

    let mut errs = vec![];
    if let Err(err) = write_dhcp_relay_config(dhcp_path, network_config, skip_reload) {
        errs.push(format!("write_dhcp_relay_config: {err:#}"));
    }
    if let Err(err) = write_interfaces(interfaces_path, network_config, skip_reload) {
        errs.push(format!("write_interfaces: {err:#}"));
    }
    if let Err(err) = write_frr(frr_path, network_config, skip_reload) {
        errs.push(format!("write_frr: {err:#}"));
    }
    let err_message = errs.join(", ");
    if !err_message.is_empty() {
        error!(err_message);
        status_out.network_config_error = Some(err_message);
        return;
    }

    status_out.network_config_version = Some(network_config.managed_host_config_version.clone());
    status_out.instance_id = network_config.instance_id.clone();
    status_out.instance_config_version = if network_config.instance_config_version.is_empty() {
        None
    } else {
        Some(network_config.instance_config_version.clone())
    };

    let mut interfaces = vec![];
    if network_config.use_admin_network {
        let Some(iface) = network_config.admin_interface.as_ref() else {
            status_out.network_config_error = Some("use_admin_network is true but admin interface is missing".to_string());
            return;
        };
        interfaces.push(rpc::InstanceInterfaceStatusObservation {
            function_type: iface.function,
            virtual_function_id: None,
            mac_address: None, // TODO get this?
            addresses: vec![iface.ip.clone()],
        });
    } else {
        for (i, iface) in network_config.tenant_interfaces.iter().enumerate() {
            interfaces.push(rpc::InstanceInterfaceStatusObservation {
                function_type: iface.function,
                virtual_function_id: if iface.function
                    == rpc::InterfaceFunctionType::Physical as i32
                {
                    None
                } else {
                    Some(i as u32)
                },
                mac_address: None, // TODO get this?
                addresses: vec![iface.ip.clone()],
            });
        }
    }
    status_out.interfaces = interfaces;
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
    skip_reload: bool,
) -> Result<(), eyre::Report> {
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
    })?;
    write(
        next_contents,
        path,
        "DHCP relay",
        if skip_reload {
            None
        } else {
            Some(dhcp::RELOAD_CMD)
        },
    )
}

fn write_interfaces<P: AsRef<Path>>(
    path: P,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    skip_reload: bool,
) -> Result<(), eyre::Report> {
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
        let mut has_used_physical = false;
        for (i, net) in nc.tenant_interfaces.iter().enumerate() {
            let name = if net.function == rpc::InterfaceFunctionType::Physical as i32 {
                has_used_physical = true;
                physical_name.clone()
            } else {
                format!(
                    "{}{}_sf",
                    DPU_VIRTUAL_NETWORK_INTERFACE_IDENTIFIER,
                    if has_used_physical { i - 1 } else { i }
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
    })?;
    write(
        next_contents,
        path,
        "/etc/network/interfaces",
        if skip_reload {
            None
        } else {
            Some(interfaces::RELOAD_CMD)
        },
    )
}

fn write_frr<P: AsRef<Path>>(
    path: P,
    nc: &rpc::ManagedHostNetworkConfigResponse,
    skip_reload: bool,
) -> Result<(), eyre::Report> {
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
            ip: admin_interface.ip.clone(),
        }]
    } else {
        let mut access_vlans = Vec::with_capacity(nc.tenant_interfaces.len());
        for net in &nc.tenant_interfaces {
            access_vlans.push(frr::FrrVlanConfig {
                vlan_id: net.vlan_id,
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
    })?;
    write(
        next_contents,
        path,
        "frr.conf",
        if skip_reload {
            None
        } else {
            Some(frr::RELOAD_CMD)
        },
    )
}

// Update configuration file
fn write<P: AsRef<Path>>(
    next_contents: String,
    path: P,
    file_type: &str,
    reload_cmd: Option<&'static str>,
) -> Result<(), eyre::Report> {
    // later we will remove the tmp file on drop, but for now it may help with debugging
    let mut path_tmp = path.as_ref().to_path_buf();
    path_tmp.set_extension("TMP");
    fs::write(&path_tmp, next_contents.clone())
        .wrap_err_with(|| format!("fs::write {}", path_tmp.display()))?;

    let path = path.as_ref();
    let should_write = if path.exists() {
        let current = fs::read_to_string(path)
            .wrap_err_with(|| format!("fs::read_to_string {}", path.display()))?;
        current != next_contents
    } else {
        true
    };
    if should_write {
        debug!("Applying new {file_type} config");

        let mut path_bak = path.to_path_buf();
        path_bak.set_extension("BAK");
        if path.exists() {
            fs::copy(path, path_bak.clone()).wrap_err("copying file to .BAK")?;
        }

        fs::rename(path_tmp.clone(), path).wrap_err("rename")?;

        match reload_cmd {
            Some(reload_cmd) => match reload(reload_cmd) {
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
                    } else {
                        fs::remove_file(path).wrap_err("remove_file on initial run")?;
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

    Ok(())
}

// Run the given command inside HBN container
fn reload(reload_cmd: &'static str) -> Result<(), eyre::Report> {
    let container_id = hbn::get_hbn_container_id()?;
    let out = Command::new("/usr/bin/crictl")
        .args(["exec", "-it", &container_id, "bash", "-c", reload_cmd])
        .output()
        .wrap_err(reload_cmd)?;
    if !out.status.success() {
        return Err(eyre::eyre!(
            "Failed reloading with '{reload_cmd}'. \nSTDOUT: {}\nSTDERR: {}",
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
    use tracing_subscriber::{fmt, prelude::*};

    // Pretend we received a new config from API server. Apply it and check the resulting files.
    #[test]
    fn test_with_tenant() -> Result<(), Box<dyn std::error::Error>> {
        tracing_subscriber::registry()
            .with(fmt::Layer::default().compact())
            .try_init()?;

        // The config we received from API server
        // Admin won't be used
        let admin_interface = rpc::FlatInterfaceConfig {
            function: rpc::InterfaceFunctionType::Physical.into(),
            vlan_id: 1,
            vni: 1001,
            gateway: "10.217.5.123/28".to_string(),
            ip: "10.217.5.123/32".to_string(),
        };
        let tenant_interfaces = vec![
            rpc::FlatInterfaceConfig {
                function: rpc::InterfaceFunctionType::Virtual.into(),
                vlan_id: 196,
                vni: 1025196,
                gateway: "10.217.5.169/29".to_string(),
                ip: "10.217.5.170/32".to_string(),
            },
            rpc::FlatInterfaceConfig {
                function: rpc::InterfaceFunctionType::Physical.into(),
                vlan_id: 185,
                vni: 1025185,
                gateway: "10.217.5.161/30".to_string(),
                ip: "10.217.5.162/32".to_string(),
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
        };

        let f = tempfile::NamedTempFile::new()?;

        // What we're testing

        let _ = super::write_dhcp_relay_config(&f, &network_config, true);
        let expected = include_str!("../templates/tests/tenant_dhcp-relay.conf");
        compare(&f, expected)?;

        let _ = super::write_interfaces(&f, &network_config, true);
        let expected = include_str!("../templates/tests/tenant_interfaces");
        compare(&f, expected)?;

        let _ = super::write_frr(&f, &network_config, true);
        let expected = include_str!("../templates/tests/tenant_frr.conf");
        compare(&f, expected)?;

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
