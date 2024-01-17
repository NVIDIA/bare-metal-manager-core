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

use std::net::{IpAddr, Ipv4Addr};
use std::process::Command;
use std::time::Instant;

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{ForgeClientCert, ForgeClientConfig};
use ::rpc::machine_discovery::DpuData;
pub use command_line::{AgentCommand, NetconfParams, Options, RunOptions, WriteTarget};
use forge_host_support::{
    agent_config::AgentConfig, hardware_enumeration::enumerate_hardware,
    registration::register_machine,
};
pub use upgrade::upgrade_check;
use util::UrlResolver;

use crate::frr::FrrVlanConfig;

mod acl_rules;
mod command_line;
pub mod config_model;
pub mod containerd;
mod daemons;
mod dhcp;
mod ethernet_virtualization;
mod frr;
mod hbn;
mod health;
mod instance_metadata_endpoint;
mod instance_metadata_fetcher;
mod instrumentation;
mod interfaces;
mod main_loop;
mod mtu;
mod network_config_fetcher;
mod nvue;
mod upgrade;
mod util;

const UPLINKS: [&str; 2] = ["p0_sf", "p1_sf"];

pub async fn start(cmdline: command_line::Options) -> eyre::Result<()> {
    if cmdline.version {
        println!("{}", forge_version::version!());
        return Ok(());
    }

    let agent = match AgentConfig::load_from(&cmdline.config_path) {
        Ok(cfg) => {
            tracing::info!("Successfully loaded agent configuration {:?}", cfg);
            cfg
        }
        Err(e) => {
            return Err(eyre::eyre!(
                "Error loading agent configuration from {}: {:?}",
                cmdline.config_path.display(),
                e
            ));
        }
    };
    if agent.machine.is_fake_dpu {
        tracing::warn!("Pretending local host is a DPU. Dev only.");
    }

    let forge_client_config = ForgeClientConfig::new(
        agent.forge_system.root_ca.clone(),
        Some(ForgeClientCert {
            cert_path: agent.forge_system.client_cert.clone(),
            key_path: agent.forge_system.client_key.clone(),
        }),
    )
    .use_mgmt_vrf()?;

    match cmdline.cmd {
        // TODO until Oct 2023 forge-dpu-agent in prod used this
        // Now the systemd service calls 'run'. Remove this in the future.
        None => {
            let Registration {
                machine_id,
                factory_mac_address,
            } = register(&agent).await?;
            main_loop::run(
                &machine_id,
                &factory_mac_address,
                forge_client_config,
                agent,
                None,
            )
            .await?;
        }

        // "run" is the normal and default command
        Some(AgentCommand::Run(options)) => {
            let Registration {
                machine_id,
                factory_mac_address,
            } = match &options.override_machine_id {
                // Normal case
                None => register(&agent).await?,
                // Dev / test override
                Some(id) => Registration {
                    machine_id: id.to_string(),
                    factory_mac_address: "11:22:33:44:55:66".to_string(),
                },
            };
            main_loop::run(
                &machine_id,
                &factory_mac_address,
                forge_client_config,
                agent,
                Some(options),
            )
            .await?;
        }

        // enumerate hardware and exit
        Some(AgentCommand::Hardware) => {
            enumerate_hardware()?;
        }

        // One-off health check.
        // Does not take into account tenant ignored peers, so it can fail when the real check would
        // succeed.
        Some(AgentCommand::Health) => {
            let health_report =
                health::health_check(&agent.hbn.root_dir, &[], Instant::now()).await;
            println!("{health_report}");
        }

        // One-off configure network and report back the observation.
        // Pretend network is healthy.
        // Development / testing only.
        Some(AgentCommand::Netconf(params)) => {
            let forge_api = agent.forge_system.api_server.clone();
            let conf = network_config_fetcher::fetch(
                &params.dpu_machine_id,
                &forge_api,
                forge_client_config.clone(),
            )
            .await?;
            let mut status_out = rpc::DpuNetworkStatus {
                dpu_machine_id: Some(params.dpu_machine_id.into()),
                dpu_agent_version: Some(forge_version::v!(build_version).to_string()),
                observed_at: None, // None makes carbide-api set it on receipt
                health: None,
                network_config_version: None,
                instance_config_version: None,
                interfaces: vec![],
                network_config_error: None,
                instance_id: None,
                client_certificate_expiry_unix_epoch_secs: None,
            };
            let mut has_changed_configs = false;

            let (pxe_ip, ntp_ip, nameservers) = if !agent.machine.is_fake_dpu {
                let mut url_resolver = UrlResolver::try_new()?;

                let pxe_ip = *url_resolver
                    .resolve("carbide-pxe.forge")
                    .await?
                    .get(0)
                    .ok_or_else(|| eyre::eyre!("No pxe ip returned by resolver"))?;

                // This log should be removed after some time.
                tracing::info!("Pxe server resolved as: {:?}", pxe_ip);

                let ntp_ip = match url_resolver.resolve("carbide-ntp.forge").await {
                    Ok(x) => {
                        let ntp_server_ip = x.get(0);
                        // This log should be removed after some time.
                        tracing::info!("Ntp server resolved as: {:?}", ntp_server_ip);
                        ntp_server_ip.cloned()
                    }
                    Err(e) => {
                        tracing::error!("NTP server couldn't be resolved. Dhcp-server won't send NTP server IP in dhcpoffer/ack. Error: {}", e);
                        None
                    }
                };

                let nameservers = url_resolver.nameservers();
                (pxe_ip, ntp_ip, nameservers)
            } else {
                (
                    Ipv4Addr::from([127, 0, 0, 1]),
                    None,
                    vec![IpAddr::from([127, 0, 0, 1])],
                )
            };

            match ethernet_virtualization::update_files(
                &agent.hbn.root_dir,
                &conf,
                agent.hbn.skip_reload,
                pxe_ip,
                ntp_ip,
                nameservers,
            )
            .await
            {
                Ok(has_changed) => {
                    status_out.network_config_version =
                        Some(conf.managed_host_config_version.clone());
                    status_out.instance_id = conf.instance_id.clone();
                    if !conf.instance_config_version.is_empty() {
                        status_out.instance_config_version =
                            Some(conf.instance_config_version.clone());
                    }
                    has_changed_configs = has_changed;
                }
                Err(err) => {
                    status_out.network_config_error = Some(err.to_string());
                }
            }
            match ethernet_virtualization::interfaces(&conf, &params.mac_address).await {
                Ok(interfaces) => status_out.interfaces = interfaces,
                Err(err) => status_out.network_config_error = Some(err.to_string()),
            }
            if let Some(v) = status_out.network_config_version.as_ref() {
                tracing::info!("Applied: {v}");
            }
            status_out.health = Some(rpc::NetworkHealth {
                // Simulate what main forge-dpu-agent does, which is
                // report network as unhealthy to give HBN/BGP time to apply the config.
                is_healthy: !has_changed_configs,
                ..Default::default()
            });
            main_loop::record_network_status(status_out, &forge_api, forge_client_config).await;
        }

        // Output a templated file
        // Normally this is (will be) done when receiving requests from carbide-api
        Some(AgentCommand::Write(target)) => match target {
            // Example:
            // forge-dpu-agent
            //     --config-path example_agent_config.toml
            //     write frr
            //     --path ~/Temp/frr.conf
            //     --asn 1234
            //     --loopback-ip 10.11.12.13
            //     --vlan 1,bob
            //     --vlan 2,bill
            WriteTarget::Frr(opts) => {
                let access_vlans = opts
                    .vlan
                    .into_iter()
                    .map(|s| {
                        let mut parts = s.split(',');
                        let vlan_id = parts.next().unwrap().parse().unwrap();
                        let ip = parts.next().unwrap().to_string();
                        FrrVlanConfig {
                            vlan_id,
                            network: ip.clone() + "/32",
                            ip,
                        }
                    })
                    .collect();
                let contents = frr::build(frr::FrrConfig {
                    asn: opts.asn,
                    uplinks: UPLINKS.iter().map(|x| x.to_string()).collect(),
                    loopback_ip: opts.loopback_ip,
                    access_vlans,
                    network_virtualization_type: Some(opts.network_virtualization_type),
                    vpc_vni: Some(opts.vpc_vni),
                    route_servers: opts.route_servers.clone(),
                    use_admin_network: opts.admin,
                })?;
                std::fs::write(&opts.path, contents)?;
                println!("Wrote {}", opts.path);
            }

            // Example:
            // forge-dpu-agent
            //    --config-path example_agent_config.toml
            //    write interfaces
            //    --path /home/graham/Temp/if
            //    --loopback-ip 1.2.3.4
            //    --vni-device ""
            //    --network '{"interface_name": "pf0hpf", "vlan": 1, "vni": 3042, "gateway_cidr": "6.5.4.3/24"}'`
            WriteTarget::Interfaces(opts) => {
                let mut networks = Vec::with_capacity(opts.network.len());
                for net_json in opts.network {
                    let c: interfaces::Network = serde_json::from_str(&net_json)?;
                    networks.push(c);
                }
                let contents = interfaces::build(interfaces::InterfacesConfig {
                    uplinks: UPLINKS.iter().map(|x| x.to_string()).collect(),
                    loopback_ip: opts.loopback_ip,
                    vni_device: opts.vni_device,
                    networks,
                    network_virtualization_type: Some(opts.network_virtualization_type),
                })?;
                std::fs::write(&opts.path, contents)?;
                println!("Wrote {}", opts.path);
            }

            WriteTarget::Dhcp(opts) => {
                let contents = dhcp::build_relay_config(dhcp::DhcpRelayConfig {
                    uplinks: UPLINKS.iter().map(|x| x.to_string()).collect(),
                    vlan_ids: opts.vlan,
                    dhcp_servers: opts.dhcp,
                    remote_id: opts.remote_id,
                    network_virtualization_type: Some(opts.network_virtualization_type),
                })?;
                std::fs::write(&opts.path, contents)?;
                println!("Wrote {}", opts.path);
            }

            // Example:
            // forge-dpu-agent write nvue
            // --path /tmp/startup.yaml
            // --loopback-ip 10.0.0.1
            // --asn 65535
            // --dpu-hostname bob
            // --ct-name ct_name
            // --ct-l3vni l3vnihere
            // --ct-vrf-loopback 10.0.0.2
            // --uplinks up1,up2
            // --route-servers 10.217.126.5  # comma separated list
            // --dhcp-servers 10.217.126.2  # comma separated list
            // --l3-domain 4096,10.0.0.1,svi  # repeat for multiple
            // --ct-external-access 4096  # comma separated list
            // --ct-port-config '{"interface_name": "if1", "vlan": 123, "vni": 456, "gateway_cidr": "10.0.0.100/32"}' # repeated for multiple
            WriteTarget::Nvue(opts) => {
                let mut port_configs = Vec::with_capacity(opts.ct_port_config.len());
                for net_json in opts.ct_port_config {
                    let c: nvue::PortConfig = serde_json::from_str(&net_json)?;
                    port_configs.push(c);
                }
                let conf = nvue::NvueConfig {
                    loopback_ip: opts.loopback_ip.to_string(),
                    asn: opts.asn,
                    dpu_hostname: opts.dpu_hostname,
                    uplinks: opts.uplinks,
                    dhcp_servers: opts.dhcp_servers,
                    route_servers: opts.route_servers,
                    l3_domains: vec![],
                    ct_name: opts.ct_name,
                    ct_l3_vni: opts.ct_l3vni,
                    ct_vrf_loopback: opts.ct_vrf_loopback,
                    ct_port_configs: port_configs,
                    ct_external_access: opts.ct_external_access,
                };
                let contents = nvue::build(conf)?;
                std::fs::write(&opts.path, contents)?;
                println!("Wrote {}", opts.path);
            }
        },
    }
    Ok(())
}

struct Registration {
    machine_id: String,
    factory_mac_address: String,
}

/// Discover hardware, register DPU with carbide-api, and return machine id
async fn register(agent: &AgentConfig) -> Result<Registration, eyre::Report> {
    let interface_id = agent.machine.interface_id;
    let mut hardware_info = enumerate_hardware()?;
    tracing::debug!("Successfully enumerated DPU hardware");

    if agent.machine.is_fake_dpu {
        // Pretend to be a bluefield DPU for local dev.
        // see model/hardware_info.rs::is_dpu
        hardware_info.machine_type = "aarch64".to_string();
        if let Some(dmi) = hardware_info.dmi_data.as_mut() {
            dmi.board_name = "BlueField SoC".to_string();
            if dmi.product_serial.is_empty() {
                // Older Dell Precision 5760 don't have any serials
                dmi.product_serial = "Stable Local Dev serial".to_string();
            }
        }
        hardware_info.dpu_info = Some(DpuData {
            part_number: "1".to_string(),
            part_description: "1".to_string(),
            product_version: "1".to_string(),
            factory_mac_address: "11:22:33:44:55:66".to_string(),
            firmware_version: "1".to_string(),
            firmware_date: "01/01/1970".to_string(),
            switches: vec![],
        });
    }
    let factory_mac_address = match hardware_info.dpu_info.as_ref() {
        Some(dpu_info) => dpu_info.factory_mac_address.clone(),
        None => eyre::bail!("Missing dpu info, should be impossible"),
    };
    let registration_data = register_machine(
        &agent.forge_system.api_server,
        agent.forge_system.root_ca.clone(),
        interface_id,
        hardware_info,
        true,
    )
    .await?;

    let machine_id = registration_data.machine_id;
    tracing::info!(%machine_id, %interface_id, %factory_mac_address, "Successfully discovered machine");

    Ok(Registration {
        machine_id,
        factory_mac_address,
    })
}

pub fn pretty_cmd(c: &Command) -> String {
    format!(
        "{} {}",
        c.get_program().to_string_lossy(),
        c.get_args()
            .map(|x| x.to_string_lossy())
            .collect::<Vec<std::borrow::Cow<'_, str>>>()
            .join(" ")
    )
}
