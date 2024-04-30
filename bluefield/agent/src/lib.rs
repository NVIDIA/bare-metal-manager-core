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

use std::process::Command;
use std::time::Instant;

use ::rpc::forge_tls_client::ForgeClientConfig;
use ::rpc::machine_discovery::DpuData;
use ::rpc::DiscoveryInfo;
use command_line::NetworkVirtualizationType;
pub use command_line::{AgentCommand, Options, RunOptions, WriteTarget};
use eyre::WrapErr;
use forge_host_support::{
    agent_config::AgentConfig, hardware_enumeration::enumerate_hardware,
    registration::register_machine,
};
use forge_tls::client_config::ClientCert;

use crate::frr::FrrVlanConfig;

pub mod dpu;

pub mod acl;
mod acl_rules;
mod command_line;
pub mod containerd;
mod daemons;
mod dhcp;
mod ethernet_virtualization;
pub use ethernet_virtualization::FPath;
mod frr;
mod hbn;
mod health;
mod instance_metadata_endpoint;
mod instance_metadata_fetcher;
mod instrumentation;
mod interfaces;

mod machine_inventory_updater;
mod main_loop;
mod mtu;
mod network_config_fetcher;
pub mod nvue; // pub so that integration tests can read nvue::PATH
mod systemd;
pub mod upgrade;
mod util;

const UPLINKS: [&str; 2] = ["p0_sf", "p1_sf"];

// What to use if the server doesn't send it. Which it always should.
// Once NVUE is rolled out we can remove this.
pub const DEFAULT_NETWORK_VIRTUALIZATION_TYPE: NetworkVirtualizationType =
    NetworkVirtualizationType::Etv;

/// The minimum version of HBN that FMDS supports
pub const FMDS_MINIMUM_HBN_VERSION: &str = "1.5.0-doca2.2.0";

/// The minimum version of HBN that has compatible NVUE
pub const NVUE_MINIMUM_HBN_VERSION: &str = "2.0.0-doca2.5.0";

pub async fn start(cmdline: command_line::Options) -> eyre::Result<()> {
    if cmdline.version {
        println!("{}", forge_version::version!());
        return Ok(());
    }

    let (agent, path) = match cmdline.config_path {
        // normal production case
        None => (AgentConfig::default(), "default".to_string()),
        // development overrides
        Some(config_path) => (
            AgentConfig::load_from(&config_path).wrap_err(format!(
                "Error loading agent configuration from {}",
                config_path.display()
            ))?,
            config_path.display().to_string(),
        ),
    };
    tracing::info!("Using configuration from {path}: {agent:?}");

    if agent.machine.is_fake_dpu {
        tracing::warn!("Pretending local host is a DPU. Dev only.");
    }

    let forge_client_config = ForgeClientConfig::new(
        agent.forge_system.root_ca.clone(),
        Some(ClientCert {
            cert_path: agent.forge_system.client_cert.clone(),
            key_path: agent.forge_system.client_key.clone(),
        }),
    )
    .use_mgmt_vrf()?;

    match cmdline.cmd {
        None => {
            tracing::error!("Missing cmd. Try `forge-dpu-agent --help`");
        }

        // "run" is the normal command
        Some(AgentCommand::Run(options)) => {
            if options.skip_upgrade_check {
                tracing::warn!("Upgrades disabled. Dev only");
            }

            let Registration {
                machine_id,
                factory_mac_address,
            } = match &options.override_machine_id {
                // Normal case
                None => register(&agent).await.wrap_err("registration error")?,
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
                options,
            )
            .await
            .wrap_err("main_loop error exit")?;
            tracing::info!("Agent exit");
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
            // --hbn_version 1.5.0-doca2.2.0
            WriteTarget::Nvue(opts) => {
                let mut port_configs = Vec::with_capacity(opts.ct_port_config.len());
                for net_json in opts.ct_port_config {
                    let c: nvue::PortConfig = serde_json::from_str(&net_json)?;
                    port_configs.push(c);
                }
                let access_vlans = opts
                    .vlan
                    .into_iter()
                    .map(|s| {
                        let mut parts = s.split(',');
                        let vlan_id = parts.next().unwrap().parse().unwrap();
                        let ip = parts.next().unwrap().to_string();
                        nvue::VlanConfig {
                            vlan_id,
                            network: ip.clone() + "/32",
                            ip,
                        }
                    })
                    .collect();

                let conf = nvue::NvueConfig {
                    is_fnn: opts.is_fnn,
                    hbn_version: opts.hbn_version,
                    use_admin_network: true,
                    loopback_ip: opts.loopback_ip.to_string(),
                    asn: opts.asn,
                    dpu_hostname: opts.dpu_hostname,
                    dpu_search_domain: "".to_string(),
                    uplinks: opts.uplinks,
                    dhcp_servers: opts.dhcp_servers,
                    deny_prefixes: vec![],
                    route_servers: opts.route_servers,
                    l3_domains: vec![],
                    use_local_dhcp: false,
                    ct_name: opts.ct_name,
                    ct_l3_vni: opts.ct_l3vni,
                    ct_vrf_loopback: opts.ct_vrf_loopback,
                    ct_port_configs: port_configs,
                    ct_external_access: opts.ct_external_access,
                    ct_access_vlans: access_vlans,
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
    let mut hardware_info = enumerate_hardware().wrap_err("enumerate_hardware failed")?;

    // Pretend to be a bluefield DPU for local dev.
    // see model/hardware_info.rs::is_dpu
    if agent.machine.is_fake_dpu {
        fill_fake_dpu_info(&mut hardware_info);
        tracing::debug!("Successfully injected fake DPU data");
    }

    let factory_mac_address = match hardware_info.dpu_info.as_ref() {
        Some(dpu_info) => dpu_info.factory_mac_address.clone(),
        None => eyre::bail!("Missing DPU info, should be impossible"),
    };

    let registration_data = register_machine(
        &agent.forge_system.api_server,
        agent.forge_system.root_ca.clone(),
        agent.machine.interface_id,
        hardware_info,
        true,
        forge_host_support::registration::DiscoveryRetry {
            secs: agent.period.discovery_retry_secs,
            max: agent.period.discovery_retries_max,
        },
        false,
    )
    .await?;

    let machine_id = registration_data.machine_id;
    tracing::info!(%machine_id, %factory_mac_address, "Successfully discovered machine");

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

// fill_fake_dpu_info will take a pre-populated DiscoveryInfo
// from enumerate_hardware (which also adds things like
// discovered cores [from your local machine] and such),
// and injects data to mock your machine to look like
// a DPU. This is intended for use with unit testing
// and local development only.
fn fill_fake_dpu_info(hardware_info: &mut DiscoveryInfo) {
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
