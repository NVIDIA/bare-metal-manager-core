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
use std::sync::Arc;
use std::time::{Duration, Instant};

use ::rpc::DiscoveryInfo;
use ::rpc::forge_tls_client::ForgeClientConfig;
use ::rpc::machine_discovery::DpuData;
use carbide_host_support::agent_config::AgentConfig;
use carbide_host_support::hardware_enumeration::enumerate_hardware;
use carbide_host_support::registration::register_machine;
pub use command_line::{AgentCommand, Options, RunOptions, WriteTarget};
use eyre::WrapErr;
use forge_tls::client_config::ClientCert;
use mac_address::MacAddress;
use network_monitor::{NetworkPingerType, Ping};
use utils::models::arch::CpuArchitecture;
use version_compare::{Part, Version};

use crate::duppet::{SummaryFormat, SyncOptions};
use crate::frr::FrrVlanConfig;

pub mod dpu;

pub mod acl;
mod acl_rules;
pub mod agent_platform;
mod command_line;
pub mod containerd;
mod daemons;
mod dhcp;
mod ethernet_virtualization;
use carbide_uuid::machine::MachineId;
pub use ethernet_virtualization::FPath;
pub mod extension_services;

pub mod duppet;
mod frr;
mod hbn;
mod health;
mod instance_metadata_endpoint;
pub mod instrumentation;
mod interfaces;
pub mod lldp;
mod machine_inventory_updater;
mod main_loop;
mod managed_files;
mod metadata_service;
mod mtu;
pub mod netlink;
pub mod network_monitor;
pub mod nvue; // pub so that integration tests can read nvue::PATH
mod ovs;
mod periodic_config_fetcher;
mod sysfs;
#[cfg(test)]
mod tests;
pub mod traffic_intercept_bridging;
pub mod upgrade;
pub mod util;

/// The minimum version of HBN that FMDS supports
pub const FMDS_MINIMUM_HBN_VERSION: &str = "1.5.0-doca2.2.0";

/// The minimum version of HBN that has compatible NVUE
pub const NVUE_MINIMUM_HBN_VERSION: &str = "2.0.0-doca2.5.0";

pub async fn start(cmdline: command_line::Options) -> eyre::Result<()> {
    if cmdline.version {
        println!("{}", carbide_version::version!());
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

    let forge_client_config = Arc::new(
        ForgeClientConfig::new(
            agent.forge_system.root_ca.clone(),
            Some(ClientCert {
                cert_path: agent.forge_system.client_cert.clone(),
                key_path: agent.forge_system.client_key.clone(),
            }),
        )
        .use_mgmt_vrf()?,
    );

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
            } = match options.override_machine_id {
                // Normal case
                None => register(&agent).await.wrap_err("registration error")?,
                // Dev / test override
                Some(machine_id) => Registration {
                    machine_id,
                    factory_mac_address: "11:22:33:44:55:66".parse().unwrap(),
                },
            };
            main_loop::setup_and_run(
                machine_id,
                factory_mac_address,
                forge_client_config,
                agent,
                *options,
            )
            .await
            .wrap_err("main_loop error exit")?;
            tracing::info!("Agent exit");
        }

        // enumerate hardware and exit
        Some(AgentCommand::Hardware) => {
            let info = enumerate_hardware()?;
            let string_result = serde_json::to_string_pretty(&info)?;
            // print to stderr so it can be re-directed to a file without logs
            eprintln!("{string_result}");
        }

        // One-off health check.
        // Does not take into account tenant ignored peers, so it can fail when the real check would
        // succeed.
        // Same thing as above with respect to "minimum healthy links" -- we don't have it here so
        // it may fail when the real one would succeed for single-port setups.
        // This also only works with the newest HBN as the ifc suffix is hard coded to the new version
        Some(AgentCommand::Health) => {
            let health_report = health::health_check(
                &agent.hbn.root_dir,
                &[],
                Instant::now(),
                false,
                2,
                &[],
                HBNDeviceNames::hbn_23(),
            )
            .await;
            println!("{}", serde_json::to_string_pretty(&health_report)?);
        }

        // One-off network monitor check.
        // dumps JSON-formatted peer DPU network reachability and latency status
        Some(AgentCommand::Network(options)) => {
            let machine_id = register(&agent)
                .await
                .wrap_err("network check machine registration error")?
                .machine_id;

            let pinger_type = match options.network_pinger_type {
                Some(pinger_type) => pinger_type,
                None => NetworkPingerType::OobNetBind,
            };

            tracing::info!("Using {}", pinger_type);
            let pinger: Arc<dyn Ping> = Arc::from(pinger_type);

            let mut network_monitor =
                network_monitor::NetworkMonitor::new(machine_id, None, pinger);

            network_monitor
                .run_onetime(&agent.forge_system.api_server, &forge_client_config)
                .await;
        }

        // The duppet subcommand does a single duppet run for duppet-managed files.
        Some(AgentCommand::Duppet(duppet_options)) => {
            let parsed_format = match duppet_options.summary_format.as_str() {
                "json" => SummaryFormat::Json,
                "yaml" => SummaryFormat::Yaml,
                _ => SummaryFormat::PlainText,
            };
            let sync_options = SyncOptions {
                dry_run: duppet_options.dry_run,
                quiet: duppet_options.quiet,
                no_color: duppet_options.no_color,
                summary_format: parsed_format,
            };

            // Since the duppet sync also syncs out the otel machine_id
            // file, we need to make a registration call to get the machine_id,
            // and a single fetch to get the host_machine_id.
            let Registration { machine_id, .. } =
                register(&agent).await.wrap_err("registration error")?;

            let forge_api_server = agent.forge_system.api_server.clone();
            let periodic_config_fetcher = periodic_config_fetcher::PeriodicConfigFetcher::new(
                periodic_config_fetcher::PeriodicConfigFetcherConfig {
                    config_fetch_interval: Duration::from_secs(
                        agent.period.network_config_fetch_secs,
                    ),
                    machine_id,
                    forge_api: forge_api_server.clone(),
                    forge_client_config: Arc::clone(&forge_client_config),
                },
            )
            .await;

            managed_files::main_sync(sync_options, &machine_id, &periodic_config_fetcher);
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
                    uplinks: HBNDeviceNames::hbn_23()
                        .uplinks
                        .iter()
                        .map(|x| x.to_string())
                        .collect(),
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
                    uplinks: HBNDeviceNames::hbn_23()
                        .uplinks
                        .iter()
                        .map(|x| x.to_string())
                        .collect(),
                    loopback_ip: opts.loopback_ip,
                    vni_device: opts.vni_device,
                    networks,
                })?;
                std::fs::write(&opts.path, contents)?;
                println!("Wrote {}", opts.path);
            }

            WriteTarget::Dhcp(_opts) => {}

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

                let network_security_policy_override_rules = opts
                    .network_security_policy_override_rule
                    .into_iter()
                    .map(|r| serde_json::from_str::<nvue::NetworkSecurityGroupRule>(&r))
                    .collect::<Result<Vec<nvue::NetworkSecurityGroupRule>, _>>()?;

                let additional_route_target_imports = opts
                    .additional_fnn_route_target_import
                    .into_iter()
                    .map(|r| serde_json::from_str::<nvue::RouteTargetConfig>(&r))
                    .collect::<Result<Vec<nvue::RouteTargetConfig>, _>>()?;

                let network_security_groups = opts
                    .network_security_group
                    .into_iter()
                    .map(|r| serde_json::from_str::<nvue::NetworkSecurityGroup>(&r))
                    .collect::<Result<Vec<nvue::NetworkSecurityGroup>, _>>()?;

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
                    site_global_vpc_vni: opts.site_global_vpc_vni,
                    vpc_virtualization_type: opts.virtualization_type,
                    hbn_version: opts.hbn_version,
                    use_admin_network: true,
                    loopback_ip: opts.loopback_ip.to_string(),
                    secondary_overlay_vtep_ip: opts.secondary_overlay_vtep_ip,
                    internal_bridge_routing_prefix: opts.internal_bridge_routing_prefix,
                    vf_intercept_bridge_port_name: opts.vf_intercept_bridge_port_name,
                    host_intercept_bridge_port_name: opts.host_intercept_bridge_port_name,
                    asn: opts.asn,
                    datacenter_asn: opts.datacenter_asn,
                    anycast_site_prefixes: vec!["5.255.255.0/24".to_string()],
                    tenant_host_asn: Some(65100),
                    common_internal_route_target: opts
                        .common_internal_route_target
                        .map(|r| serde_json::from_str::<nvue::RouteTargetConfig>(&r))
                        .transpose()?,
                    additional_route_target_imports,
                    dpu_hostname: opts.dpu_hostname,
                    dpu_search_domain: "".to_string(),
                    uplinks: opts.uplinks,
                    dhcp_servers: opts.dhcp_servers,
                    deny_prefixes: vec![],
                    site_fabric_prefixes: vec![],
                    traffic_intercept_public_prefixes: vec![],
                    vf_intercept_bridge_sf: opts.vf_intercept_bridge_sf,
                    use_vpc_isolation: true,
                    network_security_policy_override_rules,
                    stateful_acls_enabled: opts.stateful_acls_enabled,
                    route_servers: opts.route_servers,
                    l3_domains: vec![],
                    ct_vrf_name: opts.ct_vrf_name,
                    ct_l3_vni: opts.ct_l3vni,
                    ct_vrf_loopback: opts.ct_vrf_loopback,
                    ct_port_configs: port_configs,
                    ct_access_vlans: access_vlans,
                    ct_routing_profile: opts
                        .ct_routing_profile
                        .map(|r| serde_json::from_str::<nvue::RoutingProfile>(&r))
                        .transpose()?,
                    network_security_groups,
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
    machine_id: MachineId,
    factory_mac_address: MacAddress,
}

#[derive(Clone)]
struct HBNDeviceNames {
    uplinks: [&'static str; 2],
    reps: [&'static str; 2],
    virt_rep_begin: &'static str,
    sfs: [&'static str; 2],
    sf_id: &'static str,
}

impl HBNDeviceNames {
    pub fn pre_23() -> HBNDeviceNames {
        HBNDeviceNames {
            uplinks: ["p0_sf", "p1_sf"],
            reps: ["pf0hpf_sf", "pf1hpf_sf"],
            virt_rep_begin: "pf0vf",
            sfs: ["pf0dpu0_sf", "pf0dpu2_sf"],
            sf_id: "_sf",
        }
    }

    pub fn hbn_23() -> HBNDeviceNames {
        HBNDeviceNames {
            uplinks: ["p0_if", "p1_if"],
            reps: ["pf0hpf_if", "pf1hpf_if"],
            virt_rep_begin: "pf0vf",
            sfs: ["pf0dpu1", "pf0dpu3"],
            sf_id: "_if",
        }
    }
    pub fn new(hbn_version: Version) -> Self {
        let min_version: Version = Version::from_parts(
            "2.3.0-doca2.8.0",
            vec![
                Part::Number(2),
                Part::Number(3),
                Part::Number(0),
                Part::Text("doca"),
                Part::Number(2),
                Part::Number(8),
                Part::Number(0),
            ],
        );
        if hbn_version < min_version {
            HBNDeviceNames::pre_23()
        } else {
            HBNDeviceNames::hbn_23()
        }
    }
    pub fn build_virt(&self, virt_rep_id: u32) -> String {
        format!("{}{}{}", self.virt_rep_begin, virt_rep_id, self.sf_id)
    }
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

    let factory_mac_address: MacAddress = match hardware_info.dpu_info.as_ref() {
        Some(dpu_info) => dpu_info.factory_mac_address.parse().map_err(|e| {
            eyre::eyre!(
                "Failed to parse factory MAC address from DPU info: {} (err: {})",
                dpu_info.factory_mac_address,
                e
            )
        })?,
        None => eyre::bail!("Missing DPU info, should be impossible"),
    };

    let (registration_data, ..) = register_machine(
        &agent.forge_system.api_server,
        agent.forge_system.root_ca.clone(),
        agent.machine.interface_id,
        hardware_info,
        true,
        carbide_host_support::registration::DiscoveryRetry {
            secs: agent.period.discovery_retry_secs,
            max: agent.period.discovery_retries_max,
        },
        false,
        !agent.machine.is_fake_dpu,
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
    hardware_info.machine_type = CpuArchitecture::Aarch64.to_string(); // old
    hardware_info.machine_arch = Some(CpuArchitecture::Aarch64.into()); // new
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
