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

use std::{
    process::Command,
    thread::sleep,
    time::{Duration, SystemTime},
};

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client;
use forge_host_support::{
    agent_config::AgentConfig, hardware_enumeration::enumerate_hardware,
    registration::register_machine,
};
use tracing::{debug, error, info, metadata::LevelFilter, trace};
use tracing_subscriber::{filter::EnvFilter, fmt, prelude::*};

use crate::{
    command_line::{AgentCommand, WriteTarget},
    frr::FrrVlanConfig,
};

mod command_line;
mod dhcp;
mod ethernet_virtualization;
mod frr;
mod hbn;
mod health;
mod interfaces;
mod network_config_fetcher;

// Report HBN health every this long
//
// Eventually we will need an event system. Block storage requires very fast DPU responses.
const MAIN_LOOP_PERIOD: Duration = Duration::from_secs(30);

/// How often we fetch the desired network configuration for a host
const NETWORK_CONFIG_FETCH_PERIOD: Duration = Duration::from_secs(30);

const UPLINKS: [&str; 2] = ["p0_sf", "p1_sf"];

fn main() -> eyre::Result<()> {
    let cmdline = command_line::Options::load();
    if cmdline.version {
        println!("{}", forge_version::version!());
        return Ok(());
    }

    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tower=warn".parse()?)
        .add_directive("rustls=warn".parse()?)
        .add_directive("hyper=warn".parse()?)
        .add_directive("h2=warn".parse()?);
    tracing_subscriber::registry()
        .with(fmt::Layer::default().compact())
        .with(env_filter)
        .try_init()?;

    let agent = match AgentConfig::load_from(&cmdline.config_path) {
        Ok(cfg) => {
            info!("Successfully loaded agent configuration {:?}", cfg);
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

    // We need a multi-threaded runtime since background threads will queue work
    // on it, and the foreground thread might not be blocked onto the runtime
    // at all points in time
    let mut rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    match cmdline.cmd {
        // "run" is the normal and default command
        None | Some(AgentCommand::Run) => {
            let machine_id = register(&mut rt, &agent)?;
            run(
                &mut rt,
                &machine_id,
                &agent.forge_system.api_server,
                &agent.forge_system.root_ca,
            );
        }

        // already done, the cmd allows us to do only this.
        Some(AgentCommand::Hardware) => {
            enumerate_hardware()?;
        }

        // One-off health check
        Some(AgentCommand::Health) => {
            let health_report = health::health_check();
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
                        FrrVlanConfig {
                            vlan_id: parts.next().unwrap().parse().unwrap(),
                            ip: parts.next().unwrap().to_string(),
                        }
                    })
                    .collect();
                let contents = frr::build(frr::FrrConfig {
                    asn: opts.asn,
                    uplinks: UPLINKS.iter().map(|x| x.to_string()).collect(),
                    loopback_ip: opts.loopback_ip,
                    access_vlans,
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
                let contents = dhcp::build(dhcp::DhcpConfig {
                    uplinks: UPLINKS.iter().map(|x| x.to_string()).collect(),
                    vlan_ids: opts.vlan,
                    dhcp_servers: opts.dhcp,
                })?;
                std::fs::write(&opts.path, contents)?;
                println!("Wrote {}", opts.path);
            }
        },
    }
    rt.shutdown_timeout(Duration::from_secs(2));

    Ok(())
}

/// Discover hardware, register DPU with carbide-api, and return machine id
fn register(rt: &mut tokio::runtime::Runtime, agent: &AgentConfig) -> Result<String, eyre::Report> {
    let interface_id = agent.machine.interface_id;
    let hardware_info = enumerate_hardware()?;
    debug!("Successfully enumerated DPU hardware");

    let registration_data = rt.block_on(register_machine(
        &agent.forge_system.api_server,
        agent.forge_system.root_ca.clone(),
        interface_id,
        hardware_info,
    ))?;

    let machine_id = registration_data.machine_id;
    info!("Successfully discovered machine {machine_id} for interface {interface_id}");

    Ok(machine_id)
}

// main loop when running in daemon mode
fn run(rt: &mut tokio::runtime::Runtime, machine_id: &str, forge_api: &str, root_ca: &str) {
    let network_config_fetcher = network_config_fetcher::NetworkConfigFetcher::new(
        network_config_fetcher::NetworkConfigFetcherConfig {
            config_fetch_interval: NETWORK_CONFIG_FETCH_PERIOD,
            machine_id: machine_id.to_string(),
            forge_api: forge_api.to_string(),
            root_ca: root_ca.to_string(),
            runtime: rt.handle().to_owned(),
        },
    );

    let network_config_reader = network_config_fetcher.reader();

    let mut first = true;
    loop {
        if !first {
            sleep(MAIN_LOOP_PERIOD);
        }
        first = false;

        if let Some(ref network_config) = *network_config_reader.read() {
            ethernet_virtualization::update(network_config);
        }

        let health_report = health::health_check();
        trace!("{} health is {}", machine_id, health_report);

        let hs = rpc::NetworkHealth {
            is_healthy: health_report.is_healthy(),
            passed: health_report
                .checks_passed
                .iter()
                .map(|hc| hc.to_string())
                .collect(),
            failed: health_report
                .checks_failed
                .iter()
                .map(|hc| hc.to_string())
                .collect(),
            message: health_report.message,
        };
        let observation = rpc::ManagedHostNetworkStatusObservation {
            dpu_machine_id: Some(rpc::MachineId {
                id: machine_id.to_string(),
            }),
            observed_at: Some(SystemTime::now().into()),
            health: Some(hs),
        };

        let mut client = match rt
            .block_on(forge_tls_client::ForgeTlsClient::new(root_ca.to_string()).connect(forge_api))
        {
            Ok(client) => client,
            Err(err) => {
                error!("Could not connect to Forge API server at {forge_api}. Will retry. {err:#}");
                continue;
            }
        };
        let request = tonic::Request::new(observation);

        if let Err(err) = rt.block_on(client.record_managed_host_network_status(request)) {
            error!("Error while executing the record_machine_network_status gRPC call: {err:#}");
        }
    }
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
