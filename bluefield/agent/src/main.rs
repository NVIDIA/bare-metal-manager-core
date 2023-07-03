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

use std::sync::Arc;
use std::{process::Command, thread::sleep, time::Duration};

use axum::Router;
use opentelemetry::sdk::export::metrics::aggregation;
use opentelemetry::sdk::metrics;
use opentelemetry::{sdk, Context};
use opentelemetry_semantic_conventions as semcov;
use tokio::runtime::Runtime;
use tracing::{debug, error, info, trace};

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client;
use forge_host_support::{
    agent_config::AgentConfig, hardware_enumeration::enumerate_hardware,
    registration::register_machine,
};

use crate::instance_metadata_endpoint::get_instance_metadata_router;
use crate::instrumentation::{create_metrics, get_metrics_router, WithTracingLayer};
use crate::{
    command_line::{AgentCommand, WriteTarget},
    frr::FrrVlanConfig,
};

mod command_line;
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

    forge_host_support::init_logging()?;

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
        // We want to run the "run" command by default if no mode is explicitly mentioned
        None => {
            let machine_id = register(&mut rt, &agent)?;
            run(
                &mut rt,
                &machine_id,
                &agent.forge_system.api_server,
                &agent.forge_system.root_ca,
            );
        }
        // "run" is the normal and default command
        Some(AgentCommand::Run(options)) => {
            let machine_id = register(&mut rt, &agent)?;
            if options.enable_metadata_service {
                if let (Some(metadata_service_config), Some(telemetry_config)) =
                    (agent.metadata_service, agent.telemetry)
                {
                    if let Err(e) = run_metadata_service(
                        &mut rt,
                        &machine_id,
                        &agent.forge_system.api_server,
                        &agent.forge_system.root_ca,
                        metadata_service_config.address,
                        telemetry_config.metrics_address,
                    ) {
                        return Err(eyre::eyre!("Failed to run metadata service: {:?}", e));
                    }
                } else {
                    error!("metadata-service and telemetry configs are not present. Can't run metadata service");
                }
            }
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

        // One-off configure network and report back the observation
        Some(AgentCommand::Netconf(params)) => {
            let forge_api = agent.forge_system.api_server.to_string();
            let root_ca = agent.forge_system.root_ca.to_string();
            let conf = rt.block_on(network_config_fetcher::fetch(
                &params.dpu_machine_id,
                &forge_api,
                &root_ca,
            ))?;
            let mut status_out = rpc::DpuNetworkStatus {
                dpu_machine_id: Some(params.dpu_machine_id.into()),
                observed_at: None, // None makes carbide-api set it on receipt
                health: Some(rpc::NetworkHealth {
                    is_healthy: true,
                    ..Default::default()
                }),
                network_config_version: None,
                instance_config_version: None,
                interfaces: vec![],
                network_config_error: None,
                instance_id: None,
            };
            ethernet_virtualization::update(
                &params.chroot,
                &conf,
                &mut status_out,
                params.skip_reload,
            );
            if let Some(v) = status_out.network_config_version.as_ref() {
                info!("Applied: {v}");
            }
            rt.block_on(record_network_status(status_out, &forge_api, &root_ca));
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
                    network_virtualization_type: Some(opts.network_virtualization_type),
                    vpc_vni: Some(opts.vpc_vni),
                    route_servers: opts.route_servers.clone(),
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
                let contents = dhcp::build(dhcp::DhcpConfig {
                    uplinks: UPLINKS.iter().map(|x| x.to_string()).collect(),
                    vlan_ids: opts.vlan,
                    dhcp_servers: opts.dhcp,
                    network_virtualization_type: Some(opts.network_virtualization_type),
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

        let mut status_out = rpc::DpuNetworkStatus {
            dpu_machine_id: Some(machine_id.to_string().into()),
            observed_at: None, // None makes carbide-api set it on receipt
            health: Some(hs),
            network_config_version: None,
            instance_config_version: None,
            interfaces: vec![],
            network_config_error: None,
            instance_id: None,
        };
        if let Some(ref network_config) = *network_config_reader.read() {
            ethernet_virtualization::update(
                ethernet_virtualization::HBN_ROOT,
                network_config,
                &mut status_out,
                false,
            );
        };
        rt.block_on(record_network_status(status_out, forge_api, root_ca));
    }
}

async fn record_network_status(status: rpc::DpuNetworkStatus, forge_api: &str, root_ca: &str) {
    let mut client = match forge_tls_client::ForgeTlsClient::new(root_ca.to_string())
        .connect(forge_api)
        .await
    {
        Ok(client) => client,
        Err(err) => {
            error!("Could not connect to Forge API server at {forge_api}. Will retry. {err:#}");
            return;
        }
    };
    let request = tonic::Request::new(status);
    if let Err(err) = client.record_dpu_network_status(request).await {
        error!("Error while executing the record_machine_network_status gRPC call: {err:#}");
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

fn run_metadata_service(
    rt: &mut tokio::runtime::Runtime,
    machine_id: &str,
    forge_api: &str,
    root_ca: &str,
    metadata_service_address: String,
    metrics_address: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // This defines attributes that are set on the exported logs **and** metrics
    let service_telemetry_attributes = sdk::Resource::new(vec![
        semcov::resource::SERVICE_NAME.string("dpu-agent"),
        semcov::resource::SERVICE_NAMESPACE.string("forge-system"),
    ]);

    // Set up OpenTelemetry metrics export via prometheus
    // TODO: The configuration here is copy&pasted from
    // https://github.com/open-telemetry/opentelemetry-rust/blob/main/examples/hyper-prometheus/src/main.rs
    // and should likely be fine-tuned.
    // One particular challenge seems that these histogram buckets are used for all histograms
    // created by the library. But we might want different buckets for e.g. request timings
    // than for e.g. data sizes
    let metrics_controller = metrics::controllers::basic(metrics::processors::factory(
        metrics::selectors::simple::histogram([
            0.01, 0.05, 0.09, 0.1, 0.5, 0.9, 1.0, 5.0, 9.0, 10.0, 50.0, 90.0, 100.0, 500.0, 900.0,
            1000.0,
        ]),
        aggregation::cumulative_temporality_selector(),
    ))
    .with_resource(service_telemetry_attributes)
    .build();

    // This sets the global meter provider
    // After this call `global::meter()` will be available
    let metrics_exporter = Arc::new(opentelemetry_prometheus::exporter(metrics_controller).init());

    let meter = opentelemetry::global::meter("carbide-api");

    let instance_metadata_fetcher =
        Arc::new(instance_metadata_fetcher::InstanceMetadataFetcher::new(
            instance_metadata_fetcher::InstanceMetadataFetcherConfig {
                config_fetch_interval: NETWORK_CONFIG_FETCH_PERIOD,
                machine_id: machine_id.to_string(),
                forge_api: forge_api.to_string(),
                root_ca: root_ca.to_string(),
                runtime: rt.handle().to_owned(),
            },
        ));

    let instance_metadata_reader = instance_metadata_fetcher.reader();

    let metrics_state = create_metrics(meter);
    let context = Context::new();

    run_server(
        rt,
        metadata_service_address,
        Router::new().nest(
            "/latest/meta-data",
            get_instance_metadata_router(instance_metadata_reader.clone())
                .with_tracing_layer(metrics_state, context),
        ),
    )?;

    run_server(
        rt,
        metrics_address,
        Router::new().nest("/metrics", get_metrics_router(metrics_exporter)),
    )?;

    Ok(())
}

fn run_server(
    rt: &mut Runtime,
    address: String,
    router: Router,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr: std::net::SocketAddr = address.parse()?;
    let server = rt.block_on(async { axum::Server::try_bind(&addr) })?;

    rt.spawn(async move {
        if let Err(err) = server.serve(router.into_make_service()).await {
            eprintln!("Error while serving: {}", err);
        }
    });

    Ok(())
}
