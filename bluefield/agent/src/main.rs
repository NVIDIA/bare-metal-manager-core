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

use std::ops::Add;
use std::sync::Arc;
use std::time::Instant;
use std::{process::Command, thread::sleep, time::Duration};

use ::rpc::machine_discovery::DpuData;
use axum::Router;
use opentelemetry::sdk::export::metrics::aggregation;
use opentelemetry::sdk::metrics;
use opentelemetry::{sdk, Context};
use opentelemetry_semantic_conventions as semcov;
use rand::Rng;
use tokio::runtime::Runtime;
use tracing::{debug, error, info, trace, warn};

use ::rpc::forge as rpc;
use ::rpc::forge_tls_client::{self, ForgeClientCert, ForgeTlsConfig};
use forge_host_support::{
    agent_config::AgentConfig, hardware_enumeration::enumerate_hardware, registration,
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

/// Check if we have latest forge-dpu-agent version every four hours
const VERSION_CHECK_PERIOD: Duration = Duration::from_secs(4 * 3600);

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

    let forge_tls_config = ForgeTlsConfig {
        root_ca_path: agent.forge_system.root_ca.clone(),
        client_cert: Some(ForgeClientCert {
            cert_path: agent.forge_system.client_cert.clone(),
            key_path: agent.forge_system.client_key.clone(),
        }),
    };

    match cmdline.cmd {
        // We want to run the "run" command by default if no mode is explicitly mentioned
        None => {
            let machine_id = register(&mut rt, &agent)?;
            run(&mut rt, &machine_id, forge_tls_config, agent);
        }
        // "run" is the normal and default command
        Some(AgentCommand::Run(options)) => {
            if agent.machine.is_fake_dpu {
                tracing::warn!("Pretending local host is a DPU. Dev only.");
            }
            let machine_id = register(&mut rt, &agent)?;
            if options.enable_metadata_service {
                if let (Some(metadata_service_config), Some(telemetry_config)) =
                    (&agent.metadata_service, &agent.telemetry)
                {
                    if let Err(e) = run_metadata_service(
                        &mut rt,
                        &machine_id,
                        &agent.forge_system.api_server,
                        forge_tls_config.clone(),
                        metadata_service_config.address.clone(),
                        telemetry_config.metrics_address.clone(),
                    ) {
                        return Err(eyre::eyre!("Failed to run metadata service: {:?}", e));
                    }
                } else {
                    error!("metadata-service and telemetry configs are not present. Can't run metadata service");
                }
            }
            run(&mut rt, &machine_id, forge_tls_config, agent);
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
            let forge_api = agent.forge_system.api_server.clone();
            let conf = rt.block_on(network_config_fetcher::fetch(
                &params.dpu_machine_id,
                &forge_api,
                forge_tls_config.clone(),
            ))?;
            let mut status_out = rpc::DpuNetworkStatus {
                dpu_machine_id: Some(params.dpu_machine_id.into()),
                dpu_agent_version: Some(forge_version::v!(build_version).to_string()),
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
                &agent.hbn.root_dir,
                &conf,
                &mut status_out,
                agent.hbn.skip_reload,
            );
            if let Some(v) = status_out.network_config_version.as_ref() {
                info!("Applied: {v}");
            }
            rt.block_on(record_network_status(
                status_out,
                &forge_api,
                forge_tls_config,
            ));
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
                    remote_id: opts.remote_id,
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
    let mut hardware_info = enumerate_hardware()?;
    debug!("Successfully enumerated DPU hardware");

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
            tors: vec![],
        });
    }

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
fn run(rt: &mut Runtime, machine_id: &str, forge_tls_config: ForgeTlsConfig, agent: AgentConfig) {
    let forge_api = &agent.forge_system.api_server;
    let build_version = forge_version::v!(build_version).to_string();
    let network_config_fetcher = network_config_fetcher::NetworkConfigFetcher::new(
        network_config_fetcher::NetworkConfigFetcherConfig {
            config_fetch_interval: NETWORK_CONFIG_FETCH_PERIOD,
            machine_id: machine_id.to_string(),
            forge_api: forge_api.to_string(),
            forge_tls_config: forge_tls_config.clone(),
            runtime: rt.handle().to_owned(),
        },
    );
    let network_config_reader = network_config_fetcher.reader();

    let min_cert_renewal_time = 5 * 24 * 60 * 60; // 5 days
    let max_cert_renewal_time = 7 * 24 * 60 * 60; // 7 days
    let mut rng = rand::thread_rng();
    // we will attempt to refresh the cert at this frequency.
    let cert_renewal_period = rng.gen_range(min_cert_renewal_time..max_cert_renewal_time);
    let mut cert_renewal_time = Instant::now().add(Duration::from_secs(cert_renewal_period));

    let mut version_check_time = Instant::now(); // check it on the first loop
    let mut seen_blank = false;
    loop {
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
            dpu_agent_version: Some(build_version.clone()),
            observed_at: None, // None makes carbide-api set it on receipt
            health: Some(hs),
            network_config_version: None,
            instance_config_version: None,
            interfaces: vec![],
            network_config_error: None,
            instance_id: None,
        };
        match *network_config_reader.read() {
            Some(ref network_config) => {
                ethernet_virtualization::update(
                    &agent.hbn.root_dir,
                    network_config,
                    &mut status_out,
                    agent.hbn.skip_reload,
                );
                rt.block_on(record_network_status(
                    status_out,
                    forge_api,
                    forge_tls_config.clone(),
                ));
                seen_blank = false;
            }
            None => {
                // Only reset network config the _second_ time we can't find the DPU
                // Safety first
                if seen_blank {
                    ethernet_virtualization::reset(&agent.hbn.root_dir, agent.hbn.skip_reload);
                }
                seen_blank = true;
            }
        };

        let now = Instant::now();
        if now > cert_renewal_time {
            cert_renewal_time = now.add(Duration::from_secs(cert_renewal_period));
            rt.block_on(renew_certificates(forge_api, forge_tls_config.clone()));
        }
        if now > version_check_time {
            version_check_time = now.add(VERSION_CHECK_PERIOD);
            if let Err(e) = rt.block_on(version_check(forge_api, forge_tls_config.clone())) {
                error!("version_check: Cannot talk to carbide-api at {forge_api}: {e}");
            }
        }

        sleep(MAIN_LOOP_PERIOD);
    }
}

pub async fn version_check(forge_api: &str, tls_config: ForgeTlsConfig) -> eyre::Result<()> {
    let mut client = forge_tls_client::ForgeTlsClient::new(tls_config)
        .connect(forge_api)
        .await?;
    let remote_version = client
        .version(tonic::Request::new(()))
        .await
        .map(|response| response.into_inner())?;
    let remote_build = remote_version.build_version;

    let local_build = forge_version::v!(build_version);

    if remote_build == local_build {
        trace!("forge-dpu-agent is up to date");
    } else {
        warn!("forge-dpu-agent version {local_build} does not match server {remote_build}");
    }
    Ok(())
}

async fn renew_certificates(forge_api: &str, forge_tls_config: ForgeTlsConfig) {
    let mut client = match forge_tls_client::ForgeTlsClient::new(forge_tls_config)
        .connect(forge_api)
        .await
    {
        Ok(client) => client,
        Err(err) => {
            error!("Could not connect to Forge API server at {forge_api}. Will retry. {err:#}");
            return;
        }
    };

    let request = tonic::Request::new(rpc::MachineCertificateRenewRequest {});
    match client.renew_machine_certificate(request).await {
        Ok(response) => {
            let machine_certificate_result = response.into_inner();
            registration::write_certs(machine_certificate_result.machine_certificate).await;
        }
        Err(err) => {
            error!("Error while executing the renew_machine_certificate gRPC call: {err:#}");
        }
    }
}

async fn record_network_status(
    status: rpc::DpuNetworkStatus,
    forge_api: &str,
    forge_tls_config: ForgeTlsConfig,
) {
    let mut client = match forge_tls_client::ForgeTlsClient::new(forge_tls_config)
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
    forge_tls_config: ForgeTlsConfig,
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
                forge_tls_config,
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
