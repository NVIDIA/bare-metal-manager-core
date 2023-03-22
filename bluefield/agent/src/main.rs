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

mod command_line;
mod health;
mod network_config_fetcher;

use std::{
    thread::sleep,
    time::{Duration, SystemTime},
};

use ::rpc::forge as rpc;
use forge_host_support::{
    agent_config::AgentConfig, hardware_enumeration::enumerate_hardware,
    registration::register_machine,
};
use tracing::{debug, error, info, trace};
use tracing_subscriber::{filter::EnvFilter, fmt, prelude::*};

// Report HBN health every this long
//
// Eventually we will need an event system. Block storage requires very fast DPU responses.
const MAIN_LOOP_PERIOD: Duration = Duration::from_secs(30);

/// How often we fetch the desired network configuration for a host
const NETWORK_CONFIG_FETCH_PERIOD: Duration = Duration::from_secs(30);

fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let cmdline = command_line::Options::load();

    let env_filter = EnvFilter::from_default_env()
        .add_directive("tower=warn".parse()?)
        .add_directive("h2=warn".parse()?);
    tracing_subscriber::registry()
        .with(fmt::Layer::default().pretty())
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

    let interface_id = agent.machine.interface_id;
    let hardware_info = enumerate_hardware()?;
    debug!("Successfully enumerated DPU hardware");

    // We need a multi-threaded runtime since background threads will queue work
    // on it, and the foreground thread might not be blocked onto the runtime
    // at all points in time
    let mut rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let registration_data = rt.block_on(register_machine(
        &agent.forge_system.api_server,
        interface_id,
        hardware_info,
    ))?;

    let machine_id = registration_data.machine_id;
    info!("Successfully discovered machine {machine_id} for interface {interface_id}");

    match cmdline.cmd.as_str() {
        // "run" is the normal and default command
        "run" => run(&mut rt, &machine_id, &agent.forge_system.api_server),

        // already done, the cmd allows us to do only this.
        "hardware" => {}

        // One-off health check
        "health" => {
            let health_report = health::health_check();
            println!("{health_report}");
        }

        cmd => {
            error!("Unknown command {cmd}. Run with '-h' for help.");
        }
    }
    rt.shutdown_timeout(Duration::from_secs(2));

    Ok(())
}

// main loop when running in daemon mode
fn run(rt: &mut tokio::runtime::Runtime, machine_id: &str, forge_api: &str) {
    let network_config_fetcher = network_config_fetcher::NetworkConfigFetcher::new(
        network_config_fetcher::NetworkConfigFetcherConfig {
            config_fetch_interval: NETWORK_CONFIG_FETCH_PERIOD,
            machine_id: machine_id.to_string(),
            forge_api: forge_api.to_string(),
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

        let network_config = network_config_reader.read();
        trace!("Desired network config is {:?}", network_config);

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
        let mut client = match rt.block_on(rpc::forge_client::ForgeClient::connect(
            forge_api.to_string(),
        )) {
            Ok(client) => client,
            Err(err) => {
                error!("Could not connect to Forge API server at {forge_api}. Will retry. {err}");
                continue;
            }
        };
        let request = tonic::Request::new(observation);

        if let Err(err) = rt.block_on(client.record_managed_host_network_status(request)) {
            error!(
                "Error while executing the record_machine_network_status gRPC call: {}",
                err.to_string()
            );
        }
    }
}
