/*
 * SPDX-FileCopyrightText: Copyright (c) 2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */
use std::env;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

mod cfg;
mod domain;
mod instance;
mod machine;
mod network;
mod rpc;

use ::rpc::forge as forgerpc;
use cfg::carbide_options::{
    CarbideCommand, CarbideOptions, Domain, Instance, Machine, NetworkSegment,
};
use log::LevelFilter;
use prettytable::{row, Table};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Config {
    carbide_api_url: Option<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum CarbideCliError {
    #[error("Unable to connect to carbide API: {0}")]
    ApiConnectFailed(tonic::transport::Error),

    #[error("The API call to the Forge API server returned {0}")]
    ApiInvocationError(tonic::Status),

    #[error("Error while writing into string: {0}")]
    StringWriteError(#[from] std::fmt::Error),

    #[error("Generic Error: {0}")]
    GenericError(String),

    #[error("Segment not found.")]
    SegmentNotFound,

    #[error("Domain not found.")]
    DomainNotFound,

    #[error("Error while handling json: {0}")]
    JsonError(#[from] serde_json::Error),
}

pub type CarbideCliResult<T> = Result<T, CarbideCliError>;

pub fn default_uuid() -> forgerpc::Uuid {
    forgerpc::Uuid {
        value: "00000000-0000-0000-0000-000000000000".to_string(),
    }
}

pub fn default_machine_id() -> forgerpc::MachineId {
    forgerpc::MachineId {
        id: "INVALID_MACHINE".to_string(),
    }
}

fn get_carbide_api_url(carbide_api: Option<String>, config: Option<Config>) -> String {
    // First from command line, second env var.
    if let Some(carbide_api) = carbide_api {
        return carbide_api;
    }

    // Third config file
    if let Some(config) = config {
        if let Some(carbide_api_url) = config.carbide_api_url {
            return carbide_api_url;
        }
    }

    panic!(
        r#"Unknown CARBIDE_API_URL. Set (will be read in same sequence.)
           1. --carbide_api/-c flag or
           2. environment variable CARBIDE_API_URL or
           3. add carbide_api_url in $HOME/.config/carbide_api_cli.json."#
    )
}

fn get_config_from_file() -> Option<Config> {
    // Third config file
    if let Ok(home) = env::var("HOME") {
        let file = Path::new(&home).join(".config/carbide_api_cli.json");
        if file.exists() {
            let file = File::open(file).unwrap();
            let reader = BufReader::new(file);
            let config: Config = serde_json::from_reader(reader).unwrap();

            return Some(config);
        }
    }

    None
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    color_eyre::install()?;

    let config = CarbideOptions::load();
    let file_config = get_config_from_file();

    pretty_env_logger::formatted_timed_builder()
        .filter_level(match config.debug {
            0 => LevelFilter::Info,
            1 => {
                // command line overrides config file
                LevelFilter::Debug
            }
            _ => LevelFilter::Trace,
        })
        .init();

    std::env::set_var("RUST_BACKTRACE", "1");
    let carbide_api = get_carbide_api_url(config.carbide_api, file_config);

    match config.commands {
        CarbideCommand::Machine(machine) => match machine {
            Machine::Show(machine) => {
                machine::handle_show(machine, config.json, carbide_api).await?
            }
            Machine::DpuSshCredentials(query) => {
                let cred = rpc::get_dpu_ssh_credential(query.query, carbide_api).await?;
                if config.json {
                    println!("{}", serde_json::to_string_pretty(&cred).unwrap());
                } else {
                    println!("{}:{}", cred.username, cred.password);
                }
            }
            Machine::NetworkStatus => {
                let all_status = rpc::get_all_managed_host_network_status(carbide_api)
                    .await?
                    .all;
                if all_status.is_empty() {
                    println!("No reported network status");
                } else {
                    let mut table = Table::new();
                    table.add_row(row![
                        "Observed at",
                        "DPU machine ID",
                        "Is healthy?",
                        "Checks passed",
                        "Checks failed",
                        "First failure"
                    ]);
                    for mut st in all_status.into_iter().filter(|st| st.health.is_some()) {
                        let h = st.health.take().unwrap();
                        table.add_row(row![
                            st.observed_at.unwrap(),
                            st.dpu_machine_id.unwrap(),
                            h.is_healthy,
                            h.passed.join(","),
                            h.failed.join(","),
                            h.message.unwrap_or_default(),
                        ]);
                    }
                    table.printstd();
                }
            }
            Machine::Reboot(c) => {
                let bmc_auth = match (c.username, c.password, c.machine_id) {
                    (Some(user), Some(password), _) => rpc::RebootAuth::Direct { user, password },
                    (_, _, Some(machine_id)) => rpc::RebootAuth::Indirect { machine_id },
                    _ => {
                        eprintln!("Provide either --machine-id or both --username and --password");
                        return Ok(());
                    }
                };
                rpc::reboot(carbide_api, c.address, c.port, bmc_auth).await?;
            }
            Machine::ForceDelete(query) => machine::force_delete(query, carbide_api).await?,
        },
        CarbideCommand::Instance(instance) => match instance {
            Instance::Show(instance) => {
                instance::handle_show(instance, config.json, carbide_api).await?
            }
        },
        CarbideCommand::NetworkSegment(network) => match network {
            NetworkSegment::Show(network) => {
                network::handle_show(network, config.json, carbide_api).await?
            }
        },
        CarbideCommand::Domain(domain) => match domain {
            Domain::Show(domain) => domain::handle_show(domain, config.json, carbide_api).await?,
        },
    }

    Ok(())
}
