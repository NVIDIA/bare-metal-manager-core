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
use std::fs::{File, OpenOptions};
use std::io::BufReader;
use std::path::Path;

use ::rpc::{
    forge::{self as forgerpc, MachineType},
    MachineId,
};
use cfg::carbide_options::{
    CarbideCommand, CarbideOptions, Domain, Instance, Machine, ManagedHost, MigrateAction,
    NetworkCommand, NetworkSegment, OutputFormat, ResourcePool,
};
use prettytable::{row, Table};
use serde::Deserialize;
use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*};

mod cfg;
mod domain;
mod instance;
mod machine;
mod managed_host;
mod migrate;
mod network;
mod redfish;
mod resource_pool;
mod rpc;

#[derive(Debug, Deserialize)]
struct FileConfig {
    carbide_api_url: Option<String>,
    forge_root_ca_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    carbide_api_url: String,
    forge_root_ca_path: String,
}

#[derive(thiserror::Error, Debug)]
pub enum CarbideCliError {
    #[error("Unable to connect to carbide API: {0}")]
    ApiConnectFailed(String),

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

    #[error("Error parsing TOML file: {0}")]
    TomlError(#[from] toml::de::Error),

    #[error("Unexpected machine type.  expected {0:?} but found {1:?}")]
    UnexpectedMachineType(MachineType, MachineType),

    #[error("Host machine with id {0} not found")]
    MachineNotFound(MachineId),

    #[error("I/O error. Does the file exist? {0}")]
    IOError(#[from] std::io::Error),

    /// For when you expected some values but the response was empty.
    /// If empty is acceptable don't use this.
    #[error("No results returned")]
    Empty,
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

fn get_carbide_api_url(carbide_api: Option<String>, file_config: Option<&FileConfig>) -> String {
    // First from command line, second env var.
    if let Some(carbide_api) = carbide_api {
        return carbide_api;
    }

    // Third config file
    if let Some(file_config) = file_config {
        if let Some(carbide_api_url) = file_config.carbide_api_url.as_ref() {
            return carbide_api_url.clone();
        }
    }

    panic!(
        r#"Unknown CARBIDE_API_URL. Set (will be read in same sequence.)
           1. --carbide_api/-c flag or
           2. environment variable CARBIDE_API_URL or
           3. add carbide_api_url in $HOME/.config/carbide_api_cli.json."#
    )
}

fn get_forge_root_ca_path(
    forge_root_ca_path: Option<String>,
    file_config: Option<&FileConfig>,
) -> String {
    // First from command line, second env var.
    if let Some(forge_root_ca_path) = forge_root_ca_path {
        return forge_root_ca_path;
    }

    // Third config file
    if let Some(file_config) = file_config {
        if let Some(forge_root_ca_path) = file_config.forge_root_ca_path.as_ref() {
            return forge_root_ca_path.clone();
        }
    }

    // this is the location for most k8s pods
    if Path::new("/var/run/secrets/spiffe.io/ca.crt").exists() {
        return "/var/run/secrets/spiffe.io/ca.crt".to_string();
    }

    // this is the location for most compiled clients executing on x86 hosts or DPUs
    if Path::new("/opt/forge/forge_root.pem").exists() {
        return "/opt/forge/forge_root.pem".to_string();
    }

    // and this is the location for developers executing from within carbide's repo
    if let Ok(project_root) = env::var("REPO_ROOT") {
        let path = format!("{}/dev/certs/forge_root.pem", project_root);
        if Path::new(path.as_str()).exists() {
            return path;
        }
    }

    // if you make it here, you'll just have to tell me where the root CA is.
    panic!(
        r###"Unknown FORGE_ROOT_CA_PATH. Set (will be read in same sequence.)
           1. --forge_root_ca_path/-f flag or
           2. environment variable FORGE_ROOT_CA_PATH or
           3. add forge_root_ca_path in $HOME/.config/carbide_api_cli.json.
           5. a file existing at "/var/run/secrets/spiffe.io/ca.crt".
           5. a file existing at "/opt/forge/forge_root.pem".
           5. a file existing at "$REPO_ROOT/dev/certs/forge_root.pem"."###
    )
}

fn get_config_from_file() -> Option<FileConfig> {
    // Third config file
    if let Ok(home) = env::var("HOME") {
        let file = Path::new(&home).join(".config/carbide_api_cli.json");
        if file.exists() {
            let file = File::open(file).unwrap();
            let reader = BufReader::new(file);
            let file_config: FileConfig = serde_json::from_reader(reader).unwrap();

            return Some(file_config);
        }
    }

    None
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let config = CarbideOptions::load();
    if config.version {
        println!("{}", forge_version::version!());
        return Ok(());
    }
    let file_config = get_config_from_file();

    // Log level is set from, in order of preference:
    // 1. `--debug N` on cmd line
    // 2. RUST_LOG environment variable
    // 3. Level::Info
    let mut env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy()
        .add_directive("tower=warn".parse()?)
        .add_directive("rustls=warn".parse()?)
        .add_directive("h2=warn".parse()?);
    if config.debug != 0 {
        env_filter = env_filter.add_directive(
            match config.debug {
                1 => LevelFilter::DEBUG,
                _ => LevelFilter::TRACE,
            }
            .into(),
        );
    }
    tracing_subscriber::registry()
        .with(fmt::Layer::default().compact())
        .with(env_filter)
        .try_init()?;

    // Commands that don't talk to Carbide API
    if let Some(CarbideCommand::Redfish(ra)) = config.commands {
        return redfish::action(ra).await;
    }

    let carbide_api_url = get_carbide_api_url(config.carbide_api, file_config.as_ref());
    let forge_root_ca_path =
        get_forge_root_ca_path(config.forge_root_ca_path, file_config.as_ref());
    let api_config = Config {
        carbide_api_url,
        forge_root_ca_path,
    };

    let command = match config.commands {
        None => {
            eprintln!("error: 'forge-admin-cli' requires a subcommand but one was not provided. Re-run with '--help'.");
            return Ok(());
        }
        Some(s) => s,
    };

    // Command do talk to Carbide API
    match command {
        CarbideCommand::Machine(machine) => match machine {
            Machine::Show(machine) => {
                machine::handle_show(machine, config.format == OutputFormat::Json, api_config)
                    .await?
            }
            Machine::DpuSshCredentials(query) => {
                let cred = rpc::get_dpu_ssh_credential(query.query, api_config).await?;
                if config.format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&cred).unwrap());
                } else {
                    println!("{}:{}", cred.username, cred.password);
                }
            }
            Machine::Network(cmd) => match cmd {
                NetworkCommand::Status => {
                    let all_status = rpc::get_all_managed_host_network_status(api_config)
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
                NetworkCommand::Config(query) => {
                    let config =
                        rpc::get_managed_host_network_config(query.machine_id, api_config).await?;
                    println!("{config:?}");
                }
            },
            Machine::Reboot(c) => {
                let bmc_auth = match (c.username, c.password, c.machine) {
                    (Some(user), Some(password), _) => rpc::RebootAuth::Direct { user, password },
                    (_, _, Some(machine_id)) => rpc::RebootAuth::Indirect { machine_id },
                    _ => {
                        eprintln!("Provide either --machine-id or both --username and --password");
                        return Ok(());
                    }
                };
                rpc::reboot(api_config, c.address, c.port, bmc_auth).await?;
            }
            Machine::ForceDelete(query) => machine::force_delete(query, api_config).await?,
        },
        CarbideCommand::Instance(instance) => match instance {
            Instance::Show(instance) => {
                instance::handle_show(instance, config.format == OutputFormat::Json, api_config)
                    .await?
            }
        },
        CarbideCommand::NetworkSegment(network) => match network {
            NetworkSegment::Show(network) => {
                network::handle_show(network, config.format == OutputFormat::Json, api_config)
                    .await?
            }
        },
        CarbideCommand::Domain(domain) => match domain {
            Domain::Show(domain) => {
                domain::handle_show(domain, config.format == OutputFormat::Json, api_config).await?
            }
        },
        CarbideCommand::ManagedHost(managed_host) => match managed_host {
            ManagedHost::Show(managed_host) => {
                let mut output_file = if let Some(filename) = config.output {
                    Box::new(
                        OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(filename)?,
                    ) as Box<dyn std::io::Write>
                } else {
                    Box::new(std::io::stdout()) as Box<dyn std::io::Write>
                };
                managed_host::handle_show(&mut output_file, managed_host, config.format, api_config)
                    .await?
            }
        },
        CarbideCommand::ResourcePool(rp) => match rp {
            ResourcePool::Define(def) => {
                resource_pool::define_all_from(&def.filename, api_config).await?;
            }
            ResourcePool::List => {
                resource_pool::list(api_config).await?;
            }
        },
        CarbideCommand::Migrate(migration) => match migration {
            MigrateAction::Vpc => migrate::vpc(api_config).await?,
        },
        CarbideCommand::Redfish(_) => {
            // Handled earlier
            unreachable!();
        }
    }

    Ok(())
}
