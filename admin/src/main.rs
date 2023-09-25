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
use std::fs;
use std::io::BufReader;
use std::path::Path;
use std::path::PathBuf;

use ::rpc::forge_tls_client::{ForgeClientCert, ForgeTlsConfig};
use ::rpc::Uuid;
use ::rpc::{
    forge::{self as forgerpc, MachineType},
    MachineId,
};
use cfg::carbide_options::BootOverrideAction;
use cfg::carbide_options::DpuAction::Reprovision;
use cfg::carbide_options::DpuReprovision;
use cfg::carbide_options::IpAction;
use cfg::carbide_options::{
    CarbideCommand, CarbideOptions, Domain, Instance, Machine, MaintenanceAction, ManagedHost,
    MigrateAction, NetworkCommand, NetworkSegment, OutputFormat, ResourcePool,
};
use clap::CommandFactory; // for CarbideOptions::command()
use prettytable::{row, Table};
use serde::Deserialize;
use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*};

mod cfg;
mod domain;
mod dpu;
mod instance;
mod machine;
mod managed_host;
mod network;
mod network_devices;
mod redfish;
mod resource_pool;
mod rpc;

#[derive(Debug, Deserialize)]
struct FileConfig {
    carbide_api_url: Option<String>,
    forge_root_ca_path: Option<String>,
    client_key_path: Option<String>,
    client_cert_path: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Config {
    carbide_api_url: String,
    forge_tls_config: ForgeTlsConfig,
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

    // Otherwise we assume the admin-cli is called from inside a kubernetes pod
    "https://carbide-api.forge-system.svc.cluster.local:1079".to_string()
}

fn get_client_cert_info(
    client_cert_path: Option<String>,
    client_key_path: Option<String>,
    file_config: Option<&FileConfig>,
) -> ForgeClientCert {
    // First from command line, second env var.
    if let (Some(client_key_path), Some(client_cert_path)) = (client_key_path, client_cert_path) {
        return ForgeClientCert {
            cert_path: client_cert_path,
            key_path: client_key_path,
        };
    }

    // Third config file
    if let Some(file_config) = file_config {
        if let (Some(client_key_path), Some(client_cert_path)) = (
            file_config.client_key_path.as_ref(),
            file_config.client_cert_path.as_ref(),
        ) {
            return ForgeClientCert {
                cert_path: client_cert_path.clone(),
                key_path: client_key_path.clone(),
            };
        }
    }

    // this is the location for most k8s pods
    if Path::new("/var/run/secrets/spiffe.io/tls.crt").exists()
        && Path::new("/var/run/secrets/spiffe.io/tls.key").exists()
    {
        return ForgeClientCert {
            cert_path: "/var/run/secrets/spiffe.io/tls.crt".to_string(),
            key_path: "/var/run/secrets/spiffe.io/tls.key".to_string(),
        };
    }

    // this is the location for most compiled clients executing on x86 hosts or DPUs
    if Path::new("/opt/forge/machine_cert.pem").exists()
        && Path::new("/opt/forge/machine_cert.key").exists()
    {
        return ForgeClientCert {
            cert_path: "/opt/forge/machine_cert.pem".to_string(),
            key_path: "/opt/forge/machine_cert.key".to_string(),
        };
    }

    // and this is the location for developers executing from within carbide's repo
    if let Ok(project_root) = env::var("REPO_ROOT") {
        //TODO: actually fix this cert and give it one that's valid for like 10 years.
        let cert_path = format!("{}/dev/certs/server_identity.pem", project_root);
        let key_path = format!("{}/dev/certs/server_identity.key", project_root);
        if Path::new(cert_path.as_str()).exists() && Path::new(key_path.as_str()).exists() {
            return ForgeClientCert {
                cert_path,
                key_path,
            };
        }
    }

    // if you make it here, you'll just have to tell me where the client cert is.
    panic!(
        r###"Unknown client cert location. Set (will be read in same sequence.)
           1. --client-cert-path and --client-key-path flag or
           2. environment variables CLIENT_KEY_PATH and CLIENT_CERT_PATH or
           3. add client_key_path and client_cert_path in $HOME/.config/carbide_api_cli.json.
           4. a file existing at "/var/run/secrets/spiffe.io/tls.crt" and "/var/run/secrets/spiffe.io/tls.key".
           5. a file existing at "/opt/forge/machine_cert.pem" and "/opt/forge/machine_cert.key".
           6. a file existing at "$REPO_ROOT/dev/certs/server_identity.pem" and "$REPO_ROOT/dev/certs/server_identity.key."###
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
        let path = format!(
            "{}/dev/certs/forge_developer_local_only_root_cert_pem",
            project_root
        );
        if Path::new(path.as_str()).exists() {
            return path;
        }
    }

    // if you make it here, you'll just have to tell me where the root CA is.
    panic!(
        r###"Unknown FORGE_ROOT_CA_PATH. Set (will be read in same sequence.)
           1. --forge-root-ca-path flag or
           2. environment variable FORGE_ROOT_CA_PATH or
           3. add forge_root_ca_path in $HOME/.config/carbide_api_cli.json.
           4. a file existing at "/var/run/secrets/spiffe.io/ca.crt".
           5. a file existing at "/opt/forge/forge_root.pem".
           6. a file existing at "$REPO_ROOT/dev/certs/forge_developer_local_only_root_cert_pem"."###
    )
}

fn get_config_from_file() -> Option<FileConfig> {
    // Third config file
    if let Ok(home) = env::var("HOME") {
        let file = Path::new(&home).join(".config/carbide_api_cli.json");
        if file.exists() {
            let file = fs::File::open(file).unwrap();
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
    let forge_client_cert = get_client_cert_info(
        config.client_cert_path,
        config.client_key_path,
        file_config.as_ref(),
    );
    let forge_tls_config = ForgeTlsConfig {
        client_cert: Some(forge_client_cert),
        root_ca_path: forge_root_ca_path,
    };
    let api_config = Config {
        carbide_api_url,
        forge_tls_config,
    };

    let command = match config.commands {
        None => {
            return Ok(CarbideOptions::command().print_long_help()?);
        }
        Some(s) => s,
    };

    // Command do talk to Carbide API
    match command {
        CarbideCommand::Version => {
            let v = rpc::version(&api_config).await?;
            // Same as running `carbide-api --version`
            println!(
                "carbide-api\t build_version={}, build_date={}, git_sha={}, rust_version={}, build_user={}, build_hostname={}",
                v.build_version, v.build_date, v.git_sha, v.rust_version, v.build_user, v.build_hostname,
            );
            // Same as running `forge-admin-cli --version`
            println!("forge-admin-cli\t {}", forge_version::version!());
        }
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
                            "Network config version",
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
                                st.network_config_version.unwrap_or_default(),
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
            Instance::Reboot(reboot_request) => {
                instance::handle_reboot(reboot_request, api_config).await?
            }
            Instance::Release(release_request) => {
                let instance_id = match (release_request.instance, release_request.machine) {
                    (Some(instance_id), _) => uuid::Uuid::parse_str(&instance_id)?.into(),
                    (_, Some(machine_id)) => {
                        let instances =
                            rpc::get_instances_by_machine_id(api_config.clone(), machine_id)
                                .await?;
                        if instances.instances.is_empty() {
                            color_eyre::eyre::bail!("No instances assigned to that machine");
                        }
                        instances.instances[0].id.clone().unwrap()
                    }
                    _ => unreachable!("clap will enforce exactly one of the two"),
                };
                rpc::release_instance(api_config, instance_id).await?
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
                        fs::OpenOptions::new()
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
            ManagedHost::Maintenance(maint) => match maint {
                MaintenanceAction::On(maint_on) => {
                    let req = forgerpc::MaintenanceRequest {
                        operation: forgerpc::MaintenanceOperation::Enable.into(),
                        host_id: Some(maint_on.host.into()),
                        reference: Some(maint_on.reference),
                    };
                    rpc::set_maintenance(req, api_config).await?;
                }
                MaintenanceAction::Off(maint_off) => {
                    let req = forgerpc::MaintenanceRequest {
                        operation: forgerpc::MaintenanceOperation::Disable.into(),
                        host_id: Some(maint_off.host.into()),
                        reference: None,
                    };
                    rpc::set_maintenance(req, api_config).await?;
                }
            },
        },
        CarbideCommand::ResourcePool(rp) => match rp {
            ResourcePool::Grow(def) => {
                let defs = fs::read_to_string(&def.filename)?;
                let rpc_req = forgerpc::GrowResourcePoolRequest { text: defs };
                let _ = rpc::grow_resource_pool(rpc_req, api_config.clone()).await?;
                tracing::info!("Resource Pool request sent.");
            }
            ResourcePool::List => {
                resource_pool::list(api_config).await?;
            }
        },
        CarbideCommand::Ip(ip_command) => match ip_command {
            IpAction::Find(find) => {
                let req = forgerpc::FindIpAddressRequest {
                    ip: find.ip.to_string(),
                };
                // maybe handle tonic::Status's `.code()` of tonic::Code::NotFound
                let resp = rpc::find_ip_address(req, api_config).await?;
                for r in resp.matches {
                    tracing::info!("{}", r.message);
                }
                if !resp.errors.is_empty() {
                    tracing::warn!("These matchers failed:");
                    for err in resp.errors {
                        tracing::warn!("\t{err}");
                    }
                }
            }
        },
        CarbideCommand::NetworkDevice(lldp) => match lldp {
            cfg::carbide_options::NetworkDeviceAction::Show(args) => {
                network_devices::show(config.format, args, api_config).await?;
            }
        },
        CarbideCommand::Migrate(migration) => match migration {
            MigrateAction::VpcVni => migrate_vpc_vni(&api_config).await?,
        },
        CarbideCommand::Dpu(dpu_action) => match dpu_action {
            Reprovision(reprov) => match reprov {
                DpuReprovision::Set(data) => {
                    dpu::trigger_reprovisioning(data.id, true, data.update_firmware, api_config)
                        .await?
                }
                DpuReprovision::Clear(data) => {
                    dpu::trigger_reprovisioning(data.id, false, data.update_firmware, api_config)
                        .await?
                }
                DpuReprovision::List => dpu::list_dpus_pending(api_config).await?,
            },
        },
        CarbideCommand::Redfish(_) => {
            // Handled earlier
            unreachable!();
        }
        CarbideCommand::BootOverride(boot_override_args) => match boot_override_args {
            BootOverrideAction::Get(boot_override) => {
                let mbo = rpc::get_boot_override(
                    &api_config,
                    Uuid {
                        value: boot_override.interface_id,
                    },
                )
                .await?;

                tracing::info!(
                    "{}",
                    serde_json::to_string_pretty(&mbo)
                        .expect("Failed to serialize MachineBootOverride")
                );
            }
            BootOverrideAction::Set(boot_override_set) => {
                if boot_override_set.custom_pxe.is_none()
                    && boot_override_set.custom_user_data.is_none()
                {
                    return Err(CarbideCliError::GenericError(
                        "Either custom pxe or custom user data is required".to_owned(),
                    )
                    .into());
                }

                let custom_pxe_path = boot_override_set.custom_pxe.map(PathBuf::from);
                let custom_user_data_path = boot_override_set.custom_user_data.map(PathBuf::from);

                rpc::set_boot_override(
                    &api_config,
                    Uuid {
                        value: boot_override_set.interface_id,
                    },
                    custom_pxe_path.as_deref(),
                    custom_user_data_path.as_deref(),
                )
                .await?;
            }
            BootOverrideAction::Clear(boot_override) => {
                rpc::clear_boot_override(
                    &api_config,
                    Uuid {
                        value: boot_override.interface_id,
                    },
                )
                .await?;
            }
        },
    }

    Ok(())
}

pub async fn migrate_vpc_vni(api_config: &Config) -> color_eyre::eyre::Result<()> {
    let result = crate::rpc::migrate_vpc_vni(api_config).await?;
    println!(
        "Added a VNI to {} of {} VPCs",
        result.updated_count, result.total_vpc_count
    );
    Ok(())
}
