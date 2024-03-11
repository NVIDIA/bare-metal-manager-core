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
use std::fs;
use std::io;
use std::io::Write;
use std::path::PathBuf;

use ::rpc::forge as forgerpc;
use ::rpc::forge::MachineType;
use ::rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use ::rpc::CredentialType;
use ::rpc::MachineId;
use ::rpc::Uuid;
use cfg::carbide_options::AgentUpgrade;
use cfg::carbide_options::AgentUpgradePolicyChoice;
use cfg::carbide_options::BmcMachine;
use cfg::carbide_options::BootOverrideAction;
use cfg::carbide_options::CredentialAction;
use cfg::carbide_options::DpuAction;
use cfg::carbide_options::DpuAction::AgentUpgradePolicy;
use cfg::carbide_options::DpuAction::Reprovision;
use cfg::carbide_options::DpuAction::Versions;
use cfg::carbide_options::DpuReprovision;
use cfg::carbide_options::IpAction;
use cfg::carbide_options::MachineInterfaces;
use cfg::carbide_options::RouteServer;
use cfg::carbide_options::Shell;
use cfg::carbide_options::SiteExplorer;
use cfg::carbide_options::{
    CarbideCommand, CarbideOptions, Domain, Instance, Machine, MaintenanceAction, ManagedHost,
    MigrateAction, NetworkCommand, NetworkSegment, OutputFormat, ResourcePool,
};
use clap::CommandFactory; // for CarbideOptions::command()
use forge_tls::client_config::get_carbide_api_url;
use forge_tls::client_config::get_client_cert_info;
use forge_tls::client_config::get_config_from_file;
use forge_tls::client_config::get_forge_root_ca_path;
use forge_tls::client_config::get_proxy_info;
use prettytable::{row, Table};
use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*};

mod cfg;
mod domain;
mod dpu;
mod instance;
mod inventory;
mod machine;
mod machine_interfaces;
mod managed_host;
mod network;
mod network_devices;
mod ping;
mod redfish;
mod resource_pool;
mod rpc;
mod version;

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

pub fn invalid_machine_id() -> forgerpc::MachineId {
    forgerpc::MachineId {
        id: "INVALID_MACHINE".to_string(),
    }
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
        .add_directive("hyper=info".parse()?)
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
        .with(fmt::Layer::default().compact().with_writer(std::io::stderr))
        .with(env_filter)
        .try_init()?;

    // Commands that don't talk to Carbide API
    if let Some(CarbideCommand::Redfish(ra)) = config.commands {
        return redfish::action(ra).await;
    }

    let url = get_carbide_api_url(config.carbide_api, file_config.as_ref());
    let forge_root_ca_path =
        get_forge_root_ca_path(config.forge_root_ca_path, file_config.as_ref());
    let forge_client_cert = get_client_cert_info(
        config.client_cert_path,
        config.client_key_path,
        file_config.as_ref(),
    );

    let proxy = get_proxy_info()?;

    let mut client_config = ForgeClientConfig::new(forge_root_ca_path, Some(forge_client_cert));
    client_config.socks_proxy(proxy);

    // api_config is created here and subsequently
    // borrowed by all others.
    let api_config = &ApiConfig::new(&url, client_config);

    let command = match config.commands {
        None => {
            return Ok(CarbideOptions::command().print_long_help()?);
        }
        Some(s) => s,
    };

    // Command do talk to Carbide API
    match command {
        CarbideCommand::Version(version) => {
            version::handle_show_version(version, api_config).await?
        }
        CarbideCommand::Machine(machine) => match machine {
            Machine::Show(machine) => {
                machine::handle_show(machine, config.format, api_config).await?
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
                        table.set_titles(row![
                            "Observed at",
                            "DPU machine ID",
                            "Network config version",
                            "Healthy?",
                            "Check failed",
                            "Agent version",
                        ]);
                        for mut st in all_status.into_iter().filter(|st| st.health.is_some()) {
                            let h = st.health.take().unwrap();
                            let observed_at = st
                                .observed_at
                                .map(|o| {
                                    let dt: chrono::DateTime<chrono::Utc> = o.try_into().unwrap();
                                    dt.format("%Y-%m-%d %H:%M:%S.%3f").to_string()
                                })
                                .unwrap_or_default();
                            let failed_health_check = if !h.failed.is_empty() {
                                format!(
                                    "{} ({})",
                                    h.failed.first().map(String::as_str).unwrap(),
                                    h.message.unwrap_or_default(),
                                )
                            } else {
                                "".to_string()
                            };
                            table.add_row(row![
                                observed_at,
                                st.dpu_machine_id.unwrap(),
                                st.network_config_version.unwrap_or_default(),
                                h.is_healthy,
                                failed_health_check,
                                st.dpu_agent_version.unwrap_or("".to_string())
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
                instance::handle_show(instance, config.format, api_config).await?
            }
            Instance::Reboot(reboot_request) => {
                instance::handle_reboot(reboot_request, api_config).await?
            }
            Instance::Release(release_request) => {
                let instance_id = match (release_request.instance, release_request.machine) {
                    (Some(instance_id), _) => uuid::Uuid::parse_str(&instance_id)?.into(),
                    (_, Some(machine_id)) => {
                        let instances =
                            rpc::get_instances_by_machine_id(api_config, machine_id).await?;
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
                network::handle_show(network, config.format, api_config).await?
            }
        },
        CarbideCommand::Domain(domain) => match domain {
            Domain::Show(domain) => domain::handle_show(domain, config.format, api_config).await?,
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
                let _ = rpc::grow_resource_pool(rpc_req, api_config).await?;
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
        CarbideCommand::NetworkDevice(data) => match data {
            cfg::carbide_options::NetworkDeviceAction::Show(args) => {
                network_devices::show(config.format, args, api_config).await?;
            }
        },
        CarbideCommand::Migrate(migration) => match migration {
            MigrateAction::VpcVni => migrate_vpc_vni(api_config).await?,
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
            AgentUpgradePolicy(AgentUpgrade { set }) => {
                let rpc_choice = set.map(|cmd_line_policy| match cmd_line_policy {
                    AgentUpgradePolicyChoice::Off => forgerpc::AgentUpgradePolicy::Off,
                    AgentUpgradePolicyChoice::UpOnly => forgerpc::AgentUpgradePolicy::UpOnly,
                    AgentUpgradePolicyChoice::UpDown => forgerpc::AgentUpgradePolicy::UpDown,
                });
                dpu::handle_agent_upgrade_policy(api_config, rpc_choice).await?
            }
            Versions(options) => {
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

                dpu::handle_dpu_versions(
                    &mut output_file,
                    config.format,
                    api_config,
                    options.updates_only,
                )
                .await?
            }
            DpuAction::Status => {
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

                dpu::handle_dpu_status(&mut output_file, config.format, api_config).await?
            }
        },
        CarbideCommand::Redfish(_) => {
            // Handled earlier
            unreachable!();
        }
        CarbideCommand::BootOverride(boot_override_args) => match boot_override_args {
            BootOverrideAction::Get(boot_override) => {
                let mbo = rpc::get_boot_override(
                    api_config,
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
                    api_config,
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
                    api_config,
                    Uuid {
                        value: boot_override.interface_id,
                    },
                )
                .await?;
            }
        },
        CarbideCommand::BmcMachine(bmc_machine) => match bmc_machine {
            BmcMachine::Reset(c) => {
                let bmc_auth = match (c.username, c.password, c.machine) {
                    (Some(user), Some(password), _) => rpc::ResetAuth::Direct { user, password },
                    (_, _, Some(machine_id)) => rpc::ResetAuth::Indirect { machine_id },
                    _ => {
                        eprintln!("Provide either --machine-id or both --username and --password");
                        return Ok(());
                    }
                };
                rpc::bmc_reset(api_config, c.address, c.port, bmc_auth).await?;
            }
        },
        CarbideCommand::Inventory(action) => inventory::print_inventory(api_config, action).await?,
        CarbideCommand::Credential(credential_action) => match credential_action {
            CredentialAction::AddUFM(c) => {
                let username = url_validator(c.url.clone()).await?;
                let password = password_validator(c.token.clone()).await?;
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::Ufm.into(),
                    username: Some(username),
                    password,
                };
                rpc::add_credential(api_config, req).await?;
            }
            CredentialAction::DeleteUFM(c) => {
                let username = url_validator(c.url.clone()).await?;
                let req = forgerpc::CredentialDeletionRequest {
                    credential_type: CredentialType::Ufm.into(),
                    username: Some(username),
                };
                rpc::delete_credential(api_config, req).await?;
            }
            CredentialAction::AddBMC(c) => {
                let password = password_validator(c.password.clone()).await?;
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::from(c.kind).into(),
                    username: None,
                    password,
                };
                rpc::add_credential(api_config, req).await?;
            }
            CredentialAction::AddUefi(c) => {
                let password = password_validator(c.password.clone()).await?;
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::from(c.kind).into(),
                    username: None,
                    password,
                };
                rpc::add_credential(api_config, req).await?;
            }
        },
        CarbideCommand::RouteServer(action) => match action {
            RouteServer::Get => {
                let route_servers = rpc::get_route_servers(api_config).await?;
                println!("{}", serde_json::to_string(&route_servers)?);
            }
            RouteServer::Add(ip) => {
                rpc::add_route_server(api_config, ip.ip).await?;
            }
            RouteServer::Remove(ip) => {
                rpc::remove_route_server(api_config, ip.ip).await?;
            }
        },
        CarbideCommand::SiteExplorer(action) => match action {
            SiteExplorer::GetReport => {
                let exploration_report = rpc::get_site_exploration_report(api_config).await?;
                println!("{}", serde_json::to_string_pretty(&exploration_report)?);
            }
        },
        CarbideCommand::MachineInterfaces(machine_interfaces) => match machine_interfaces {
            MachineInterfaces::Show(machine_interfaces) => {
                machine_interfaces::handle_show(machine_interfaces, config.format, api_config)
                    .await?
            }
        },
        CarbideCommand::GenerateShellComplete(shell) => {
            let mut cmd = CarbideOptions::command();
            match shell.shell {
                Shell::Bash => {
                    clap_complete::generate(
                        clap_complete::shells::Bash,
                        &mut cmd,
                        "forge-admin-cli",
                        &mut io::stdout(),
                    );
                    // Make completion work for alias `fa`
                    io::stdout().write_all(
                        b"complete -F _forge-admin-cli -o nosort -o bashdefault -o default fa\n",
                    )?;
                }
                Shell::Fish => {
                    clap_complete::generate(
                        clap_complete::shells::Fish,
                        &mut cmd,
                        "forge-admin-cli",
                        &mut io::stdout(),
                    );
                }
                Shell::Zsh => {
                    clap_complete::generate(
                        clap_complete::shells::Zsh,
                        &mut cmd,
                        "forge-admin-cli",
                        &mut io::stdout(),
                    );
                }
            }
        }
        CarbideCommand::Ping(opts) => ping::ping(api_config, opts).await?,
    }

    Ok(())
}

pub async fn migrate_vpc_vni(api_config: &ApiConfig<'_>) -> color_eyre::eyre::Result<()> {
    let result = crate::rpc::migrate_vpc_vni(api_config).await?;
    println!(
        "Added a VNI to {} of {} VPCs",
        result.updated_count, result.total_vpc_count
    );
    Ok(())
}

pub async fn url_validator(url: String) -> Result<String, CarbideCliError> {
    let addr = tonic::transport::Uri::try_from(&url)
        .map_err(|_| CarbideCliError::GenericError("invalid url".to_string()))?;
    Ok(addr.to_string())
}

pub async fn password_validator(s: String) -> Result<String, CarbideCliError> {
    // TODO: check password according BMC pwd rule.
    if s.is_empty() {
        return Err(CarbideCliError::GenericError("invalid input".to_string()));
    }

    Ok(s)
}
