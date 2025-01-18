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
use std::collections::HashMap;
use std::collections::VecDeque;

use std::fs;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

use crate::cfg::storage::{
    OsImageActions, StorageActions, StorageClusterActions, StoragePoolActions, StorageVolumeActions,
};
use ::rpc::common::MachineId;
use ::rpc::forge as forgerpc;
use ::rpc::forge::dpu_reprovisioning_request::Mode;
use ::rpc::forge::ConfigSetting;
use ::rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use ::rpc::CredentialType;
use ::rpc::Uuid;
use cfg::carbide_options::AgentUpgrade;
use cfg::carbide_options::AgentUpgradePolicyChoice;
use cfg::carbide_options::BmcAction;
use cfg::carbide_options::BootOverrideAction;
use cfg::carbide_options::CredentialAction;
use cfg::carbide_options::DpuAction;
use cfg::carbide_options::DpuAction::AgentUpgradePolicy;
use cfg::carbide_options::DpuAction::Reprovision;
use cfg::carbide_options::DpuAction::Versions;
use cfg::carbide_options::DpuReprovision;
use cfg::carbide_options::ExpectedMachineJson;
use cfg::carbide_options::HostAction;
use cfg::carbide_options::IbPartitionOptions;
use cfg::carbide_options::IpAction;
use cfg::carbide_options::MachineInterfaces;
use cfg::carbide_options::RouteServer;
use cfg::carbide_options::SetAction;
use cfg::carbide_options::Shell;
use cfg::carbide_options::SiteExplorer;
use cfg::carbide_options::TenantKeySetOptions;
use cfg::carbide_options::TpmCa;
use cfg::carbide_options::VpcPrefixOptions;
use cfg::carbide_options::{
    CarbideCommand, CarbideOptions, Domain, Instance, Machine, MaintenanceAction, ManagedHost,
    NetworkCommand, NetworkSegment, ResourcePool, VpcOptions,
};
use clap::CommandFactory;
use forge_secrets::credentials::Credentials;
use forge_tls::client_config::get_carbide_api_url;
use forge_tls::client_config::get_client_cert_info;
use forge_tls::client_config::get_config_from_file;
use forge_tls::client_config::get_forge_root_ca_path;
use forge_tls::client_config::get_proxy_info;
use mac_address::MacAddress;
use prettytable::{row, Table};
use serde::Deserialize;
use serde::Serialize;
use site_explorer::show_site_explorer_discovered_managed_host;
use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*};
use utils::admin_cli::{CarbideCliError, OutputFormat};

mod cfg;
mod domain;
mod dpu;
mod expected_machines;
mod ib_partition;
mod instance;
mod inventory;
mod machine;
mod machine_interfaces;
mod machine_validation;
mod managed_host;
mod measurement;
mod network;
mod network_devices;
mod ping;
mod redfish;
mod resource_pool;
mod rpc;
mod site_explorer;
mod storage;
mod tenant_keyset;
mod tpm;
mod uefi;
mod version;
mod vpc;
mod vpc_prefix;

pub fn default_uuid() -> ::rpc::common::Uuid {
    ::rpc::common::Uuid {
        value: "00000000-0000-0000-0000-000000000000".to_string(),
    }
}

pub fn invalid_machine_id() -> ::rpc::common::MachineId {
    ::rpc::common::MachineId {
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

    if let Some(CarbideCommand::Redfish(ra)) = config.commands {
        return redfish::action(api_config, ra).await;
    }

    let command = match config.commands {
        None => {
            return Ok(CarbideOptions::command().print_long_help()?);
        }
        Some(s) => s,
    };

    // Command do talk to Carbide API
    match command {
        CarbideCommand::Version(version) => {
            version::handle_show_version(version, config.format, api_config).await?
        }
        CarbideCommand::Machine(machine) => match machine {
            Machine::Show(machine) => {
                machine::handle_show(
                    machine,
                    config.format,
                    api_config,
                    config.internal_page_size,
                )
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
                        let all_ids: Vec<MachineId> = all_status
                            .iter()
                            .filter_map(|status| status.dpu_machine_id.clone())
                            .collect();
                        let all_dpus = rpc::get_machines_by_ids(api_config, &all_ids)
                            .await?
                            .machines;
                        let mut dpus_by_id = HashMap::new();
                        for dpu in all_dpus.into_iter() {
                            if let Some(id) = dpu.id.clone() {
                                dpus_by_id.insert(id.id, dpu);
                            }
                        }

                        let mut table = Table::new();
                        table.set_titles(row![
                            "Observed at",
                            "DPU machine ID",
                            "Network config version",
                            "Healthy?",
                            "Health Probe Alerts",
                            "Agent version",
                        ]);
                        for st in all_status.into_iter() {
                            let Some(dpu_id) = st.dpu_machine_id.clone() else {
                                continue;
                            };
                            let Some(dpu) = dpus_by_id.get(&dpu_id.id) else {
                                continue;
                            };
                            let observed_at = st
                                .observed_at
                                .map(|o| {
                                    let dt: chrono::DateTime<chrono::Utc> = o.try_into().unwrap();
                                    dt.format("%Y-%m-%d %H:%M:%S.%3f").to_string()
                                })
                                .unwrap_or_default();
                            let mut probe_alerts = String::new();
                            if let Some(health) = &dpu.health {
                                for alert in health.alerts.iter() {
                                    if !probe_alerts.is_empty() {
                                        probe_alerts.push('\n');
                                    }
                                    if let Some(target) = &alert.target {
                                        probe_alerts +=
                                            &format!("{} [Target: {}]", alert.id, target)
                                    } else {
                                        probe_alerts += &alert.id.to_string();
                                    }
                                }
                            }
                            table.add_row(row![
                                observed_at,
                                st.dpu_machine_id.unwrap(),
                                st.network_config_version.unwrap_or_default(),
                                dpu.health
                                    .as_ref()
                                    .map(|health| health.alerts.is_empty().to_string())
                                    .unwrap_or_else(|| "unknown".to_string()),
                                probe_alerts,
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
            Machine::HealthOverride(command) => {
                machine::handle_override(command, config.format, api_config).await?;
            }
            Machine::Reboot(c) => {
                rpc::admin_power_control(
                    api_config,
                    None,
                    Some(c.machine),
                    ::rpc::forge::admin_power_control_request::SystemPowerControl::ForceRestart,
                )
                .await?;
            }
            Machine::ForceDelete(query) => machine::force_delete(query, api_config).await?,
            Machine::AutoUpdate(cfg) => machine::autoupdate(cfg, api_config).await?,
        },
        CarbideCommand::Instance(instance) => match instance {
            Instance::Show(instance) => {
                instance::handle_show(
                    instance,
                    config.format,
                    api_config,
                    config.internal_page_size,
                )
                .await?
            }
            Instance::Reboot(reboot_request) => {
                instance::handle_reboot(reboot_request, api_config).await?
            }
            Instance::Release(release_request) => {
                if !config.cloud_unsafe_op {
                    return Err(CarbideCliError::GenericError(
                        "Operation not allowed due to potential inconsistencies with cloud database.".to_owned(),
                    )
                    .into());
                }

                let mut instance_ids: Vec<::rpc::common::Uuid> = Vec::new();

                match (
                    release_request.instance,
                    release_request.machine,
                    release_request.label_key,
                ) {
                    (Some(instance_id), _, _) => {
                        instance_ids.push(uuid::Uuid::parse_str(&instance_id)?.into())
                    }
                    (_, Some(machine_id), _) => {
                        let instances =
                            rpc::get_instances_by_machine_id(api_config, machine_id).await?;
                        if instances.instances.is_empty() {
                            color_eyre::eyre::bail!("No instances assigned to that machine");
                        }
                        instance_ids.push(instances.instances[0].id.clone().unwrap());
                    }
                    (_, _, Some(key)) => {
                        let instances = rpc::get_all_instances(
                            api_config,
                            None,
                            None,
                            Some(key),
                            release_request.label_value,
                            config.internal_page_size,
                        )
                        .await?;
                        if instances.instances.is_empty() {
                            color_eyre::eyre::bail!("No instances with the passed label.key exist");
                        }
                        instance_ids = instances
                            .instances
                            .iter()
                            .filter_map(|instance| instance.id.clone())
                            .collect();
                    }
                    _ => {}
                };
                rpc::release_instances(api_config, instance_ids).await?
            }
            Instance::Allocate(allocate_request) => {
                if !config.cloud_unsafe_op {
                    return Err(CarbideCliError::GenericError(
                        "Operation not allowed due to potential inconsistencies with cloud database.".to_owned(),
                    )
                    .into());
                }
                let mut machine_ids: VecDeque<_> =
                    rpc::find_machine_ids(api_config, Some(forgerpc::MachineType::Host), false)
                        .await
                        .unwrap()
                        .machine_ids
                        .into_iter()
                        .map(|id| id.to_string())
                        .collect();

                for i in 0..allocate_request.number.unwrap_or(1) {
                    let Some(hid_for_instance) =
                        machine::get_next_free_machine(&api_config.clone(), &mut machine_ids).await
                    else {
                        tracing::error!("No available machines.");
                        break;
                    };

                    match rpc::allocate_instance(
                        &api_config.clone(),
                        &hid_for_instance,
                        &allocate_request,
                        &format!("{}_{}", allocate_request.prefix_name.clone(), i),
                    )
                    .await
                    {
                        Ok(_) => {
                            tracing::info!("allocate_instance was successful. ");
                        }
                        Err(e) => {
                            tracing::info!("allocate_instance failed with {} ", e);
                        }
                    };
                }
            }
        },
        CarbideCommand::NetworkSegment(network) => match network {
            NetworkSegment::Show(network) => {
                network::handle_show(
                    network,
                    config.format,
                    api_config,
                    config.internal_page_size,
                )
                .await?
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
                managed_host::handle_show(
                    &mut output_file,
                    managed_host,
                    config.format,
                    api_config,
                    config.internal_page_size,
                )
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
        CarbideCommand::Measurement(cmd) => {
            let args = cfg::measurement::GlobalOptions {
                format: config.format,
                extended: config.extended,
            };
            measurement::dispatch(&cmd, &args, api_config).await?
        }
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
        CarbideCommand::Dpu(dpu_action) => match dpu_action {
            Reprovision(reprov) => match reprov {
                DpuReprovision::Set(data) => {
                    dpu::trigger_reprovisioning(
                        data.id,
                        Mode::Set,
                        data.update_firmware,
                        api_config,
                        data.maintenance_reference,
                    )
                    .await?
                }
                DpuReprovision::Clear(data) => {
                    dpu::trigger_reprovisioning(
                        data.id,
                        Mode::Clear,
                        data.update_firmware,
                        api_config,
                        None,
                    )
                    .await?
                }
                DpuReprovision::List => dpu::list_dpus_pending(api_config).await?,
                DpuReprovision::Restart(data) => {
                    dpu::trigger_reprovisioning(
                        data.id,
                        Mode::Restart,
                        data.update_firmware,
                        api_config,
                        None,
                    )
                    .await?
                }
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
                    config.internal_page_size,
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

                dpu::handle_dpu_status(
                    &mut output_file,
                    config.format,
                    api_config,
                    config.internal_page_size,
                )
                .await?
            }
        },
        CarbideCommand::Host(host_action) => match host_action {
            HostAction::SetUefiPassword(query) => {
                uefi::set_host_uefi_password(query, api_config).await?;
            }
            HostAction::ClearUefiPassword(query) => {
                uefi::clear_host_uefi_password(query, api_config).await?;
            }
            HostAction::GenerateHostUefiPassword => {
                let password = Credentials::generate_password_no_special_char();
                println!("Generated Bios Admin Password: {}", password);
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
            BmcAction::BmcReset(args) => {
                rpc::bmc_reset(api_config, None, Some(args.machine), args.use_ipmitool).await?;
            }
            BmcAction::AdminPowerControl(args) => {
                rpc::admin_power_control(api_config, None, Some(args.machine), args.action.into())
                    .await?;
            }
        },
        CarbideCommand::Inventory(action) => {
            inventory::print_inventory(api_config, action, config.internal_page_size).await?
        }
        CarbideCommand::Credential(credential_action) => match credential_action {
            CredentialAction::AddUFM(c) => {
                let username = url_validator(c.url.clone()).await?;
                let password = c.token.clone();
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::Ufm.into(),
                    username: Some(username),
                    password,
                    mac_address: None,
                    vendor: None,
                };
                rpc::add_credential(api_config, req).await?;
            }
            CredentialAction::DeleteUFM(c) => {
                let username = url_validator(c.url.clone()).await?;
                let req = forgerpc::CredentialDeletionRequest {
                    credential_type: CredentialType::Ufm.into(),
                    username: Some(username),
                    mac_address: None,
                };
                rpc::delete_credential(api_config, req).await?;
            }
            CredentialAction::GenerateUFMCert(c) => {
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::Ufm.into(),
                    username: None,
                    password: "".to_string(),
                    mac_address: None,
                    vendor: Some(c.fabric),
                };
                rpc::add_credential(api_config, req).await?;
            }
            CredentialAction::AddBMC(c) => {
                let password = password_validator(c.password.clone()).await?;
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::from(c.kind).into(),
                    username: c.username,
                    password,
                    mac_address: c.mac_address.map(|mac| mac.to_string()),
                    vendor: None,
                };
                rpc::add_credential(api_config, req).await?;
            }
            CredentialAction::DeleteBMC(c) => {
                let req = forgerpc::CredentialDeletionRequest {
                    credential_type: CredentialType::from(c.kind).into(),
                    username: None,
                    mac_address: c.mac_address.map(|mac| mac.to_string()),
                };
                rpc::delete_credential(api_config, req).await?;
            }
            CredentialAction::AddUefi(c) => {
                let mut password = password_validator(c.password.clone()).await?;
                if c.password.is_empty() {
                    password = Credentials::generate_password_no_special_char();
                }

                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::from(c.kind).into(),
                    username: None,
                    password,
                    mac_address: None,
                    vendor: None,
                };
                rpc::add_credential(api_config, req).await?;
            }
            CredentialAction::AddHostFactoryDefault(c) => {
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::HostBmcFactoryDefault.into(),
                    username: Some(c.username),
                    password: c.password,
                    mac_address: None,
                    vendor: Some(c.vendor.to_string()),
                };
                rpc::add_credential(api_config, req).await?;
            }
            CredentialAction::AddDpuFactoryDefault(c) => {
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::DpuBmcFactoryDefault.into(),
                    username: Some(c.username),
                    password: c.password,
                    mac_address: None,
                    vendor: None,
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
            SiteExplorer::GetReport(mode) => {
                show_site_explorer_discovered_managed_host(
                    api_config,
                    config.format,
                    config.internal_page_size,
                    mode,
                )
                .await?;
            }
            SiteExplorer::Explore(opts) => {
                let report = rpc::explore(api_config, &opts.address, opts.mac).await?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            SiteExplorer::ReExplore(opts) => {
                rpc::re_explore_endpoint(api_config, &opts.address).await?;
            }
            SiteExplorer::ClearError(opts) => {
                rpc::clear_site_explorer_last_known_error(api_config, opts.address).await?;
            }
            SiteExplorer::IsBmcInManagedHost(opts) => {
                let is_bmc_in_managed_host =
                    rpc::is_bmc_in_managed_host(api_config, &opts.address, opts.mac).await?;
                println!(
                    "Is {} in a managed host?: {}",
                    opts.address, is_bmc_in_managed_host.in_managed_host
                );
            }
            SiteExplorer::HaveCredentials(opts) => {
                let have_credentials =
                    rpc::bmc_credential_status(api_config, &opts.address, opts.mac).await?;
                println!("{}", have_credentials.have_credentials);
            }
        },
        CarbideCommand::MachineInterfaces(machine_interfaces) => match machine_interfaces {
            MachineInterfaces::Show(machine_interfaces) => {
                machine_interfaces::handle_show(machine_interfaces, config.format, api_config)
                    .await?
            }
            MachineInterfaces::Delete(args) => {
                machine_interfaces::handle_delete(args, api_config).await?
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
        CarbideCommand::Set(subcmd) => match subcmd {
            SetAction::LogFilter(opts) => {
                rpc::set_dynamic_config(
                    api_config,
                    ConfigSetting::LogFilter,
                    opts.filter,
                    Some(opts.expiry),
                )
                .await?
            }
            SetAction::CreateMachines(opts) => {
                rpc::set_dynamic_config(
                    api_config,
                    ConfigSetting::CreateMachines,
                    opts.enabled.to_string(),
                    None,
                )
                .await?
            }
            SetAction::BmcProxy(opts) => {
                if opts.enabled {
                    rpc::set_dynamic_config(
                        api_config,
                        ConfigSetting::BmcProxy,
                        opts.proxy.unwrap_or("".to_string()),
                        None,
                    )
                    .await?
                } else {
                    rpc::set_dynamic_config(
                        api_config,
                        ConfigSetting::BmcProxy,
                        "".to_string(),
                        None,
                    )
                    .await?
                }
            }
        },
        CarbideCommand::ExpectedMachine(expected_machine_action) => match expected_machine_action {
            cfg::carbide_options::ExpectedMachineAction::Show(expected_machine_query) => {
                expected_machines::show_expected_machines(
                    &expected_machine_query,
                    api_config,
                    config.format,
                )
                .await?;
            }
            cfg::carbide_options::ExpectedMachineAction::Add(expected_machine_data) => {
                if expected_machine_data.has_duplicate_dpu_serials() {
                    eprintln!("Duplicate values not allowed for --fallback-dpu-serial-number");
                    return Ok(());
                }
                let metadata = expected_machine_data.metadata()?;
                rpc::add_expected_machine(
                    expected_machine_data.bmc_mac_address,
                    expected_machine_data.bmc_username,
                    expected_machine_data.bmc_password,
                    expected_machine_data.chassis_serial_number,
                    expected_machine_data.fallback_dpu_serial_numbers,
                    metadata,
                    api_config,
                )
                .await?;
            }
            cfg::carbide_options::ExpectedMachineAction::Delete(expected_machine_query) => {
                rpc::delete_expected_machine(expected_machine_query.bmc_mac_address, api_config)
                    .await?;
            }
            cfg::carbide_options::ExpectedMachineAction::Update(expected_machine_data) => {
                if let Err(e) = expected_machine_data.validate() {
                    eprintln!("{e}");
                    return Ok(());
                }
                let metadata = expected_machine_data.metadata()?;
                rpc::update_expected_machine(
                    expected_machine_data.bmc_mac_address,
                    expected_machine_data.bmc_username,
                    expected_machine_data.bmc_password,
                    expected_machine_data.chassis_serial_number,
                    expected_machine_data.fallback_dpu_serial_numbers,
                    metadata,
                    api_config,
                )
                .await?;
            }
            cfg::carbide_options::ExpectedMachineAction::ReplaceAll(request) => {
                let json_file_path = Path::new(&request.filename);
                let reader = BufReader::new(File::open(json_file_path)?);
                #[derive(Debug, Serialize, Deserialize)]
                struct ExpectedMachineList {
                    expected_machines: Vec<ExpectedMachineJson>,
                    expected_machines_count: Option<usize>,
                }
                let expected_machine_list: ExpectedMachineList = serde_json::from_reader(reader)?;

                if expected_machine_list
                    .expected_machines_count
                    .is_some_and(|count| count != expected_machine_list.expected_machines.len())
                {
                    return Err(CarbideCliError::GenericError(format!(
                        "Json File specified an invalid count: {:#?}; actual count: {}",
                        expected_machine_list
                            .expected_machines_count
                            .unwrap_or_default(),
                        expected_machine_list.expected_machines.len()
                    ))
                    .into());
                }

                rpc::replace_all_expected_machines(
                    expected_machine_list.expected_machines,
                    api_config,
                )
                .await?;
            }
            cfg::carbide_options::ExpectedMachineAction::Erase => {
                rpc::delete_all_expected_machines(api_config).await?;
            }
        },
        CarbideCommand::Vpc(vpc) => match vpc {
            VpcOptions::Show(vpc) => {
                vpc::handle_show(vpc, config.format, api_config, config.internal_page_size).await?
            }
            VpcOptions::SetVirtualizer(set_vpc_virt) => {
                vpc::set_network_virtualization_type(api_config, set_vpc_virt).await?
            }
        },
        CarbideCommand::VpcPrefix(vpc_prefix_command) => {
            use VpcPrefixOptions::*;
            match vpc_prefix_command {
                Create(create_options) => {
                    vpc_prefix::handle_create(create_options, config.format, api_config).await?
                }
                Show(show_options) => {
                    vpc_prefix::handle_show(
                        show_options,
                        config.format,
                        api_config,
                        config.internal_page_size,
                    )
                    .await?
                }
                Delete(delete_options) => {
                    vpc_prefix::handle_delete(delete_options, api_config).await?
                }
            }
        }
        CarbideCommand::IbPartition(ibp) => match ibp {
            IbPartitionOptions::Show(ibp) => {
                ib_partition::handle_show(ibp, config.format, api_config, config.internal_page_size)
                    .await?
            }
        },
        CarbideCommand::TenantKeySet(tks) => match tks {
            TenantKeySetOptions::Show(tks) => {
                tenant_keyset::handle_show(
                    tks,
                    config.format,
                    api_config,
                    config.internal_page_size,
                )
                .await?
            }
        },
        CarbideCommand::Jump(j) => {
            // Is it a machine ID?
            // Grab the machine details.
            if forge_uuid::machine::MachineId::from_str(&j.id).is_ok() {
                machine::handle_show(
                    cfg::carbide_options::ShowMachine {
                        machine: j.id,
                        help: None,
                        hosts: false,
                        all: false,
                        dpus: false,
                        history_count: 5,
                    },
                    config.format,
                    api_config,
                    config.internal_page_size,
                )
                .await?;

                return Ok(());
            }

            // Is it an IP?
            if IpAddr::from_str(&j.id).is_ok() {
                let req = forgerpc::FindIpAddressRequest { ip: j.id };

                let resp = rpc::find_ip_address(req, api_config).await?;

                // Go through each object that matched the IP search,
                // and perform any more specific searches available for
                // the object type of the owner.   E.g., if it's an IP
                // attached to an instance, get the details of the instance.
                for m in resp.matches {
                    let ip_type = match forgerpc::IpType::try_from(m.ip_type) {
                        Ok(t) => t,
                        Err(err) => {
                            tracing::error!(ip_type = m.ip_type, error = %err, "Invalid IpType");
                            continue;
                        }
                    };

                    let config_format = config.format.clone();

                    use forgerpc::IpType::*;
                    match ip_type {
                        StaticDataDhcpServer => tracing::info!("DHCP Server"),
                        StaticDataRouteServer => tracing::info!("Route Server"),
                        InstanceAddress => {
                            instance::handle_show(
                                cfg::carbide_options::ShowInstance {
                                    id: m.owner_id.ok_or(CarbideCliError::GenericError(
                                        "failed to unwrap owner_id after finding instance for IP".to_string(),
                                    ))?,
                                    extrainfo: true,
                                    tenant_org_id: None,
                                    vpc_id: None,
                                    label_key: None,
                                    label_value: None,
                                },
                                config_format,
                                api_config,
                                config.internal_page_size,
                            )
                            .await?
                        }
                        MachineAddress | BmcIp | LoopbackIp => {
                            machine::handle_show(
                                cfg::carbide_options::ShowMachine {
                                    machine: m.owner_id.ok_or(CarbideCliError::GenericError(
                                        "failed to unwrap owner_id after finding machine for IP".to_string(),
                                    ))?,
                                    help: None,
                                    hosts: false,
                                    all: false,
                                    dpus: false,
                                    history_count: 5
                                },
                                config_format,
                                api_config,
                                config.internal_page_size,
                            )
                            .await?;
                        }

                        ExploredEndpoint => {
                            site_explorer::show_site_explorer_discovered_managed_host(
                                api_config,
                                config_format,
                                config.internal_page_size,
                                cfg::carbide_options::GetReportMode::Endpoint(cfg::carbide_options::EndpointInfo{
                                    address: if m.owner_id.is_some() { m.owner_id } else {
                                        color_eyre::eyre::bail!(CarbideCliError::GenericError("IP type is explored-endpoint but returned owner_id is empty".to_string()))
                                    },
                                    erroronly: false,
                                    successonly: false,
                                    unpairedonly: false,
                                    vendor: None,
                                }),
                            )
                            .await?;
                        }

                        NetworkSegment => {
                            network::handle_show(
                                cfg::carbide_options::ShowNetwork {
                                    network: m.owner_id.ok_or(CarbideCliError::GenericError(
                                        "failed to unwrap owner_id after finding network segment for IP".to_string(),
                                    ))?,
                                    tenant_org_id: None,
                                    name: None,
                                },
                                config_format,
                                api_config,
                                config.internal_page_size,
                            )
                            .await?
                        }
                        ResourcePool => resource_pool::list(api_config).await?,
                    };
                }

                return Ok(());
            }

            // Is it the UUID of some type of object?
            // Try to identify the type of object and then perform
            // a search for the object's details.  E.g., if it's the
            // UUID of an instance, then get the details of the instance.
            if let Ok(u) = j.id.parse::<uuid::Uuid>() {
                match rpc::identify_uuid(api_config, u).await {
                    Ok(o) => match o {
                        forgerpc::UuidType::NetworkSegment => {
                            network::handle_show(
                                cfg::carbide_options::ShowNetwork {
                                    network: j.id,
                                    tenant_org_id: None,
                                    name: None,
                                },
                                config.format,
                                api_config,
                                config.internal_page_size,
                            )
                            .await?
                        }
                        forgerpc::UuidType::Instance => {
                            instance::handle_show(
                                cfg::carbide_options::ShowInstance {
                                    id: j.id,
                                    extrainfo: true,
                                    tenant_org_id: None,
                                    vpc_id: None,
                                    label_key: None,
                                    label_value: None,
                                },
                                config.format,
                                api_config,
                                config.internal_page_size,
                            )
                            .await?
                        }
                        forgerpc::UuidType::MachineInterface => {
                            machine_interfaces::handle_show(
                                cfg::carbide_options::ShowMachineInterfaces {
                                    interface_id: j.id,
                                    all: false,
                                    more: true,
                                },
                                config.format,
                                api_config,
                            )
                            .await?
                        }
                        forgerpc::UuidType::Vpc => {
                            vpc::handle_show(
                                cfg::carbide_options::ShowVpc {
                                    id: j.id,
                                    tenant_org_id: None,
                                    name: None,
                                    label_key: None,
                                    label_value: None,
                                },
                                config.format,
                                api_config,
                                1,
                            )
                            .await?
                        }
                        forgerpc::UuidType::Domain => {
                            domain::handle_show(
                                cfg::carbide_options::ShowDomain {
                                    domain: j.id,
                                    all: false,
                                },
                                config.format,
                                api_config,
                            )
                            .await?
                        }
                    },
                    Err(e) => {
                        color_eyre::eyre::bail!(e);
                    }
                }

                return Ok(());
            }

            // Is it a MAC?
            // Grab the details for the interface it's associated with.
            if let Ok(m) = MacAddress::from_str(&j.id) {
                match rpc::identify_mac(api_config, m).await {
                    Ok((mac_owner, mac_type)) => match mac_owner {
                        forgerpc::MacOwner::MachineInterface => {
                            machine_interfaces::handle_show(
                                cfg::carbide_options::ShowMachineInterfaces {
                                    interface_id: mac_type,
                                    all: false,
                                    more: true,
                                },
                                config.format,
                                api_config,
                            )
                            .await?
                        }
                        forgerpc::MacOwner::ExploredEndpoint => {
                            color_eyre::eyre::bail!(
                                "Searching explored-endpoints from MAC not yet implemented"
                            );
                        }
                        forgerpc::MacOwner::ExpectedMachine => {
                            color_eyre::eyre::bail!(
                                "Searching expected-machines from MAC not yet implemented"
                            );
                        }
                    },
                    Err(e) => {
                        color_eyre::eyre::bail!(e);
                    }
                }

                return Ok(());
            }

            // Is it a serial number?!??!?!
            // Grab the machine ID and look-up the machine.
            if let Ok(machine_id) = rpc::identify_serial(api_config, j.id).await {
                machine::handle_show(
                    cfg::carbide_options::ShowMachine {
                        machine: machine_id.to_string(),
                        help: None,
                        hosts: false,
                        all: false,
                        dpus: false,
                        history_count: 5,
                    },
                    config.format,
                    api_config,
                    config.internal_page_size,
                )
                .await?;

                return Ok(());
            }

            // Do we have no idea what it is?
            color_eyre::eyre::bail!("Unable to determine ID type");
        }

        CarbideCommand::MachineValidation(command) => match command {
            cfg::carbide_options::MachineValidationCommand::ExternalConfig(config_command) => {
                match config_command {
                    cfg::carbide_options::MachineValidationExternalConfigCommand::Show(opts) => {
                        machine_validation::external_config_show(
                            api_config,
                            opts.name,
                            config.extended,
                            config.format,
                        )
                        .await?;
                    }
                    cfg::carbide_options::MachineValidationExternalConfigCommand::AddUpdate(
                        opts,
                    ) => {
                        machine_validation::external_config_add_update(
                            api_config,
                            opts.name,
                            opts.file_name,
                            opts.description,
                        )
                        .await?;
                    }
                    cfg::carbide_options::MachineValidationExternalConfigCommand::Remove(opts) => {
                        machine_validation::remove_external_config(api_config, opts.name).await?;
                    }
                }
            }
            cfg::carbide_options::MachineValidationCommand::Results(cmd) => match cmd {
                cfg::carbide_options::MachineValidationResultsCommand::Show(options) => {
                    machine_validation::handle_results_show(
                        options,
                        config.format,
                        api_config,
                        config.internal_page_size,
                        config.extended,
                    )
                    .await?;
                }
            },
            cfg::carbide_options::MachineValidationCommand::Runs(cmd) => match cmd {
                cfg::carbide_options::MachineValidationRunsCommand::Show(options) => {
                    machine_validation::handle_runs_show(
                        options,
                        config.format,
                        api_config,
                        config.internal_page_size,
                    )
                    .await?;
                }
            },
            cfg::carbide_options::MachineValidationCommand::OnDemand(on_demand_command) => {
                match on_demand_command {
                    cfg::carbide_options::MachineValidationOnDemandCommand::Start(options) => {
                        machine_validation::on_demand_machine_validation(api_config, options)
                            .await?;
                    }
                }
            }
            cfg::carbide_options::MachineValidationCommand::Tests(
                machine_validation_tests_command,
            ) => match *machine_validation_tests_command {
                cfg::carbide_options::MachineValidationTestsCommand::Show(options) => {
                    machine_validation::show_tests(
                        api_config,
                        options,
                        config.format,
                        config.extended,
                    )
                    .await?;
                }
                cfg::carbide_options::MachineValidationTestsCommand::Verify(options) => {
                    machine_validation::machine_validation_test_verfied(api_config, options)
                        .await?;
                }
                cfg::carbide_options::MachineValidationTestsCommand::Enable(options) => {
                    machine_validation::machine_validation_test_enable(api_config, options).await?;
                }
                cfg::carbide_options::MachineValidationTestsCommand::Disable(options) => {
                    machine_validation::machine_validation_test_disable(api_config, options)
                        .await?;
                }
                cfg::carbide_options::MachineValidationTestsCommand::Add(options) => {
                    machine_validation::machine_validation_test_add(api_config, options).await?;
                }
                cfg::carbide_options::MachineValidationTestsCommand::Update(options) => {
                    machine_validation::machine_validation_test_update(api_config, options).await?;
                }
            },
        },
        CarbideCommand::Storage(storage_cmd) => match storage_cmd {
            StorageActions::Cluster(storage_cluster) => match storage_cluster {
                StorageClusterActions::Show(storage_cluster) => {
                    storage::cluster_show(
                        storage_cluster,
                        config.format,
                        api_config,
                        config.internal_page_size,
                    )
                    .await?
                }
                StorageClusterActions::Import(storage_cluster) => {
                    storage::cluster_import(storage_cluster, api_config).await?
                }
                StorageClusterActions::Delete(storage_cluster) => {
                    storage::cluster_delete(storage_cluster, api_config).await?
                }
                StorageClusterActions::Update(storage_cluster) => {
                    storage::cluster_update(storage_cluster, api_config).await?
                }
            },
            StorageActions::Pool(storage_pool) => match storage_pool {
                StoragePoolActions::Show(storage_pool) => {
                    storage::pool_show(
                        storage_pool,
                        config.format,
                        api_config,
                        config.internal_page_size,
                    )
                    .await?
                }
                StoragePoolActions::Create(storage_pool) => {
                    storage::pool_create(storage_pool, api_config).await?
                }
                StoragePoolActions::Delete(storage_pool) => {
                    storage::pool_delete(storage_pool, api_config).await?
                }
                StoragePoolActions::Update(storage_pool) => {
                    storage::pool_update(storage_pool, api_config).await?
                }
            },
            StorageActions::Volume(storage_volume) => match storage_volume {
                StorageVolumeActions::Show(storage_volume) => {
                    storage::volume_show(
                        storage_volume,
                        config.format,
                        api_config,
                        config.internal_page_size,
                    )
                    .await?
                }
                StorageVolumeActions::Create(storage_volume) => {
                    storage::volume_create(storage_volume, api_config).await?
                }
                StorageVolumeActions::Delete(storage_volume) => {
                    storage::volume_delete(storage_volume, api_config).await?
                }
                StorageVolumeActions::Update(storage_volume) => {
                    storage::volume_update(storage_volume, api_config).await?
                }
            },
        },
        CarbideCommand::OsImage(os_image) => match os_image {
            OsImageActions::Show(os_image) => {
                storage::os_image_show(
                    os_image,
                    config.format,
                    api_config,
                    config.internal_page_size,
                )
                .await?
            }
            OsImageActions::Create(os_image) => {
                storage::os_image_create(os_image, api_config).await?
            }
            OsImageActions::Delete(os_image) => {
                storage::os_image_delete(os_image, api_config).await?
            }
            OsImageActions::Update(os_image) => {
                storage::os_image_update(os_image, api_config).await?
            }
        },
        CarbideCommand::TpmCa(subcmd) => match subcmd {
            TpmCa::Show => tpm::show_ca_certs(api_config).await?,
            TpmCa::Delete(delete_opts) => {
                tpm::delete_ca_cert(delete_opts.ca_id, api_config).await?
            }
            TpmCa::Add(add_opts) => {
                tpm::add_ca_cert_filename(&add_opts.filename, api_config).await?
            }
            TpmCa::AddBulk(add_opts) => {
                tpm::add_ca_cert_bulk(&add_opts.dirname, api_config).await?
            }
            TpmCa::ShowUnmatchedEk => tpm::show_unmatched_ek_certs(api_config).await?,
        },
    }

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

#[cfg(test)]
mod tests {
    use crate::cfg::carbide_options::{
        CarbideCommand, CarbideOptions, ExpectedMachine, ExpectedMachineAction::Update,
        UpdateExpectedMachine,
    };
    use clap::Parser;

    #[test]
    fn forge_admin_cli_expected_machine_test() {
        assert!(ExpectedMachine::try_parse_from([
            "ExpectedMachine",
            "--bmc-mac-address",
            "0a:0b:0c:0d:0e:0f",
            "--bmc-username",
            "me",
            "--bmc-password",
            "my-pw",
            "--chassis-serial-number",
            "<CHASSIS_SERIAL_NUMBER>",
        ])
        .is_ok());

        // No dpu serial
        assert!(ExpectedMachine::try_parse_from([
            "ExpectedMachine",
            "--bmc-mac-address",
            "0a:0b:0c:0d:0e:0f",
            "--bmc-username",
            "me",
            "--bmc-password",
            "my-pw",
            "--chassis-serial-number",
            "<CHASSIS_SERIAL_NUMBER>",
        ])
        .is_ok_and(|t1| { !t1.has_duplicate_dpu_serials() }));

        assert!(ExpectedMachine::try_parse_from([
            "ExpectedMachine",
            "--bmc-mac-address",
            "0a:0b:0c:0d:0e:0f",
            "--bmc-username",
            "me",
            "--bmc-password",
            "my-pw",
            "--chassis-serial-number",
            "<CHASSIS_SERIAL_NUMBER>",
            "--fallback-dpu-serial-number",
            "dpu_serial",
        ])
        .is_ok());

        assert!(ExpectedMachine::try_parse_from([
            "ExpectedMachine",
            "--bmc-mac-address",
            "0a:0b:0c:0d:0e:0f",
            "--bmc-username",
            "me",
            "--bmc-password",
            "my-pw",
            "--chassis-serial-number",
            "<CHASSIS_SERIAL_NUMBER>",
            "--fallback-dpu-serial-number",
            "dpu_serial",
            "-d",
            "dpu_serial2",
        ])
        .is_ok());

        // Duplicate dpu_serial
        assert!(ExpectedMachine::try_parse_from([
            "ExpectedMachine",
            "--bmc-mac-address",
            "0a:0b:0c:0d:0e:0f",
            "--bmc-username",
            "me",
            "--bmc-password",
            "my-pw",
            "--chassis-serial-number",
            "<CHASSIS_SERIAL_NUMBER>",
            "-d",
            "dpu_serial1",
            "-d",
            "dpu_serial2",
            "-d",
            "dpu_serial3",
            "-d",
            "dpu_serial1"
        ])
        .is_ok_and(|t| { t.has_duplicate_dpu_serials() }));

        // option --fallback-dpu-serial-number used w/o value
        assert!(ExpectedMachine::try_parse_from([
            "ExpectedMachine",
            "--bmc-mac-address",
            "0a:0b:0c:0d:0e:0f",
            "--bmc-username",
            "me",
            "--bmc-password",
            "my-pw",
            "--chassis-serial-number",
            "<CHASSIS_SERIAL_NUMBER>",
            "--fallback-dpu-serial-number"
        ])
        .is_err());

        fn test_update_expected_machine<F: Fn(UpdateExpectedMachine) -> bool>(
            options: CarbideOptions,
            pred: F,
        ) -> bool {
            let mut update_args = None;
            if let Some(CarbideCommand::ExpectedMachine(Update(args))) = options.commands {
                update_args = Some(args);
            }
            update_args.is_some() && pred(update_args.unwrap())
        }
        // update 1 dpu serial
        assert!(test_update_expected_machine(
            CarbideOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--fallback-dpu-serial-number",
                "<DPU_SERIAL_NUMBER>",
            ])
            .ok()
            .unwrap(),
            |args| { args.validate().is_ok() }
        ));
        // update 2 dpu serials
        assert!(test_update_expected_machine(
            CarbideOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--fallback-dpu-serial-number",
                "<DPU_SERIAL_NUMBER_1>",
                "-d",
                "<DPU_SERIAL_NUMBER_2>",
            ])
            .unwrap(),
            |args| { args.validate().is_ok() }
        ));

        assert!(CarbideOptions::try_parse_from([
            "forge-admin-cli",
            "expected-machine",
            "update",
            "--bmc-mac-address",
            "00:00:00:00:00:00",
            "--fallback-dpu-serial-number",
        ])
        .is_err());

        // Fail if duplicate dpu serials are given
        // duplicate dpu serials -
        assert!(test_update_expected_machine(
            CarbideOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--fallback-dpu-serial-number",
                "dpu1",
                "-d",
                "dpu2",
                "-d",
                "dpu3",
                "-d",
                "dpu2",
                "-d",
                "dpu4",
            ])
            .ok()
            .unwrap(),
            |args| { args.validate().is_err() }
        ));

        // Update credential
        assert!(CarbideOptions::try_parse_from([
            "forge-admin-cli",
            "expected-machine",
            "update",
            "--bmc-mac-address",
            "00:00:00:00:00:00",
            "--bmc-username",
            "<BMC_USERNAME>",
            "--bmc-password",
            "<BMC_PASSWORD>",
        ])
        .is_ok());
        // update all
        assert!(test_update_expected_machine(
            CarbideOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-username",
                "ssss",
                "--bmc-password",
                "ssss",
                "--chassis-serial-number",
                "sss",
                "--fallback-dpu-serial-number",
                "<DPU_SERIAL_NUMBER>",
            ])
            .ok()
            .unwrap(),
            |args| { args.validate().is_ok() }
        ));
        // update - user name only - error
        assert!(CarbideOptions::try_parse_from([
            "forge-admin-cli",
            "expected-machine",
            "update",
            "--bmc-mac-address",
            "00:00:00:00:00:00",
            "--bmc-username",
            "ssss",
        ])
        .is_err());
        // update - password  only - error
        assert!(CarbideOptions::try_parse_from([
            "forge-admin-cli",
            "expected-machine",
            "update",
            "--bmc-mac-address",
            "00:00:00:00:00:00",
            "--bmc-password",
            "ssss",
        ])
        .is_err());
    }

    #[test]
    fn forge_admin_cli_credential_test() {
        //  bmc-root credential w.o optional username
        assert!(CarbideOptions::try_parse_from([
            "forge-admin-cli",
            "credential",
            "add-bmc",
            "--kind=bmc-root",
            "--mac-address",
            "0a:0b:0c:0d:0e:0f",
            "--password",
            "my-pw",
        ])
        .is_ok());

        //  bmc-root credential with optional username
        assert!(CarbideOptions::try_parse_from([
            "forge-admin-cli",
            "credential",
            "add-bmc",
            "--kind=bmc-root",
            "--mac-address",
            "0a:0b:0c:0d:0e:0f",
            "--password",
            "my-pw",
            "--username",
            "me"
        ])
        .is_ok());
    }

    #[test]
    fn forge_admin_cli_tpm_ca_test() {
        assert!(CarbideOptions::try_parse_from(["forge-admin-cli", "tpm-ca", "show"]).is_ok());

        assert!(CarbideOptions::try_parse_from([
            "forge-admin-cli",
            "tpm-ca",
            "add",
            "--filename",
            "/tmp/somefile.cer"
        ])
        .is_ok());

        assert!(CarbideOptions::try_parse_from([
            "forge-admin-cli",
            "tpm-ca",
            "add-bulk",
            "--dirname",
            "/tmp"
        ])
        .is_ok());

        assert!(CarbideOptions::try_parse_from([
            "forge-admin-cli",
            "tpm-ca",
            "delete",
            "--ca-id",
            "4"
        ])
        .is_ok());
    }
}
