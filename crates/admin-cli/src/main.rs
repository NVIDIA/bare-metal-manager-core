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

// CLI enums variants can be rather large, we are ok with that.
#![allow(clippy::large_enum_variant)]
use std::io;
use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;

use ::rpc::admin_cli::CarbideCliError;
use ::rpc::forge::ConfigSetting;
use ::rpc::forge_api_client::ForgeApiClient;
use ::rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use ::rpc::{CredentialType, forge as forgerpc};
use carbide_uuid::machine::MachineId;
use cfg::cli_options::{
    BmcAction, BootOverrideAction, CliCommand, CliOptions, CredentialAction, HostAction,
    HostReprovision, IpAction, SetAction, Shell,
};
use clap::CommandFactory;
use devenv::apply_devenv_config;
use forge_secrets::credentials::Credentials;
use forge_ssh::ssh::{
    copy_bfb_to_bmc_rshim, disable_rshim, enable_rshim, is_rshim_enabled, read_obmc_console_log,
};
use forge_tls::client_config::{
    get_carbide_api_url, get_client_cert_info, get_config_from_file, get_forge_root_ca_path,
    get_proxy_info,
};
use mac_address::MacAddress;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use crate::cfg::cli_options::AdminPowerControlAction;
use crate::cfg::dispatch::Dispatch;
use crate::cfg::runtime::{RuntimeConfig, RuntimeContext};
use crate::cfg::storage::OsImageActions;
use crate::rpc::ApiClient;

mod async_write;

mod cfg;
mod debug_bundle;
mod devenv;
mod domain;
mod dpa;
mod dpu;
mod dpu_remediation;
mod expected_machines;
mod expected_power_shelf;
mod expected_switch;
mod extension_service;
mod firmware;
mod host;
mod ib_partition;
mod instance;
mod instance_type;
mod inventory;
mod machine;
mod machine_interfaces;
mod machine_validation;
mod managed_host;
mod measurement;
mod metadata;
mod mlx;
mod network_devices;
mod network_security_group;
mod network_segment;
mod nvl_logical_partition;
mod nvl_partition;
mod ping;

mod power_shelf;
mod rack;
mod redfish;
mod resource_pool;
mod route_server;
mod rpc;
mod scout_stream;
mod site_explorer;
mod sku;
mod storage;
mod switch;
mod tenant;
mod tenant_keyset;
mod tpm_ca;
mod uefi;
mod version;
mod vpc;
mod vpc_peering;
mod vpc_prefix;

pub fn default_uuid() -> ::rpc::common::Uuid {
    ::rpc::common::Uuid {
        value: "00000000-0000-0000-0000-000000000000".to_string(),
    }
}

pub fn invalid_machine_id() -> String {
    "INVALID_MACHINE".to_string()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let config = CliOptions::load();
    if config.version {
        println!("{}", carbide_version::version!());
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

    if let Some(CliCommand::Redfish(ref ra)) = config.commands {
        match ra.command {
            redfish::Cmd::Browse(_) => {}
            _ => {
                return redfish::action(ra.clone()).await;
            }
        }
    }

    let url = get_carbide_api_url(config.carbide_api, file_config.as_ref());
    let forge_root_ca_path =
        get_forge_root_ca_path(config.forge_root_ca_path, file_config.as_ref());

    let command = match config.commands {
        None => {
            return Ok(CliOptions::command().print_long_help()?);
        }
        Some(s) => s,
    };

    let forge_client_cert = if matches!(command, CliCommand::Version(_)) {
        None
    } else {
        Some(get_client_cert_info(
            config.client_cert_path,
            config.client_key_path,
            file_config.as_ref(),
        ))
    };

    let proxy = get_proxy_info()?;

    let mut client_config = ForgeClientConfig::new(forge_root_ca_path, forge_client_cert);
    client_config.socks_proxy(proxy);

    // api_client is created here and subsequently
    // borrowed by all others.
    let api_client = ApiClient(ForgeApiClient::new(&ApiConfig::new(&url, &client_config)));

    let output_file = get_output_file_or_stdout(config.output.as_deref()).await?;

    // Build RuntimeContext before the match - ctx is moved into whichever arm executes
    let mut ctx = RuntimeContext {
        api_client,
        config: RuntimeConfig {
            format: config.format.clone(),
            page_size: config.internal_page_size,
            extended: config.extended,
            cloud_unsafe_op_enabled: config.cloud_unsafe_op.is_some(),
            sort_by: config.sort_by.clone(),
        },
        output_file,
    };

    // Command to talk to Carbide API.
    match command {
        CliCommand::Domain(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Dpa(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Dpu(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::DpuRemediation(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ExpectedMachine(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ExpectedPowerShelf(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ExpectedSwitch(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ExtensionService(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Firmware(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::IbPartition(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Instance(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::InstanceType(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::LogicalPartition(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Machine(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::MachineInterfaces(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::MachineValidation(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ManagedHost(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Measurement(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Mlx(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::NetworkDevice(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::NetworkSecurityGroup(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::NetworkSegment(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::NvlPartition(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Ping(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::PowerShelf(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Rack(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ResourcePool(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::RouteServer(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::ScoutStream(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::SiteExplorer(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Sku(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Switch(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Tenant(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::TenantKeySet(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::TpmCa(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Version(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Vpc(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::VpcPeering(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::VpcPrefix(cmd) => cmd.dispatch(ctx).await?,
        CliCommand::Ip(ip_command) => match ip_command {
            IpAction::Find(find) => {
                let req = forgerpc::FindIpAddressRequest {
                    ip: find.ip.to_string(),
                };
                // maybe handle tonic::Status's `.code()` of tonic::Code::NotFound
                let resp = ctx.api_client.0.find_ip_address(req).await?;
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
        CliCommand::Host(host_action) => match host_action {
            HostAction::SetUefiPassword(query) => {
                uefi::cmds::set_password(&query, &ctx.api_client).await?;
            }
            HostAction::ClearUefiPassword(query) => {
                uefi::cmds::clear_password(&query, &ctx.api_client).await?;
            }
            HostAction::GenerateHostUefiPassword => {
                let password = Credentials::generate_password_no_special_char();
                println!("Generated Bios Admin Password: {password}");
            }
            HostAction::Reprovision(reprovision) => match reprovision {
                HostReprovision::Set(data) => {
                    host::cmds::trigger_reprovisioning(
                        data.id,
                        ::rpc::forge::host_reprovisioning_request::Mode::Set,
                        &ctx.api_client,
                        data.update_message,
                    )
                    .await?
                }
                HostReprovision::Clear(data) => {
                    host::cmds::trigger_reprovisioning(
                        data.id,
                        ::rpc::forge::host_reprovisioning_request::Mode::Clear,
                        &ctx.api_client,
                        None,
                    )
                    .await?
                }
                HostReprovision::List => host::cmds::list_hosts_pending(&ctx.api_client).await?,
            },
        },
        CliCommand::Redfish(action) => {
            if let redfish::Cmd::Browse(redfish::UriInfo { uri }) = &action.command {
                return redfish::handle_browse_command(&ctx.api_client, uri).await;
            }

            // Handled earlier
            unreachable!();
        }
        CliCommand::BootOverride(boot_override_args) => match boot_override_args {
            BootOverrideAction::Get(boot_override) => {
                let mbo = ctx
                    .api_client
                    .0
                    .get_machine_boot_override(boot_override.interface_id)
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

                ctx.api_client
                    .set_boot_override(
                        boot_override_set.interface_id,
                        custom_pxe_path.as_deref(),
                        custom_user_data_path.as_deref(),
                    )
                    .await?;
            }
            BootOverrideAction::Clear(boot_override) => {
                ctx.api_client
                    .0
                    .clear_machine_boot_override(boot_override.interface_id)
                    .await?;
            }
        },
        CliCommand::BmcMachine(bmc_machine) => match bmc_machine {
            BmcAction::BmcReset(args) => {
                ctx.api_client
                    .bmc_reset(None, Some(args.machine), args.use_ipmitool)
                    .await?;
            }
            BmcAction::AdminPowerControl(args) => {
                ctx.api_client
                    .admin_power_control(None, Some(args.machine), args.action.into())
                    .await?;
            }
            BmcAction::CreateBmcUser(args) => {
                ctx.api_client
                    .create_bmc_user(
                        args.ip_address,
                        args.mac_address,
                        args.machine,
                        args.username,
                        args.password,
                        args.role_id,
                    )
                    .await?;
            }
            BmcAction::DeleteBmcUser(args) => {
                ctx.api_client
                    .delete_bmc_user(
                        args.ip_address,
                        args.mac_address,
                        args.machine,
                        args.username,
                    )
                    .await?;
            }
            BmcAction::EnableInfiniteBoot(args) => {
                let machine = args.machine;
                ctx.api_client
                    .enable_infinite_boot(None, Some(machine.clone()))
                    .await?;
                if args.reboot {
                    ctx.api_client
                        .admin_power_control(
                            None,
                            Some(machine),
                            AdminPowerControlAction::ForceRestart.into(),
                        )
                        .await?;
                }
            }
            BmcAction::IsInfiniteBootEnabled(args) => {
                let response = ctx
                    .api_client
                    .is_infinite_boot_enabled(None, Some(args.machine))
                    .await?;
                match response.is_enabled {
                    Some(true) => println!("Enabled"),
                    Some(false) => println!("Disabled"),
                    None => println!("Unknown"),
                }
            }
            BmcAction::Lockdown(args) => {
                let machine = args.machine;
                let action = if args.enable {
                    forgerpc::LockdownAction::Enable
                } else if args.disable {
                    forgerpc::LockdownAction::Disable
                } else {
                    return Err(CarbideCliError::GenericError(
                        "Either --enable or --disable must be specified".to_string(),
                    )
                    .into());
                };

                ctx.api_client.lockdown(None, machine, action).await?;

                let action_str = if args.enable { "enabled" } else { "disabled" };

                if args.reboot {
                    ctx.api_client
                        .admin_power_control(
                            None,
                            Some(machine.to_string()),
                            AdminPowerControlAction::ForceRestart.into(),
                        )
                        .await?;
                    println!(
                        "Lockdown {} and reboot initiated to apply the change.",
                        action_str
                    );
                } else {
                    println!(
                        "Lockdown {}. Please reboot the machine to apply the change.",
                        action_str
                    );
                }
            }
            BmcAction::LockdownStatus(args) => {
                let response = ctx.api_client.lockdown_status(None, args.machine).await?;
                // Convert status enum to string
                let status_str = match response.status {
                    0 => "Enabled",  // InternalLockdownStatus::ENABLED
                    1 => "Partial",  // InternalLockdownStatus::PARTIAL
                    2 => "Disabled", // InternalLockdownStatus::DISABLED
                    _ => "Unknown",
                };
                println!("{}: {}", status_str, response.message);
            }
        },
        CliCommand::Inventory(action) => {
            inventory::print_inventory(&ctx.api_client, action, ctx.config.page_size).await?
        }
        CliCommand::Credential(credential_action) => match credential_action {
            CredentialAction::AddUFM(c) => {
                let username = url_validator(c.url.clone())?;
                let password = c.token.clone();
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::Ufm.into(),
                    username: Some(username),
                    password,
                    mac_address: None,
                    vendor: None,
                };
                ctx.api_client.0.create_credential(req).await?;
            }
            CredentialAction::DeleteUFM(c) => {
                let username = url_validator(c.url.clone())?;
                let req = forgerpc::CredentialDeletionRequest {
                    credential_type: CredentialType::Ufm.into(),
                    username: Some(username),
                    mac_address: None,
                };
                ctx.api_client.0.delete_credential(req).await?;
            }
            CredentialAction::GenerateUFMCert(c) => {
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::Ufm.into(),
                    username: None,
                    password: "".to_string(),
                    mac_address: None,
                    vendor: Some(c.fabric),
                };
                ctx.api_client.0.create_credential(req).await?;
            }
            CredentialAction::AddBMC(c) => {
                let password = password_validator(c.password.clone())?;
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::from(c.kind).into(),
                    username: c.username,
                    password,
                    mac_address: c.mac_address.map(|mac| mac.to_string()),
                    vendor: None,
                };
                ctx.api_client.0.create_credential(req).await?;
            }
            CredentialAction::DeleteBMC(c) => {
                let req = forgerpc::CredentialDeletionRequest {
                    credential_type: CredentialType::from(c.kind).into(),
                    username: None,
                    mac_address: c.mac_address.map(|mac| mac.to_string()),
                };
                ctx.api_client.0.delete_credential(req).await?;
            }
            CredentialAction::AddUefi(c) => {
                let mut password = password_validator(c.password.clone())?;
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
                ctx.api_client.0.create_credential(req).await?;
            }
            CredentialAction::AddHostFactoryDefault(c) => {
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::HostBmcFactoryDefault.into(),
                    username: Some(c.username),
                    password: c.password,
                    mac_address: None,
                    vendor: Some(c.vendor.to_string()),
                };
                ctx.api_client.0.create_credential(req).await?;
            }
            CredentialAction::AddDpuFactoryDefault(c) => {
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::DpuBmcFactoryDefault.into(),
                    username: Some(c.username),
                    password: c.password,
                    mac_address: None,
                    vendor: None,
                };
                ctx.api_client.0.create_credential(req).await?;
            }
            CredentialAction::AddNmxM(c) => {
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::NmxM.into(),
                    username: Some(c.username),
                    password: c.password,
                    mac_address: None,
                    vendor: None,
                };
                ctx.api_client.0.create_credential(req).await?;
            }
            CredentialAction::DeleteNmxM(c) => {
                let req = forgerpc::CredentialDeletionRequest {
                    credential_type: CredentialType::NmxM.into(),
                    username: Some(c.username),
                    mac_address: None,
                };
                ctx.api_client.0.delete_credential(req).await?;
            }
        },
        CliCommand::GenerateShellComplete(shell) => {
            let mut cmd = CliOptions::command();
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
        CliCommand::Set(subcmd) => match subcmd {
            SetAction::LogFilter(opts) => {
                ctx.api_client
                    .set_dynamic_config(ConfigSetting::LogFilter, opts.filter, Some(opts.expiry))
                    .await?
            }
            SetAction::CreateMachines(opts) => {
                ctx.api_client
                    .set_dynamic_config(
                        ConfigSetting::CreateMachines,
                        opts.enabled.to_string(),
                        None,
                    )
                    .await?
            }
            SetAction::BmcProxy(opts) => {
                if opts.enabled {
                    ctx.api_client
                        .set_dynamic_config(
                            ConfigSetting::BmcProxy,
                            opts.proxy.unwrap_or("".to_string()),
                            None,
                        )
                        .await?
                } else {
                    ctx.api_client
                        .set_dynamic_config(ConfigSetting::BmcProxy, "".to_string(), None)
                        .await?
                }
            }
            SetAction::TracingEnabled {
                value: tracing_enabled,
            } => {
                ctx.api_client
                    .set_dynamic_config(
                        ConfigSetting::TracingEnabled,
                        tracing_enabled.to_string(),
                        None,
                    )
                    .await?
            }
        },
        CliCommand::Jump(j) => {
            // Is it a machine ID?
            // Grab the machine details.
            if let Ok(machine_id) = j.id.parse::<MachineId>() {
                machine::handle_show(
                    machine::ShowMachine {
                        machine: Some(machine_id),
                        help: None,
                        hosts: false,
                        all: false,
                        dpus: false,
                        instance_type_id: None,
                        history_count: 5,
                    },
                    &ctx.config.format,
                    &mut ctx.output_file,
                    &ctx.api_client,
                    ctx.config.page_size,
                    &ctx.config.sort_by,
                )
                .await?;

                return Ok(());
            }

            // Is it an IP?
            if IpAddr::from_str(&j.id).is_ok() {
                let req = forgerpc::FindIpAddressRequest { ip: j.id };

                let resp = ctx.api_client.0.find_ip_address(req).await?;

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

                    let config_format = ctx.config.format.clone();

                    use forgerpc::IpType::*;
                    match ip_type {
                        StaticDataDhcpServer => tracing::info!("DHCP Server"),
                        StaticDataRouteServer => tracing::info!("Route Server"),
                        RouteServerFromConfigFile => tracing::info!("Route Server from Carbide config"),
                        RouteServerFromAdminApi => tracing::info!("Route Server from Admin API"),
                        InstanceAddress => {
                            instance::cmds::handle_show(
                                instance::args::ShowInstance {
                                    id: m.owner_id.ok_or(CarbideCliError::GenericError(
                                        "failed to unwrap owner_id after finding instance for IP".to_string(),
                                    ))?,
                                    extrainfo: true,
                                    tenant_org_id: None,
                                    vpc_id: None,
                                    label_key: None,
                                    label_value: None,
                                    instance_type_id: None,
                                },
                                &mut ctx.output_file,
                                &config_format,
                                &ctx.api_client,
                                ctx.config.page_size,
                                &ctx.config.sort_by,
                            )
                            .await?
                        }
                        MachineAddress | BmcIp | LoopbackIp => {
                            machine::handle_show(
                                machine::ShowMachine {
                                    machine: Some(m.owner_id.and_then(|id| id.parse::<MachineId>().ok()).ok_or(CarbideCliError::GenericError(
                                        "failed to unwrap owner_id after finding machine for IP".to_string(),
                                    ))?),
                                    help: None,
                                    hosts: false,
                                    all: false,
                                    dpus: false,
                                    instance_type_id: None,
                                    history_count: 5
                                },
                                &config_format,
                                &mut ctx.output_file,
                                &ctx.api_client,
                                ctx.config.page_size,
                                &ctx.config.sort_by,
                            )
                            .await?;
                        }

                        ExploredEndpoint => {
                            site_explorer::show_site_explorer_discovered_managed_host(
                                &ctx.api_client,
                                &mut ctx.output_file,
                                config_format,
                                ctx.config.page_size,
                                site_explorer::args::GetReportMode::Endpoint(site_explorer::args::EndpointInfo{
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
                            network_segment::cmds::handle_show(
                                network_segment::args::ShowNetworkSegment {
                                    network: Some(m.owner_id.ok_or(CarbideCliError::GenericError(
                                        "failed to unwrap owner_id after finding network segment for IP".to_string(),
                                    ))?.parse()?),
                                    tenant_org_id: None,
                                    name: None,
                                },
                                config_format,
                                &ctx.api_client,
                                ctx.config.page_size,
                            )
                            .await?
                        }
                        ResourcePool => resource_pool::cmds::list(&ctx.api_client).await?,
                    };
                }

                return Ok(());
            }

            // Is it the UUID of some type of object?
            // Try to identify the type of object and then perform
            // a search for the object's details.  E.g., if it's the
            // UUID of an instance, then get the details of the instance.
            if let Ok(u) = j.id.parse::<uuid::Uuid>() {
                match ctx.api_client.identify_uuid(u).await {
                    Ok(o) => match o {
                        forgerpc::UuidType::NetworkSegment => {
                            network_segment::cmds::handle_show(
                                network_segment::args::ShowNetworkSegment {
                                    network: Some(j.id.parse()?),
                                    tenant_org_id: None,
                                    name: None,
                                },
                                ctx.config.format.clone(),
                                &ctx.api_client,
                                ctx.config.page_size,
                            )
                            .await?
                        }
                        forgerpc::UuidType::Instance => {
                            instance::cmds::handle_show(
                                instance::args::ShowInstance {
                                    id: j.id,
                                    extrainfo: true,
                                    tenant_org_id: None,
                                    vpc_id: None,
                                    label_key: None,
                                    label_value: None,
                                    instance_type_id: None,
                                },
                                &mut ctx.output_file,
                                &ctx.config.format,
                                &ctx.api_client,
                                ctx.config.page_size,
                                &ctx.config.sort_by,
                            )
                            .await?
                        }
                        forgerpc::UuidType::MachineInterface => {
                            machine_interfaces::cmds::handle_show(
                                machine_interfaces::args::ShowMachineInterfaces {
                                    interface_id: Some(j.id.parse()?),
                                    all: false,
                                    more: true,
                                },
                                ctx.config.format.clone(),
                                &ctx.api_client,
                            )
                            .await?
                        }
                        forgerpc::UuidType::Vpc => {
                            vpc::cmds::show(
                                vpc::args::ShowVpc {
                                    id: Some(j.id.parse()?),
                                    tenant_org_id: None,
                                    name: None,
                                    label_key: None,
                                    label_value: None,
                                },
                                ctx.config.format.clone(),
                                &ctx.api_client,
                                1,
                            )
                            .await?
                        }
                        forgerpc::UuidType::Domain => {
                            domain::cmds::handle_show(
                                &domain::args::ShowDomain {
                                    domain: Some(j.id.parse()?),
                                    all: false,
                                },
                                ctx.config.format.clone(),
                                &ctx.api_client,
                            )
                            .await?
                        }
                        forgerpc::UuidType::DpaInterfaceId => {
                            dpa::cmds::show(
                                &dpa::args::ShowDpa {
                                    id: Some(j.id.parse()?),
                                },
                                ctx.config.format.clone(),
                                &ctx.api_client,
                                1,
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
                match ctx.api_client.identify_mac(m).await {
                    Ok((mac_owner, primary_key)) => match mac_owner {
                        forgerpc::MacOwner::MachineInterface => {
                            machine_interfaces::cmds::handle_show(
                                machine_interfaces::args::ShowMachineInterfaces {
                                    interface_id: Some(primary_key.parse()?),
                                    all: false,
                                    more: true,
                                },
                                ctx.config.format.clone(),
                                &ctx.api_client,
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
            if let Ok(machine_id) = ctx.api_client.identify_serial(j.id, false).await {
                machine::handle_show(
                    machine::ShowMachine {
                        machine: Some(machine_id),
                        help: None,
                        hosts: false,
                        all: false,
                        dpus: false,
                        instance_type_id: None,
                        history_count: 5,
                    },
                    &ctx.config.format,
                    &mut ctx.output_file,
                    &ctx.api_client,
                    ctx.config.page_size,
                    &ctx.config.sort_by,
                )
                .await?;

                return Ok(());
            }

            // Do we have no idea what it is?
            color_eyre::eyre::bail!("Unable to determine ID type");
        }

        CliCommand::OsImage(os_image) => match os_image {
            OsImageActions::Show(os_image) => {
                storage::os_image_show(
                    os_image,
                    ctx.config.format,
                    &ctx.api_client,
                    ctx.config.page_size,
                )
                .await?
            }
            OsImageActions::Create(os_image) => {
                storage::os_image_create(os_image, &ctx.api_client).await?
            }
            OsImageActions::Delete(os_image) => {
                storage::os_image_delete(os_image, &ctx.api_client).await?
            }
            OsImageActions::Update(os_image) => {
                storage::os_image_update(os_image, &ctx.api_client).await?
            }
        },
        CliCommand::DevEnv(command) => match command {
            cfg::cli_options::DevEnv::Config(dev_env_config) => match dev_env_config {
                cfg::cli_options::DevEnvConfig::Apply(dev_env_config_apply) => {
                    apply_devenv_config(dev_env_config_apply, &ctx.api_client).await?;
                }
            },
        },
        CliCommand::Ssh(action) => match action {
            cfg::cli_options::SshActions::GetRshimStatus(ssh_args) => {
                let is_rshim_enabled = is_rshim_enabled(
                    ssh_args.credentials.bmc_ip_address,
                    ssh_args.credentials.bmc_username,
                    ssh_args.credentials.bmc_password,
                )
                .await?;
                tracing::info!("{is_rshim_enabled}");
            }
            cfg::cli_options::SshActions::DisableRshim(ssh_args) => {
                disable_rshim(
                    ssh_args.credentials.bmc_ip_address,
                    ssh_args.credentials.bmc_username,
                    ssh_args.credentials.bmc_password,
                )
                .await?;
            }
            cfg::cli_options::SshActions::EnableRshim(ssh_args) => {
                enable_rshim(
                    ssh_args.credentials.bmc_ip_address,
                    ssh_args.credentials.bmc_username,
                    ssh_args.credentials.bmc_password,
                )
                .await?;
            }
            cfg::cli_options::SshActions::CopyBfb(copy_bfb_args) => {
                copy_bfb_to_bmc_rshim(
                    copy_bfb_args.ssh_args.credentials.bmc_ip_address,
                    copy_bfb_args.ssh_args.credentials.bmc_username,
                    copy_bfb_args.ssh_args.credentials.bmc_password,
                    copy_bfb_args.bfb_path,
                )
                .await?;
            }
            cfg::cli_options::SshActions::ShowObmcLog(ssh_args) => {
                let log = read_obmc_console_log(
                    ssh_args.credentials.bmc_ip_address,
                    ssh_args.credentials.bmc_username,
                    ssh_args.credentials.bmc_password,
                )
                .await?;

                println!("OBMC Console Log:\n{log}");
            }
        },
        CliCommand::Rms(action) => match action {
            cfg::cli_options::RmsActions::Inventory => {
                rack::cmds::get_inventory(&ctx.api_client).await?;
            }
            cfg::cli_options::RmsActions::RemoveNode(remove_node_opts) => {
                rack::cmds::remove_node(&ctx.api_client, &remove_node_opts).await?;
            }
            cfg::cli_options::RmsActions::PoweronOrder => {
                rack::cmds::get_poweron_order(&ctx.api_client).await?;
            }
            cfg::cli_options::RmsActions::PowerState(power_state_opts) => {
                rack::cmds::get_power_state(&ctx.api_client, &power_state_opts).await?;
            }
            cfg::cli_options::RmsActions::FirmwareInventory(firmware_inventory_opts) => {
                rack::cmds::get_firmware_inventory(&ctx.api_client, &firmware_inventory_opts)
                    .await?;
            }
            cfg::cli_options::RmsActions::AvailableFwImages(available_fw_images_opts) => {
                rack::cmds::get_available_fw_images(&ctx.api_client, &available_fw_images_opts)
                    .await?;
            }
            cfg::cli_options::RmsActions::BkcFiles => {
                rack::cmds::get_bkc_files(&ctx.api_client).await?;
            }
            cfg::cli_options::RmsActions::CheckBkcCompliance => {
                rack::cmds::check_bkc_compliance(&ctx.api_client).await?;
            }
        },
        CliCommand::TrimTable(target) => {
            match target {
                cfg::cli_options::TrimTableTarget::MeasuredBoot(keep_entries) => {
                    // create a request and send it
                    let request = ::rpc::forge::TrimTableRequest {
                        target: ::rpc::forge::TrimTableTarget::MeasuredBoot.into(),
                        keep_entries: keep_entries.keep_entries,
                    };

                    let response = ctx.api_client.0.trim_table(request).await?;

                    println!(
                        "Trimmed {} reports from Measured Boot",
                        response.total_deleted
                    );
                }
            }
        }
    }

    Ok(())
}

pub fn url_validator(url: String) -> Result<String, CarbideCliError> {
    let addr = tonic::transport::Uri::try_from(&url)
        .map_err(|_| CarbideCliError::GenericError("invalid url".to_string()))?;
    Ok(addr.to_string())
}

pub fn password_validator(s: String) -> Result<String, CarbideCliError> {
    // TODO: check password according BMC pwd rule.
    if s.is_empty() {
        return Err(CarbideCliError::GenericError("invalid input".to_string()));
    }

    Ok(s)
}

pub async fn get_output_file_or_stdout(
    output_filename: Option<&str>,
) -> Result<Pin<Box<dyn tokio::io::AsyncWrite>>, CarbideCliError> {
    if let Some(filename) = output_filename {
        let file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(filename)
            .await?;
        Ok(Box::pin(file))
    } else {
        Ok(Box::pin(tokio::io::stdout()))
    }
}
