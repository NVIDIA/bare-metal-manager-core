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

// CLI enums variants can be rather large, we ok with that.
#![allow(clippy::large_enum_variant)]

use std::collections::HashSet;
use std::collections::VecDeque;

use std::fs;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::Write;
use std::net::IpAddr;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::str::FromStr;

use crate::cfg::cli_options::QuarantineAction;
use crate::cfg::storage::{
    OsImageActions, StorageActions, StorageClusterActions, StoragePoolActions, StorageVolumeActions,
};
use crate::rpc::ApiClient;
use ::rpc::CredentialType;
use ::rpc::Uuid;
use ::rpc::forge as forgerpc;
use ::rpc::forge::ConfigSetting;
use ::rpc::forge::dpu_reprovisioning_request::Mode;
use ::rpc::forge_api_client::ForgeApiClient;
use ::rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use cfg::cli_options::AgentUpgrade;
use cfg::cli_options::AgentUpgradePolicyChoice;
use cfg::cli_options::BmcAction;
use cfg::cli_options::BootOverrideAction;
use cfg::cli_options::CredentialAction;
use cfg::cli_options::DpuAction;
use cfg::cli_options::DpuAction::AgentUpgradePolicy;
use cfg::cli_options::DpuAction::Reprovision;
use cfg::cli_options::DpuAction::Versions;
use cfg::cli_options::DpuReprovision;
use cfg::cli_options::ExpectedMachineJson;
use cfg::cli_options::HostAction;
use cfg::cli_options::HostReprovision;
use cfg::cli_options::IbPartitionOptions;
use cfg::cli_options::IpAction;
use cfg::cli_options::MachineInterfaces;
use cfg::cli_options::MachineMetadataCommand;
use cfg::cli_options::RedfishCommand;
use cfg::cli_options::RouteServer;
use cfg::cli_options::SetAction;
use cfg::cli_options::Shell;
use cfg::cli_options::SiteExplorer;
use cfg::cli_options::TenantKeySetOptions;
use cfg::cli_options::TpmCa;
use cfg::cli_options::UriInfo;
use cfg::cli_options::VpcPeeringOptions;
use cfg::cli_options::VpcPrefixOptions;
use cfg::cli_options::{
    CliCommand, CliOptions, Domain, Instance, Machine, MachineHardwareInfo,
    MachineHardwareInfoCommand, MaintenanceAction, ManagedHost, NetworkCommand, NetworkSegment,
    ResourcePool, VpcOptions,
};
use cfg::instance_type::InstanceTypeActions;
use cfg::network_security_group::NetworkSecurityGroupActions;
use clap::CommandFactory;
use devenv::apply_devenv_config;
use forge_secrets::credentials::Credentials;
use forge_ssh::ssh::copy_bfb_to_bmc_rshim;
use forge_ssh::ssh::disable_rshim;
use forge_ssh::ssh::enable_rshim;
use forge_ssh::ssh::is_rshim_enabled;
use forge_ssh::ssh::read_obmc_console_log;
use forge_tls::client_config::get_carbide_api_url;
use forge_tls::client_config::get_client_cert_info;
use forge_tls::client_config::get_config_from_file;
use forge_tls::client_config::get_forge_root_ca_path;
use forge_tls::client_config::get_proxy_info;
use mac_address::MacAddress;
use machine::{handle_show_machine_hardware_info, handle_update_machine_hardware_info_gpus};
use serde::Deserialize;
use serde::Serialize;
use site_explorer::show_site_explorer_discovered_managed_host;
use tracing_subscriber::{filter::EnvFilter, filter::LevelFilter, fmt, prelude::*};
use utils::admin_cli::{CarbideCliError, OutputFormat};

mod async_write;
mod cfg;
mod devenv;
mod domain;
mod dpu;
mod expected_machines;
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
mod network;
mod network_devices;
mod network_security_group;
mod ping;
mod redfish;
mod resource_pool;
mod rpc;
mod site_explorer;
mod sku;
mod storage;
mod tenant_keyset;
mod tpm;
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

pub fn invalid_machine_id() -> ::rpc::common::MachineId {
    ::rpc::common::MachineId {
        id: "INVALID_MACHINE".to_string(),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> color_eyre::Result<()> {
    color_eyre::install()?;

    let config = CliOptions::load();
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

    if let Some(CliCommand::Redfish(ref ra)) = config.commands {
        match ra.command {
            RedfishCommand::Browse(_) => {}
            _ => {
                return redfish::action(ra.clone()).await;
            }
        }
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

    // api_client is created here and subsequently
    // borrowed by all others.
    let api_client = ApiClient(ForgeApiClient::new(&ApiConfig::new(&url, &client_config)));

    let command = match config.commands {
        None => {
            return Ok(CliOptions::command().print_long_help()?);
        }
        Some(s) => s,
    };

    let mut output_file = get_output_file_or_stdout(config.output.as_deref()).await?;

    // Command do talk to Carbide API
    match command {
        CliCommand::Version(version) => {
            version::handle_show_version(version, config.format, &api_client).await?
        }
        CliCommand::Machine(machine) => match machine {
            Machine::Show(machine) => {
                machine::handle_show(
                    machine,
                    &config.format,
                    &mut output_file,
                    &api_client,
                    config.internal_page_size,
                    &config.sort_by,
                )
                .await?
            }
            Machine::Metadata(metadata_command) => match metadata_command {
                MachineMetadataCommand::Show(cmd) => {
                    let mut machines = api_client
                        .get_machines_by_ids(&[cmd.machine.clone().into()])
                        .await?
                        .machines;
                    let Some(machine) = machines.pop() else {
                        return Err(eyre::eyre!("Machine with ID {} was not found", cmd.machine));
                    };
                    machine::handle_metadata_show(
                        &mut output_file,
                        &config.format,
                        config.extended,
                        machine,
                    )
                    .await?;
                }
                MachineMetadataCommand::Set(cmd) => {
                    let mut machines = api_client
                        .get_machines_by_ids(&[cmd.machine.clone().into()])
                        .await?
                        .machines;
                    if machines.len() != 1 {
                        return Err(eyre::eyre!("Machine with ID {} was not found", cmd.machine));
                    }
                    let machine = machines.remove(0);

                    let mut metadata = machine.metadata.ok_or_else(|| {
                        eyre::eyre!("Machine does not carry Metadata that can be patched")
                    })?;
                    if let Some(name) = cmd.name {
                        metadata.name = name;
                    }
                    if let Some(description) = cmd.description {
                        metadata.description = description;
                    }

                    api_client
                        .update_machine_metadata(machine.id.unwrap(), metadata, machine.version)
                        .await?;
                }
                MachineMetadataCommand::FromExpectedMachine(cmd) => {
                    let mut machines = api_client
                        .get_machines_by_ids(&[cmd.machine.clone().into()])
                        .await?
                        .machines;
                    if machines.len() != 1 {
                        return Err(eyre::eyre!("Machine with ID {} was not found", cmd.machine));
                    }
                    let machine = machines.remove(0);
                    let bmc_mac = machine
                        .bmc_info
                        .as_ref()
                        .and_then(|bmc_info| bmc_info.mac.clone())
                        .ok_or_else(|| {
                            eyre::eyre!(
                                "No BMC MAC address found for Machine with ID {}",
                                cmd.machine
                            )
                        })?
                        .to_ascii_lowercase();

                    let mut metadata = machine.metadata.ok_or_else(|| {
                        eyre::eyre!("Machine does not carry Metadata that can be patched")
                    })?;

                    let expected_machines = api_client
                        .0
                        .get_all_expected_machines()
                        .await?
                        .expected_machines;
                    let expected_machine =
                        expected_machines
                        .iter()
                        .find(|em| em.bmc_mac_address.to_ascii_lowercase() == bmc_mac)
                        .ok_or_else(|| eyre::eyre!("No expected Machine found for Machine with ID {} and BMC Mac address {}",
                            cmd.machine, bmc_mac))?;
                    let expected_machine_metadata =
                        expected_machine.metadata.clone()
                        .ok_or_else(|| eyre::eyre!("No expected Machine Metadata found for Machine with ID {} and BMC Mac address {}", cmd.machine, bmc_mac))?;

                    if cmd.replace_all {
                        // Configure the Machines metadata in the same way as if the Machine was freshly ingested
                        metadata.name = if expected_machine_metadata.name.is_empty() {
                            machine.id.clone().unwrap().id
                        } else {
                            expected_machine_metadata.name
                        };
                        metadata.description = expected_machine_metadata.description;
                        metadata.labels = expected_machine_metadata.labels;
                    } else {
                        // Add new data from expected-machines, but current values that might have been the
                        // result of previous changed to the Machine.
                        // This operation is lossless for existing Metadata.
                        if !expected_machine_metadata.name.is_empty()
                            && (metadata.name.is_empty() || metadata.name == cmd.machine)
                        {
                            metadata.name = expected_machine_metadata.name;
                        };
                        if !expected_machine_metadata.description.is_empty()
                            && metadata.description.is_empty()
                        {
                            metadata.description = expected_machine_metadata.description;
                        };
                        for label in expected_machine_metadata.labels {
                            if !metadata.labels.iter().any(|l| l.key == label.key) {
                                metadata.labels.push(label);
                            }
                        }
                    }

                    api_client
                        .update_machine_metadata(machine.id.unwrap(), metadata, machine.version)
                        .await?;
                }
                MachineMetadataCommand::AddLabel(cmd) => {
                    let mut machines = api_client
                        .get_machines_by_ids(&[cmd.machine.clone().into()])
                        .await?
                        .machines;
                    if machines.len() != 1 {
                        return Err(eyre::eyre!("Machine with ID {} was not found", cmd.machine));
                    }
                    let machine = machines.remove(0);

                    let mut metadata = machine.metadata.ok_or_else(|| {
                        eyre::eyre!("Machine does not carry Metadata that can be patched")
                    })?;
                    metadata.labels.retain_mut(|l| l.key != cmd.key);
                    metadata.labels.push(::rpc::forge::Label {
                        key: cmd.key,
                        value: cmd.value,
                    });

                    api_client
                        .update_machine_metadata(machine.id.unwrap(), metadata, machine.version)
                        .await?;
                }
                MachineMetadataCommand::RemoveLabels(cmd) => {
                    let mut machines = api_client
                        .get_machines_by_ids(&[cmd.machine.clone().into()])
                        .await?
                        .machines;
                    if machines.len() != 1 {
                        return Err(eyre::eyre!("Machine with ID {} was not found", cmd.machine));
                    }
                    let machine = machines.remove(0);

                    let mut metadata = machine.metadata.ok_or_else(|| {
                        eyre::eyre!("Machine does not carry Metadata that can be patched")
                    })?;

                    // Retain everything that isn't specified as removed
                    let removed_labels: HashSet<String> = cmd.keys.into_iter().collect();
                    metadata.labels.retain(|l| !removed_labels.contains(&l.key));

                    api_client
                        .update_machine_metadata(machine.id.unwrap(), metadata, machine.version)
                        .await?;
                }
            },
            Machine::DpuSshCredentials(query) => {
                let cred = api_client.0.get_dpu_ssh_credential(query.query).await?;
                if config.format == OutputFormat::Json {
                    println!("{}", serde_json::to_string_pretty(&cred)?);
                } else {
                    println!("{}:{}", cred.username, cred.password);
                }
            }
            Machine::Network(cmd) => match cmd {
                NetworkCommand::Status => {
                    println!(
                        "Deprecated: Use dpu network, instead machine network. machine network will be removed in future."
                    );
                    dpu::show_dpu_status(&api_client, &mut output_file).await?;
                }
                NetworkCommand::Config(query) => {
                    println!(
                        "Deprecated: Use dpu network, instead of machine network. machine network will be removed in future."
                    );
                    let network_config = api_client
                        .0
                        .get_managed_host_network_config(query.machine_id)
                        .await?;
                    if config.format == OutputFormat::Json {
                        println!("{}", serde_json::ser::to_string_pretty(&network_config)?);
                    } else {
                        // someone might be parsing this output
                        println!("{network_config:?}");
                    }
                }
            },
            Machine::HealthOverride(command) => {
                machine::handle_override(command, config.format, &api_client).await?;
            }
            Machine::Reboot(c) => {
                api_client
                    .admin_power_control(
                        None,
                        Some(c.machine),
                        ::rpc::forge::admin_power_control_request::SystemPowerControl::ForceRestart,
                    )
                    .await?;
            }
            Machine::ForceDelete(query) => machine::force_delete(query, &api_client).await?,
            Machine::AutoUpdate(cfg) => machine::autoupdate(cfg, &api_client).await?,
            Machine::HardwareInfo(hardware_info_command) => match hardware_info_command {
                MachineHardwareInfoCommand::Show(show_command) => {
                    handle_show_machine_hardware_info(
                        &api_client,
                        &mut output_file,
                        &config.format,
                        show_command.machine,
                    )
                    .await?
                }
                MachineHardwareInfoCommand::Update(capability) => match capability {
                    MachineHardwareInfo::Gpus(gpus) => {
                        // Handle the gRPC to update GPUs
                        handle_update_machine_hardware_info_gpus(&api_client, gpus).await?
                    }
                },
            },
        },
        CliCommand::Instance(instance) => match instance {
            Instance::Show(instance) => {
                instance::handle_show(
                    instance,
                    &mut output_file,
                    &config.format,
                    &api_client,
                    config.internal_page_size,
                    &config.sort_by,
                )
                .await?
            }
            Instance::Reboot(reboot_request) => {
                instance::handle_reboot(reboot_request, &api_client).await?
            }
            Instance::Release(release_request) => {
                if config.cloud_unsafe_op.is_none() {
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
                            api_client.0.find_instance_by_machine_id(machine_id).await?;
                        if instances.instances.is_empty() {
                            color_eyre::eyre::bail!("No instances assigned to that machine");
                        }
                        instance_ids.push(instances.instances[0].id.clone().unwrap());
                    }
                    (_, _, Some(key)) => {
                        let instances = api_client
                            .get_all_instances(
                                None,
                                None,
                                Some(key),
                                release_request.label_value,
                                None,
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
                api_client.release_instances(instance_ids).await?
            }
            Instance::Allocate(allocate_request) => {
                if config.cloud_unsafe_op.is_none() {
                    return Err(CarbideCliError::GenericError(
                        "Operation not allowed due to potential inconsistencies with cloud database."
                            .to_owned(),
                    )
                    .into());
                }

                let mut machine_ids: VecDeque<_> = if !allocate_request.machine_id.is_empty() {
                    allocate_request
                        .machine_id
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect()
                } else {
                    api_client
                        .0
                        .find_machine_ids(::rpc::forge::MachineSearchConfig {
                            include_predicted_host: true,
                            ..Default::default()
                        })
                        .await?
                        .machine_ids
                        .into_iter()
                        .map(|id| id.to_string())
                        .collect()
                };

                let min_interface_count = if !allocate_request.vpc_prefix_id.is_empty() {
                    allocate_request.vpc_prefix_id.len()
                } else {
                    allocate_request.subnet.len()
                };

                for i in 0..allocate_request.number.unwrap_or(1) {
                    let Some(machine) = machine::get_next_free_machine(
                        &api_client,
                        &mut machine_ids,
                        min_interface_count,
                    )
                    .await
                    else {
                        tracing::error!("No available machines.");
                        break;
                    };

                    match api_client
                        .allocate_instance(
                            machine,
                            &allocate_request,
                            &format!("{}_{}", allocate_request.prefix_name.clone(), i),
                            config.cloud_unsafe_op.clone(),
                        )
                        .await
                    {
                        Ok(i) => {
                            tracing::info!("allocate was successful. Created instance: {:?} ", i);
                        }
                        Err(e) => {
                            tracing::info!("allocate failed with {} ", e);
                        }
                    };
                }
            }
            Instance::UpdateOS(update_request) => {
                if config.cloud_unsafe_op.is_none() {
                    return Err(CarbideCliError::GenericError(
                        "Operation not allowed due to potential inconsistencies with cloud database.".to_owned(),
                    )
                    .into());
                }

                match api_client
                    .update_instance_os(update_request, config.cloud_unsafe_op)
                    .await
                {
                    Ok(i) => {
                        tracing::info!("update-os was successful. Updated instance: {:?}", i);
                    }
                    Err(e) => {
                        tracing::info!("update-os failed with {} ", e);
                    }
                };
            }
        },
        CliCommand::NetworkSegment(network) => match network {
            NetworkSegment::Show(network) => {
                network::handle_show(
                    network,
                    config.format,
                    &api_client,
                    config.internal_page_size,
                )
                .await?
            }
        },
        CliCommand::Domain(domain) => match domain {
            Domain::Show(domain) => domain::handle_show(domain, config.format, &api_client).await?,
        },
        CliCommand::ManagedHost(managed_host) => match managed_host {
            ManagedHost::Show(managed_host) => {
                managed_host::handle_show(
                    &mut output_file,
                    managed_host,
                    config.format,
                    &api_client,
                    config.internal_page_size,
                    config.sort_by,
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
                    api_client.0.set_maintenance(req).await?;
                }
                MaintenanceAction::Off(maint_off) => {
                    let req = forgerpc::MaintenanceRequest {
                        operation: forgerpc::MaintenanceOperation::Disable.into(),
                        host_id: Some(maint_off.host.into()),
                        reference: None,
                    };
                    api_client.0.set_maintenance(req).await?;
                }
            },
            ManagedHost::Quarantine(quarantine_action) => match quarantine_action {
                QuarantineAction::On(quarantine_on) => {
                    let host = quarantine_on.host.clone();
                    let req = forgerpc::SetManagedHostQuarantineStateRequest {
                        machine_id: Some(quarantine_on.host.into()),
                        quarantine_state: Some(forgerpc::ManagedHostQuarantineState {
                            mode: forgerpc::ManagedHostQuarantineMode::BlockAllTraffic as i32,
                            reason: Some(quarantine_on.reason),
                        }),
                    };
                    let prior_state = api_client.0.set_managed_host_quarantine_state(req).await?;
                    println!(
                        "quarantine set for host {}, prior state: {:?}",
                        host, prior_state.prior_quarantine_state
                    );
                }
                QuarantineAction::Off(quarantine_off) => {
                    let host = quarantine_off.host.clone();
                    let req = forgerpc::ClearManagedHostQuarantineStateRequest {
                        machine_id: Some(quarantine_off.host.into()),
                    };
                    let prior_state = api_client
                        .0
                        .clear_managed_host_quarantine_state(req)
                        .await?;
                    println!(
                        "quarantine set for host {}, prior state: {:?}",
                        host, prior_state.prior_quarantine_state
                    );
                }
            },
            ManagedHost::ResetHostReprovisioning(machine_id) => {
                let machine_id = ::rpc::common::MachineId {
                    id: machine_id.machine,
                };
                api_client.0.reset_host_reprovisioning(machine_id).await?;
            }
            ManagedHost::PowerOptions(options) => match options {
                cfg::cli_options::PowerOptions::Show(show_power_options) => {
                    managed_host::handle_power_options_show(
                        show_power_options,
                        config.format,
                        &api_client,
                    )
                    .await?;
                }
                cfg::cli_options::PowerOptions::Update(update_power_options) => {
                    managed_host::update_power_option(update_power_options, &api_client).await?;
                }
            },
        },
        CliCommand::Measurement(cmd) => {
            let args = cfg::measurement::GlobalOptions {
                format: config.format,
                extended: config.extended,
            };
            measurement::dispatch(&cmd, &args, &api_client).await?
        }
        CliCommand::ResourcePool(rp) => match rp {
            ResourcePool::Grow(def) => {
                let defs = fs::read_to_string(&def.filename)?;
                let rpc_req = forgerpc::GrowResourcePoolRequest { text: defs };
                let _ = api_client.0.admin_grow_resource_pool(rpc_req).await?;
                tracing::info!("Resource Pool request sent.");
            }
            ResourcePool::List => {
                resource_pool::list(&api_client).await?;
            }
        },
        CliCommand::Ip(ip_command) => match ip_command {
            IpAction::Find(find) => {
                let req = forgerpc::FindIpAddressRequest {
                    ip: find.ip.to_string(),
                };
                // maybe handle tonic::Status's `.code()` of tonic::Code::NotFound
                let resp = api_client.0.find_ip_address(req).await?;
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
        CliCommand::NetworkDevice(data) => match data {
            cfg::cli_options::NetworkDeviceAction::Show(args) => {
                network_devices::show(config.format, args, &api_client).await?;
            }
        },
        CliCommand::Dpu(dpu_action) => match dpu_action {
            Reprovision(reprov) => match reprov {
                DpuReprovision::Set(data) => {
                    dpu::trigger_reprovisioning(
                        data.id,
                        Mode::Set,
                        data.update_firmware,
                        &api_client,
                        data.update_message,
                    )
                    .await?
                }
                DpuReprovision::Clear(data) => {
                    dpu::trigger_reprovisioning(
                        data.id,
                        Mode::Clear,
                        data.update_firmware,
                        &api_client,
                        None,
                    )
                    .await?
                }
                DpuReprovision::List => dpu::list_dpus_pending(&api_client).await?,
                DpuReprovision::Restart(data) => {
                    dpu::trigger_reprovisioning(
                        data.id,
                        Mode::Restart,
                        data.update_firmware,
                        &api_client,
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
                dpu::handle_agent_upgrade_policy(&api_client, rpc_choice).await?
            }
            Versions(options) => {
                dpu::handle_dpu_versions(
                    &mut output_file,
                    config.format,
                    &api_client,
                    options.updates_only,
                    config.internal_page_size,
                )
                .await?
            }
            DpuAction::Status => {
                dpu::handle_dpu_status(
                    &mut output_file,
                    config.format,
                    &api_client,
                    config.internal_page_size,
                )
                .await?
            }

            DpuAction::Network(network) => match network {
                NetworkCommand::Config(query) => {
                    dpu::show_dpu_network_config(
                        &api_client,
                        &mut output_file,
                        query.machine_id,
                        config.format,
                    )
                    .await?;
                }
                NetworkCommand::Status => {
                    dpu::show_dpu_status(&api_client, &mut output_file).await?;
                }
            },
        },
        CliCommand::Host(host_action) => match host_action {
            HostAction::SetUefiPassword(query) => {
                uefi::set_host_uefi_password(query, &api_client).await?;
            }
            HostAction::ClearUefiPassword(query) => {
                uefi::clear_host_uefi_password(query, &api_client).await?;
            }
            HostAction::GenerateHostUefiPassword => {
                let password = Credentials::generate_password_no_special_char();
                println!("Generated Bios Admin Password: {}", password);
            }
            HostAction::Reprovision(reprovision) => match reprovision {
                HostReprovision::Set(data) => {
                    host::trigger_reprovisioning(
                        data.id,
                        ::rpc::forge::host_reprovisioning_request::Mode::Set,
                        &api_client,
                        data.update_message,
                    )
                    .await?
                }
                HostReprovision::Clear(data) => {
                    host::trigger_reprovisioning(
                        data.id,
                        ::rpc::forge::host_reprovisioning_request::Mode::Clear,
                        &api_client,
                        None,
                    )
                    .await?
                }
                HostReprovision::List => host::list_hosts_pending(&api_client).await?,
            },
        },
        CliCommand::Redfish(action) => {
            if let RedfishCommand::Browse(UriInfo { uri }) = &action.command {
                return redfish::handle_browse_command(&api_client, uri).await;
            }

            // Handled earlier
            unreachable!();
        }
        CliCommand::BootOverride(boot_override_args) => match boot_override_args {
            BootOverrideAction::Get(boot_override) => {
                let mbo = api_client
                    .0
                    .get_machine_boot_override(Uuid {
                        value: boot_override.interface_id,
                    })
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

                api_client
                    .set_boot_override(
                        Uuid {
                            value: boot_override_set.interface_id,
                        },
                        custom_pxe_path.as_deref(),
                        custom_user_data_path.as_deref(),
                    )
                    .await?;
            }
            BootOverrideAction::Clear(boot_override) => {
                api_client
                    .0
                    .clear_machine_boot_override(Uuid {
                        value: boot_override.interface_id,
                    })
                    .await?;
            }
        },
        CliCommand::BmcMachine(bmc_machine) => match bmc_machine {
            BmcAction::BmcReset(args) => {
                api_client
                    .bmc_reset(None, Some(args.machine), args.use_ipmitool)
                    .await?;
            }
            BmcAction::AdminPowerControl(args) => {
                api_client
                    .admin_power_control(None, Some(args.machine), args.action.into())
                    .await?;
            }
            BmcAction::CreateBmcUser(args) => {
                api_client
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
                api_client
                    .delete_bmc_user(
                        args.ip_address,
                        args.mac_address,
                        args.machine,
                        args.username,
                    )
                    .await?;
            }
        },
        CliCommand::Inventory(action) => {
            inventory::print_inventory(&api_client, action, config.internal_page_size).await?
        }
        CliCommand::Credential(credential_action) => match credential_action {
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
                api_client.0.create_credential(req).await?;
            }
            CredentialAction::DeleteUFM(c) => {
                let username = url_validator(c.url.clone()).await?;
                let req = forgerpc::CredentialDeletionRequest {
                    credential_type: CredentialType::Ufm.into(),
                    username: Some(username),
                    mac_address: None,
                };
                api_client.0.delete_credential(req).await?;
            }
            CredentialAction::GenerateUFMCert(c) => {
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::Ufm.into(),
                    username: None,
                    password: "".to_string(),
                    mac_address: None,
                    vendor: Some(c.fabric),
                };
                api_client.0.create_credential(req).await?;
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
                api_client.0.create_credential(req).await?;
            }
            CredentialAction::DeleteBMC(c) => {
                let req = forgerpc::CredentialDeletionRequest {
                    credential_type: CredentialType::from(c.kind).into(),
                    username: None,
                    mac_address: c.mac_address.map(|mac| mac.to_string()),
                };
                api_client.0.delete_credential(req).await?;
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
                api_client.0.create_credential(req).await?;
            }
            CredentialAction::AddHostFactoryDefault(c) => {
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::HostBmcFactoryDefault.into(),
                    username: Some(c.username),
                    password: c.password,
                    mac_address: None,
                    vendor: Some(c.vendor.to_string()),
                };
                api_client.0.create_credential(req).await?;
            }
            CredentialAction::AddDpuFactoryDefault(c) => {
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::DpuBmcFactoryDefault.into(),
                    username: Some(c.username),
                    password: c.password,
                    mac_address: None,
                    vendor: None,
                };
                api_client.0.create_credential(req).await?;
            }
        },
        CliCommand::RouteServer(action) => match action {
            RouteServer::Get => {
                let route_servers = api_client.get_route_servers().await?;
                println!("{}", serde_json::to_string(&route_servers)?);
            }
            RouteServer::Add(ip) => {
                api_client
                    .0
                    .add_route_servers(vec![ip.ip.to_string()])
                    .await?;
            }
            RouteServer::Remove(ip) => {
                api_client
                    .0
                    .remove_route_servers(vec![ip.ip.to_string()])
                    .await?;
            }
        },
        CliCommand::SiteExplorer(action) => match action {
            SiteExplorer::GetReport(mode) => {
                show_site_explorer_discovered_managed_host(
                    &api_client,
                    &mut output_file,
                    config.format,
                    config.internal_page_size,
                    mode,
                )
                .await?;
            }
            SiteExplorer::Explore(opts) => {
                let report = api_client.explore(&opts.address, opts.mac).await?;
                println!("{}", serde_json::to_string_pretty(&report)?);
            }
            SiteExplorer::ReExplore(opts) => {
                api_client.re_explore_endpoint(&opts.address).await?;
            }
            SiteExplorer::ClearError(opts) => {
                api_client
                    .0
                    .clear_site_exploration_error(opts.address)
                    .await?;
            }
            SiteExplorer::Delete(opts) => {
                let response = api_client.0.delete_explored_endpoint(opts.address).await?;

                if response.deleted {
                    println!(
                        "{}",
                        response
                            .message
                            .unwrap_or_else(|| "Endpoint deleted successfully.".to_string())
                    );
                } else {
                    eprintln!(
                        "{}",
                        response
                            .message
                            .unwrap_or_else(|| "Failed to delete endpoint.".to_string())
                    );
                }
            }
            SiteExplorer::IsBmcInManagedHost(opts) => {
                let is_bmc_in_managed_host = api_client
                    .is_bmc_in_managed_host(&opts.address, opts.mac)
                    .await?;
                println!(
                    "Is {} in a managed host?: {}",
                    opts.address, is_bmc_in_managed_host.in_managed_host
                );
            }
            SiteExplorer::HaveCredentials(opts) => {
                let have_credentials = api_client
                    .bmc_credential_status(&opts.address, opts.mac)
                    .await?;
                println!("{}", have_credentials.have_credentials);
            }
            SiteExplorer::CopyBfbToDpuRshim(args) => {
                api_client
                    .copy_bfb_to_dpu_rshim(args.address, args.mac, args.timeout_config)
                    .await?;
            }
        },
        CliCommand::MachineInterfaces(machine_interfaces) => match machine_interfaces {
            MachineInterfaces::Show(machine_interfaces) => {
                machine_interfaces::handle_show(machine_interfaces, config.format, &api_client)
                    .await?
            }
            MachineInterfaces::Delete(args) => {
                machine_interfaces::handle_delete(args, &api_client).await?
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
        CliCommand::Ping(opts) => ping::ping(&api_client, opts).await?,
        CliCommand::Set(subcmd) => match subcmd {
            SetAction::LogFilter(opts) => {
                api_client
                    .set_dynamic_config(ConfigSetting::LogFilter, opts.filter, Some(opts.expiry))
                    .await?
            }
            SetAction::CreateMachines(opts) => {
                api_client
                    .set_dynamic_config(
                        ConfigSetting::CreateMachines,
                        opts.enabled.to_string(),
                        None,
                    )
                    .await?
            }
            SetAction::BmcProxy(opts) => {
                if opts.enabled {
                    api_client
                        .set_dynamic_config(
                            ConfigSetting::BmcProxy,
                            opts.proxy.unwrap_or("".to_string()),
                            None,
                        )
                        .await?
                } else {
                    api_client
                        .set_dynamic_config(ConfigSetting::BmcProxy, "".to_string(), None)
                        .await?
                }
            }
            SetAction::TracingEnabled {
                value: tracing_enabled,
            } => {
                api_client
                    .set_dynamic_config(
                        ConfigSetting::TracingEnabled,
                        tracing_enabled.to_string(),
                        None,
                    )
                    .await?
            }
        },
        CliCommand::ExpectedMachine(expected_machine_action) => match expected_machine_action {
            cfg::cli_options::ExpectedMachineAction::Show(expected_machine_query) => {
                expected_machines::show_expected_machines(
                    &expected_machine_query,
                    &api_client,
                    config.format,
                    &mut output_file,
                )
                .await?;
            }
            cfg::cli_options::ExpectedMachineAction::Add(expected_machine_data) => {
                if expected_machine_data.has_duplicate_dpu_serials() {
                    eprintln!("Duplicate values not allowed for --fallback-dpu-serial-number");
                    return Ok(());
                }
                let metadata = expected_machine_data.metadata()?;
                api_client
                    .add_expected_machine(
                        expected_machine_data.bmc_mac_address,
                        expected_machine_data.bmc_username,
                        expected_machine_data.bmc_password,
                        expected_machine_data.chassis_serial_number,
                        expected_machine_data.fallback_dpu_serial_numbers,
                        metadata,
                        expected_machine_data.sku_id,
                    )
                    .await?;
            }
            cfg::cli_options::ExpectedMachineAction::Delete(expected_machine_query) => {
                api_client
                    .0
                    .delete_expected_machine(expected_machine_query.bmc_mac_address.to_string())
                    .await?;
            }
            cfg::cli_options::ExpectedMachineAction::Update(expected_machine_data) => {
                if let Err(e) = expected_machine_data.validate() {
                    eprintln!("{e}");
                    return Ok(());
                }
                let metadata = expected_machine_data.metadata()?;
                api_client
                    .update_expected_machine(
                        expected_machine_data.bmc_mac_address,
                        expected_machine_data.bmc_username,
                        expected_machine_data.bmc_password,
                        expected_machine_data.chassis_serial_number,
                        expected_machine_data.fallback_dpu_serial_numbers,
                        metadata,
                        expected_machine_data.sku_id,
                    )
                    .await?;
            }
            cfg::cli_options::ExpectedMachineAction::ReplaceAll(request) => {
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

                api_client
                    .replace_all_expected_machines(expected_machine_list.expected_machines)
                    .await?;
            }
            cfg::cli_options::ExpectedMachineAction::Erase => {
                api_client.0.delete_all_expected_machines().await?;
            }
        },
        CliCommand::Vpc(vpc) => match vpc {
            VpcOptions::Show(vpc) => {
                vpc::handle_show(vpc, config.format, &api_client, config.internal_page_size).await?
            }
            VpcOptions::SetVirtualizer(set_vpc_virt) => {
                vpc::set_network_virtualization_type(&api_client, set_vpc_virt).await?
            }
        },
        CliCommand::VpcPeering(vpc_peering_command) => {
            use VpcPeeringOptions::*;
            match vpc_peering_command {
                Create(create_options) => {
                    vpc_peering::handle_create(create_options, config.format, &api_client).await?;
                }
                Show(show_options) => {
                    vpc_peering::handle_show(show_options, config.format, &api_client).await?;
                }
                Delete(delete_options) => {
                    vpc_peering::handle_delete(delete_options, config.format, &api_client).await?;
                }
            }
        }
        CliCommand::VpcPrefix(vpc_prefix_command) => {
            use VpcPrefixOptions::*;
            match vpc_prefix_command {
                Create(create_options) => {
                    vpc_prefix::handle_create(create_options, config.format, &api_client).await?
                }
                Show(show_options) => {
                    vpc_prefix::handle_show(
                        show_options,
                        config.format,
                        &api_client,
                        config.internal_page_size,
                    )
                    .await?
                }
                Delete(delete_options) => {
                    vpc_prefix::handle_delete(delete_options, &api_client).await?
                }
            }
        }
        CliCommand::IbPartition(ibp) => match ibp {
            IbPartitionOptions::Show(ibp) => {
                ib_partition::handle_show(
                    ibp,
                    config.format,
                    &api_client,
                    config.internal_page_size,
                )
                .await?
            }
        },
        CliCommand::TenantKeySet(tks) => match tks {
            TenantKeySetOptions::Show(tks) => {
                tenant_keyset::handle_show(
                    tks,
                    config.format,
                    &api_client,
                    config.internal_page_size,
                )
                .await?
            }
        },
        CliCommand::Jump(j) => {
            // Is it a machine ID?
            // Grab the machine details.
            if forge_uuid::machine::MachineId::from_str(&j.id).is_ok() {
                machine::handle_show(
                    cfg::cli_options::ShowMachine {
                        machine: j.id,
                        help: None,
                        hosts: false,
                        all: false,
                        dpus: false,
                        instance_type_id: None,
                        history_count: 5,
                    },
                    &config.format,
                    &mut output_file,
                    &api_client,
                    config.internal_page_size,
                    &config.sort_by,
                )
                .await?;

                return Ok(());
            }

            // Is it an IP?
            if IpAddr::from_str(&j.id).is_ok() {
                let req = forgerpc::FindIpAddressRequest { ip: j.id };

                let resp = api_client.0.find_ip_address(req).await?;

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
                                cfg::cli_options::ShowInstance {
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
                                &mut output_file,
                                &config_format,
                                &api_client,
                                config.internal_page_size,
                                &config.sort_by,
                            )
                            .await?
                        }
                        MachineAddress | BmcIp | LoopbackIp => {
                            machine::handle_show(
                                cfg::cli_options::ShowMachine {
                                    machine: m.owner_id.ok_or(CarbideCliError::GenericError(
                                        "failed to unwrap owner_id after finding machine for IP".to_string(),
                                    ))?,
                                    help: None,
                                    hosts: false,
                                    all: false,
                                    dpus: false,
                                    instance_type_id: None,
                                    history_count: 5
                                },
                                &config_format,
                                &mut output_file,
                                &api_client,
                                config.internal_page_size,
                                &config.sort_by,
                            )
                            .await?;
                        }

                        ExploredEndpoint => {
                            site_explorer::show_site_explorer_discovered_managed_host(
                                &api_client,
                                &mut output_file,
                                config_format,
                                config.internal_page_size,
                                cfg::cli_options::GetReportMode::Endpoint(cfg::cli_options::EndpointInfo{
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
                                cfg::cli_options::ShowNetwork {
                                    network: m.owner_id.ok_or(CarbideCliError::GenericError(
                                        "failed to unwrap owner_id after finding network segment for IP".to_string(),
                                    ))?,
                                    tenant_org_id: None,
                                    name: None,
                                },
                                config_format,
                                &api_client,
                                config.internal_page_size,
                            )
                            .await?
                        }
                        ResourcePool => resource_pool::list(&api_client).await?,
                    };
                }

                return Ok(());
            }

            // Is it the UUID of some type of object?
            // Try to identify the type of object and then perform
            // a search for the object's details.  E.g., if it's the
            // UUID of an instance, then get the details of the instance.
            if let Ok(u) = j.id.parse::<uuid::Uuid>() {
                match api_client.identify_uuid(u).await {
                    Ok(o) => match o {
                        forgerpc::UuidType::NetworkSegment => {
                            network::handle_show(
                                cfg::cli_options::ShowNetwork {
                                    network: j.id,
                                    tenant_org_id: None,
                                    name: None,
                                },
                                config.format,
                                &api_client,
                                config.internal_page_size,
                            )
                            .await?
                        }
                        forgerpc::UuidType::Instance => {
                            instance::handle_show(
                                cfg::cli_options::ShowInstance {
                                    id: j.id,
                                    extrainfo: true,
                                    tenant_org_id: None,
                                    vpc_id: None,
                                    label_key: None,
                                    label_value: None,
                                    instance_type_id: None,
                                },
                                &mut output_file,
                                &config.format,
                                &api_client,
                                config.internal_page_size,
                                &config.sort_by,
                            )
                            .await?
                        }
                        forgerpc::UuidType::MachineInterface => {
                            machine_interfaces::handle_show(
                                cfg::cli_options::ShowMachineInterfaces {
                                    interface_id: j.id,
                                    all: false,
                                    more: true,
                                },
                                config.format,
                                &api_client,
                            )
                            .await?
                        }
                        forgerpc::UuidType::Vpc => {
                            vpc::handle_show(
                                cfg::cli_options::ShowVpc {
                                    id: j.id,
                                    tenant_org_id: None,
                                    name: None,
                                    label_key: None,
                                    label_value: None,
                                },
                                config.format,
                                &api_client,
                                1,
                            )
                            .await?
                        }
                        forgerpc::UuidType::Domain => {
                            domain::handle_show(
                                cfg::cli_options::ShowDomain {
                                    domain: j.id,
                                    all: false,
                                },
                                config.format,
                                &api_client,
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
                match api_client.identify_mac(m).await {
                    Ok((mac_owner, mac_type)) => match mac_owner {
                        forgerpc::MacOwner::MachineInterface => {
                            machine_interfaces::handle_show(
                                cfg::cli_options::ShowMachineInterfaces {
                                    interface_id: mac_type,
                                    all: false,
                                    more: true,
                                },
                                config.format,
                                &api_client,
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
            if let Ok(machine_id) = api_client.identify_serial(j.id, false).await {
                machine::handle_show(
                    cfg::cli_options::ShowMachine {
                        machine: machine_id.to_string(),
                        help: None,
                        hosts: false,
                        all: false,
                        dpus: false,
                        instance_type_id: None,
                        history_count: 5,
                    },
                    &config.format,
                    &mut output_file,
                    &api_client,
                    config.internal_page_size,
                    &config.sort_by,
                )
                .await?;

                return Ok(());
            }

            // Do we have no idea what it is?
            color_eyre::eyre::bail!("Unable to determine ID type");
        }

        CliCommand::MachineValidation(command) => match command {
            cfg::cli_options::MachineValidationCommand::ExternalConfig(config_command) => {
                match config_command {
                    cfg::cli_options::MachineValidationExternalConfigCommand::Show(opts) => {
                        machine_validation::external_config_show(
                            &api_client,
                            opts.name,
                            config.extended,
                            config.format,
                        )
                        .await?;
                    }
                    cfg::cli_options::MachineValidationExternalConfigCommand::AddUpdate(opts) => {
                        machine_validation::external_config_add_update(
                            &api_client,
                            opts.name,
                            opts.file_name,
                            opts.description,
                        )
                        .await?;
                    }
                    cfg::cli_options::MachineValidationExternalConfigCommand::Remove(opts) => {
                        machine_validation::remove_external_config(&api_client, opts.name).await?;
                    }
                }
            }
            cfg::cli_options::MachineValidationCommand::Results(cmd) => match cmd {
                cfg::cli_options::MachineValidationResultsCommand::Show(options) => {
                    machine_validation::handle_results_show(
                        options,
                        config.format,
                        &api_client,
                        config.internal_page_size,
                        config.extended,
                    )
                    .await?;
                }
            },
            cfg::cli_options::MachineValidationCommand::Runs(cmd) => match cmd {
                cfg::cli_options::MachineValidationRunsCommand::Show(options) => {
                    machine_validation::handle_runs_show(
                        options,
                        config.format,
                        &api_client,
                        config.internal_page_size,
                    )
                    .await?;
                }
            },
            cfg::cli_options::MachineValidationCommand::OnDemand(on_demand_command) => {
                match on_demand_command {
                    cfg::cli_options::MachineValidationOnDemandCommand::Start(options) => {
                        machine_validation::on_demand_machine_validation(&api_client, options)
                            .await?;
                    }
                }
            }
            cfg::cli_options::MachineValidationCommand::Tests(machine_validation_tests_command) => {
                match *machine_validation_tests_command {
                    cfg::cli_options::MachineValidationTestsCommand::Show(options) => {
                        machine_validation::show_tests(
                            &api_client,
                            options,
                            config.format,
                            config.extended,
                        )
                        .await?;
                    }
                    cfg::cli_options::MachineValidationTestsCommand::Verify(options) => {
                        machine_validation::machine_validation_test_verfied(&api_client, options)
                            .await?;
                    }
                    cfg::cli_options::MachineValidationTestsCommand::Enable(options) => {
                        machine_validation::machine_validation_test_enable(&api_client, options)
                            .await?;
                    }
                    cfg::cli_options::MachineValidationTestsCommand::Disable(options) => {
                        machine_validation::machine_validation_test_disable(&api_client, options)
                            .await?;
                    }
                    cfg::cli_options::MachineValidationTestsCommand::Add(options) => {
                        machine_validation::machine_validation_test_add(&api_client, options)
                            .await?;
                    }
                    cfg::cli_options::MachineValidationTestsCommand::Update(options) => {
                        machine_validation::machine_validation_test_update(&api_client, options)
                            .await?;
                    }
                }
            }
        },
        CliCommand::Storage(storage_cmd) => match storage_cmd {
            StorageActions::Cluster(storage_cluster) => match storage_cluster {
                StorageClusterActions::Show(storage_cluster) => {
                    storage::cluster_show(
                        storage_cluster,
                        config.format,
                        &api_client,
                        config.internal_page_size,
                    )
                    .await?
                }
                StorageClusterActions::Import(storage_cluster) => {
                    storage::cluster_import(storage_cluster, &api_client).await?
                }
                StorageClusterActions::Delete(storage_cluster) => {
                    storage::cluster_delete(storage_cluster, &api_client).await?
                }
                StorageClusterActions::Update(storage_cluster) => {
                    storage::cluster_update(storage_cluster, &api_client).await?
                }
            },
            StorageActions::Pool(storage_pool) => match storage_pool {
                StoragePoolActions::Show(storage_pool) => {
                    storage::pool_show(
                        storage_pool,
                        config.format,
                        &api_client,
                        config.internal_page_size,
                    )
                    .await?
                }
                StoragePoolActions::Create(storage_pool) => {
                    storage::pool_create(storage_pool, &api_client).await?
                }
                StoragePoolActions::Delete(storage_pool) => {
                    storage::pool_delete(storage_pool, &api_client).await?
                }
                StoragePoolActions::Update(storage_pool) => {
                    storage::pool_update(storage_pool, &api_client).await?
                }
            },
            StorageActions::Volume(storage_volume) => match storage_volume {
                StorageVolumeActions::Show(storage_volume) => {
                    storage::volume_show(
                        storage_volume,
                        config.format,
                        &api_client,
                        config.internal_page_size,
                    )
                    .await?
                }
                StorageVolumeActions::Create(storage_volume) => {
                    storage::volume_create(storage_volume, &api_client).await?
                }
                StorageVolumeActions::Delete(storage_volume) => {
                    storage::volume_delete(storage_volume, &api_client).await?
                }
                StorageVolumeActions::Update(storage_volume) => {
                    storage::volume_update(storage_volume, &api_client).await?
                }
            },
        },
        CliCommand::OsImage(os_image) => match os_image {
            OsImageActions::Show(os_image) => {
                storage::os_image_show(
                    os_image,
                    config.format,
                    &api_client,
                    config.internal_page_size,
                )
                .await?
            }
            OsImageActions::Create(os_image) => {
                storage::os_image_create(os_image, &api_client).await?
            }
            OsImageActions::Delete(os_image) => {
                storage::os_image_delete(os_image, &api_client).await?
            }
            OsImageActions::Update(os_image) => {
                storage::os_image_update(os_image, &api_client).await?
            }
        },
        CliCommand::TpmCa(subcmd) => match subcmd {
            TpmCa::Show => tpm::show_ca_certs(&api_client).await?,
            TpmCa::Delete(delete_opts) => {
                tpm::delete_ca_cert(delete_opts.ca_id, &api_client).await?
            }
            TpmCa::Add(add_opts) => {
                tpm::add_ca_cert_filename(&add_opts.filename, &api_client).await?
            }
            TpmCa::AddBulk(add_opts) => {
                tpm::add_ca_cert_bulk(&add_opts.dirname, &api_client).await?
            }
            TpmCa::ShowUnmatchedEk => tpm::show_unmatched_ek_certs(&api_client).await?,
        },
        CliCommand::NetworkSecurityGroup(nsg_action) => match nsg_action {
            NetworkSecurityGroupActions::Create(args) => {
                network_security_group::nsg_create(args, config.format, &api_client).await?
            }
            NetworkSecurityGroupActions::Show(args) => {
                network_security_group::nsg_show(
                    args,
                    config.format,
                    &api_client,
                    config.internal_page_size,
                    config.extended,
                )
                .await?
            }
            NetworkSecurityGroupActions::Update(args) => {
                network_security_group::nsg_update(args, config.format, &api_client).await?
            }
            NetworkSecurityGroupActions::Delete(args) => {
                network_security_group::nsg_delete(args, &api_client).await?
            }
            NetworkSecurityGroupActions::ShowAttachments(args) => {
                network_security_group::nsg_show_attachments(args, config.format, &api_client)
                    .await?
            }
            NetworkSecurityGroupActions::Attach(args) => {
                network_security_group::nsg_attach(args, &api_client).await?
            }
            NetworkSecurityGroupActions::Detach(args) => {
                network_security_group::nsg_detach(args, &api_client).await?
            }
        },
        CliCommand::Sku(sku_command) => {
            let mut output_file = get_output_file_or_stdout(config.output.as_deref()).await?;

            sku::handle_sku_command(
                &api_client,
                &mut output_file,
                &config.format,
                config.extended,
                sku_command,
            )
            .await?;
        }
        CliCommand::DevEnv(command) => match command {
            cfg::cli_options::DevEnv::Config(dev_env_config) => match dev_env_config {
                cfg::cli_options::DevEnvConfig::Apply(dev_env_config_apply) => {
                    apply_devenv_config(dev_env_config_apply, &api_client).await?;
                }
            },
        },
        CliCommand::InstanceType(action) => match action {
            InstanceTypeActions::Create(args) => {
                instance_type::create(args, config.format, &api_client).await?
            }
            InstanceTypeActions::Show(args) => {
                instance_type::show(
                    args,
                    config.format,
                    &api_client,
                    config.internal_page_size,
                    config.extended,
                )
                .await?
            }
            InstanceTypeActions::Update(args) => {
                instance_type::update(args, config.format, &api_client).await?
            }
            InstanceTypeActions::Delete(args) => instance_type::delete(args, &api_client).await?,
            InstanceTypeActions::Associate(associate_instance_type) => {
                instance_type::create_association(associate_instance_type, &api_client).await?;
            }
            InstanceTypeActions::Disassociate(disassociate_instance_type) => {
                instance_type::remove_association(
                    disassociate_instance_type,
                    config.cloud_unsafe_op.is_some(),
                    &api_client,
                )
                .await?;
            }
        },
        CliCommand::Ssh(action) => match action {
            cfg::cli_options::SshActions::GetRshimStatus(ssh_args) => {
                let is_rshim_enabled = is_rshim_enabled(
                    ssh_args.credentials.bmc_ip_address,
                    ssh_args.credentials.bmc_username,
                    ssh_args.credentials.bmc_password,
                    None,
                )
                .await?;
                tracing::info!("{is_rshim_enabled}");
            }
            cfg::cli_options::SshActions::DisableRshim(ssh_args) => {
                disable_rshim(
                    ssh_args.credentials.bmc_ip_address,
                    ssh_args.credentials.bmc_username,
                    ssh_args.credentials.bmc_password,
                    ssh_args
                        .timeouts
                        .map(|timeout_config| timeout_config.to_ssh_config()),
                )
                .await?;
            }
            cfg::cli_options::SshActions::EnableRshim(ssh_args) => {
                enable_rshim(
                    ssh_args.credentials.bmc_ip_address,
                    ssh_args.credentials.bmc_username,
                    ssh_args.credentials.bmc_password,
                    ssh_args
                        .timeouts
                        .map(|timeout_config| timeout_config.to_ssh_config()),
                )
                .await?;
            }
            cfg::cli_options::SshActions::CopyBfb(copy_bfb_args) => {
                copy_bfb_to_bmc_rshim(
                    copy_bfb_args.ssh_args.credentials.bmc_ip_address,
                    copy_bfb_args.ssh_args.credentials.bmc_username,
                    copy_bfb_args.ssh_args.credentials.bmc_password,
                    copy_bfb_args
                        .ssh_args
                        .timeouts
                        .map(|timeout_config| timeout_config.to_ssh_config()),
                    copy_bfb_args.bfb_path,
                )
                .await?;
            }
            cfg::cli_options::SshActions::ShowObmcLog(ssh_args) => {
                let log = read_obmc_console_log(
                    ssh_args.credentials.bmc_ip_address,
                    ssh_args.credentials.bmc_username,
                    ssh_args.credentials.bmc_password,
                    ssh_args
                        .timeouts
                        .map(|timeout_config| timeout_config.to_ssh_config()),
                )
                .await?;

                println!("OBMC Console Log:\n{}", log);
            }
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

#[cfg(test)]
mod tests {
    use crate::cfg::cli_options::{
        CliCommand, CliOptions, ExpectedMachine, ExpectedMachineAction::Update,
        UpdateExpectedMachine,
    };
    use clap::Parser;

    #[test]
    fn forge_admin_cli_expected_machine_test() {
        assert!(
            ExpectedMachine::try_parse_from([
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
            .is_ok()
        );

        // No dpu serial
        assert!(
            ExpectedMachine::try_parse_from([
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
            .is_ok_and(|t1| { !t1.has_duplicate_dpu_serials() })
        );

        assert!(
            ExpectedMachine::try_parse_from([
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
            .is_ok()
        );

        assert!(
            ExpectedMachine::try_parse_from([
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
            .is_ok()
        );

        // Duplicate dpu_serial
        assert!(
            ExpectedMachine::try_parse_from([
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
            .is_ok_and(|t| { t.has_duplicate_dpu_serials() })
        );

        // option --fallback-dpu-serial-number used w/o value
        assert!(
            ExpectedMachine::try_parse_from([
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
            .is_err()
        );

        fn test_update_expected_machine<F: Fn(UpdateExpectedMachine) -> bool>(
            options: CliOptions,
            pred: F,
        ) -> bool {
            let mut update_args = None;
            if let Some(CliCommand::ExpectedMachine(Update(args))) = options.commands {
                update_args = Some(args);
            }
            update_args.is_some() && pred(update_args.unwrap())
        }
        // update 1 dpu serial
        assert!(test_update_expected_machine(
            CliOptions::try_parse_from([
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
            CliOptions::try_parse_from([
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

        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--fallback-dpu-serial-number",
            ])
            .is_err()
        );

        // Fail if duplicate dpu serials are given
        // duplicate dpu serials -
        assert!(test_update_expected_machine(
            CliOptions::try_parse_from([
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
        assert!(
            CliOptions::try_parse_from([
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
            .is_ok()
        );
        // update all
        assert!(test_update_expected_machine(
            CliOptions::try_parse_from([
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
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-username",
                "ssss",
            ])
            .is_err()
        );
        // update - password  only - error
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "expected-machine",
                "update",
                "--bmc-mac-address",
                "00:00:00:00:00:00",
                "--bmc-password",
                "ssss",
            ])
            .is_err()
        );
    }

    #[test]
    fn forge_admin_cli_credential_test() {
        //  bmc-root credential w.o optional username
        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "credential",
                "add-bmc",
                "--kind=bmc-root",
                "--mac-address",
                "0a:0b:0c:0d:0e:0f",
                "--password",
                "my-pw",
            ])
            .is_ok()
        );

        //  bmc-root credential with optional username
        assert!(
            CliOptions::try_parse_from([
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
            .is_ok()
        );
    }

    #[test]
    fn forge_admin_cli_tpm_ca_test() {
        assert!(CliOptions::try_parse_from(["forge-admin-cli", "tpm-ca", "show"]).is_ok());

        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "tpm-ca",
                "add",
                "--filename",
                "/tmp/somefile.cer"
            ])
            .is_ok()
        );

        assert!(
            CliOptions::try_parse_from([
                "forge-admin-cli",
                "tpm-ca",
                "add-bulk",
                "--dirname",
                "/tmp"
            ])
            .is_ok()
        );

        assert!(
            CliOptions::try_parse_from(["forge-admin-cli", "tpm-ca", "delete", "--ca-id", "4"])
                .is_ok()
        );
    }
}
