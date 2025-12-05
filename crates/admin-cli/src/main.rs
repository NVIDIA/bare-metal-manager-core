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
use std::collections::{HashSet, VecDeque};
use std::fs::File;
use std::io::{BufReader, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::str::FromStr;
use std::{fs, io};

use ::rpc::admin_cli::{CarbideCliError, OutputFormat};
use ::rpc::forge::ConfigSetting;
use ::rpc::forge::dpu_reprovisioning_request::Mode;
use ::rpc::forge_api_client::ForgeApiClient;
use ::rpc::forge_tls_client::{ApiConfig, ForgeClientConfig};
use ::rpc::{CredentialType, forge as forgerpc};
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::MachineId;
use cfg::cli_options::DpuAction::{AgentUpgradePolicy, Reprovision, Versions};
use cfg::cli_options::{
    AgentUpgrade, AgentUpgradePolicyChoice, BmcAction, BootOverrideAction, CliCommand, CliOptions,
    CredentialAction, Domain, DpaOptions, DpuAction, DpuReprovision, ExpectedMachineJson,
    ExpectedPowerShelfJson, ExpectedSwitchJson, Firmware, HostAction, HostReprovision,
    IbPartitionOptions, Instance, IpAction, LogicalPartitionOptions, Machine, MachineHardwareInfo,
    MachineHardwareInfoCommand, MachineInterfaces, MachineMetadataCommand, MaintenanceAction,
    ManagedHost, NetworkCommand, NetworkSegment, NvlPartitionOptions, RedfishCommand, ResourcePool,
    SetAction, Shell, SiteExplorer, TenantKeySetOptions, TpmCa, UriInfo, VpcOptions,
    VpcPeeringOptions, VpcPrefixOptions,
};
use cfg::instance_type::InstanceTypeActions;
use cfg::network_security_group::NetworkSecurityGroupActions;
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
use machine::{handle_show_machine_hardware_info, handle_update_machine_hardware_info_gpus};
use serde::{Deserialize, Serialize};
use site_explorer::show_site_explorer_discovered_managed_host;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};
use tracing_subscriber::fmt;
use tracing_subscriber::prelude::*;

use crate::cfg::cli_options::{AdminPowerControlAction, QuarantineAction};
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
mod expected_power_shelves;
mod expected_switches;
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
mod network;
mod network_devices;
mod network_security_group;
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
            RedfishCommand::Browse(_) => {}
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

    let mut output_file = get_output_file_or_stdout(config.output.as_deref()).await?;

    // Command to talk to Carbide API.
    match command {
        CliCommand::Version(version) => {
            version::handle_show_version(version, config.format, &api_client).await?
        }
        CliCommand::Mlx(cmd) => mlx::dispatch(cmd, &api_client, &config.format).await?,
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
                        .get_machines_by_ids(&[cmd.machine])
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
                        .get_machines_by_ids(&[cmd.machine])
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
                        .get_machines_by_ids(&[cmd.machine])
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
                            machine.id.unwrap().to_string()
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
                            && (metadata.name.is_empty()
                                || metadata.name == cmd.machine.to_string())
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
                        .get_machines_by_ids(&[cmd.machine])
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
                        .get_machines_by_ids(&[cmd.machine])
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
                let cred = api_client
                    .0
                    .get_dpu_ssh_credential(query.query.to_string())
                    .await?;
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
                let res = api_client
                    .admin_power_control(
                        None,
                        Some(c.machine),
                        ::rpc::forge::admin_power_control_request::SystemPowerControl::ForceRestart,
                    )
                    .await?;

                if let Some(msg) = res.msg {
                    println!("{msg}");
                }
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

                let mut instance_ids: Vec<InstanceId> = Vec::new();

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
                        instance_ids.push(instances.instances[0].id.unwrap());
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
                            .filter_map(|instance| instance.id)
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

                let number = allocate_request.number.unwrap_or(1);

                // Validate: --transactional requires --number > 1
                if allocate_request.transactional && number <= 1 {
                    return Err(CarbideCliError::GenericError(
                        "--transactional requires --number > 1".to_owned(),
                    )
                    .into());
                }

                let mut machine_ids: VecDeque<_> = if !allocate_request.machine_id.is_empty() {
                    allocate_request.machine_id.clone().into()
                } else {
                    api_client
                        .0
                        .find_machine_ids(::rpc::forge::MachineSearchConfig {
                            include_predicted_host: true,
                            ..Default::default()
                        })
                        .await?
                        .machine_ids
                        .into()
                };

                let min_interface_count = if !allocate_request.vpc_prefix_id.is_empty() {
                    allocate_request.vpc_prefix_id.len()
                } else {
                    allocate_request.subnet.len()
                };

                if allocate_request.transactional {
                    // Batch mode: all-or-nothing
                    let mut requests = Vec::new();
                    for i in 0..number {
                        let Some(machine) = machine::get_next_free_machine(
                            &api_client,
                            &mut machine_ids,
                            min_interface_count,
                        )
                        .await
                        else {
                            return Err(CarbideCliError::GenericError(format!(
                                "Need {} machines but only {} available.",
                                number, i
                            ))
                            .into());
                        };

                        let request = api_client
                            .build_instance_request(
                                machine,
                                &allocate_request,
                                &format!("{}_{}", allocate_request.prefix_name, i),
                                config.cloud_unsafe_op.clone(),
                            )
                            .await?;
                        requests.push(request);
                    }

                    match api_client.allocate_instances(requests).await {
                        Ok(instances) => {
                            tracing::info!(
                                "Batch allocate was successful. Created {} instances.",
                                instances.len()
                            );
                            for instance in instances {
                                tracing::info!("  Created: {:?}", instance);
                            }
                        }
                        Err(e) => {
                            tracing::error!("Batch allocate failed: {}", e);
                        }
                    }
                } else {
                    // Sequential mode: partial success allowed
                    for i in 0..number {
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
                                &format!("{}_{}", allocate_request.prefix_name, i),
                                config.cloud_unsafe_op.clone(),
                            )
                            .await
                        {
                            Ok(i) => {
                                tracing::info!(
                                    "allocate was successful. Created instance: {:?} ",
                                    i
                                );
                            }
                            Err(e) => {
                                tracing::info!("allocate failed with {} ", e);
                            }
                        };
                    }
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
                    .update_instance_config_with(
                        update_request.instance,
                        |config| {
                            config.os = Some(update_request.os);
                        },
                        |_metadata| {},
                        config.cloud_unsafe_op,
                    )
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
            Instance::UpdateIbConfig(update_request) => {
                if config.cloud_unsafe_op.is_none() {
                    return Err(CarbideCliError::GenericError(
                        "Operation not allowed due to potential inconsistencies with cloud database.".to_owned(),
                    )
                    .into());
                }

                match api_client
                    .update_instance_config_with(
                        update_request.instance,
                        |config| {
                            config.infiniband = Some(update_request.config);
                        },
                        |_metadata| {},
                        config.cloud_unsafe_op,
                    )
                    .await
                {
                    Ok(i) => {
                        tracing::info!(
                            "update-ib-config was successful. Updated instance: {:?}",
                            i
                        );
                    }
                    Err(e) => {
                        tracing::info!("update-ib-config failed with {} ", e);
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
            NetworkSegment::Delete(delete_network_segment) => {
                if config.cloud_unsafe_op.is_none() {
                    return Err(CarbideCliError::GenericError(
                        "Operation not allowed due to potential inconsistencies with cloud database.".to_owned(),
                    )
                    .into());
                }
                api_client
                    .delete_network_segment(delete_network_segment.id)
                    .await?;
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
                        host_id: Some(maint_on.host),
                        reference: Some(maint_on.reference),
                    };
                    api_client.0.set_maintenance(req).await?;
                }
                MaintenanceAction::Off(maint_off) => {
                    let req = forgerpc::MaintenanceRequest {
                        operation: forgerpc::MaintenanceOperation::Disable.into(),
                        host_id: Some(maint_off.host),
                        reference: None,
                    };
                    api_client.0.set_maintenance(req).await?;
                }
            },
            ManagedHost::Quarantine(quarantine_action) => match quarantine_action {
                QuarantineAction::On(quarantine_on) => {
                    let host = quarantine_on.host;
                    let req = forgerpc::SetManagedHostQuarantineStateRequest {
                        machine_id: Some(quarantine_on.host),
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
                    let host = quarantine_off.host;
                    let req = forgerpc::ClearManagedHostQuarantineStateRequest {
                        machine_id: Some(host),
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
                api_client
                    .0
                    .reset_host_reprovisioning(machine_id.machine)
                    .await?;
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
            ManagedHost::StartUpdates(options) => {
                crate::firmware::start_updates(&api_client, options).await?
            }
            ManagedHost::DebugBundle(debug_bundle) => {
                debug_bundle::handle_debug_bundle(debug_bundle, &api_client).await?;
            }
            ManagedHost::SetPrimaryDpu(set_primary_args) => {
                api_client
                    .0
                    .set_primary_dpu(forgerpc::SetPrimaryDpuRequest {
                        host_machine_id: Some(set_primary_args.host_machine_id),
                        dpu_machine_id: Some(set_primary_args.dpu_machine_id),
                        reboot: set_primary_args.reboot,
                    })
                    .await?;
            }
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
                println!("Generated Bios Admin Password: {password}");
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
        CliCommand::ScoutStream(cmd) => {
            scout_stream::dispatch(cmd, &api_client, &config.format).await?
        }
        CliCommand::BootOverride(boot_override_args) => match boot_override_args {
            BootOverrideAction::Get(boot_override) => {
                let mbo = api_client
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

                api_client
                    .set_boot_override(
                        boot_override_set.interface_id,
                        custom_pxe_path.as_deref(),
                        custom_user_data_path.as_deref(),
                    )
                    .await?;
            }
            BootOverrideAction::Clear(boot_override) => {
                api_client
                    .0
                    .clear_machine_boot_override(boot_override.interface_id)
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
            BmcAction::EnableInfiniteBoot(args) => {
                let machine = args.machine;
                api_client
                    .enable_infinite_boot(None, Some(machine.clone()))
                    .await?;
                if args.reboot {
                    api_client
                        .admin_power_control(
                            None,
                            Some(machine),
                            AdminPowerControlAction::ForceRestart.into(),
                        )
                        .await?;
                }
            }
            BmcAction::IsInfiniteBootEnabled(args) => {
                let response = api_client
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

                api_client.lockdown(None, machine, action).await?;

                let action_str = if args.enable { "enabled" } else { "disabled" };

                if args.reboot {
                    api_client
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
                let response = api_client.lockdown_status(None, args.machine).await?;
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
            CredentialAction::AddNmxM(c) => {
                let req = forgerpc::CredentialCreationRequest {
                    credential_type: CredentialType::NmxM.into(),
                    username: Some(c.username),
                    password: c.password,
                    mac_address: None,
                    vendor: None,
                };
                api_client.0.create_credential(req).await?;
            }
            CredentialAction::DeleteNmxM(c) => {
                let req = forgerpc::CredentialDeletionRequest {
                    credential_type: CredentialType::NmxM.into(),
                    username: Some(c.username),
                    mac_address: None,
                };
                api_client.0.delete_credential(req).await?;
            }
        },
        CliCommand::RouteServer(cmd) => {
            route_server::dispatch(&cmd, &api_client, config.format).await?
        }
        CliCommand::SiteExplorer(action) => {
            match action {
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
                SiteExplorer::Remediation(opts) => {
                    if opts.pause {
                        api_client
                            .pause_explored_endpoint_remediation(&opts.address, true)
                            .await?;
                        println!("Remediation paused for endpoint {}", opts.address);
                    } else if opts.resume {
                        api_client
                            .pause_explored_endpoint_remediation(&opts.address, false)
                            .await?;
                        println!("Remediation resumed for endpoint {}", opts.address);
                    } else {
                        return Err(CarbideCliError::GenericError(
                            "Must specify either --pause or --resume".to_owned(),
                        )
                        .into());
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
                    // Power cycle host if requested
                    if let Some(host_ip) = &args.host_bmc_ip {
                        tracing::info!(
                            "Power cycling host at {} to ensure the DPU has rshim control",
                            host_ip
                        );

                        // Power off
                        tracing::info!("Powering off host...");
                        api_client
                            .admin_power_control(
                                Some(::rpc::forge::BmcEndpointRequest {
                                    ip_address: host_ip.clone(),
                                    mac_address: None,
                                }),
                                None,
                                ::rpc::forge::admin_power_control_request::SystemPowerControl::ForceOff,
                            )
                            .await?;

                        // Wait for power off
                        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

                        // Power on
                        tracing::info!("Powering on host");
                        api_client
                            .admin_power_control(
                                Some(::rpc::forge::BmcEndpointRequest {
                                    ip_address: host_ip.clone(),
                                    mac_address: None,
                                }),
                                None,
                                ::rpc::forge::admin_power_control_request::SystemPowerControl::On,
                            )
                            .await?;
                    }

                    tracing::info!("Follow SCP progress in the carbide-api logs...");

                    api_client
                        .copy_bfb_to_dpu_rshim(args.address, args.mac)
                        .await?;
                }
            }
        }
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
                let host_nics = Vec::new();
                api_client
                    .add_expected_machine(
                        expected_machine_data.bmc_mac_address,
                        expected_machine_data.bmc_username,
                        expected_machine_data.bmc_password,
                        expected_machine_data.chassis_serial_number,
                        expected_machine_data.fallback_dpu_serial_numbers,
                        metadata,
                        expected_machine_data.sku_id,
                        expected_machine_data.id,
                        host_nics,
                        expected_machine_data.rack_id,
                    )
                    .await?;
            }
            cfg::cli_options::ExpectedMachineAction::Delete(expected_machine_query) => {
                api_client
                    .0
                    .delete_expected_machine(::rpc::forge::ExpectedMachineRequest {
                        bmc_mac_address: expected_machine_query.bmc_mac_address.to_string(),
                        id: None,
                    })
                    .await?;
            }
            cfg::cli_options::ExpectedMachineAction::Patch(expected_machine_data) => {
                if let Err(e) = expected_machine_data.validate() {
                    eprintln!("{e}");
                    return Ok(());
                }
                api_client
                    .patch_expected_machine(
                        expected_machine_data.bmc_mac_address,
                        expected_machine_data.bmc_username,
                        expected_machine_data.bmc_password,
                        expected_machine_data.chassis_serial_number,
                        expected_machine_data.fallback_dpu_serial_numbers,
                        expected_machine_data.meta_name,
                        expected_machine_data.meta_description,
                        expected_machine_data.labels,
                        expected_machine_data.sku_id,
                        expected_machine_data.rack_id,
                    )
                    .await?;
            }
            cfg::cli_options::ExpectedMachineAction::Update(request) => {
                let json_file_path = Path::new(&request.filename);
                let file_content = std::fs::read_to_string(json_file_path)?;
                let expected_machine: cfg::cli_options::ExpectedMachineJson =
                    serde_json::from_str(&file_content)?;

                let metadata = expected_machine.metadata.unwrap_or_default();

                // Use patch API but provide all fields from JSON for full replacement
                api_client
                    .patch_expected_machine(
                        expected_machine.bmc_mac_address,
                        Some(expected_machine.bmc_username),
                        Some(expected_machine.bmc_password),
                        Some(expected_machine.chassis_serial_number),
                        expected_machine.fallback_dpu_serial_numbers,
                        Some(metadata.name),
                        Some(metadata.description),
                        Some(
                            metadata
                                .labels
                                .into_iter()
                                .map(|label| {
                                    if let Some(value) = label.value {
                                        format!("{}:{}", label.key, value)
                                    } else {
                                        label.key
                                    }
                                })
                                .collect(),
                        ),
                        expected_machine.sku_id,
                        expected_machine.rack_id,
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
        CliCommand::ExpectedPowerShelf(expected_power_shelf_action) => {
            match expected_power_shelf_action {
                cfg::cli_options::ExpectedPowerShelfAction::Show(expected_power_shelf_query) => {
                    expected_power_shelves::show_expected_power_shelves(
                        &expected_power_shelf_query,
                        &api_client,
                        config.format,
                    )
                    .await?;
                }
                cfg::cli_options::ExpectedPowerShelfAction::Add(expected_power_shelf_data) => {
                    let metadata = expected_power_shelf_data.metadata()?;
                    api_client
                        .add_expected_power_shelf(
                            expected_power_shelf_data.bmc_mac_address,
                            expected_power_shelf_data.bmc_username,
                            expected_power_shelf_data.bmc_password,
                            expected_power_shelf_data.shelf_serial_number,
                            metadata,
                            expected_power_shelf_data.rack_id,
                            expected_power_shelf_data.ip_address,
                        )
                        .await?;
                }
                cfg::cli_options::ExpectedPowerShelfAction::Delete(expected_power_shelf_query) => {
                    api_client
                        .0
                        .delete_expected_power_shelf(
                            expected_power_shelf_query.bmc_mac_address.to_string(),
                        )
                        .await?;
                }
                cfg::cli_options::ExpectedPowerShelfAction::Update(expected_power_shelf_data) => {
                    if let Err(e) = expected_power_shelf_data.validate() {
                        eprintln!("{e}");
                        return Ok(());
                    }
                    let metadata = expected_power_shelf_data.metadata()?;
                    api_client
                        .update_expected_power_shelf(
                            expected_power_shelf_data.bmc_mac_address,
                            expected_power_shelf_data.bmc_username,
                            expected_power_shelf_data.bmc_password,
                            expected_power_shelf_data.shelf_serial_number,
                            metadata,
                            expected_power_shelf_data.rack_id,
                            expected_power_shelf_data.ip_address,
                        )
                        .await?;
                }
                cfg::cli_options::ExpectedPowerShelfAction::ReplaceAll(request) => {
                    let json_file_path = Path::new(&request.filename);
                    let reader = BufReader::new(File::open(json_file_path)?);
                    #[derive(Debug, Serialize, Deserialize)]
                    struct ExpectedPowerShelfList {
                        expected_power_shelves: Vec<ExpectedPowerShelfJson>,
                        expected_power_shelves_count: Option<usize>,
                    }
                    let expected_power_shelf_list: ExpectedPowerShelfList =
                        serde_json::from_reader(reader)?;

                    if expected_power_shelf_list
                        .expected_power_shelves_count
                        .is_some_and(|count| {
                            count != expected_power_shelf_list.expected_power_shelves.len()
                        })
                    {
                        return Err(CarbideCliError::GenericError(format!(
                            "Json File specified an invalid count: {:#?}; actual count: {}",
                            expected_power_shelf_list
                                .expected_power_shelves_count
                                .unwrap_or_default(),
                            expected_power_shelf_list.expected_power_shelves.len()
                        ))
                        .into());
                    }

                    api_client
                        .replace_all_expected_power_shelves(
                            expected_power_shelf_list.expected_power_shelves,
                        )
                        .await?;
                }
                cfg::cli_options::ExpectedPowerShelfAction::Erase => {
                    api_client.0.delete_all_expected_power_shelves().await?;
                }
            }
        }
        CliCommand::ExpectedSwitch(expected_switch_action) => match expected_switch_action {
            cfg::cli_options::ExpectedSwitchAction::Show(expected_switch_query) => {
                expected_switches::show_expected_switches(
                    &expected_switch_query,
                    &api_client,
                    config.format,
                )
                .await?;
            }
            cfg::cli_options::ExpectedSwitchAction::Add(expected_switch_data) => {
                let metadata = expected_switch_data.metadata()?;
                api_client
                    .add_expected_switch(
                        expected_switch_data.bmc_mac_address,
                        expected_switch_data.bmc_username,
                        expected_switch_data.bmc_password,
                        expected_switch_data.switch_serial_number,
                        metadata,
                        expected_switch_data.rack_id,
                    )
                    .await?;
            }
            cfg::cli_options::ExpectedSwitchAction::Delete(expected_switch_query) => {
                api_client
                    .0
                    .delete_expected_switch(expected_switch_query.bmc_mac_address.to_string())
                    .await?;
            }
            cfg::cli_options::ExpectedSwitchAction::Update(expected_switch_data) => {
                if let Err(e) = expected_switch_data.validate() {
                    eprintln!("{e}");
                    return Ok(());
                }
                let metadata = expected_switch_data.metadata()?;
                api_client
                    .update_expected_switch(
                        expected_switch_data.bmc_mac_address,
                        expected_switch_data.bmc_username,
                        expected_switch_data.bmc_password,
                        expected_switch_data.switch_serial_number,
                        metadata,
                        expected_switch_data.rack_id,
                    )
                    .await?;
            }
            cfg::cli_options::ExpectedSwitchAction::ReplaceAll(request) => {
                let json_file_path = Path::new(&request.filename);
                let reader = BufReader::new(File::open(json_file_path)?);
                #[derive(Debug, Serialize, Deserialize)]
                struct ExpectedSwitchList {
                    expected_switches: Vec<ExpectedSwitchJson>,
                    expected_switches_count: Option<usize>,
                }
                let expected_switch_list: ExpectedSwitchList = serde_json::from_reader(reader)?;

                if expected_switch_list
                    .expected_switches_count
                    .is_some_and(|count| count != expected_switch_list.expected_switches.len())
                {
                    return Err(CarbideCliError::GenericError(format!(
                        "Json File specified an invalid count: {:#?}; actual count: {}",
                        expected_switch_list
                            .expected_switches_count
                            .unwrap_or_default(),
                        expected_switch_list.expected_switches.len()
                    ))
                    .into());
                }

                api_client
                    .replace_all_expected_switches(expected_switch_list.expected_switches)
                    .await?;
            }
            cfg::cli_options::ExpectedSwitchAction::Erase => {
                api_client.0.delete_all_expected_switches().await?;
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
        CliCommand::Dpa(dpa) => match dpa {
            DpaOptions::Show(dpa) => {
                dpa::handle_show(dpa, config.format, &api_client, config.internal_page_size).await?
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
            if let Ok(machine_id) = j.id.parse::<MachineId>() {
                machine::handle_show(
                    cfg::cli_options::ShowMachine {
                        machine: Some(machine_id),
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
                        RouteServerFromConfigFile => tracing::info!("Route Server from Carbide config"),
                        RouteServerFromAdminApi => tracing::info!("Route Server from Admin API"),
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
                                    network: Some(m.owner_id.ok_or(CarbideCliError::GenericError(
                                        "failed to unwrap owner_id after finding network segment for IP".to_string(),
                                    ))?.parse()?),
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
                                    network: Some(j.id.parse()?),
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
                                    interface_id: Some(j.id.parse()?),
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
                                    id: Some(j.id.parse()?),
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
                                    domain: Some(j.id.parse()?),
                                    all: false,
                                },
                                config.format,
                                &api_client,
                            )
                            .await?
                        }
                        forgerpc::UuidType::DpaInterfaceId => {
                            dpa::handle_show(
                                cfg::cli_options::ShowDpa {
                                    id: Some(j.id.parse()?),
                                },
                                config.format,
                                &api_client,
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
                match api_client.identify_mac(m).await {
                    Ok((mac_owner, primary_key)) => match mac_owner {
                        forgerpc::MacOwner::MachineInterface => {
                            machine_interfaces::handle_show(
                                cfg::cli_options::ShowMachineInterfaces {
                                    interface_id: Some(primary_key.parse()?),
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
                        machine: Some(machine_id),
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
        CliCommand::PowerShelf(action) => match action {
            cfg::cli_options::PowerShelfActions::Show(show_opts) => {
                power_shelf::handle_show(show_opts, config.format, &api_client).await?;
            }
            cfg::cli_options::PowerShelfActions::List => {
                power_shelf::list_power_shelves(&api_client).await?;
            }
        },
        CliCommand::Switch(action) => match action {
            cfg::cli_options::SwitchActions::Show(show_opts) => {
                switch::handle_show(show_opts, config.format, &api_client).await?;
            }
            cfg::cli_options::SwitchActions::List => {
                switch::list_switches(&api_client).await?;
            }
        },
        CliCommand::Rack(action) => match action {
            cfg::cli_options::RackActions::Show(show_opts) => {
                rack::show_rack(&api_client, &show_opts).await?;
            }
            cfg::cli_options::RackActions::List => {
                rack::list_racks(&api_client).await?;
            }
            cfg::cli_options::RackActions::Delete(delete_opts) => {
                rack::delete_rack(&api_client, &delete_opts).await?;
            }
        },
        CliCommand::Rms(action) => match action {
            cfg::cli_options::RmsActions::Inventory => {
                rack::get_inventory(&api_client).await?;
            }
            cfg::cli_options::RmsActions::RemoveNode(remove_node_opts) => {
                rack::remove_node(&api_client, &remove_node_opts).await?;
            }
            cfg::cli_options::RmsActions::PoweronOrder => {
                rack::get_poweron_order(&api_client).await?;
            }
            cfg::cli_options::RmsActions::PowerState(power_state_opts) => {
                rack::get_power_state(&api_client, &power_state_opts).await?;
            }
            cfg::cli_options::RmsActions::FirmwareInventory(firmware_inventory_opts) => {
                rack::get_firmware_inventory(&api_client, &firmware_inventory_opts).await?;
            }
            cfg::cli_options::RmsActions::AvailableFwImages(available_fw_images_opts) => {
                rack::get_available_fw_images(&api_client, &available_fw_images_opts).await?;
            }
            cfg::cli_options::RmsActions::BkcFiles => {
                rack::get_bkc_files(&api_client).await?;
            }
            cfg::cli_options::RmsActions::CheckBkcCompliance => {
                rack::check_bkc_compliance(&api_client).await?;
            }
        },
        CliCommand::Firmware(action) => match action {
            Firmware::Show(_) => {
                firmware::firmware_show(&api_client, config.format, &mut output_file).await?;
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

                    let response = api_client.0.trim_table(request).await?;

                    println!(
                        "Trimmed {} reports from Measured Boot",
                        response.total_deleted
                    );
                }
            }
        }
        CliCommand::DpuRemediation(command) => match command {
            cfg::cli_options::DpuRemediation::Create(create_remediation) => {
                dpu_remediation::create_dpu_remediation(create_remediation, &api_client).await?;
            }
            cfg::cli_options::DpuRemediation::Approve(approve_remediation) => {
                dpu_remediation::approve_dpu_remediation(approve_remediation, &api_client).await?;
            }
            cfg::cli_options::DpuRemediation::Revoke(revoke_remediation) => {
                dpu_remediation::revoke_dpu_remediation(revoke_remediation, &api_client).await?;
            }

            cfg::cli_options::DpuRemediation::Enable(enable_remediation) => {
                dpu_remediation::enable_dpu_remediation(enable_remediation, &api_client).await?;
            }
            cfg::cli_options::DpuRemediation::Disable(disable_remediation) => {
                dpu_remediation::disable_dpu_remediation(disable_remediation, &api_client).await?;
            }
            cfg::cli_options::DpuRemediation::Show(show_remediation) => {
                dpu_remediation::handle_show(
                    show_remediation,
                    config.format,
                    &mut output_file,
                    &api_client,
                    config.internal_page_size,
                )
                .await?;
            }
            cfg::cli_options::DpuRemediation::ListApplied(list_applied_remediations) => {
                dpu_remediation::handle_list_applied(
                    list_applied_remediations,
                    config.format,
                    &mut output_file,
                    &api_client,
                    config.internal_page_size,
                )
                .await?;
            }
        },
        CliCommand::ExtensionService(extension_service_command) => {
            match extension_service_command {
                cfg::cli_options::ExtensionServiceOptions::Create(create_options) => {
                    extension_service::handle_create(create_options, config.format, &api_client)
                        .await?;
                }
                cfg::cli_options::ExtensionServiceOptions::Update(update_options) => {
                    extension_service::handle_update(update_options, config.format, &api_client)
                        .await?;
                }
                cfg::cli_options::ExtensionServiceOptions::Delete(delete_options) => {
                    extension_service::handle_delete(delete_options, config.format, &api_client)
                        .await?;
                }
                cfg::cli_options::ExtensionServiceOptions::Show(show_options) => {
                    extension_service::handle_show(
                        show_options,
                        config.format,
                        &api_client,
                        config.internal_page_size,
                    )
                    .await?;
                }
                cfg::cli_options::ExtensionServiceOptions::GetVersion(get_version_options) => {
                    extension_service::handle_get_version(get_version_options, &api_client).await?;
                }
                cfg::cli_options::ExtensionServiceOptions::ShowInstances(
                    show_instances_options,
                ) => {
                    extension_service::handle_show_instances(
                        show_instances_options,
                        config.format,
                        &api_client,
                    )
                    .await?;
                }
            }
        }

        CliCommand::NvlPartition(nvlp) => match nvlp {
            NvlPartitionOptions::Show(show_options) => {
                nvl_partition::handle_show(
                    show_options,
                    config.format,
                    &api_client,
                    config.internal_page_size,
                )
                .await?
            }
        },

        CliCommand::LogicalPartition(lp) => match lp {
            LogicalPartitionOptions::Show(show_options) => {
                nvl_logical_partition::handle_show(
                    show_options,
                    config.format,
                    &api_client,
                    config.internal_page_size,
                )
                .await?
            }
            LogicalPartitionOptions::Create(create_options) => {
                nvl_logical_partition::handle_create(create_options, &api_client).await?
            }
            LogicalPartitionOptions::Delete(delete_options) => {
                nvl_logical_partition::handle_delete(delete_options, &api_client).await?
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
