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
use std::fmt::Write;

use ::rpc::forge as forgerpc;
use ::rpc::forge_tls_client::ApiConfig;
use prettytable::{row, Table};
use tracing::warn;

use super::cfg::carbide_options::ShowInstance;
use super::{default_uuid, invalid_machine_id, rpc, CarbideCliResult};
use crate::cfg::carbide_options::{OutputFormat, RebootInstance};
use crate::CarbideCliError;

fn convert_instance_to_nice_format(
    instance: &forgerpc::Instance,
    extrainfo: bool,
) -> CarbideCliResult<String> {
    let width = 25;
    let mut lines = String::new();

    let mut data = vec![
        ("ID", instance.id.clone().unwrap_or_default().value),
        (
            "MACHINE ID",
            instance.machine_id.clone().unwrap_or_default().id,
        ),
        (
            "TENANT ORG",
            instance
                .config
                .as_ref()
                .and_then(|config| config.tenant.as_ref())
                .map(|tenant| tenant.tenant_organization_id.clone())
                .unwrap_or_default(),
        ),
        (
            "TENANT STATE",
            instance
                .status
                .as_ref()
                .and_then(|status| status.tenant.as_ref())
                .and_then(|tenant| forgerpc::TenantState::try_from(tenant.state).ok())
                .map(|state| format!("{:?}", state))
                .unwrap_or_default(),
        ),
        (
            "TENANT STATE DETAILS",
            instance
                .status
                .as_ref()
                .and_then(|status| status.tenant.as_ref())
                .map(|tenant| tenant.state_details.clone())
                .unwrap_or_default(),
        ),
        (
            "CONFIGS SYNCED",
            instance
                .status
                .as_ref()
                .and_then(|status| forgerpc::SyncState::try_from(status.configs_synced).ok())
                .map(|state| format!("{:?}", state))
                .unwrap_or_default(),
        ),
        (
            "NETWORK CONFIG SYNCED",
            instance
                .status
                .as_ref()
                .and_then(|status| status.network.as_ref())
                .and_then(|status| forgerpc::SyncState::try_from(status.configs_synced).ok())
                .map(|state| format!("{:?}", state))
                .unwrap_or_default(),
        ),
        (
            "NETWORK CONFIG VERSION",
            instance.network_config_version.clone(),
        ),
    ];

    let mut extra_info = vec![
        (
            "CUSTOM IPXE",
            instance
                .config
                .as_ref()
                .and_then(|config| config.tenant.as_ref())
                .map(|tenant| tenant.custom_ipxe.clone())
                .unwrap_or_default(),
        ),
        (
            "USERDATA",
            instance
                .config
                .as_ref()
                .and_then(|config| config.tenant.as_ref())
                .and_then(|tenant| tenant.user_data.clone())
                .unwrap_or_default(),
        ),
        (
            "ALWAYS BOOT CUSTOM IPXE",
            instance
                .config
                .as_ref()
                .and_then(|config| config.tenant.as_ref())
                .map(|tenant| tenant.always_boot_with_custom_ipxe)
                .unwrap_or_default()
                .to_string(),
        ),
    ];

    if extrainfo {
        data.append(&mut extra_info);
    }

    for (key, value) in data {
        writeln!(&mut lines, "{:<width$}: {}", key, value)?;
    }

    let width = 25;
    writeln!(&mut lines, "INTERFACES:")?;
    let if_configs = instance
        .config
        .as_ref()
        .and_then(|config| config.network.as_ref())
        .map(|config| config.interfaces.as_slice())
        .unwrap_or_default();
    let if_status = instance
        .status
        .as_ref()
        .and_then(|status| status.network.as_ref())
        .map(|status| status.interfaces.as_slice())
        .unwrap_or_default();

    if if_configs.is_empty() || if_status.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else if if_configs.len() != if_status.len() {
        writeln!(&mut lines, "\tLENGTH MISMATCH")?;
    } else {
        for (i, interface) in if_configs.iter().enumerate() {
            let status = &if_status[i];
            let data = &[
                (
                    "FUNCTION_TYPE",
                    forgerpc::InterfaceFunctionType::try_from(interface.function_type)
                        .ok()
                        .map(|ty| format!("{:?}", ty))
                        .unwrap_or_else(|| "INVALID".to_string()),
                ),
                (
                    "VF ID",
                    status
                        .virtual_function_id
                        .map(|id| id.to_string())
                        .unwrap_or_default(),
                ),
                (
                    "SEGMENT ID",
                    interface
                        .network_segment_id
                        .clone()
                        .unwrap_or_else(default_uuid)
                        .to_string(),
                ),
                ("MAC ADDR", status.mac_address.clone().unwrap_or_default()),
                ("ADDRESSES", status.addresses.clone().join(", ")),
            ];

            for (key, value) in data {
                writeln!(&mut lines, "\t{:<width$}: {}", key, value)?;
            }
            writeln!(
                &mut lines,
                "\t--------------------------------------------------"
            )?;
        }
    }

    Ok(lines)
}

fn convert_instances_to_nice_table(instances: forgerpc::InstanceList) -> Box<Table> {
    let mut table = Table::new();

    table.set_titles(row![
        "Id",
        "MachineId",
        "TenantOrg",
        "TenantState",
        "ConfigsSynced",
        "IPAddresses",
    ]);

    for instance in instances.instances {
        let tenant_org = instance
            .config
            .as_ref()
            .and_then(|config| config.tenant.as_ref())
            .map(|tenant| tenant.tenant_organization_id.clone())
            .unwrap_or_default();

        let tenant_state = instance
            .status
            .as_ref()
            .and_then(|status| status.tenant.as_ref())
            .and_then(|tenant| forgerpc::TenantState::try_from(tenant.state).ok())
            .map(|state| format!("{:?}", state))
            .unwrap_or_default();

        let configs_synced = instance
            .status
            .as_ref()
            .and_then(|status| forgerpc::SyncState::try_from(status.configs_synced).ok())
            .map(|state| format!("{:?}", state))
            .unwrap_or_default();

        let instance_addresses: Vec<&str> = instance
            .status
            .as_ref()
            .and_then(|status| status.network.as_ref())
            .map(|network| network.interfaces.as_slice())
            .unwrap_or_default()
            .iter()
            .filter(|x| x.virtual_function_id.is_none())
            .flat_map(|status| status.addresses.iter().map(|addr| addr.as_str()))
            .collect();

        table.add_row(row![
            instance.id.unwrap_or_default(),
            instance.machine_id.unwrap_or_else(invalid_machine_id),
            tenant_org,
            tenant_state,
            configs_synced,
            instance_addresses.join(",")
        ]);
    }

    table.into()
}

async fn show_all_instances(json: bool, api_config: &ApiConfig<'_>) -> CarbideCliResult<()> {
    let instances = rpc::get_instances(api_config, None).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&instances).unwrap());
    } else {
        convert_instances_to_nice_table(instances).printstd();
    }
    Ok(())
}

async fn show_instance_details(
    id: String,
    json: bool,
    api_config: &ApiConfig<'_>,
    extrainfo: bool,
) -> CarbideCliResult<()> {
    let instance = if id.starts_with("fm100") {
        rpc::get_instances_by_machine_id(api_config, id).await?
    } else {
        rpc::get_instances(api_config, Some(id)).await?
    };

    if instance.instances.len() != 1 {
        println!("Unknown UUID.");
        return Err(CarbideCliError::GenericError("Unknow UUID".to_string()));
    }

    let instance = &instance.instances[0];

    if json {
        println!("{}", serde_json::to_string_pretty(instance).unwrap());
    } else {
        println!(
            "{}",
            convert_instance_to_nice_format(instance, extrainfo).unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

pub async fn handle_show(
    args: ShowInstance,
    output_format: OutputFormat,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if args.all || args.id.is_empty() {
        show_all_instances(is_json, api_config).await?;
        // TODO(chet): Remove this ~March 2024.
        // Use tracing::warn for this so its both a little more
        // noticeable, and a little more annoying/naggy. If people
        // complain, it means its working.
        if args.all && output_format == OutputFormat::AsciiTable {
            warn!("redundant `--all` with basic `show` is deprecated. just do `instance show`")
        }
        return Ok(());
    }
    show_instance_details(args.id, is_json, api_config, args.extrainfo).await?;
    Ok(())
}

pub async fn handle_reboot(
    args: RebootInstance,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let machine_id = rpc::get_instances(api_config, Some(args.instance.clone()))
        .await?
        .instances
        .last()
        .ok_or_else(|| CarbideCliError::GenericError("Unknown UUID".to_string()))?
        .machine_id
        .clone()
        .ok_or_else(|| {
            CarbideCliError::GenericError("Instance has no machine associated.".to_string())
        })?;

    rpc::reboot_instance(
        api_config,
        machine_id.clone(),
        args.custom_pxe,
        args.apply_updates_on_reboot,
    )
    .await?;
    println!(
        "Reboot for instance {} (machine {}) is requested successfully!",
        args.instance, machine_id
    );

    Ok(())
}
