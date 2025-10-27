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
use std::pin::Pin;
use std::str::FromStr;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge as forgerpc;
use forge_uuid::instance::InstanceId;
use forge_uuid::machine::MachineId;
use prettytable::{Table, row};

use super::cfg::cli_options::ShowInstance;
use super::invalid_machine_id;
use crate::cfg::cli_options::{RebootInstance, SortField};
use crate::rpc::ApiClient;
use crate::{async_write, async_writeln};

fn convert_instance_to_nice_format(
    instance: &forgerpc::Instance,
    extrainfo: bool,
) -> CarbideCliResult<String> {
    let width = 25;
    let mut lines = String::new();

    let mut data = vec![
        (
            "ID",
            instance.id.map(|id| id.to_string()).unwrap_or_default(),
        ),
        (
            "MACHINE ID",
            instance
                .machine_id
                .map(|id| id.to_string())
                .unwrap_or_default(),
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
                .map(|state| format!("{state:?}"))
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
            "INSTANCE TYPE ID",
            instance.instance_type_id.clone().unwrap_or_default(),
        ),
        (
            "CONFIGS SYNCED",
            instance
                .status
                .as_ref()
                .and_then(|status| forgerpc::SyncState::try_from(status.configs_synced).ok())
                .map(|state| format!("{state:?}"))
                .unwrap_or_default(),
        ),
        ("CONFIG VERSION", instance.config_version.clone()),
        (
            "NETWORK CONFIG SYNCED",
            instance
                .status
                .as_ref()
                .and_then(|status| status.network.as_ref())
                .and_then(|status| forgerpc::SyncState::try_from(status.configs_synced).ok())
                .map(|state| format!("{state:?}"))
                .unwrap_or_default(),
        ),
        (
            "NETWORK CONFIG VERSION",
            instance.network_config_version.clone(),
        ),
    ];

    let mut extra_info = vec![
        (
            "IPXE SCRIPT",
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
            "ALWAYS BOOT WITH IPXE",
            instance
                .config
                .as_ref()
                .and_then(|config| config.tenant.as_ref())
                .map(|tenant| tenant.always_boot_with_custom_ipxe)
                .unwrap_or_default()
                .to_string(),
        ),
        (
            "PHONE HOME ENABLED",
            instance
                .config
                .as_ref()
                .and_then(|config| config.tenant.as_ref())
                .map(|tenant| tenant.phone_home_enabled)
                .unwrap_or_default()
                .to_string(),
        ),
    ];

    if extrainfo {
        data.append(&mut extra_info);
    }

    for (key, value) in data {
        writeln!(&mut lines, "{key:<width$}: {value}")?;
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
                        .map(|ty| format!("{ty:?}"))
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
                    interface.network_segment_id.unwrap_or_default().to_string(),
                ),
                (
                    "VPC PREFIX ID",
                    match &interface.network_details {
                        Some(forgerpc::instance_interface_config::NetworkDetails::SegmentId(_)) => {
                            "Segment Based Allocation".to_string()
                        }
                        Some(forgerpc::instance_interface_config::NetworkDetails::VpcPrefixId(
                            x,
                        )) => x.to_string(),
                        None => "NA".to_string(),
                    },
                ),
                ("MAC ADDR", status.mac_address.clone().unwrap_or_default()),
                ("ADDRESSES", status.addresses.clone().join(", ")),
            ];

            for (key, value) in data {
                writeln!(&mut lines, "\t{key:<width$}: {value}")?;
            }
            writeln!(
                &mut lines,
                "\t--------------------------------------------------"
            )?;
        }
    }

    if let Some(ib_config) = instance.config.clone().unwrap().infiniband
        && let Some(ib_status) = instance.status.clone().unwrap().infiniband
    {
        writeln!(&mut lines, "IB INTERFACES:")?;
        writeln!(
            &mut lines,
            "\t{:<width$}: {}",
            "IB CONFIG VERSION",
            instance.ib_config_version.clone()
        )?;
        writeln!(
            &mut lines,
            "\t{:<width$}: {}",
            "CONFIG SYNCED", ib_status.configs_synced
        )?;
        for (i, interface) in ib_config.ib_interfaces.iter().enumerate() {
            let status = &ib_status.ib_interfaces[i];
            let data = &[
                (
                    "FUNCTION_TYPE",
                    forgerpc::InterfaceFunctionType::try_from(interface.function_type)
                        .ok()
                        .map(|ty| format!("{ty:?}"))
                        .unwrap_or_else(|| "INVALID".to_string()),
                ),
                ("VENDOR", interface.vendor.clone().unwrap_or_default()),
                ("DEVICE", interface.device.clone()),
                ("DEVICE INSTANCE", interface.device_instance.to_string()),
                (
                    "VF ID",
                    interface
                        .virtual_function_id
                        .map(|x| x.to_string())
                        .unwrap_or_default(),
                ),
                (
                    "PARTITION ID",
                    interface
                        .ib_partition_id
                        .map(|x| x.to_string())
                        .unwrap_or_default(),
                ),
                ("PF GUID", status.pf_guid.clone().unwrap_or_default()),
                ("GUID", status.guid.clone().unwrap_or_default()),
                ("LID", status.lid.to_string()),
            ];

            for (key, value) in data {
                writeln!(&mut lines, "\t{key:<width$}: {value}")?;
            }
            writeln!(
                &mut lines,
                "\t--------------------------------------------------"
            )?;
        }
    }

    if let Some(nsg_id) = instance.config.clone().unwrap().network_security_group_id {
        writeln!(&mut lines, "NETWORK SECURITY GROUP ID: {nsg_id}")?;
    }

    if let Some(metadata) = instance.metadata.clone() {
        writeln!(
            &mut lines,
            "LABELS: {}",
            metadata
                .labels
                .iter()
                .map(|x| format!("{}: {}", x.key, x.value.clone().unwrap_or_default()))
                .collect::<Vec<String>>()
                .join(", ")
        )?;
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
        "InstanceTypeId",
        "ConfigsSynced",
        "IPAddresses",
        "Labels",
    ]);

    for instance in instances.instances {
        let tenant_org = instance
            .config
            .as_ref()
            .and_then(|config| config.tenant.as_ref())
            .map(|tenant| tenant.tenant_organization_id.clone())
            .unwrap_or_default();

        let labels = crate::metadata::get_nice_labels_from_rpc_metadata(&instance.metadata);

        let tenant_state = instance
            .status
            .as_ref()
            .and_then(|status| status.tenant.as_ref())
            .and_then(|tenant| forgerpc::TenantState::try_from(tenant.state).ok())
            .map(|state| format!("{state:?}"))
            .unwrap_or_default();

        let configs_synced = instance
            .status
            .as_ref()
            .and_then(|status| forgerpc::SyncState::try_from(status.configs_synced).ok())
            .map(|state| format!("{state:?}"))
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
            instance
                .machine_id
                .map(|id| id.to_string())
                .unwrap_or_else(invalid_machine_id),
            tenant_org,
            tenant_state,
            instance.instance_type_id.unwrap_or_default(),
            configs_synced,
            instance_addresses.join(","),
            labels.join(", ")
        ]);
    }

    table.into()
}

async fn show_instance_details(
    id: String,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
    api_client: &ApiClient,
    extrainfo: bool,
) -> CarbideCliResult<()> {
    let instance = if let Ok(id) = MachineId::from_str(&id) {
        api_client.0.find_instance_by_machine_id(id).await?
    } else {
        let instance_id = InstanceId::from_str(&id)
            .map_err(|_| CarbideCliError::GenericError("UUID Conversion failed.".to_string()))?;
        match api_client.get_one_instance(instance_id).await {
            Ok(instance) => instance,
            Err(e) => return Err(e),
        }
    };

    if instance.instances.len() != 1 {
        return Err(CarbideCliError::GenericError(
            "Unknown Instance ID".to_string(),
        ));
    }

    let instance = &instance.instances[0];
    match output_format {
        OutputFormat::Json => {
            async_writeln!(output_file, "{}", serde_json::to_string_pretty(instance)?)?;
        }
        OutputFormat::AsciiTable => {
            async_write!(
                output_file,
                "{}",
                convert_instance_to_nice_format(instance, extrainfo)?
            )?;
        }
        OutputFormat::Csv => {
            return Err(CarbideCliError::NotImplemented(
                "CSV formatted output".to_string(),
            ));
        }
        OutputFormat::Yaml => {
            return Err(CarbideCliError::NotImplemented(
                "YAML formatted output".to_string(),
            ));
        }
    }
    Ok(())
}

pub async fn handle_show(
    args: ShowInstance,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
    sort_by: &SortField,
) -> CarbideCliResult<()> {
    if args.id.is_empty() {
        let mut all_instances = api_client
            .get_all_instances(
                args.tenant_org_id,
                args.vpc_id,
                args.label_key,
                args.label_value,
                args.instance_type_id,
                page_size,
            )
            .await?;

        match sort_by {
            SortField::PrimaryId => all_instances.instances.sort_by(|i1, i2| i1.id.cmp(&i2.id)),
            SortField::State => all_instances.instances.sort_by(|i1, i2| {
                let tenant_status1 = i1
                    .status
                    .as_ref()
                    .and_then(|status| status.tenant.as_ref())
                    .and_then(|tenant| forgerpc::TenantState::try_from(tenant.state).ok())
                    .map(|state| format!("{state:?}"))
                    .unwrap_or_default();
                let tenant_status2 = i2
                    .status
                    .as_ref()
                    .and_then(|status| status.tenant.as_ref())
                    .and_then(|tenant| forgerpc::TenantState::try_from(tenant.state).ok())
                    .map(|state| format!("{state:?}"))
                    .unwrap_or_default();
                tenant_status1.cmp(&tenant_status2)
            }),
        }
        match output_format {
            OutputFormat::Json => {
                async_writeln!(
                    output_file,
                    "{}",
                    serde_json::to_string_pretty(&all_instances)?
                )?;
            }
            OutputFormat::AsciiTable => {
                let table = convert_instances_to_nice_table(all_instances);
                async_write!(output_file, "{}", table)?;
            }
            OutputFormat::Csv => {
                return Err(CarbideCliError::NotImplemented(
                    "CSV formatted output".to_string(),
                ));
            }
            OutputFormat::Yaml => {
                return Err(CarbideCliError::NotImplemented(
                    "YAML formatted output".to_string(),
                ));
            }
        }
        return Ok(());
    }
    show_instance_details(
        args.id,
        output_file,
        output_format,
        api_client,
        args.extrainfo,
    )
    .await?;
    Ok(())
}

pub async fn handle_reboot(args: RebootInstance, api_client: &ApiClient) -> CarbideCliResult<()> {
    let machine_id = api_client
        .get_one_instance(args.instance)
        .await?
        .instances
        .last()
        .ok_or_else(|| CarbideCliError::GenericError("Unknown UUID".to_string()))?
        .machine_id
        .ok_or_else(|| {
            CarbideCliError::GenericError("Instance has no machine associated.".to_string())
        })?;

    api_client
        .reboot_instance(machine_id, args.custom_pxe, args.apply_updates_on_reboot)
        .await?;
    println!(
        "Reboot for instance {} (machine {}) is requested successfully!",
        args.instance, machine_id
    );

    Ok(())
}
