/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
use std::borrow::Cow;
use std::collections::VecDeque;
use std::fmt::Write;
use std::pin::Pin;
use std::str::FromStr;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge::{self as forgerpc, InstancePowerRequest, InstanceReleaseRequest};
use carbide_uuid::instance::InstanceId;
use carbide_uuid::machine::MachineId;
use carbide_uuid::network::NetworkSegmentId;
use carbide_uuid::vpc::VpcId;
use prettytable::{Table, row};
use rpc::forge::{Vpc, VpcsByIdsRequest};

use super::args::{
    AllocateInstance, GlobalOptions, RebootInstance, ReleaseInstance, ShowInstance, UpdateIbConfig,
    UpdateInstanceOS,
};
use crate::cfg::cli_options::SortField;
use crate::rpc::ApiClient;
use crate::{async_write, async_writeln, invalid_machine_id, machine};

async fn convert_instance_to_nice_format(
    api_client: &ApiClient,
    instance: &forgerpc::Instance,
    extrainfo: bool,
) -> CarbideCliResult<String> {
    let width = 25;
    let mut lines = String::new();

    let mut data = vec![
        (
            "ID",
            instance
                .id
                .map(|id| Cow::Owned(id.to_string()))
                .unwrap_or_default(),
        ),
        (
            "MACHINE ID",
            instance
                .machine_id
                .map(|id| Cow::Owned(id.to_string()))
                .unwrap_or_default(),
        ),
        (
            "TENANT ORG",
            instance
                .config
                .as_ref()
                .and_then(|config| config.tenant.as_ref())
                .map(|tenant| Cow::Borrowed(tenant.tenant_organization_id.as_str()))
                .unwrap_or_default(),
        ),
        (
            "TENANT STATE",
            instance
                .status
                .as_ref()
                .and_then(|status| status.tenant.as_ref())
                .and_then(|tenant| forgerpc::TenantState::try_from(tenant.state).ok())
                .map(|state| Cow::Owned(format!("{state:?}")))
                .unwrap_or_default(),
        ),
        (
            "TENANT STATE DETAILS",
            instance
                .status
                .as_ref()
                .and_then(|status| status.tenant.as_ref())
                .map(|tenant| Cow::Borrowed(tenant.state_details.as_str()))
                .unwrap_or_default(),
        ),
        (
            "INSTANCE TYPE ID",
            instance
                .instance_type_id
                .as_ref()
                .map(|id| Cow::Borrowed(id.as_str()))
                .unwrap_or_default(),
        ),
        (
            "CONFIGS SYNCED",
            instance
                .status
                .as_ref()
                .and_then(|status| forgerpc::SyncState::try_from(status.configs_synced).ok())
                .map(|state| Cow::Owned(format!("{state:?}")))
                .unwrap_or_default(),
        ),
        ("CONFIG VERSION", instance.config_version.as_str().into()),
        (
            "NETWORK CONFIG SYNCED",
            instance
                .status
                .as_ref()
                .and_then(|status| status.network.as_ref())
                .and_then(|status| forgerpc::SyncState::try_from(status.configs_synced).ok())
                .map(|state| Cow::Owned(format!("{state:?}")))
                .unwrap_or_default(),
        ),
        (
            "NETWORK CONFIG VERSION",
            instance.network_config_version.as_str().into(),
        ),
    ];

    let instance_os = instance
        .config
        .as_ref()
        .and_then(|config| config.os.as_ref());

    let mut extra_info = vec![
        (
            "IPXE SCRIPT",
            instance_os
                .and_then(|os| match os.variant.as_ref() {
                    Some(::rpc::forge::operating_system::Variant::Ipxe(ipxe_os)) => {
                        Some(Cow::Borrowed(ipxe_os.ipxe_script.as_str()))
                    }
                    Some(::rpc::forge::operating_system::Variant::OsImageId(image)) => {
                        Some(Cow::Owned(format!("OS Image ID: {}", image.value)))
                    }
                    None => None,
                })
                .unwrap_or_default(),
        ),
        (
            "USERDATA",
            instance_os
                .and_then(|os| os.user_data.as_ref())
                .map(|ud| ud.as_str().into())
                .unwrap_or_default(),
        ),
        (
            "RUN PROVISIONING ON EVERY BOOT",
            instance_os
                .map(|os| os.run_provisioning_instructions_on_every_boot)
                .unwrap_or_default()
                .to_string()
                .into(),
        ),
        (
            "PHONE HOME ENABLED",
            instance_os
                .map(|os| os.phone_home_enabled)
                .unwrap_or_default()
                .to_string()
                .into(),
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

            let vpc = if let Some(network_segment_id) = interface.network_segment_id {
                get_vpc_for_interface_network_segment(api_client, network_segment_id).await?
            } else {
                None
            };

            let data: &[(&str, Cow<str>)] = &[
                (
                    "FUNCTION_TYPE",
                    forgerpc::InterfaceFunctionType::try_from(interface.function_type)
                        .ok()
                        .map(|ty| format!("{ty:?}").into())
                        .unwrap_or_else(|| "INVALID".into()),
                ),
                (
                    "VF ID",
                    status
                        .virtual_function_id
                        .map(|id| id.to_string().into())
                        .unwrap_or_default(),
                ),
                (
                    "SEGMENT ID",
                    interface
                        .network_segment_id
                        .unwrap_or_default()
                        .to_string()
                        .into(),
                ),
                (
                    "VPC PREFIX ID",
                    match &interface.network_details {
                        Some(forgerpc::instance_interface_config::NetworkDetails::SegmentId(_)) => {
                            "Segment Based Allocation".into()
                        }
                        Some(forgerpc::instance_interface_config::NetworkDetails::VpcPrefixId(
                            x,
                        )) => x.to_string().into(),
                        None => "NA".into(),
                    },
                ),
                (
                    "MAC ADDR",
                    status
                        .mac_address
                        .as_ref()
                        .map(|s| s.as_str().into())
                        .unwrap_or_default(),
                ),
                ("ADDRESSES", status.addresses.as_slice().join(", ").into()),
                (
                    "VPC ID",
                    vpc.as_ref()
                        .map(|v| v.id.unwrap_or_default().to_string().into())
                        .unwrap_or("<not found>".into()),
                ),
                (
                    "VPC NAME",
                    vpc.as_ref()
                        .map(|v| v.name.as_str().into())
                        .unwrap_or("<not found>".into()),
                ),
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

    if let Some(ib_config) = instance.config.as_ref().and_then(|c| c.infiniband.as_ref())
        && let Some(ib_status) = instance.status.as_ref().and_then(|s| s.infiniband.as_ref())
    {
        writeln!(&mut lines, "IB INTERFACES:")?;
        writeln!(
            &mut lines,
            "\t{:<width$}: {}",
            "IB CONFIG VERSION", instance.ib_config_version,
        )?;
        writeln!(
            &mut lines,
            "\t{:<width$}: {}",
            "CONFIG SYNCED", ib_status.configs_synced
        )?;
        for (i, interface) in ib_config.ib_interfaces.iter().enumerate() {
            let status = &ib_status.ib_interfaces[i];
            let data: &[(&str, Cow<str>)] = &[
                (
                    "FUNCTION_TYPE",
                    forgerpc::InterfaceFunctionType::try_from(interface.function_type)
                        .ok()
                        .map(|ty| format!("{ty:?}").into())
                        .unwrap_or_else(|| "INVALID".into()),
                ),
                (
                    "VENDOR",
                    interface
                        .vendor
                        .as_ref()
                        .map(|v| v.as_str().into())
                        .unwrap_or_default(),
                ),
                ("DEVICE", interface.device.as_str().into()),
                (
                    "DEVICE INSTANCE",
                    interface.device_instance.to_string().into(),
                ),
                (
                    "VF ID",
                    interface
                        .virtual_function_id
                        .map(|x| x.to_string().into())
                        .unwrap_or_default(),
                ),
                (
                    "PARTITION ID",
                    interface
                        .ib_partition_id
                        .map(|x| x.to_string().into())
                        .unwrap_or_default(),
                ),
                (
                    "PF GUID",
                    status
                        .pf_guid
                        .as_ref()
                        .map(|g| g.as_str().into())
                        .unwrap_or_default(),
                ),
                (
                    "GUID",
                    status
                        .guid
                        .as_ref()
                        .map(|g| g.as_str().into())
                        .unwrap_or_default(),
                ),
                ("LID", status.lid.to_string().into()),
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

    if let Some(nsg_id) = instance
        .config
        .as_ref()
        .and_then(|c| c.network_security_group_id.as_ref())
    {
        writeln!(&mut lines, "NETWORK SECURITY GROUP ID: {nsg_id}")?;
    }

    if let Some(metadata) = instance.metadata.as_ref() {
        writeln!(
            &mut lines,
            "LABELS: {}",
            metadata
                .labels
                .iter()
                .map(|x| format!("{}: {}", x.key, x.value.as_deref().unwrap_or_default()))
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
            .map(|tenant| tenant.tenant_organization_id.as_str())
            .unwrap_or_default();

        let labels = crate::metadata::get_nice_labels_from_rpc_metadata(instance.metadata.as_ref());

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
                convert_instance_to_nice_format(api_client, instance, extrainfo).await?
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
        .0
        .invoke_instance_power(InstancePowerRequest {
            instance_id: Some(args.instance),
            machine_id: Some(machine_id),
            operation: forgerpc::instance_power_request::Operation::PowerReset as i32,
            boot_with_custom_ipxe: args.custom_pxe,
            apply_updates_on_reboot: args.apply_updates_on_reboot,
        })
        .await?;
    println!(
        "Reboot for instance {} (machine {}) is requested successfully!",
        args.instance, machine_id
    );

    Ok(())
}

pub async fn release(
    api_client: &ApiClient,
    release_request: ReleaseInstance,
    opts: GlobalOptions<'_>,
) -> CarbideCliResult<()> {
    if opts.cloud_unsafe_op.is_none() {
        return Err(CarbideCliError::GenericError(
            "Operation not allowed due to potential inconsistencies with cloud database."
                .to_owned(),
        ));
    }

    let mut instance_ids: Vec<InstanceId> = Vec::new();

    match (
        release_request.instance,
        release_request.machine,
        release_request.label_key,
    ) {
        (Some(instance_id), _, _) => instance_ids.push(
            uuid::Uuid::parse_str(&instance_id)
                .map_err(|e| CarbideCliError::GenericError(e.to_string()))?
                .into(),
        ),
        (_, Some(machine_id), _) => {
            let instances = api_client.0.find_instance_by_machine_id(machine_id).await?;
            if instances.instances.is_empty() {
                return Err(CarbideCliError::GenericError(
                    "No instances assigned to that machine".to_string(),
                ));
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
                    opts.page_size,
                )
                .await?;
            if instances.instances.is_empty() {
                return Err(CarbideCliError::GenericError(
                    "No instances with the passed label.key exist".to_string(),
                ));
            }
            instance_ids = instances
                .instances
                .iter()
                .filter_map(|instance| instance.id)
                .collect();
        }
        _ => {}
    };
    for instance_id in instance_ids {
        api_client
            .0
            .release_instance(InstanceReleaseRequest {
                id: Some(instance_id),
                issue: None,
                is_repair_tenant: None,
            })
            .await?;
    }
    Ok(())
}

pub async fn allocate(
    api_client: &ApiClient,
    allocate_request: AllocateInstance,
    opts: GlobalOptions<'_>,
) -> CarbideCliResult<()> {
    if opts.cloud_unsafe_op.is_none() {
        return Err(CarbideCliError::GenericError(
            "Operation not allowed due to potential inconsistencies with cloud database."
                .to_owned(),
        ));
    }

    let number = allocate_request.number.unwrap_or(1);

    // Validate: --transactional requires --number > 1
    if allocate_request.transactional && number <= 1 {
        return Err(CarbideCliError::GenericError(
            "--transactional requires --number > 1".to_owned(),
        ));
    }

    let mut machine_ids: VecDeque<_> = if !allocate_request.machine_id.is_empty() {
        allocate_request.machine_id.iter().copied().collect()
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
            let Some(machine) =
                machine::get_next_free_machine(api_client, &mut machine_ids, min_interface_count)
                    .await
            else {
                return Err(CarbideCliError::GenericError(format!(
                    "Need {} machines but only {} available.",
                    number, i
                )));
            };

            let request = api_client
                .build_instance_request(
                    machine,
                    &allocate_request,
                    &format!("{}_{}", allocate_request.prefix_name, i),
                    opts.cloud_unsafe_op.clone(),
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
            let Some(machine) =
                machine::get_next_free_machine(api_client, &mut machine_ids, min_interface_count)
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
                    opts.cloud_unsafe_op.clone(),
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
    Ok(())
}

pub async fn update_os(
    api_client: &ApiClient,
    update_request: UpdateInstanceOS,
    opts: GlobalOptions<'_>,
) -> CarbideCliResult<()> {
    if opts.cloud_unsafe_op.is_none() {
        return Err(CarbideCliError::GenericError(
            "Operation not allowed due to potential inconsistencies with cloud database."
                .to_owned(),
        ));
    }

    match api_client
        .update_instance_config_with(
            update_request.instance,
            |config| {
                config.os = Some(update_request.os);
            },
            |_metadata| {},
            opts.cloud_unsafe_op,
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
    Ok(())
}

pub async fn update_ib_config(
    api_client: &ApiClient,
    update_request: UpdateIbConfig,
    opts: GlobalOptions<'_>,
) -> CarbideCliResult<()> {
    if opts.cloud_unsafe_op.is_none() {
        return Err(CarbideCliError::GenericError(
            "Operation not allowed due to potential inconsistencies with cloud database."
                .to_owned(),
        ));
    }

    match api_client
        .update_instance_config_with(
            update_request.instance,
            |config| {
                config.infiniband = Some(update_request.config);
            },
            |_metadata| {},
            opts.cloud_unsafe_op,
        )
        .await
    {
        Ok(i) => {
            tracing::info!("update-ib-config was successful. Updated instance: {:?}", i);
        }
        Err(e) => {
            tracing::info!("update-ib-config failed with {} ", e);
        }
    };
    Ok(())
}

async fn get_vpc_for_interface_network_segment(
    api_client: &ApiClient,
    network_segment_id: NetworkSegmentId,
) -> CarbideCliResult<Option<Vpc>> {
    let network_segments = api_client
        .get_segments_by_ids(&[network_segment_id])
        .await?;

    if !network_segments.network_segments.is_empty()
        && let Some(vpc_id) = network_segments
            .network_segments
            .first()
            .and_then(|s| s.vpc_id)
    {
        let vpc_ids: Vec<VpcId> = vec![vpc_id];
        Ok(api_client
            .0
            .find_vpcs_by_ids(VpcsByIdsRequest { vpc_ids })
            .await?
            .vpcs
            .into_iter()
            .next())
    } else {
        Ok(None)
    }
}
