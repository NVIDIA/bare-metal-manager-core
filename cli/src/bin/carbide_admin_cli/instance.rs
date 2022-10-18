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
use super::cfg::carbide_options::ShowInstance;
use super::{default_uuid, rpc, CarbideCliResult};
use crate::carbide_admin_cli::CarbideCliError;
use ::rpc::forge as forgerpc;
use prettytable::{row, Table};
use serde_json;
use std::fmt::Write;

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
            instance.machine_id.clone().unwrap_or_default().value,
        ),
        (
            "MANAGED RES ID",
            instance
                .managed_resource_id
                .clone()
                .unwrap_or_default()
                .value,
        ),
        (
            "REQUESTED",
            instance.requested.clone().unwrap_or_default().to_string(),
        ),
        (
            "STARTED",
            instance.started.clone().unwrap_or_default().to_string(),
        ),
        (
            "FINISHED",
            instance.finished.clone().unwrap_or_default().to_string(),
        ),
        (
            "CUSTOM PXE ON NEXT BOOT",
            instance.use_custom_pxe_on_boot.to_string(),
        ),
    ];

    let mut extra_info = vec![
        ("CUSTOM IPXE", instance.custom_ipxe.clone()),
        ("USERDATA", instance.user_data.clone().unwrap_or_default()),
        ("SSH KEYS", instance.ssh_keys.join(", ")),
    ];

    if extrainfo {
        data.append(&mut extra_info);
    }

    for (key, value) in data {
        writeln!(&mut lines, "{:<width$}: {}", key, value)?;
    }

    let width = 25;
    writeln!(&mut lines, "INTERFACES:")?;
    if instance.interfaces.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        for (i, interface) in instance.interfaces.clone().into_iter().enumerate() {
            let data = &[
                ("SN", i.to_string()),
                ("ID", interface.id.clone().unwrap_or_default().to_string()),
                (
                    "Machine Interface Id",
                    interface
                        .machine_interface_id
                        .clone()
                        .unwrap_or_else(default_uuid)
                        .to_string(),
                ),
                (
                    "Segment Id",
                    interface
                        .network_segment_id
                        .clone()
                        .unwrap_or_else(default_uuid)
                        .to_string(),
                ),
                (
                    "VF Id",
                    interface
                        .vfid
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "None".to_string()),
                ),
                ("Addresses", interface.addresses.clone().join(", ")),
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

fn convert_instances_to_nice_table(instances: forgerpc::InstanceList) -> String {
    let mut table = Table::new();

    table.add_row(row![
        "Id",
        "Requested",
        "MachineId",
        "MachineInterfaceId",
        "IPAddresses",
    ]);

    for instance in instances.instances {
        let mut instance_interfaces = instance
            .interfaces
            .into_iter()
            .filter(|x| x.vfid.is_none())
            .collect::<Vec<forgerpc::InstanceSubnet>>();

        let (machine_interface, ipaddress) = if instance_interfaces.is_empty() {
            ("None".to_string(), "None".to_string())
        } else {
            let ii = instance_interfaces.remove(0);

            (
                ii.machine_interface_id
                    .unwrap_or_else(default_uuid)
                    .to_string(),
                ii.addresses.join(","),
            )
        };

        table.add_row(row![
            instance.id.unwrap_or_default(),
            instance.requested.unwrap_or_default(),
            instance.machine_id.unwrap_or_else(default_uuid),
            machine_interface,
            ipaddress
        ]);
    }

    table.to_string()
}

async fn show_all_instances(json: bool, carbide_api: String) -> CarbideCliResult<()> {
    let instances = rpc::get_instances(carbide_api, None).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&instances).unwrap());
    } else {
        println!("{}", convert_instances_to_nice_table(instances));
    }
    Ok(())
}

async fn show_instance_details(
    id: String,
    json: bool,
    carbide_api: String,
    extrainfo: bool,
) -> CarbideCliResult<()> {
    let instance = rpc::get_instances(carbide_api, Some(id)).await?;
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

async fn show_machine_details(
    id: String,
    json: bool,
    carbide_api: String,
    extrainfo: bool,
) -> CarbideCliResult<()> {
    let instance = rpc::get_instances_by_machine_id(carbide_api, id).await?;
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
    json: bool,
    carbide_api: String,
) -> CarbideCliResult<()> {
    if args.all {
        show_all_instances(json, carbide_api).await?;
    } else if let Some(uuid) = args.uuid {
        show_instance_details(uuid, json, carbide_api, args.extrainfo).await?;
    } else if let Some(uuid) = args.machineid {
        show_machine_details(uuid, json, carbide_api, args.extrainfo).await?;
    }

    Ok(())
}
