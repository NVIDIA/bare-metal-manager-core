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
use prettytable::{row, Table};
use serde_json;

use super::cfg::carbide_options::ShowMachine;
use super::{default_uuid, rpc, CarbideCliResult};

fn convert_machine_to_nice_format(machine: forgerpc::Machine) -> CarbideCliResult<String> {
    let width = 10;
    let mut lines = String::new();

    let data = vec![
        ("ID", machine.id.clone().unwrap_or_default().value),
        (
            "CREATED",
            machine.created.clone().unwrap_or_default().to_string(),
        ),
        (
            "UPDATED",
            machine.updated.clone().unwrap_or_default().to_string(),
        ),
        (
            "DEPLOYED",
            machine.deployed.clone().unwrap_or_default().to_string(),
        ),
        ("STATE", machine.state.clone().to_uppercase()),
    ];
    for (key, value) in data {
        writeln!(&mut lines, "{:<width$}: {}", key, value)?;
    }

    writeln!(&mut lines, "EVENTS: (Latest 5 only)")?;
    if machine.events.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        writeln!(&mut lines, "\tId    Event          Time")?;
        writeln!(&mut lines, "\t----------------------------")?;
        for x in machine.events.iter().rev().take(5).rev() {
            writeln!(
                &mut lines,
                "\t{:<5} {:15} {}",
                x.id,
                forgerpc::MachineAction::try_from(x.event)
                    .unwrap()
                    .as_str_name(),
                x.time.clone().unwrap_or_default()
            )?;
        }
    }

    let width = 13;
    writeln!(&mut lines, "INTERFACES:")?;
    if machine.interfaces.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        for (i, interface) in machine.interfaces.into_iter().enumerate() {
            let m_type = if interface.primary_interface {
                if interface.attached_dpu_machine_id.is_some()
                    && interface.attached_dpu_machine_id == interface.machine_id
                {
                    "DPU"
                } else {
                    "X86_64"
                }
            } else {
                "NA"
            }
            .to_string();
            let data = vec![
                ("SN", i.to_string()),
                ("ID", interface.id.clone().unwrap_or_default().to_string()),
                (
                    "DPU ID",
                    interface
                        .attached_dpu_machine_id
                        .clone()
                        .unwrap_or_else(default_uuid)
                        .to_string(),
                ),
                (
                    "Machine ID",
                    interface
                        .machine_id
                        .clone()
                        .unwrap_or_else(default_uuid)
                        .to_string(),
                ),
                (
                    "Segment ID",
                    interface
                        .segment_id
                        .clone()
                        .unwrap_or_else(default_uuid)
                        .to_string(),
                ),
                (
                    "Domain ID",
                    interface
                        .domain_id
                        .clone()
                        .unwrap_or_else(default_uuid)
                        .to_string(),
                ),
                ("Hostname", interface.hostname.clone()),
                ("Primary", interface.primary_interface.to_string()),
                ("MAC Address", interface.mac_address.clone()),
                ("Addresses", interface.address.join(",")),
                ("Type", m_type),
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

fn convert_machines_to_nice_table(machines: forgerpc::MachineList) -> String {
    let mut table = Table::new();

    table.add_row(row![
        "Id",
        "Created",
        "State",
        "Attached DPU",
        "Primary Interface",
        "IP Address",
        "MAC Address",
        "Type"
    ]);

    for machine in machines.machines {
        let mut machine_interfaces = machine
            .interfaces
            .into_iter()
            .filter(|x| x.primary_interface)
            .collect::<Vec<forgerpc::MachineInterface>>();

        let (id, address, mac, machine_type, dpu_id) = if machine_interfaces.is_empty() {
            (
                "None".to_string(),
                "None".to_string(),
                "None".to_string(),
                "None".to_string(),
                "None".to_string(),
            )
        } else {
            let mi = machine_interfaces.remove(0);

            (
                mi.id.unwrap_or_default().to_string(),
                mi.address.join(","),
                mi.mac_address,
                if mi.attached_dpu_machine_id == mi.machine_id
                    && mi.attached_dpu_machine_id.is_some()
                {
                    "DPU"
                } else {
                    "X86_64"
                }
                .to_string(),
                mi.attached_dpu_machine_id
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "NA".to_string()),
            )
        };

        table.add_row(row![
            machine.id.unwrap_or_default(),
            machine.created.unwrap_or_default(),
            machine.state.to_uppercase(),
            dpu_id,
            id,
            address,
            mac,
            machine_type
        ]);
    }

    table.to_string()
}

async fn show_all_machines(json: bool, carbide_api: String) -> CarbideCliResult<()> {
    let machines = rpc::get_all_machines(carbide_api).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&machines).unwrap());
    } else {
        println!("{}", convert_machines_to_nice_table(machines));
    }
    Ok(())
}

async fn show_machine_information(
    id: String,
    json: bool,
    carbide_api: String,
) -> CarbideCliResult<()> {
    let machine = rpc::get_machine(id, carbide_api).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&machine).unwrap());
    } else {
        println!(
            "{}",
            convert_machine_to_nice_format(machine).unwrap_or_else(|x| x.to_string())
        );
    }
    Ok(())
}

pub async fn handle_show(
    args: ShowMachine,
    json: bool,
    carbide_api: String,
) -> CarbideCliResult<()> {
    if args.all {
        show_all_machines(json, carbide_api).await?;
    } else if let Some(uuid) = args.uuid {
        show_machine_information(uuid, json, carbide_api).await?;
    }

    Ok(())
}
