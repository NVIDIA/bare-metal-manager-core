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
use std::time::Duration;

use prettytable::{row, Table};

use ::rpc::forge as forgerpc;

use crate::cfg::carbide_options::ForceDeleteMachineQuery;
use crate::Config;

use super::cfg::carbide_options::ShowMachine;
use super::{default_machine_id, default_uuid, rpc, CarbideCliResult};

fn convert_machine_to_nice_format(machine: forgerpc::Machine) -> CarbideCliResult<String> {
    let width = 10;
    let mut lines = String::new();

    let data = vec![
        ("ID", machine.id.clone().unwrap_or_default().id),
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

    writeln!(&mut lines, "STATE HISTORY: (Latest 5 only)")?;
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
                x.event,
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
                        .unwrap_or_else(default_machine_id)
                        .to_string(),
                ),
                (
                    "Machine ID",
                    interface
                        .machine_id
                        .clone()
                        .unwrap_or_else(default_machine_id)
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

fn convert_machines_to_nice_table(machines: forgerpc::MachineList) -> Box<Table> {
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

    table.into()
}

async fn show_all_machines(json: bool, api_config: Config) -> CarbideCliResult<()> {
    let machines = rpc::get_all_machines(api_config).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&machines).unwrap());
    } else {
        convert_machines_to_nice_table(machines).printstd();
    }
    Ok(())
}

async fn show_machine_information(
    id: String,
    json: bool,
    api_config: Config,
) -> CarbideCliResult<()> {
    let machine = rpc::get_machine(id, api_config).await?;
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
    api_config: Config,
) -> CarbideCliResult<()> {
    if args.all {
        show_all_machines(json, api_config).await?;
    } else if let Some(machine_id) = args.machine {
        show_machine_information(machine_id, json, api_config).await?;
    }

    Ok(())
}

pub async fn force_delete(
    mut query: ForceDeleteMachineQuery,
    api_config: Config,
) -> CarbideCliResult<()> {
    const RETRY_TIME: Duration = Duration::from_secs(5);
    const MAX_WAIT_TIME: Duration = Duration::from_secs(60 * 20);

    let start = std::time::Instant::now();
    let mut dpu_machine_id = String::new();

    loop {
        let response = rpc::machine_admin_force_delete(query.clone(), api_config.clone()).await?;
        println!(
            "Force delete response: {}",
            serde_json::to_string_pretty(&response).unwrap()
        );

        if dpu_machine_id.is_empty() && !response.dpu_machine_id.is_empty() {
            dpu_machine_id = response.dpu_machine_id.clone();
        }

        if response.all_done {
            println!("Force delete for {} succeeded", query.machine);

            // If we only searched for a Machine, then the DPU might be left behind
            // since the site controller can't look up the DPU by host machine ID anymore.
            // To also clean up the DPU, we modify our query and continue to delete
            if !dpu_machine_id.is_empty() && query.machine != dpu_machine_id {
                println!(
                    "Starting to delete potentially stale DPU machine {}",
                    dpu_machine_id
                );
                query.machine = dpu_machine_id.clone();
            } else {
                // No DPU to delete
                break;
            }
        }

        if start.elapsed() > MAX_WAIT_TIME {
            return Err(crate::CarbideCliError::GenericError(format!(
                "Unable to force delete machine after {}s. Exiting",
                MAX_WAIT_TIME.as_secs()
            )));
        }

        println!(
            "Machine has not been fully deleted. Retrying after {}s",
            RETRY_TIME.as_secs()
        );
        tokio::time::sleep(RETRY_TIME).await;
    }

    Ok(())
}
