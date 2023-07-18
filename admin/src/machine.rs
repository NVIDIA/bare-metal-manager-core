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
    let width = 14;
    let mut lines = String::new();
    let machine_id = machine.id.clone().unwrap_or_default().id;

    let data = vec![
        ("ID", machine.id.clone().unwrap_or_default().id),
        ("STATE", machine.state.clone().to_uppercase()),
        ("STATE_VERSION", machine.state_version.clone()),
        ("MACHINE TYPE", get_machine_type(&machine_id)),
    ];
    for (key, value) in data {
        writeln!(&mut lines, "{:<width$}: {}", key, value)?;
    }

    writeln!(&mut lines, "STATE HISTORY: (Latest 5 only)")?;
    if machine.events.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        let mut max_state_len = 0;
        let mut max_version_len = 0;
        for x in machine.events.iter().rev().take(5).rev() {
            max_state_len = max_state_len.max(x.event.len());
            max_version_len = max_version_len.max(x.version.len());
        }
        let header = format!(
            "{:<max_state_len$} {:<max_version_len$} Time",
            "State", "Version"
        );
        writeln!(&mut lines, "\t{header}")?;
        let mut div = "".to_string();
        for _ in 0..header.len() + 27 {
            div.push('-')
        }
        writeln!(&mut lines, "\t{}", div)?;
        for x in machine.events.iter().rev().take(5).rev() {
            writeln!(
                &mut lines,
                "\t{:<max_state_len$} {:<max_version_len$} {}",
                x.event,
                x.version,
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

fn get_machine_type(machine_id: &str) -> String {
    if machine_id.starts_with("fm100p") {
        "Host (Predicted)"
    } else if machine_id.starts_with("fm100h") {
        "Host"
    } else {
        "DPU"
    }
    .to_string()
}

fn convert_machines_to_nice_table(machines: forgerpc::MachineList) -> Box<Table> {
    let mut table = Table::new();

    table.add_row(row![
        "Id",
        "State",
        "State Version",
        "Attached DPU",
        "Primary Interface",
        "IP Address",
        "MAC Address",
        "Type"
    ]);

    for machine in machines.machines {
        let machine_id = machine.id.unwrap_or_default().id;
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
                get_machine_type(&machine_id),
                mi.attached_dpu_machine_id
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "NA".to_string()),
            )
        };

        table.add_row(row![
            machine_id,
            machine.state.to_uppercase(),
            machine.state_version.clone(),
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
