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

use std::collections::VecDeque;
use std::fmt::Write;
use std::pin::Pin;

use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use ::rpc::forge as forgerpc;
use carbide_uuid::machine::MachineId;
use prettytable::{Table, row};
use rpc::Machine;

use super::args::Args;
use crate::cfg::cli_options::SortField;
use crate::rpc::ApiClient;
use crate::{async_write, async_write_table_as_csv, async_writeln};

fn convert_machine_to_nice_format(
    machine: forgerpc::Machine,
    history_count: u32,
) -> CarbideCliResult<String> {
    let mut lines = String::new();
    let sku = machine.hw_sku.unwrap_or_default();
    let sku_device_type = machine.hw_sku_device_type.unwrap_or_default();

    let mut data = vec![
        (
            "ID",
            machine.id.map(|id| id.to_string()).unwrap_or_default(),
        ),
        ("STATE", machine.state.to_uppercase()),
        ("STATE_VERSION", machine.state_version),
        ("MACHINE TYPE", get_machine_type(machine.id)),
        (
            "FAILURE",
            machine.failure_details.unwrap_or("None".to_string()),
        ),
        ("VERSION", machine.version),
        ("SKU", sku),
        ("SKU DEVICE TYPE", sku_device_type),
    ];
    if let Some(di) = machine.discovery_info
        && let Some(dmi) = di.dmi_data
    {
        data.push(("VENDOR", dmi.sys_vendor));
        data.push(("PRODUCT NAME", dmi.product_name));
        data.push(("PRODUCT SERIAL", dmi.product_serial));
        data.push(("BOARD SERIAL", dmi.board_serial));
        data.push(("CHASSIS SERIAL", dmi.chassis_serial));
        data.push(("BIOS VERSION", dmi.bios_version));
        data.push(("BOARD VERSION", dmi.board_version));
    }
    let autoupdate = if let Some(autoupdate) = machine.firmware_autoupdate {
        autoupdate.to_string()
    } else {
        "Default".to_string()
    };
    data.push(("FIRMWARE AUTOUPDATE", autoupdate));

    let width = 1 + data
        .iter()
        .fold(0, |accum, (key, _value)| std::cmp::max(accum, key.len()));

    for (key, value) in data {
        writeln!(&mut lines, "{key:<width$}: {value}")?;
    }

    let metadata = machine.metadata.unwrap_or_default();
    writeln!(&mut lines, "METADATA")?;
    writeln!(&mut lines, "\tNAME: {}", metadata.name)?;
    writeln!(&mut lines, "\tDESCRIPTION: {}", metadata.description)?;
    writeln!(&mut lines, "\tLABELS:")?;
    for label in metadata.labels {
        writeln!(
            &mut lines,
            "\t\t{}:{}",
            label.key,
            label.value.unwrap_or_default()
        )?;
    }

    writeln!(&mut lines, "STATE HISTORY: (Latest {history_count} only)")?;
    if machine.events.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        let mut max_state_len = 0;
        let mut max_version_len = 0;
        for x in machine
            .events
            .iter()
            .rev()
            .take(history_count as usize)
            .rev()
        {
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
        writeln!(&mut lines, "\t{div}")?;
        for x in machine
            .events
            .iter()
            .rev()
            .take(history_count as usize)
            .rev()
        {
            writeln!(
                &mut lines,
                "\t{:<max_state_len$} {:<max_version_len$} {}",
                x.event,
                x.version,
                x.time.unwrap_or_default()
            )?;
        }
    }

    writeln!(&mut lines, "INTERFACES:")?;
    if machine.interfaces.is_empty() {
        writeln!(&mut lines, "\tEMPTY")?;
    } else {
        for (i, interface) in machine.interfaces.into_iter().enumerate() {
            let data = vec![
                ("SN", i.to_string()),
                ("ID", interface.id.unwrap_or_default().to_string()),
                (
                    "DPU ID",
                    interface
                        .attached_dpu_machine_id
                        .as_ref()
                        .map(MachineId::to_string)
                        .unwrap_or_default(),
                ),
                (
                    "Machine ID",
                    interface
                        .machine_id
                        .as_ref()
                        .map(MachineId::to_string)
                        .unwrap_or_default(),
                ),
                (
                    "Segment ID",
                    interface.segment_id.unwrap_or_default().to_string(),
                ),
                (
                    "Domain ID",
                    interface.domain_id.unwrap_or_default().to_string(),
                ),
                ("Hostname", interface.hostname),
                ("Primary", interface.primary_interface.to_string()),
                ("MAC Address", interface.mac_address),
                ("Addresses", interface.address.join(",")),
            ];

            let width = 1 + data
                .iter()
                .fold(0, |accum, (key, _value)| std::cmp::max(accum, key.len()));
            for (key, value) in data {
                writeln!(&mut lines, "\t{key:<width$}: {value}")?;
            }
            writeln!(
                &mut lines,
                "\t--------------------------------------------------"
            )?;
        }
    }

    if let Some(health) = machine.health
        && !health.alerts.is_empty()
    {
        writeln!(&mut lines, "ALERTS:")?;
        for alert in health.alerts {
            writeln!(&mut lines, "\t- {}", alert.message)?;
        }
    }

    Ok(lines)
}

fn get_machine_type(machine_id: Option<MachineId>) -> String {
    machine_id
        .map(|id| id.machine_type().to_string())
        .unwrap_or_else(|| "Unknown".to_string())
}

fn convert_machines_to_nice_table(machines: forgerpc::MachineList) -> Box<Table> {
    let mut table = Box::new(Table::new());

    table.set_titles(row![
        "",
        "Id",
        "State",
        "State Version",
        "Attached DPUs",
        "Primary Interface",
        "IP Address",
        "MAC Address",
        "Type",
        "Vendor",
        "Labels",
    ]);

    for machine in machines.machines {
        let machine_id_string = machine.id.map(|id| id.to_string()).unwrap_or_default();
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
            let dpu_ids = if !machine.associated_dpu_machine_ids.is_empty() {
                machine
                    .associated_dpu_machine_ids
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
            } else {
                vec![
                    mi.attached_dpu_machine_id
                        .map(|i| i.to_string())
                        .unwrap_or_else(|| "NA".to_string()),
                ]
            };

            (
                mi.id.unwrap_or_default().to_string(),
                mi.address.join(","),
                mi.mac_address,
                get_machine_type(machine.id),
                dpu_ids.join("\n"),
            )
        };
        let mut vendor = String::new();
        if let Some(di) = machine.discovery_info
            && let Some(dmi) = di.dmi_data
        {
            vendor = dmi.sys_vendor;
        }

        let labels = crate::metadata::get_nice_labels_from_rpc_metadata(machine.metadata.as_ref());

        let is_unhealthy = machine
            .health
            .map(|x| !x.alerts.is_empty())
            .unwrap_or_default();

        table.add_row(row![
            String::from(if is_unhealthy { "U" } else { "H" }),
            machine_id_string,
            machine.state.to_uppercase(),
            machine.state_version,
            dpu_id,
            id,
            address,
            mac,
            machine_type,
            vendor,
            labels.join(", ")
        ]);
    }

    table
}

async fn show_all_machines(
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: &OutputFormat,
    api_client: &ApiClient,
    search_config: rpc::forge::MachineSearchConfig,
    page_size: usize,
    sort_by: &SortField,
) -> CarbideCliResult<()> {
    let mut machines = api_client
        .get_all_machines(search_config, page_size)
        .await?;

    match sort_by {
        SortField::PrimaryId => machines.machines.sort_by(|m1, m2| m1.id.cmp(&m2.id)),
        SortField::State => machines.machines.sort_by(|m1, m2| m1.state.cmp(&m2.state)),
    };

    match output_format {
        OutputFormat::Json => {
            async_writeln!(output_file, "{}", serde_json::to_string_pretty(&machines)?)?;
        }
        OutputFormat::AsciiTable => {
            let table = convert_machines_to_nice_table(machines);
            async_write!(output_file, "{}", table)?;
        }
        OutputFormat::Csv => {
            let table = convert_machines_to_nice_table(machines);
            async_write_table_as_csv!(output_file, table)?;
        }
        OutputFormat::Yaml => {
            return Err(CarbideCliError::NotImplemented(
                "YAML formatted output".to_string(),
            ));
        }
    }
    Ok(())
}

async fn show_machine_information(
    machine_id: MachineId,
    args: &Args,
    output_format: &OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
) -> CarbideCliResult<()> {
    let machine = api_client.get_machine(machine_id).await?;
    match output_format {
        OutputFormat::Json => {
            async_write!(output_file, "{}", serde_json::to_string_pretty(&machine)?)?
        }
        OutputFormat::AsciiTable => async_write!(
            output_file,
            "{}",
            convert_machine_to_nice_format(machine, args.history_count)
                .unwrap_or_else(|x| x.to_string())
        )?,
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
    args: Args,
    output_format: &OutputFormat,
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    api_client: &ApiClient,
    page_size: usize,
    sort_by: &SortField,
) -> CarbideCliResult<()> {
    if let Some(machine_id) = args.machine {
        show_machine_information(machine_id, &args, output_format, output_file, api_client).await?;
    } else {
        // Show both hosts and DPUs if neither flag is specified
        let show_all_types = !args.dpus && !args.hosts;
        let dpus_only = args.dpus && !args.hosts;
        let search_config = rpc::forge::MachineSearchConfig {
            include_dpus: args.dpus || show_all_types,
            exclude_hosts: dpus_only,
            include_predicted_host: args.hosts || show_all_types,
            ..Default::default()
        };
        show_all_machines(
            output_file,
            output_format,
            api_client,
            search_config,
            page_size,
            sort_by,
        )
        .await?;
    }

    Ok(())
}

pub async fn get_next_free_machine(
    api_client: &ApiClient,
    machine_ids: &mut VecDeque<MachineId>,
    min_interface_count: usize,
) -> Option<Machine> {
    while let Some(id) = machine_ids.pop_front() {
        tracing::debug!("Checking {}", id);
        if let Ok(machine) = api_client.get_machine(id).await {
            if machine.state != "Ready" {
                tracing::debug!("Machine is not ready");
                continue;
            }
            if let Some(discovery_info) = &machine.discovery_info {
                let dpu_interfaces = discovery_info
                    .network_interfaces
                    .iter()
                    .filter(|i| {
                        i.pci_properties.as_ref().is_some_and(|pci_properties| {
                            pci_properties
                                .vendor
                                .to_ascii_lowercase()
                                .contains("mellanox")
                        })
                    })
                    .count();

                if dpu_interfaces >= min_interface_count && machine.state == "Ready" {
                    return Some(machine);
                }
            }
        }
    }
    None
}
