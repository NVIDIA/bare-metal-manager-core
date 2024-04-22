/*
 * SPDX-FileCopyrightText: Copyright (c) 2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use std::collections::BTreeMap;
use std::fmt::Write;

use ::rpc::Uuid;
use prettytable::Cell;
use prettytable::Row;
use tracing::warn;

use super::cfg::carbide_options::{OutputFormat, ShowMachineInterfaces};
use super::CarbideCliResult;

use super::rpc;
use crate::cfg::carbide_options::DeleteMachineInterfaces;
use crate::default_uuid;
use ::rpc::forge as forgerpc;
use ::rpc::forge_tls_client::ApiConfig;
use prettytable::Table;

pub async fn handle_show(
    args: ShowMachineInterfaces,
    output_format: OutputFormat,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let is_json = output_format == OutputFormat::Json;
    if args.all || args.interface_id.is_empty() {
        show_all_machine_interfaces(is_json, args.more, api_config).await?;
        // TODO(chet): Remove this ~March 2024.
        // Use tracing::warn for this so its both a little more
        // noticeable, and a little more annoying/naggy. If people
        // complain, it means its working.
        if args.all && output_format == OutputFormat::AsciiTable {
            warn!("redundant `--all` with basic `show` is deprecated. just do `machine-interfaces show`")
        }
        return Ok(());
    }
    show_machine_interfaces_information(args.interface_id, is_json, api_config).await?;
    Ok(())
}

async fn show_all_machine_interfaces(
    is_json: bool,
    has_more: bool,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let machine_interfaces = rpc::get_all_machines_interfaces(api_config, None).await?;

    if is_json {
        println!(
            "{}",
            serde_json::to_string_pretty(&machine_interfaces).unwrap()
        );
    } else {
        let domain_list = rpc::get_domains(None, api_config).await?;

        convert_machines_to_nice_table(has_more, machine_interfaces, domain_list).printstd();
    }
    Ok(())
}

async fn show_machine_interfaces_information(
    id: String,
    is_json: bool,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let interface_id = Some(Uuid { value: id });
    let machine_interfaces = rpc::get_all_machines_interfaces(api_config, interface_id).await?;
    if !machine_interfaces.interfaces.is_empty() {
        if is_json {
            println!(
                "{}",
                serde_json::to_string_pretty(&machine_interfaces.interfaces.first()).unwrap()
            );
        } else {
            let interface = machine_interfaces.interfaces.first().unwrap().to_owned();
            let domain_list = rpc::get_domains(interface.domain_id.clone(), api_config).await?;
            println!(
                "{}",
                convert_machine_to_nice_format(interface, domain_list)
                    .unwrap_or_else(|x| x.to_string())
            );
        }
    }
    Ok(())
}

fn convert_machines_to_nice_table(
    has_more: bool,
    machine_interfaces: forgerpc::InterfaceList,
    domain_list: forgerpc::DomainList,
) -> Box<Table> {
    let mut table = Table::new();

    let domainlist_map = domain_list
        .domains
        .into_iter()
        .map(|x| (x.id.clone().unwrap_or_default().value, x.name.clone()))
        .collect::<BTreeMap<_, _>>();
    let mut headers = vec![
        "Id",
        "MAC Address",
        "IP Address",
        "Machine Id",
        "Hostname",
        "Vendor",
    ];
    if has_more {
        headers.extend_from_slice(&["Domain Name"]);
    }
    table.set_titles(Row::new(
        headers.into_iter().map(Cell::new).collect::<Vec<Cell>>(),
    ));

    for machine_interface in machine_interfaces.interfaces {
        let domain_name = domainlist_map.get(
            &machine_interface
                .domain_id
                .clone()
                .unwrap_or_default()
                .value,
        );
        let mut row = vec![
            machine_interface.id.unwrap_or_default().value,
            machine_interface.mac_address,
            machine_interface.address.join(","),
            machine_interface
                .machine_id
                .as_ref()
                .map(::rpc::MachineId::to_string)
                .unwrap_or_default(),
            machine_interface.hostname,
            machine_interface.vendor.unwrap_or_default(),
        ];
        if has_more {
            row.extend_from_slice(&[domain_name.unwrap().to_owned()]);
        }
        table.add_row(row.into());
    }

    table.into()
}

#[doc = r"Function to print the machine interface in Table format"]
fn convert_machine_to_nice_format(
    machine_interface: forgerpc::MachineInterface,
    domain_list: forgerpc::DomainList,
) -> CarbideCliResult<String> {
    let domainlist_map = domain_list
        .domains
        .into_iter()
        .map(|x| (x.id.clone().unwrap_or_default().value, x.name.clone()))
        .collect::<BTreeMap<_, _>>();
    let domain_name = domainlist_map.get(
        &machine_interface
            .domain_id
            .clone()
            .unwrap_or_default()
            .value,
    );

    let width = 13;

    let data = vec![
        (
            "ID",
            machine_interface.id.clone().unwrap_or_default().to_string(),
        ),
        (
            "DPU ID",
            machine_interface
                .attached_dpu_machine_id
                .as_ref()
                .map(::rpc::MachineId::to_string)
                .unwrap_or_default(),
        ),
        (
            "Machine ID",
            machine_interface
                .machine_id
                .as_ref()
                .map(::rpc::MachineId::to_string)
                .unwrap_or_default(),
        ),
        (
            "Segment ID",
            machine_interface
                .segment_id
                .clone()
                .unwrap_or_else(default_uuid)
                .to_string(),
        ),
        (
            "Domain Id",
            machine_interface.domain_id.unwrap_or_default().to_string(),
        ),
        ("Domain Name", domain_name.unwrap().to_string()),
        ("Hostname", machine_interface.hostname.clone()),
        ("Primary", machine_interface.primary_interface.to_string()),
        ("MAC Address", machine_interface.mac_address.clone()),
        ("Addresses", machine_interface.address.join(",")),
        (
            "Vendor",
            machine_interface
                .vendor
                .clone()
                .unwrap_or_default()
                .to_string(),
        ),
    ];
    let mut lines = String::new();

    for (key, value) in data {
        writeln!(&mut lines, "\t{:<width$}: {}", key, value)?;
    }
    Ok(lines)
}

pub async fn handle_delete(
    args: DeleteMachineInterfaces,
    api_config: &ApiConfig<'_>,
) -> CarbideCliResult<()> {
    let interface_id = Some(Uuid {
        value: args.interface_id,
    });
    rpc::delete_machine_interface(api_config, interface_id).await?;
    Ok(())
}
