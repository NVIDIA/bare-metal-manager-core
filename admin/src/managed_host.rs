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

use std::convert::From;
use std::fmt::Write;

use ::rpc::site_explorer::ExploredManagedHost;
use ::rpc::Machine;
use prettytable::{Cell, Row, Table};
use serde::Serialize;
use tracing::warn;

use super::{rpc, CarbideCliResult};
use crate::cfg::carbide_options::{OutputFormat, ShowManagedHost};
use crate::Config;

const UNKNOWN: &str = "Unknown";

#[derive(Default, Serialize)]
struct ManagedHostOutputWrapper {
    show_ips: bool,
    more_details: bool,
    has_maintenance: bool,
    managed_host_output: utils::ManagedHostOutput,
}

impl From<ManagedHostOutputWrapper> for Row {
    fn from(src: ManagedHostOutputWrapper) -> Self {
        let value = src.managed_host_output;
        let machine_ids = format!(
            "{}\n{}",
            value.machine_id.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_machine_id.unwrap_or(UNKNOWN.to_owned())
        );

        let bmc_ip = format!(
            "{}\n{}",
            value.host_bmc_ip.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_bmc_ip.unwrap_or(UNKNOWN.to_owned()),
        );

        let bmc_mac = format!(
            "{}\n{}",
            value.host_bmc_mac.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_bmc_mac.unwrap_or(UNKNOWN.to_owned()),
        );

        let ips = format!(
            "{}\n{}",
            value.host_admin_ip.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_oob_ip.unwrap_or(UNKNOWN.to_owned())
        );

        let macs = format!(
            "{}\n{}",
            value.host_admin_mac.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_oob_mac.unwrap_or(UNKNOWN.to_owned())
        );

        let mut row_data = vec![
            value.hostname.unwrap_or(UNKNOWN.to_owned()),
            machine_ids,
            value.state,
        ];

        if src.has_maintenance {
            row_data.extend_from_slice(&[
                value.maintenance_reference.unwrap_or_default(),
                value.maintenance_start_time.unwrap_or_default(),
            ]);
        }

        if src.show_ips {
            row_data.extend_from_slice(&[bmc_ip, bmc_mac, ips, macs]);
        }

        if src.more_details {
            row_data.extend_from_slice(&[
                value.host_gpu_count.to_string(),
                value.host_memory.unwrap_or(UNKNOWN.to_owned()),
            ]);
        }

        Row::new(row_data.into_iter().map(|x| Cell::new(&x)).collect())
    }
}

fn convert_managed_hosts_to_nice_output(
    managed_hosts: Vec<utils::ManagedHostOutput>,
    show_ips: bool,
    more_details: bool,
) -> Box<Table> {
    let has_maintenance = managed_hosts
        .iter()
        .any(|m| m.maintenance_reference.is_some());
    let managed_hosts_wrapper = managed_hosts
        .into_iter()
        .map(|x| ManagedHostOutputWrapper {
            show_ips,
            more_details,
            has_maintenance,
            managed_host_output: x,
        })
        .collect::<Vec<ManagedHostOutputWrapper>>();

    let mut table = Table::new();

    let mut headers = vec!["Hostname", "Machine IDs (H/D)", "State"];
    // if any machines in the list are in maintenance mode we add the columns
    if has_maintenance {
        headers.extend_from_slice(&["Maintenance reference", "Maintenance since"]);
    }

    if show_ips {
        headers.extend_from_slice(&[
            "BMC IP(H/D)",
            "BMC MAC(H/D)",
            "ADMIN/OOB IP",
            "ADMIN/OOB MAC",
        ])
    }

    if more_details {
        headers.extend_from_slice(&["GPU #", "Host Memory"]);
    }

    // TODO additional discovery work needed for remaining information
    table.add_row(Row::new(
        headers.into_iter().map(Cell::new).collect::<Vec<Cell>>(),
    ));

    for managed_host in managed_hosts_wrapper {
        table.add_row(managed_host.into());
    }

    table.into()
}

async fn show_managed_hosts(
    output: &mut dyn std::io::Write,
    output_format: OutputFormat,
    machines: Vec<Machine>,
    show_ips: bool,
    more_details: bool,
    site_explorer_managed_host: Vec<ExploredManagedHost>,
) -> CarbideCliResult<()> {
    let managed_hosts = utils::get_managed_host_output(machines, site_explorer_managed_host);

    match output_format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&managed_hosts).unwrap()),
        OutputFormat::Csv => {
            let result =
                convert_managed_hosts_to_nice_output(managed_hosts, show_ips, more_details);

            if let Err(error) = result.to_csv(output) {
                warn!("Error writing csv data: {}", error);
            }
        }
        _ => {
            let result =
                convert_managed_hosts_to_nice_output(managed_hosts, show_ips, more_details);
            if let Err(error) = result.print(output) {
                warn!("Error writing table data: {}", error);
            }
        }
    }
    Ok(())
}

fn show_managed_host_details_view(m: utils::ManagedHostOutput) -> CarbideCliResult<()> {
    let width = 21;
    let mut lines = String::new();

    writeln!(
        &mut lines,
        "Hostname    : {}",
        m.hostname.clone().unwrap_or(UNKNOWN.to_string())
    )?;

    writeln!(&mut lines, "State       : {}", m.state)?;

    if m.maintenance_reference.is_some() {
        writeln!(&mut lines, "Host is in maintenance mode")?;
        writeln!(
            &mut lines,
            "  Reference  : {}",
            m.maintenance_reference
                .expect("Host in maintenance mode without reference - impossible")
        )?;
        writeln!(
            &mut lines,
            "  Started at : {}",
            m.maintenance_start_time
                .expect("Missing maintenance_start_time - impossible")
        )?;
    }

    writeln!(
        &mut lines,
        "\nHost:\n----------------------------------------"
    )?;

    let mut data = vec![
        ("  ID", m.machine_id.clone()),
        ("  Last reboot", m.host_last_reboot_time),
        ("  Serial Number", m.host_serial_number.clone()),
        ("  BIOS Version", m.host_bios_version.clone()),
        ("  GPU Count", Some(m.host_gpu_count.to_string())),
        ("  Memory", m.host_memory.clone()),
        ("  Admin IP", m.host_admin_ip.clone()),
        ("  Admin MAC", m.host_admin_mac.clone()),
    ];
    if m.is_network_healthy {
        data.push(("  Network is healthy", Some("".to_string())));
    } else {
        data.push((
            "  Network unhealthy",
            Some(m.network_err_message.clone().unwrap_or_default()),
        ));
    }
    let mut bmc_details = vec![
        ("  BMC", Some("".to_string())),
        ("    Version", m.host_bmc_version.clone()),
        ("    Firmware Version", m.host_bmc_firmware_version.clone()),
        ("    IP", m.host_bmc_ip.clone()),
        ("    MAC", m.host_bmc_mac.clone()),
    ];
    data.append(&mut bmc_details);

    for (key, value) in data {
        if matches!(&value, Some(x) if x.is_empty()) {
            writeln!(&mut lines, "{:<width$}", key)?;
        } else {
            writeln!(
                &mut lines,
                "{:<width$}: {}",
                key,
                value.unwrap_or(UNKNOWN.to_string())
            )?;
        }
    }

    writeln!(
        &mut lines,
        "\nDPU:\n----------------------------------------"
    )?;

    let data = vec![
        ("  ID", m.dpu_machine_id.clone()),
        ("  Last reboot", m.dpu_last_reboot_time),
        ("  Last seen", m.dpu_last_observation_time),
        ("  Serial Number", m.dpu_serial_number.clone()),
        ("  BIOS Version", m.dpu_bios_version.clone()),
        ("  Admin IP", m.dpu_oob_ip.clone()),
        ("  Admin MAC", m.dpu_oob_mac.clone()),
        ("  BMC", Some("".to_string())),
        ("    Version", m.dpu_bmc_version.clone()),
        ("    Firmware Version", m.dpu_bmc_firmware_version.clone()),
        ("    IP", m.dpu_bmc_ip.clone()),
        ("    MAC", m.dpu_bmc_mac.clone()),
    ];

    for (key, value) in data {
        if matches!(&value, Some(x) if x.is_empty()) {
            writeln!(&mut lines, "{:<width$}", key)?;
        } else {
            writeln!(
                &mut lines,
                "{:<width$}: {}",
                key,
                value.unwrap_or(UNKNOWN.to_string())
            )?;
        }
    }

    println!("{}", lines);

    Ok(())
}

pub async fn handle_show(
    output: &mut dyn std::io::Write,
    args: ShowManagedHost,
    output_format: OutputFormat,
    api_config: Config,
) -> CarbideCliResult<()> {
    let requested_machine = args.machine.or(args.host);
    let site_report_managed_hosts = rpc::get_site_exploration_report(&api_config)
        .await?
        .managed_hosts;

    if args.all {
        let machines = rpc::get_all_machines(api_config, args.fix).await?.machines;
        show_managed_hosts(
            output,
            output_format,
            machines,
            args.ips,
            args.more,
            site_report_managed_hosts,
        )
        .await?;
    } else if let Some(requested_machine_id) = requested_machine {
        let mut machines = Vec::default();
        let requested_machine = rpc::get_machine(requested_machine_id, api_config.clone()).await?;

        if let Some(associated_machine_id) = requested_machine
            .associated_dpu_machine_id
            .as_ref()
            .or(requested_machine.associated_host_machine_id.as_ref())
        {
            let associated_machine: Machine =
                rpc::get_machine(associated_machine_id.to_string(), api_config.clone()).await?;
            machines.push(associated_machine);
        }

        machines.push(requested_machine);
        if args.fix {
            machines.retain(|m| m.maintenance_reference.is_some());
        }
        for m in utils::get_managed_host_output(machines, site_report_managed_hosts).into_iter() {
            show_managed_host_details_view(m)?;
        }
    }

    Ok(())
}
