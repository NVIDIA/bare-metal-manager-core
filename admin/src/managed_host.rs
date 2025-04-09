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

use crate::cfg::cli_options::ShowManagedHost;
use crate::rpc::ApiClient;
use ::rpc::{Machine, MachineId};
use prettytable::{Cell, Row, Table};
use serde::Serialize;
use std::collections::HashSet;
use std::fmt::Write;
use tracing::warn;
use utils::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};

const UNKNOWN: &str = "Unknown";

#[derive(Default, Serialize)]
struct ManagedHostOutputWrapper {
    options: ManagedHostOutputOptions,
    managed_host_output: utils::ManagedHostOutput,
}

#[derive(Default, Clone, Copy, Serialize)]
struct ManagedHostOutputOptions {
    show_ips: bool,
    more_details: bool,
    has_maintenance: bool,
    show_quarantine_reason: bool,
    single_host_detail_view: bool,
}

macro_rules! concat_host_and_dpu_props {
    ($host:ident, $host_prop:ident, $dpu_prop:ident) => {
        [
            vec![$host.$host_prop.unwrap_or(UNKNOWN.to_owned())],
            $host
                .dpus
                .iter()
                .map(|d| d.$dpu_prop.clone().unwrap_or(UNKNOWN.to_owned()))
                .collect(),
        ]
        .concat()
        .join("\n")
    };
}

impl From<ManagedHostOutputWrapper> for Row {
    fn from(src: ManagedHostOutputWrapper) -> Self {
        let value = src.managed_host_output;
        let machine_ids = concat_host_and_dpu_props!(value, machine_id, machine_id);
        let bmc_ip = concat_host_and_dpu_props!(value, host_bmc_ip, bmc_ip);
        let bmc_mac = concat_host_and_dpu_props!(value, host_bmc_mac, bmc_mac);

        let ips = concat_host_and_dpu_props!(value, host_admin_ip, oob_ip);
        let macs = concat_host_and_dpu_props!(value, host_admin_mac, oob_mac);

        let mut states = vec![value.state];

        let dpu_state = value
            .dpus
            .first()
            .map(|x| x.state.clone().unwrap_or_default())
            .unwrap_or_default();

        if states[0] != dpu_state {
            let dpu_states = value
                .dpus
                .iter()
                .enumerate()
                .map(|(i, x)| {
                    format!(
                        "DPU{}:{}",
                        i,
                        x.state.clone().unwrap_or("Unknown State".to_string())
                    )
                })
                .collect::<Vec<String>>();

            states.extend(dpu_states);
        }

        let state = states
            .iter()
            .map(|x| {
                x.split_once(' ')
                    .map(|(x, y)| format!("{x}\n{y}"))
                    .unwrap_or(x.clone())
            })
            .collect::<Vec<String>>()
            .join("\n");

        let is_unhealthy = !value.health.alerts.is_empty()
            | value.dpus.iter().any(|x| !x.health.alerts.is_empty());

        let mut row_data = vec![
            String::from(if is_unhealthy { "U" } else { "H" }),
            value.hostname.unwrap_or(UNKNOWN.to_owned()),
            machine_ids,
            state,
        ];

        if src.options.has_maintenance {
            row_data.extend_from_slice(&[format!(
                "{}\n{}",
                value.maintenance_reference.unwrap_or_default(),
                value.maintenance_start_time.unwrap_or_default()
            )]);
        }

        if src.options.show_ips {
            row_data.extend_from_slice(&[bmc_ip, bmc_mac, ips, macs]);
        }

        if src.options.more_details {
            row_data.extend_from_slice(&[
                value.host_gpu_count.to_string(),
                value.host_ib_ifs_count.to_string(),
                value.host_memory.unwrap_or(UNKNOWN.to_owned()),
            ]);
        }

        if src.options.show_quarantine_reason {
            row_data.extend_from_slice(&[value
                .quarantine_state
                .and_then(|s| s.reason)
                .unwrap_or_default()]);
        }

        Row::new(row_data.into_iter().map(|x| Cell::new(&x)).collect())
    }
}

fn convert_managed_hosts_to_nice_output(
    managed_hosts: Vec<utils::ManagedHostOutput>,
    options: ManagedHostOutputOptions,
) -> Box<Table> {
    let managed_hosts_wrapper = managed_hosts
        .into_iter()
        .map(|x| ManagedHostOutputWrapper {
            options,
            managed_host_output: x,
        })
        .collect::<Vec<ManagedHostOutputWrapper>>();

    let mut table = Table::new();

    let mut headers = vec!["", "Hostname", "Machine IDs (H/D)", "State"];
    // if any machines in the list are in maintenance mode we add the columns
    if options.has_maintenance {
        headers.extend_from_slice(&["Maintenance reference/since"]);
    }

    if options.show_ips {
        headers.extend_from_slice(&[
            "BMC IP(H/D)",
            "BMC MAC(H/D)",
            "ADMIN/OOB IP",
            "ADMIN/OOB MAC",
        ])
    }

    if options.more_details {
        headers.extend_from_slice(&["GPU #", "IB IFs #", "Host Memory"]);
    }

    if options.show_quarantine_reason {
        headers.extend_from_slice(&["Quarantine reason"]);
    }

    // TODO additional discovery work needed for remaining information
    table.set_titles(Row::new(
        headers.into_iter().map(Cell::new).collect::<Vec<Cell>>(),
    ));

    for managed_host in managed_hosts_wrapper {
        table.add_row(managed_host.into());
    }

    table.into()
}

async fn show_managed_hosts(
    managed_host_data: utils::ManagedHostMetadata,
    output: &mut dyn std::io::Write,
    output_format: OutputFormat,
    output_options: ManagedHostOutputOptions,
) -> CarbideCliResult<()> {
    let managed_hosts = utils::get_managed_host_output(managed_host_data);
    match output_format {
        OutputFormat::Json => {
            if output_options.single_host_detail_view {
                // Print a single object, not an array
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        managed_hosts.first().ok_or(CarbideCliError::Empty)?
                    )?
                )
            } else {
                println!("{}", serde_json::to_string_pretty(&managed_hosts)?)
            }
        }
        OutputFormat::Yaml => {
            // Print a single object, not an array
            if output_options.single_host_detail_view {
                println!(
                    "{}",
                    serde_yaml::to_string(managed_hosts.first().ok_or(CarbideCliError::Empty)?)?
                )
            } else {
                println!("{}", serde_yaml::to_string(&managed_hosts)?)
            }
        }
        OutputFormat::Csv => {
            let result = convert_managed_hosts_to_nice_output(managed_hosts, output_options);

            if let Err(error) = result.to_csv(output) {
                warn!("Error writing csv data: {}", error);
            }
        }
        _ => {
            if output_options.single_host_detail_view {
                show_managed_host_details_view(
                    managed_hosts
                        .into_iter()
                        .next()
                        .ok_or(CarbideCliError::Empty)?,
                )?;
            } else {
                let result = convert_managed_hosts_to_nice_output(managed_hosts, output_options);
                if let Err(error) = result.print(output) {
                    warn!("Error writing table data: {}", error);
                }
            }
        }
    }
    Ok(())
}

fn show_managed_host_details_view(m: utils::ManagedHostOutput) -> CarbideCliResult<()> {
    let width = 24;
    let mut lines = String::new();

    writeln!(
        &mut lines,
        "Hostname    : {}",
        m.hostname.clone().unwrap_or(UNKNOWN.to_string())
    )?;

    writeln!(&mut lines, "State       : {}", m.state)?;
    writeln!(&mut lines, "    Time in State : {}", m.time_in_state)?;
    writeln!(
        &mut lines,
        "    State SLA     : {}",
        m.state_sla_duration.unwrap_or_default()
    )?;
    writeln!(
        &mut lines,
        "    In State > SLA: {}",
        m.time_in_state_above_sla
    )?;
    if !m.state_reason.is_empty() {
        writeln!(&mut lines, "    Reason        : {}", m.state_reason)?;
    }

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
        ("  Last reboot completed", m.host_last_reboot_time),
        (
            "  Last reboot requested",
            m.host_last_reboot_requested_time_and_mode,
        ),
        ("  Serial Number", m.host_serial_number.clone()),
        ("  BIOS Version", m.host_bios_version.clone()),
        ("  GPU Count", Some(m.host_gpu_count.to_string())),
        (
            "  IB Interface Count",
            Some(m.host_ib_ifs_count.to_string()),
        ),
        ("  Memory", m.host_memory.clone()),
        ("  Admin IP", m.host_admin_ip.clone()),
        ("  Admin MAC", m.host_admin_mac.clone()),
        (
            "  Quarantined",
            Some(
                m.quarantine_state
                    .map(|q| format!("yes (reason: {})", q.reason.as_deref().unwrap_or("<none>")))
                    .unwrap_or("no".to_string()),
            ),
        ),
    ];
    if m.failure_details.is_some() {
        data.push(("  Failure Details", m.failure_details))
    }

    let mut health_details = vec![
        ("  Health", Some("".to_string())),
        (
            "    Probe Alerts",
            Some(
                m.health
                    .alerts
                    .iter()
                    .map(|alert| {
                        if let Some(target) = &alert.target {
                            format!("{} [Target: {}]: {}", alert.id, target, alert.message)
                        } else {
                            format!("{}: {}", alert.id, alert.message)
                        }
                    })
                    .collect::<Vec<String>>()
                    .join(","),
            ),
        ),
        ("    Overrides", Some(m.health_overrides.clone().join(","))),
    ];
    data.append(&mut health_details);

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

    for (i, dpu) in m.dpus.iter().enumerate() {
        writeln!(
            &mut lines,
            "\nDPU{}:\n----------------------------------------",
            i
        )?;
        let data = vec![
            ("  ID", dpu.machine_id.clone()),
            ("  State", dpu.state.clone()),
            ("  Primary", Some(dpu.is_primary.to_string())),
            ("  Failure details", dpu.failure_details.clone()),
            ("  Last reboot", dpu.last_reboot_time.clone()),
            (
                "  Last reboot requested",
                dpu.last_reboot_requested_time_and_mode.clone(),
            ),
            ("  Last seen", dpu.last_observation_time.clone()),
            ("  Serial Number", dpu.serial_number.clone()),
            ("  BIOS Version", dpu.bios_version.clone()),
            ("  Admin IP", dpu.oob_ip.clone()),
            ("  Admin MAC", dpu.oob_mac.clone()),
            ("  BMC", Some("".to_string())),
            ("    Version", dpu.bmc_version.clone()),
            ("    Firmware Version", dpu.bmc_firmware_version.clone()),
            ("    IP", dpu.bmc_ip.clone()),
            ("    MAC", dpu.bmc_mac.clone()),
            ("  Health", Some("".to_string())),
            (
                "    Probe Alerts",
                Some(
                    dpu.health
                        .alerts
                        .iter()
                        .map(|alert| {
                            if let Some(target) = &alert.target {
                                format!("{} [Target: {}]: {}", alert.id, target, alert.message)
                            } else {
                                format!("{}: {}", alert.id, alert.message)
                            }
                        })
                        .collect::<Vec<String>>()
                        .join(","),
                ),
            ),
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
    }

    println!("{}", lines);

    Ok(())
}

pub async fn handle_show(
    output: &mut dyn std::io::Write,
    args: ShowManagedHost,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
) -> CarbideCliResult<()> {
    let site_explorer_managed_hosts = api_client.get_all_explored_managed_hosts(page_size).await?;

    // TODO(chet): Remove this ~March 2024.
    // Use tracing::warn for this so its both a little more
    // noticeable, and a little more annoying/naggy. If people
    // complain, it means its working.
    if args.all && args.machine.is_empty() {
        warn!("redundant `--all` with basic `show` is deprecated. just do `mh show`")
    }

    let show_all_machines = args.all || args.machine.is_empty();

    let machines: Vec<Machine> = if show_all_machines {
        // Get all machines: DPUs will arrive as part of this request
        api_client
            .get_all_machines(
                rpc::forge::MachineSearchConfig {
                    include_dpus: true,
                    only_maintenance: args.fix,
                    only_quarantine: args.quarantine,
                    ..Default::default()
                },
                page_size,
            )
            .await?
            .machines
    } else {
        // Get a single managed host: We need to find associated DPU IDs along with the machine ID,
        // so make a few RPC fetches to get everything in the managed host.
        // Start by getting the requested machine
        let requested_machine = api_client.get_machine(args.machine).await?;

        if !requested_machine.associated_dpu_machine_ids.is_empty() {
            // If requested machine is a host, get the DPUs too.
            let dpu_machines = api_client
                .get_machines_by_ids(&requested_machine.associated_dpu_machine_ids)
                .await?
                .machines;
            [&[requested_machine], dpu_machines.as_slice()].concat()
        } else if let Some(ref host_id) = requested_machine.associated_host_machine_id {
            // the requested machine is a DPU, get the host machine...
            if let Some(host_machine) = api_client
                .get_machines_by_ids(&[host_id.clone()])
                .await?
                .machines
                .into_iter()
                .next()
            {
                // ... plus get all the other attached DPUs of that host machine.
                let dpu_machines = api_client
                    .get_machines_by_ids(host_machine.associated_dpu_machine_ids.as_slice())
                    .await?
                    .machines;

                [&[host_machine], dpu_machines.as_slice()].concat()
            } else {
                vec![requested_machine]
            }
        } else {
            // Host has no associated DPUs nor associated host, it must not be completely set up.
            vec![requested_machine]
        }
    };

    // Find connected devices for all machines
    let dpu_machine_ids = machines
        .iter()
        .filter_map(|m| m.id.clone())
        .collect::<Vec<MachineId>>();

    let connected_devices = api_client
        .0
        .find_connected_devices_by_dpu_machine_ids(dpu_machine_ids)
        .await?
        .connected_devices;

    let network_device_ids: HashSet<String> = connected_devices
        .iter()
        .filter_map(|d| d.network_device_id.clone())
        .collect();

    let network_devices = api_client
        .0
        .find_network_devices_by_device_ids(
            network_device_ids
                .iter()
                .map(|id| id.to_owned())
                .collect::<Vec<_>>(),
        )
        .await?
        .network_devices;

    let output_options = ManagedHostOutputOptions {
        show_ips: args.ips,
        more_details: args.more,
        has_maintenance: args.fix,
        show_quarantine_reason: args.quarantine,
        single_host_detail_view: !show_all_machines,
    };

    show_managed_hosts(
        utils::ManagedHostMetadata {
            machines,
            site_explorer_managed_hosts,
            connected_devices,
            network_devices,
            exploration_reports: vec![], //Todo - add exploration reports
        },
        output,
        output_format,
        output_options,
    )
    .await
}
