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
use std::collections::{HashMap, HashSet};
use std::fmt::Write;
use std::pin::Pin;

use ::rpc::Machine;
use ::rpc::admin_cli::{CarbideCliError, CarbideCliResult, OutputFormat};
use carbide_uuid::machine::MachineId;
use health_report::HealthProbeAlert;
use prettytable::{Cell, Row, Table};
use serde::Serialize;
use tracing::warn;

use super::args::Args;
use crate::cfg::cli_options::SortField;
use crate::rpc::ApiClient;
use crate::{async_write, async_write_table_as_csv};

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
            vec![
                $host
                    .$host_prop
                    .as_ref()
                    .map(|s| s.as_str())
                    .unwrap_or(UNKNOWN),
            ],
            $host
                .dpus
                .iter()
                .map(|d| d.$dpu_prop.as_ref().map(|s| s.as_str()).unwrap_or(UNKNOWN))
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
            .map(|x| x.state.as_deref().unwrap_or_default())
            .unwrap_or_default();

        if states[0] != dpu_state {
            let dpu_states = value
                .dpus
                .iter()
                .enumerate()
                .map(|(i, x)| format!("DPU{}:{}", i, x.state.as_deref().unwrap_or("Unknown State")))
                .collect::<Vec<String>>();

            states.extend(dpu_states);
        }

        let state = states
            .iter()
            .map(|x| {
                x.split_once(' ')
                    .map(|(x, y)| Cow::Owned(format!("{x}\n{}", y.replace(", ", "\n"))))
                    .unwrap_or(Cow::Borrowed(x.as_str()))
            })
            .collect::<Vec<Cow<str>>>()
            .join("\n");

        let is_unhealthy = !value.health.alerts.is_empty()
            | value.dpus.iter().any(|x| !x.health.alerts.is_empty());

        let mut row_data = vec![
            String::from(if is_unhealthy { "U" } else { "H" }),
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
                value.instance_type_id.unwrap_or_default(),
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

    let mut headers = vec!["", "Machine IDs (H/D)", "State"];
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
        headers.extend_from_slice(&["GPU #", "IB IFs #", "Host Memory", "Instance Type"]);
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
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    output_format: OutputFormat,
    output_options: ManagedHostOutputOptions,
    sort_by: SortField,
) -> CarbideCliResult<()> {
    let mut managed_hosts = utils::get_managed_host_output(managed_host_data);
    match sort_by {
        SortField::PrimaryId => managed_hosts.sort_by(|m1, m2| m1.machine_id.cmp(&m2.machine_id)),
        SortField::State => managed_hosts.sort_by(|m1, m2| m1.state.cmp(&m2.state)),
    };
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
            async_write_table_as_csv!(output_file, result)?;
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
                async_write!(output_file, "{}", result)?;
            }
        }
    }
    Ok(())
}

fn show_managed_host_details_view(m: utils::ManagedHostOutput) -> CarbideCliResult<()> {
    let width = 27;
    let mut lines = String::new();

    writeln!(
        &mut lines,
        "Hostname    : {}",
        m.hostname.unwrap_or(UNKNOWN.to_string())
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
        ("  ID", m.machine_id),
        ("  Last reboot completed", m.host_last_reboot_time),
        (
            "  Last reboot requested",
            m.host_last_reboot_requested_time_and_mode,
        ),
        ("  Serial Number", m.host_serial_number),
        ("  BIOS Version", m.host_bios_version),
        ("  GPU Count", Some(m.host_gpu_count.to_string())),
        (
            "  IB Interface Count",
            Some(m.host_ib_ifs_count.to_string()),
        ),
        ("  Memory", m.host_memory),
        ("  Admin IP", m.host_admin_ip),
        ("  Admin MAC", m.host_admin_mac),
        (
            "  Associated Instance Type",
            Some(m.instance_type_id.unwrap_or("Unassociated".to_string())),
        ),
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
            Some(format_health_alerts(&m.health.alerts, width)),
        ),
        ("    Overrides", Some(m.health_overrides.join(","))),
    ];
    data.append(&mut health_details);

    let mut bmc_details = vec![
        ("  BMC", Some("".to_string())),
        ("    Version", m.host_bmc_version),
        ("    Firmware Version", m.host_bmc_firmware_version),
        ("    IP", m.host_bmc_ip),
        ("    MAC", m.host_bmc_mac),
    ];
    data.append(&mut bmc_details);

    for (key, value) in data {
        if matches!(&value, Some(x) if x.is_empty()) {
            writeln!(&mut lines, "{key:<width$}")?;
        } else {
            writeln!(
                &mut lines,
                "{:<width$}: {}",
                key,
                value.unwrap_or(UNKNOWN.to_string())
            )?;
        }
    }

    for (i, dpu) in m.dpus.into_iter().enumerate() {
        writeln!(
            &mut lines,
            "\nDPU{i}:\n----------------------------------------"
        )?;
        let data = vec![
            ("  ID", dpu.machine_id),
            ("  State", dpu.state),
            ("  Primary", Some(dpu.is_primary.to_string())),
            ("  Failure details", dpu.failure_details),
            ("  Last reboot", dpu.last_reboot_time),
            (
                "  Last reboot requested",
                dpu.last_reboot_requested_time_and_mode,
            ),
            ("  Last seen", dpu.last_observation_time),
            ("  Serial Number", dpu.serial_number),
            ("  BIOS Version", dpu.bios_version),
            ("  Admin IP", dpu.oob_ip),
            ("  Admin MAC", dpu.oob_mac),
            ("  BMC", Some("".to_string())),
            ("    Version", dpu.bmc_version),
            ("    Firmware Version", dpu.bmc_firmware_version),
            ("    IP", dpu.bmc_ip),
            ("    MAC", dpu.bmc_mac),
            ("  Health", Some("".to_string())),
            (
                "    Probe Alerts",
                Some(format_health_alerts(&dpu.health.alerts, width)),
            ),
        ];

        for (key, value) in data {
            if matches!(&value, Some(x) if x.is_empty()) {
                writeln!(&mut lines, "{key:<width$}")?;
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

    println!("{lines}");

    Ok(())
}

fn format_health_alerts(alerts: &[HealthProbeAlert], width: usize) -> String {
    alerts
        .iter()
        .flat_map(|alert| {
            let mut dup_map: HashMap<&str, i32> = HashMap::default();
            let alert_messages = alert.message.split('\n');
            for a in alert_messages {
                dup_map
                    .entry(a)
                    .and_modify(|count| *count += 1)
                    .or_insert(1);
            }
            let mut out_vec = Vec::default();
            for (msg, count) in dup_map {
                let alert_message = if count > 1 {
                    format!("{msg} (x{count})")
                } else {
                    msg.to_string()
                };
                out_vec.push(if let Some(target) = &alert.target {
                    format!("{} [Target: {}]: {}", alert.id, target, alert_message)
                } else {
                    format!("{}: {}", alert.id, alert_message)
                });
            }
            out_vec
        })
        .collect::<Vec<String>>()
        .join(&format!("\n{:<width$}: ", " "))
}

pub async fn show(
    output_file: &mut Pin<Box<dyn tokio::io::AsyncWrite>>,
    args: Args,
    output_format: OutputFormat,
    api_client: &ApiClient,
    page_size: usize,
    sort_by: SortField,
) -> CarbideCliResult<()> {
    let site_explorer_managed_hosts = api_client.get_all_explored_managed_hosts(page_size).await?;

    // TODO(chet): Remove this ~March 2024.
    // Use tracing::warn for this so its both a little more
    // noticeable, and a little more annoying/naggy. If people
    // complain, it means its working.
    if args.all && args.machine.is_none() {
        warn!("redundant `--all` with basic `show` is deprecated. just do `mh show`")
    }

    let show_all_machines = args.all || args.machine.is_none();

    let machines: Vec<Machine> = if let Some(machine_id) = args.machine {
        // Get a single managed host: We need to find associated DPU IDs along with the machine ID,
        // so make a few RPC fetches to get everything in the managed host.
        // Start by getting the requested machine
        let requested_machine = api_client.get_machine(machine_id).await?;

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
                .get_machines_by_ids(&[*host_id])
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
    } else {
        // Get all machines: DPUs will arrive as part of this request
        api_client
            .get_all_machines(
                rpc::forge::MachineSearchConfig {
                    include_dpus: true,
                    only_maintenance: args.fix,
                    only_quarantine: args.quarantine,
                    include_predicted_host: true,
                    ..Default::default()
                },
                page_size,
            )
            .await?
            .machines
    };

    // Find connected devices for all machines
    let dpu_machine_ids = machines
        .iter()
        .filter_map(|m| m.id)
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
        .find_network_devices_by_device_ids(network_device_ids.into_iter().collect::<Vec<_>>())
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
        output_file,
        output_format,
        output_options,
        sort_by,
    )
    .await
}
