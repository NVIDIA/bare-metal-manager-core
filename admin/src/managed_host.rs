use std::collections::BTreeMap;
use std::convert::From;
use std::fmt::Write;
use std::time::SystemTime;

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
use ::rpc::forge::{MachineId, MachineInterface, MachineType};
use ::rpc::machine_discovery::MemoryDevice;
use ::rpc::Machine;
use ::rpc::Timestamp;
use chrono::{DateTime, Utc};
use prettytable::{Cell, Row, Table};
use serde::Serialize;
use tracing::warn;

use super::{rpc, CarbideCliResult};
use crate::cfg::carbide_options::{OutputFormat, ShowManagedHost};
use crate::Config;

const UNKNOWN: &str = "Unknown";

macro_rules! get_dmi_data_from_machine {
    ($m:ident, $d:ident) => {
        $m.discovery_info
            .as_ref()
            .and_then(|di| di.dmi_data.as_ref())
            .and_then(|dd| {
                if dd.$d.trim().is_empty() {
                    None
                } else {
                    Some(dd.$d.clone())
                }
            })
    };
}

macro_rules! get_bmc_info_from_machine {
    ($m:ident, $d:ident) => {
        $m.bmc_info
            .as_ref()
            .and_then(|bi| bi.$d.as_ref())
            .and_then(|value| {
                if value.trim().is_empty() {
                    None
                } else {
                    Some(value.clone())
                }
            })
    };
}

fn get_memory_details(memory_devices: &Vec<MemoryDevice>) -> Option<String> {
    let mut breakdown = BTreeMap::default();
    let mut total_size = 0;
    for md in memory_devices {
        let size =
            byte_unit::Byte::from_unit(md.size_mb.unwrap_or(0) as f64, byte_unit::ByteUnit::MiB)
                .unwrap_or(byte_unit::Byte::default());
        total_size += size.get_bytes();
        *breakdown.entry(size).or_insert(0u32) += 1;
    }

    let total_size = byte_unit::Byte::from(total_size);

    if memory_devices.len() == 1 {
        Some(total_size.get_appropriate_unit(true).to_string())
    } else if total_size.get_bytes() > 0 {
        let mut breakdown_str = String::default();
        for (ind, s) in breakdown.iter().enumerate() {
            if ind != 0 {
                breakdown_str.push_str(", ");
            }
            breakdown_str.push_str(format!("{}x{}", s.0.get_appropriate_unit(true), s.1).as_ref());
        }
        Some(format!(
            "{} ({})",
            total_size.get_appropriate_unit(true),
            breakdown_str
        ))
    } else {
        None
    }
}

#[derive(Default, Serialize, PartialEq)]
struct ManagedHostOutput {
    hostname: Option<String>,
    machine_id: Option<String>,
    state: String,
    host_serial_number: Option<String>,
    host_bios_version: Option<String>,
    host_bmc_ip: Option<String>,
    host_bmc_mac: Option<String>,
    host_bmc_version: Option<String>,
    host_bmc_firmware_version: Option<String>,
    host_admin_ip: Option<String>,
    host_admin_mac: Option<String>,
    host_gpu_count: usize,
    host_memory: Option<String>,
    maintenance_reference: Option<String>,
    maintenance_start_time: Option<String>,
    host_last_reboot_time: Option<String>,
    is_network_healthy: bool,
    network_err_message: Option<String>,

    dpu_machine_id: Option<String>,
    dpu_serial_number: Option<String>,
    dpu_bios_version: Option<String>,
    dpu_bmc_ip: Option<String>,
    dpu_bmc_mac: Option<String>,
    dpu_bmc_version: Option<String>,
    dpu_bmc_firmware_version: Option<String>,
    dpu_oob_ip: Option<String>,
    dpu_oob_mac: Option<String>,
    dpu_last_reboot_time: Option<String>,
    dpu_last_observation_time: Option<String>,
}

#[derive(Default, Serialize)]
struct ManagedHostOutputWrapper {
    show_ips: bool,
    more_details: bool,
    has_maintenance: bool,
    managed_host_output: ManagedHostOutput,
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

fn get_managed_host_output(machines: Vec<Machine>) -> Vec<ManagedHostOutput> {
    let mut result = Vec::default();

    for machine in machines.iter() {
        let mut managed_host_output = ManagedHostOutput::default();
        if machine.machine_type != MachineType::Host as i32 {
            continue;
        }

        let machine_id = match &machine.id {
            Some(id) => id,
            None => {
                warn!("Machine with no id found.  skipping {:?}", machine);
                continue;
            }
        };

        let machine_interfaces = machine
            .interfaces
            .iter()
            .filter(|x| x.primary_interface)
            .cloned()
            .collect::<Vec<MachineInterface>>();

        if machine_interfaces.is_empty() {
            warn!("No interfaces for machine id {}.  Skipped", machine_id);
            continue;
        }

        if machine_interfaces.len() > 1 {
            warn!(
                "Multiple primary interfaces for machine id {}.  Will only use first",
                machine_id
            );
        }

        let primary_interface = &machine_interfaces[0];

        managed_host_output.hostname = if primary_interface.hostname.trim().is_empty() {
            None
        } else {
            Some(primary_interface.hostname.clone())
        };
        managed_host_output.machine_id = Some(machine_id.to_string());
        managed_host_output.state = machine.state.clone();
        managed_host_output.host_serial_number =
            get_dmi_data_from_machine!(machine, chassis_serial);
        managed_host_output.host_bios_version = get_dmi_data_from_machine!(machine, bios_version);
        managed_host_output.host_bmc_ip = get_bmc_info_from_machine!(machine, ip);
        managed_host_output.host_bmc_mac = get_bmc_info_from_machine!(machine, mac);
        managed_host_output.host_bmc_version = get_bmc_info_from_machine!(machine, version);
        managed_host_output.host_bmc_firmware_version =
            get_bmc_info_from_machine!(machine, firmware_version);
        managed_host_output.host_admin_ip = Some(primary_interface.address.join(","));
        managed_host_output.host_admin_mac = Some(primary_interface.mac_address.to_string());
        managed_host_output.host_gpu_count = machine
            .discovery_info
            .as_ref()
            .map_or(0, |di| di.gpus.len());
        managed_host_output.host_memory = machine
            .discovery_info
            .as_ref()
            .and_then(|di| get_memory_details(&di.memory_devices));
        managed_host_output.maintenance_reference = machine.maintenance_reference.clone();
        managed_host_output.maintenance_start_time =
            to_time(machine.maintenance_start_time.clone(), machine_id);
        managed_host_output.host_last_reboot_time =
            to_time(machine.last_reboot_time.clone(), machine_id);

        if let Some(dpu_machine_id) = primary_interface.attached_dpu_machine_id.as_ref() {
            if dpu_machine_id != machine_id {
                let dpu_machine = machines
                    .iter()
                    .find(|m| m.id.as_ref().map_or(false, |id| id == dpu_machine_id));

                if let Some(dpu_machine) = dpu_machine {
                    // Network health is in observation, on DPU, but it relates to
                    // the managed host as a whole.
                    managed_host_output.is_network_healthy = match &dpu_machine.health {
                        Some(h) => h.is_healthy,
                        None => false,
                    };
                    managed_host_output.network_err_message = match &dpu_machine.health {
                        Some(h) => h.message.clone(),
                        None => None,
                    };

                    managed_host_output.dpu_machine_id = Some(dpu_machine_id.to_string());
                    managed_host_output.dpu_serial_number =
                        get_dmi_data_from_machine!(dpu_machine, chassis_serial);
                    managed_host_output.dpu_bios_version =
                        get_dmi_data_from_machine!(dpu_machine, bios_version);
                    managed_host_output.dpu_bmc_ip = get_bmc_info_from_machine!(dpu_machine, ip);
                    managed_host_output.dpu_bmc_mac = get_bmc_info_from_machine!(dpu_machine, mac);
                    managed_host_output.dpu_bmc_version =
                        get_bmc_info_from_machine!(dpu_machine, version);
                    managed_host_output.dpu_bmc_firmware_version =
                        get_bmc_info_from_machine!(dpu_machine, firmware_version);
                    managed_host_output.dpu_last_reboot_time =
                        to_time(dpu_machine.last_reboot_time.clone(), dpu_machine_id);
                    managed_host_output.dpu_last_observation_time =
                        to_time(dpu_machine.last_observation_time.clone(), dpu_machine_id);

                    if let Some(primary_interface) =
                        dpu_machine.interfaces.iter().find(|x| x.primary_interface)
                    {
                        managed_host_output.dpu_oob_ip = Some(primary_interface.address.join(","));
                        managed_host_output.dpu_oob_mac =
                            Some(primary_interface.mac_address.to_owned());
                    }
                };
            }
        };

        result.push(managed_host_output);
    }

    result
}

fn convert_managed_hosts_to_nice_output(
    managed_hosts: Vec<ManagedHostOutput>,
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
) -> CarbideCliResult<()> {
    let managed_hosts = get_managed_host_output(machines);

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

fn show_managed_host_details_view(m: ManagedHostOutput) -> CarbideCliResult<()> {
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
    if args.all {
        let machines = rpc::get_all_machines(api_config, args.fix).await?.machines;
        show_managed_hosts(output, output_format, machines, args.ips, args.more).await?;
    } else if let Some(requested_host_machine_id) = args.host {
        let mut machines = Vec::default();
        let requested_machine =
            rpc::get_host_machine(requested_host_machine_id, api_config.clone()).await?;

        for interface in requested_machine.interfaces.iter() {
            if interface.primary_interface {
                if let Some(attached_machine_id) = interface.attached_dpu_machine_id.as_ref() {
                    let attached_machine =
                        rpc::get_dpu_machine(attached_machine_id.to_string(), api_config.clone())
                            .await?;
                    machines.push(attached_machine);
                }
                break;
            }
        }
        machines.push(requested_machine);
        if args.fix {
            machines.retain(|m| m.maintenance_reference.is_some());
        }
        for m in get_managed_host_output(machines).into_iter() {
            show_managed_host_details_view(m)?;
        }
    }

    Ok(())
}

// Prepare an Option<rpc::Timestamp> for display:
// - Parse the timestamp into a chrono::Time and format as string.
// - Or return empty string
// machine_id is only for logging a more useful error.
fn to_time(t: Option<Timestamp>, machine_id: &MachineId) -> Option<String> {
    match t {
        None => None,
        Some(tt) => match SystemTime::try_from(tt) {
            Ok(system_time) => {
                let dt: DateTime<Utc> = DateTime::from(system_time);
                Some(dt.to_string())
            }
            Err(err) => {
                warn!("get_managed_host_output {machine_id}, invalid timestamp: {err}");
                None
            }
        },
    }
}
