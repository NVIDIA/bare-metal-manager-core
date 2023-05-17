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

use ::rpc::forge::{MachineInterface, MachineType};
use ::rpc::Machine;
use prettytable::{row, Row, Table};
use serde::Serialize;
use tracing::warn;

use crate::cfg::carbide_options::{OutputFormat, ShowManagedHost};
use crate::Config;

use super::{rpc, CarbideCliResult};

use std::convert::From;

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

#[derive(Default, Serialize)]
struct ManagedHostOutput {
    hostname: Option<String>,
    machine_id: Option<String>,
    host_serial_number: Option<String>,
    host_bios_version: Option<String>,
    host_bmc_ip: Option<String>,
    host_bmc_mac: Option<String>,
    host_bmc_version: Option<String>,
    host_bmc_firmware_version: Option<String>,
    host_gpu_count: usize,
    dpu_machine_id: Option<String>,
    dpu_serial_number: Option<String>,
    dpu_bios_version: Option<String>,
    dpu_bmc_ip: Option<String>,
    dpu_bmc_mac: Option<String>,
    dpu_bmc_version: Option<String>,
    dpu_bmc_firmware_version: Option<String>,
    dpu_oob_ip: Option<String>,
    dpu_oob_mac: Option<String>,
}

impl From<ManagedHostOutput> for Row {
    fn from(value: ManagedHostOutput) -> Self {
        row![
            value.hostname.unwrap_or(UNKNOWN.to_owned()),
            value.machine_id.unwrap_or(UNKNOWN.to_owned()),
            value.host_serial_number.unwrap_or(UNKNOWN.to_owned()),
            value.host_bios_version.unwrap_or(UNKNOWN.to_owned()),
            value.host_bmc_ip.unwrap_or(UNKNOWN.to_owned()),
            value.host_bmc_mac.unwrap_or(UNKNOWN.to_owned()),
            value.host_bmc_version.unwrap_or(UNKNOWN.to_owned()),
            value
                .host_bmc_firmware_version
                .unwrap_or(UNKNOWN.to_owned()),
            value.host_gpu_count,
            value.dpu_machine_id.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_serial_number.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_bios_version.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_bmc_ip.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_bmc_mac.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_bmc_version.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_bmc_firmware_version.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_oob_ip.unwrap_or(UNKNOWN.to_owned()),
            value.dpu_oob_mac.unwrap_or(UNKNOWN.to_owned()),
        ]
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
        managed_host_output.host_serial_number =
            get_dmi_data_from_machine!(machine, chassis_serial);
        managed_host_output.host_bios_version = get_dmi_data_from_machine!(machine, bios_version);
        managed_host_output.host_bmc_ip = get_bmc_info_from_machine!(machine, ip);
        managed_host_output.host_bmc_mac = get_bmc_info_from_machine!(machine, mac);
        managed_host_output.host_bmc_version = get_bmc_info_from_machine!(machine, version);
        managed_host_output.host_bmc_firmware_version =
            get_bmc_info_from_machine!(machine, firmware_version);
        managed_host_output.host_gpu_count = machine
            .discovery_info
            .as_ref()
            .map_or(0, |di| di.gpus.len());

        if let Some(dpu_machine_id) = primary_interface.attached_dpu_machine_id.as_ref() {
            if dpu_machine_id != machine_id {
                let dpu_machine = machines
                    .iter()
                    .find(|m| m.id.as_ref().map_or(false, |id| id == dpu_machine_id));

                if let Some(dpu_machine) = dpu_machine {
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

fn convert_managed_hosts_to_nice_output(managed_hosts: Vec<ManagedHostOutput>) -> Box<Table> {
    let mut table = Table::new();

    // TODO additional discovery work needed for remaining information
    table.add_row(row![
        "Hostname",
        "Machine ID",
        "Host Serial Number",
        "Host BIOS Version",
        "Host BMC IP",
        "Host BMC MAC",
        "Host BMC Version",
        "Host BMC Firmware Version",
        "Host GPU Count",
        "DPU Machine ID",
        "DPU Serial Number",
        "DPU Bios Version",
        "DPU BMC IP",
        "DPU BMC MAC",
        "DPU BMC Version",
        "DPU Firmware Version",
        "DPU OOB IP",
        "DPU OOB MAC",
    ]);

    for managed_host in managed_hosts {
        table.add_row(managed_host.into());
    }

    table.into()
}

async fn show_managed_hosts(
    output: &mut dyn std::io::Write,
    output_format: OutputFormat,
    machines: Vec<Machine>,
) -> CarbideCliResult<()> {
    let managed_hosts = get_managed_host_output(machines);

    match output_format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&managed_hosts).unwrap()),
        OutputFormat::Csv => {
            let result = convert_managed_hosts_to_nice_output(managed_hosts);

            if let Err(error) = result.to_csv(output) {
                warn!("Error writing csv data: {}", error);
            }
        }
        _ => {
            let result = convert_managed_hosts_to_nice_output(managed_hosts);

            if let Err(error) = result.print(output) {
                warn!("Error writing table data: {}", error);
            }
        }
    }
    Ok(())
}

pub async fn handle_show(
    output: &mut dyn std::io::Write,
    args: ShowManagedHost,
    output_format: OutputFormat,
    api_config: Config,
) -> CarbideCliResult<()> {
    let machines = if args.all {
        rpc::get_all_machines(api_config).await?.machines
    } else if let Some(requested_machine_id) = args.machine {
        let mut machines = Vec::default();

        let requested_machine =
            rpc::get_host_machine(requested_machine_id, api_config.clone()).await?;

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
        machines
    } else {
        Vec::default()
    };

    show_managed_hosts(output, output_format, machines).await
}
