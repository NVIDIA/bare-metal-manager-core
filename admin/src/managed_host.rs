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
use tracing::warn;

use super::{rpc, CarbideCliResult};
use crate::cfg::carbide_options::{OutputFormat, ShowManagedHost};
use crate::Config;

const UNKNOWN: &str = "Unknown";

macro_rules! get_dmi_data_from_machine {
    ($m:ident, $d:ident) => {
        match $m.discovery_info.as_ref() {
            Some(di) => di
                .dmi_data
                .as_ref()
                .map_or(UNKNOWN.to_owned(), |dmi| dmi.$d.clone()),
            None => UNKNOWN.to_owned(),
        }
    };
}

macro_rules! get_bmc_info_from_machine {
    ($m:ident, $d:ident) => {
        match $m.discovery_info.as_ref() {
            Some(di) => match di.bmc_info.as_ref() {
                Some(bmc_info) => bmc_info
                    .$d
                    .as_ref()
                    .map_or(UNKNOWN.to_owned(), |t| t.clone()),
                None => UNKNOWN.to_owned(),
            },
            None => UNKNOWN.to_owned(),
        }
    };
}

struct ManagedHostOutput {
    hostname: String,
    machine_id: String,
    host_serial_number: String,
    host_bios_version: String,
    host_bmc_ip: String,
    host_bmc_mac: String,
    host_bmc_version: String,
    host_bmc_firmware_version: String,
    //host bmc serial number,
    dpu_machine_id: String,
    dpu_serial_number: String,
    dpu_bios_version: String,
    dpu_bmc_ip: String,
    dpu_bmc_mac: String,
    dpu_bmc_version: String,
    dpu_bmc_firmware_version: String,
    dpu_oob_ip: String,
    dpu_oob_mac: String,
}

impl Default for ManagedHostOutput {
    fn default() -> Self {
        Self {
            hostname: UNKNOWN.to_owned(),
            machine_id: UNKNOWN.to_owned(),
            host_serial_number: UNKNOWN.to_owned(),
            host_bios_version: UNKNOWN.to_owned(),
            host_bmc_ip: UNKNOWN.to_owned(),
            host_bmc_mac: UNKNOWN.to_owned(),
            host_bmc_version: UNKNOWN.to_owned(),
            host_bmc_firmware_version: UNKNOWN.to_owned(),
            dpu_machine_id: UNKNOWN.to_owned(),
            dpu_serial_number: UNKNOWN.to_owned(),
            dpu_bios_version: UNKNOWN.to_owned(),
            dpu_bmc_ip: UNKNOWN.to_owned(),
            dpu_bmc_mac: UNKNOWN.to_owned(),
            dpu_bmc_version: UNKNOWN.to_owned(),
            dpu_bmc_firmware_version: UNKNOWN.to_owned(),
            dpu_oob_ip: UNKNOWN.to_owned(),
            dpu_oob_mac: UNKNOWN.to_owned(),
        }
    }
}

impl From<ManagedHostOutput> for Row {
    fn from(value: ManagedHostOutput) -> Self {
        row![
            value.hostname,
            value.machine_id,
            value.host_serial_number,
            value.host_bios_version,
            value.host_bmc_ip,
            value.host_bmc_mac,
            value.host_bmc_version,
            value.host_bmc_firmware_version,
            value.dpu_machine_id,
            value.dpu_serial_number,
            value.dpu_bios_version,
            value.dpu_bmc_ip,
            value.dpu_bmc_mac,
            value.dpu_bmc_version,
            value.dpu_bmc_firmware_version,
            value.dpu_oob_ip,
            value.dpu_oob_mac,
        ]
    }
}

fn convert_managed_hosts_to_nice_output(machines: Vec<Machine>) -> Box<Table> {
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

        managed_host_output.machine_id = machine_id.to_string();
        managed_host_output.host_serial_number =
            get_dmi_data_from_machine!(machine, chassis_serial);
        managed_host_output.host_bios_version = get_dmi_data_from_machine!(machine, bios_version);
        managed_host_output.host_bmc_ip = machine
            .bmc_ip
            .as_ref()
            .map_or(UNKNOWN.to_owned(), |t| t.clone());
        managed_host_output.host_bmc_mac = get_bmc_info_from_machine!(machine, mac);
        managed_host_output.host_bmc_version = get_bmc_info_from_machine!(machine, version);
        managed_host_output.host_bmc_firmware_version =
            get_bmc_info_from_machine!(machine, firmware_version);

        if let Some(dpu_machine_id) = primary_interface.attached_dpu_machine_id.as_ref() {
            if dpu_machine_id != machine_id {
                managed_host_output.dpu_machine_id = dpu_machine_id.to_string();
                let dpu_machine = machines
                    .iter()
                    .find(|m| m.id.as_ref().map_or(false, |id| id == dpu_machine_id));

                if let Some(dpu_machine) = dpu_machine {
                    managed_host_output.dpu_serial_number =
                        get_dmi_data_from_machine!(dpu_machine, chassis_serial);
                    managed_host_output.dpu_bios_version =
                        get_dmi_data_from_machine!(dpu_machine, bios_version);
                    managed_host_output.dpu_bmc_ip = dpu_machine
                        .bmc_ip
                        .as_ref()
                        .map_or(UNKNOWN.to_owned(), |t| t.clone());
                    managed_host_output.dpu_bmc_mac = get_bmc_info_from_machine!(dpu_machine, mac);
                    managed_host_output.dpu_bmc_version =
                        get_bmc_info_from_machine!(dpu_machine, version);
                    managed_host_output.dpu_bmc_firmware_version =
                        get_bmc_info_from_machine!(dpu_machine, firmware_version);

                    if let Some(primary_interface) =
                        dpu_machine.interfaces.iter().find(|x| x.primary_interface)
                    {
                        managed_host_output.dpu_oob_ip = primary_interface.address.join(",");
                        managed_host_output.dpu_oob_mac = primary_interface.mac_address.to_owned();
                    }
                };
            }
        };

        table.add_row(managed_host_output.into());
    }

    table.into()
}

async fn show_managed_hosts(
    output: &mut dyn std::io::Write,
    output_format: OutputFormat,
    machines: Vec<Machine>,
) -> CarbideCliResult<()> {
    match output_format {
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&machines).unwrap()),
        OutputFormat::Csv => {
            let result = convert_managed_hosts_to_nice_output(machines);

            if let Err(error) = result.to_csv(output) {
                warn!("Error writing csv data: {}", error);
            }
        }
        _ => {
            let result = convert_managed_hosts_to_nice_output(machines);

            if let Err(error) = result.print(output) {
                warn!("Error writing csv data: {}", error);
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
