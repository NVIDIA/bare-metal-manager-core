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
use log::warn;
use prettytable::{row, Table};

use crate::cfg::carbide_options::{OutputFormat, ShowManagedHost};
use crate::Config;

use super::{rpc, CarbideCliResult};

const UNKNOWN: &str = "Unknown";

fn get_serial_and_version(machine: &Machine) -> (String, String) {
    machine
        .discovery_info
        .as_ref()
        .map_or((UNKNOWN.to_owned(), UNKNOWN.to_owned()), |di| {
            di.dmi_data
                .as_ref()
                .map_or((UNKNOWN.to_owned(), UNKNOWN.to_owned()), |dmi| {
                    let bios_version = if !dmi.bios_version.is_empty() {
                        dmi.bios_version.clone()
                    } else {
                        UNKNOWN.to_owned()
                    };
                    let chassis_serial = if !dmi.chassis_serial.is_empty() {
                        dmi.chassis_serial.clone()
                    } else {
                        UNKNOWN.to_owned()
                    };

                    (chassis_serial, bios_version)
                })
        })
}

fn get_bmc_info(machine: &Machine) -> (String, String) {
    match machine.bmc_info.as_ref() {
        Some(bmc_info) => (
            bmc_info
                .ip
                .as_ref()
                .map_or(UNKNOWN.to_owned(), |ip| ip.clone()),
            bmc_info
                .mac
                .as_ref()
                .map_or(UNKNOWN.to_owned(), |mac| mac.clone()),
        ),
        None => (UNKNOWN.to_owned(), UNKNOWN.to_owned()),
    }
}

fn convert_managed_hosts_to_nice_output(machines: Vec<Machine>) -> Box<Table> {
    let mut table = Table::new();

    // TODO additional discovery work needed for remaining information
    table.add_row(row![
        "Hostname",
        "Machine ID",
        "Host BMC IP",
        "Host BMC MAC",
        //        "Host BMC Firmware Version",
        //        "Host BMC Version",
        //        "Host BMC Serial Number",
        "Host Serial Number",
        "Host BIOS Version",
        // DPU IPMI data not shown because it is reliably available
        //        "DPU BMC IP",
        //        "DPU BMC MAC",
        "DPU OOB IP",
        "DPU OOB MAC",
        //        "DPU Firmware Version",
        //        "DPU BMC Version",
        "DPU Serial Number",
        "DPU Bios Version",
    ]);

    for machine in machines.iter() {
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
        let hostname = primary_interface.hostname.to_owned();
        let (host_serial_number, host_bios_version) = get_serial_and_version(machine);
        let (host_bmc_ip, host_bmc_mac) = get_bmc_info(machine);

        let (
            dpu_oob_ip,
            dpu_oob_mac,
            dpu_serial_number,
            dpu_bios_version,
            _dpu_bmc_ip,
            _dpu_bmc_mac,
        ) = if let Some(dpu_machine_id) = primary_interface.attached_dpu_machine_id.as_ref() {
            let dpu_machine = machines
                .iter()
                .find(|m| m.id.as_ref().map_or(false, |id| id == dpu_machine_id));

            let (dpu_serial_number, dpu_bios_version, dpu_bmc_ip, dpu_bmc_mac) = match dpu_machine {
                Some(dpu_machine) => {
                    let (dpu_serial_number, dpu_bios_version) = get_serial_and_version(dpu_machine);
                    let (dpu_bmc_ip, dpu_bmc_mac) = get_bmc_info(machine);

                    (dpu_serial_number, dpu_bios_version, dpu_bmc_ip, dpu_bmc_mac)
                }
                None => {
                    warn!(
                        "DPU Not found for machine id {:?}",
                        primary_interface.attached_dpu_machine_id
                    );
                    (
                        UNKNOWN.to_owned(),
                        UNKNOWN.to_owned(),
                        UNKNOWN.to_owned(),
                        UNKNOWN.to_owned(),
                    )
                }
            };

            machine
                .interfaces
                .iter()
                .find(|x| x.primary_interface)
                .map_or(
                    (
                        UNKNOWN.to_owned(),
                        UNKNOWN.to_owned(),
                        UNKNOWN.to_owned(),
                        UNKNOWN.to_owned(),
                        UNKNOWN.to_owned(),
                        UNKNOWN.to_owned(),
                    ),
                    |primary_interface| {
                        (
                            primary_interface.address.join(","),
                            primary_interface.mac_address.to_owned(),
                            dpu_serial_number,
                            dpu_bios_version,
                            dpu_bmc_ip,
                            dpu_bmc_mac,
                        )
                    },
                )
        } else {
            (
                UNKNOWN.to_owned(),
                UNKNOWN.to_owned(),
                UNKNOWN.to_owned(),
                UNKNOWN.to_owned(),
                UNKNOWN.to_owned(),
                UNKNOWN.to_owned(),
            )
        };

        table.add_row(row![
            hostname,
            machine_id,
            host_bmc_ip,
            host_bmc_mac,
            host_serial_number,
            host_bios_version,
            //dpu_bmc_ip,
            //dpu_bmc_mac,
            dpu_oob_ip,
            dpu_oob_mac,
            dpu_serial_number,
            dpu_bios_version,
        ]);
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
